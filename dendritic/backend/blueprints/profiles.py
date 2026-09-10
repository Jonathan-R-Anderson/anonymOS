import mimetypes
import re
from flask import Blueprint, abort, jsonify, render_template, request, redirect, url_for, flash, session, current_app

from model.Profile import Profile, normalize_chat_accent
from model.Media import Media, resolve_attachment_content_type, storage
from model.Slip import (
    AUTH_MODE_LABELS,
    AUTH_MODE_WALLET,
    AUTH_MODES,
    get_slip,
    session_proved_by_wallet,
    slip_auth_mode,
    slip_for_wallet,
    slip_wallet_address,
)
from services.wallet_auth import build_message, issue_challenge, recover_signer, take_challenge
from shared import db
from services.css_rewrite import rewrite_css_image_urls


def _save_profile_avatar(profile):
    """Store an uploaded profile picture and point the profile at it. Replaces
    (and deletes) any previous avatar. Raises ValueError on a non-image."""
    uploaded = request.files.get("avatar")
    if uploaded is None or not getattr(uploaded, "filename", ""):
        return
    mimetype = resolve_attachment_content_type(uploaded)
    if not mimetype.startswith("image/"):
        raise ValueError("Your profile picture must be an image file.")
    media = storage.save_attachment(uploaded, mimetype)
    old_media_id = profile.avatar_media_id
    profile.avatar_media_id = media.id
    if old_media_id and old_media_id != media.id:
        old_media = db.session.query(Media).filter(Media.id == old_media_id).one_or_none()
        if old_media is not None:
            try:
                old_media.delete_attachment()
            except Exception:
                current_app.logger.exception("Failed deleting old avatar media %s", old_media_id)
            db.session.delete(old_media)

profiles_blueprint = Blueprint('profiles', __name__, template_folder='template')
PROFILE_SLUG_PATTERN = re.compile(r"[^a-z0-9-]+")

def sanitize_profile_html(html):
    return html

def sanitize_profile_css(css):
    return rewrite_css_image_urls(css)


def _suggest_profile_slug(slip):
    base = PROFILE_SLUG_PATTERN.sub("-", (slip.name or "").strip().lower()).strip("-")
    if not base:
        base = "user"
    return "%s-%d" % (base, slip.id)

@profiles_blueprint.route("/edit", methods=["GET", "POST"])
def edit():
    from model.Membership import membership_for
    from services.membership import plan as membership_plan

    slip = get_slip()
    if not slip:
        flash("You must be logged in to manage your profile.")
        return redirect(url_for("slip.landing"))
    
    profile = db.session.query(Profile).filter(Profile.slip_id == slip.id).one_or_none()
    if request.method == "POST":
        slug = (request.form.get("slug") or "").strip().lower()
        # Normalize to the channel-safe charset so each profile maps to exactly
        # one unique IRC channel (#profile-<slug>) — the chat client strips any
        # other characters, which could otherwise collide two slugs onto the same
        # channel — and so it stays a clean URL slug.
        slug = re.sub(r"[^a-z0-9_-]", "", slug)
        if not slug:
            flash("Custom URL slug is required (letters, numbers, hyphens or underscores).")
            return redirect(url_for("profiles.edit"))
        
        # Check slug uniqueness across BOTH namespaces that share this path.
        #
        # Author pages live at one URL space whether the author is a profile or
        # a newsroom pen name, and `model.PenName.slug_is_available` already
        # checks both when a pen name is created. This side was unguarded, and
        # it is the worse direction because it is a CHANGE path: an existing
        # account could claim a pen name's slug at any time.
        #
        # Pen-name slugs are published in every byline link, so the target is
        # sitting in the HTML. Capturing one makes /news/author/<slug> serve the
        # pen name's archive from the attacker's byline, puts the pen name's
        # stories in the "more from this author" rail under the attacker's
        # article, and leaves the pen name's own page unreachable -- the site
        # publishing a claim that links a pseudonymous body of work to a named
        # account. It also works as denial-of-identity in the other direction.
        existing = db.session.query(Profile).filter(Profile.slug == slug).one_or_none()
        if existing and existing.slip_id != slip.id:
            flash("That URL slug is already taken.")
            return redirect(url_for("profiles.edit"))

        from model.PenName import PenName

        # Retired pen names still count as taken: a released name is never
        # reissued, precisely so nobody inherits its readers.
        pen_name_holder = (db.session.query(PenName.id)
                           .filter(PenName.slug == slug).first())
        if pen_name_holder is not None:
            flash("That URL slug is already taken.")
            return redirect(url_for("profiles.edit"))

        if not profile:
            profile = Profile(slip_id=slip.id, slug=slug)
            db.session.add(profile)
        
        profile.slug = slug
        profile.is_public = request.form.get("is_public") == "on"
        profile.embed_stream = request.form.get("embed_stream") == "on"
        profile.link_on_comments = request.form.get("link_on_comments") == "on"
        # Where this author's payment-channel node can be reached, so awards can
        # be paid over a channel instead of on chain (roadmap P9). Blank is the
        # normal answer and simply means awards keep arriving as transfers.
        #
        # https only, and validated here rather than at award time: a tip flow
        # pointed at http:// would let a network attacker rewrite the state the
        # giver's browser is about to sign against. Refusing silently would be
        # worse than refusing loudly, so a bad value is dropped and said so.
        _endpoint = (request.form.get("channel_endpoint") or "").strip()
        if not _endpoint:
            profile.channel_endpoint = None
        elif _endpoint.startswith("https://") and len(_endpoint) <= 255:
            profile.channel_endpoint = _endpoint
        else:
            flash("A payment-channel address must start with https:// — that one was not saved.")
        # Pooled tipping (P15). A switch and a label — the platform stores no
        # balance and no channel list. Enabling it only advertises that the
        # owner accepts tips; it does NOT open a channel or move any funds,
        # which stay explicit actions requiring the owner's own wallet.
        profile.pool_enabled = request.form.get("pool_enabled") == "on"
        _pool_name = (request.form.get("pool_name") or "").strip()
        profile.pool_name = _pool_name[:64] or None
        # Which volunteer carries this creator's tips, and on what terms.
        #
        # THE MODE IS A LABEL, NOT AN AUTHORITY. Whether a volunteer may
        # actually sign is decided by AxonChannels.canSign; writing
        # "delegate" here without doing the on-chain authorisation produces a
        # volunteer that cannot sign, which is the safe direction to fail. An
        # unrecognised value reads as mailbox for the same reason.
        _volunteer = (request.form.get("pool_volunteer") or "").strip()
        profile.pool_volunteer = _volunteer[:128] or None
        _mode = (request.form.get("pool_signing_mode") or "").strip().lower()
        profile.pool_signing_mode = _mode if _mode in ("mailbox", "delegate") else "mailbox"
        # The volunteer's mailbox. https only, and a bad value is dropped LOUDLY
        # rather than stored: a mailbox nobody can reach produces a Tip button
        # that queues nowhere.
        _vol_ep = (request.form.get("pool_volunteer_endpoint") or "").strip()
        if not _vol_ep:
            profile.pool_volunteer_endpoint = None
        elif _vol_ep.startswith("https://") and len(_vol_ep) <= 255:
            profile.pool_volunteer_endpoint = _vol_ep
        else:
            flash("A tip mailbox address must start with https:// — that one was not saved.")

        profile.enable_chat = request.form.get("enable_chat") == "on"
        profile.show_avatar = request.form.get("show_avatar") == "on"
        profile.chat_theme = "dark" if request.form.get("chat_theme") == "dark" else "light"
        profile.chat_accent = normalize_chat_accent(request.form.get("chat_accent"))
        profile.enable_place = request.form.get("enable_place") == "on"
        try:
            _tl_days = int(request.form.get("place_timelapse_days") or 7)
        except (TypeError, ValueError):
            _tl_days = 7
        profile.place_timelapse_days = min(60, max(1, _tl_days))
        try:
            _timeout = int(request.form.get("session_timeout_minutes") or 0)
        except (TypeError, ValueError):
            _timeout = 0
        profile.session_timeout_minutes = min(43200, max(0, _timeout))  # cap at 30 days
        try:
            _save_profile_avatar(profile)
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc))
            return redirect(url_for("profiles.edit"))
        profile.custom_html = sanitize_profile_html(request.form.get("custom_html", ""))
        profile.custom_css = sanitize_profile_css(request.form.get("custom_css", ""))

        db.session.commit()
        flash("Profile updated successfully!")
        return redirect(url_for("profiles.edit"))

    from model.BotToken import bot_tokens_for_slip
    return render_template(
        "profile-settings.html",
        profile=profile,
        # The username card renders slip.name. Missing here, the whole settings
        # page 500s on an undefined — the route already had `slip` in hand and
        # simply never passed it.
        slip=slip,
        # Whether this session was proved by a signature. Decides whether the
        # form asks for a current password, and must agree with the route that
        # receives it — a form that asks for something the handler does not want
        # is how somebody ends up unable to rename their own account.
        proved_by_wallet=session_proved_by_wallet(),
        # Account settings is where people go to cancel a subscription, so the
        # membership is shown here as well as on the page that sells it.
        membership=membership_for(slip.id),
        membership_plan=membership_plan(),
        suggested_slug=_suggest_profile_slug(slip),
        bot_tokens=bot_tokens_for_slip(slip.id),
        new_bot_token=session.pop("_new_bot_token", None),
        wallet_address=slip_wallet_address(slip),
        auth_mode=slip_auth_mode(slip),
        auth_mode_labels=AUTH_MODE_LABELS,
        auth_modes=AUTH_MODES,
    )


@profiles_blueprint.route("/delete", methods=["POST"])
def delete():
    slip = get_slip()
    if not slip:
        flash("You must be logged in to manage your profile.")
        return redirect(url_for("slip.landing"))

    profile = db.session.query(Profile).filter(Profile.slip_id == slip.id).one_or_none()
    if profile is None:
        flash("You do not have a profile page to delete.")
        return redirect(url_for("profiles.edit"))

    db.session.delete(profile)
    db.session.commit()
    flash("Your custom profile page has been deleted.")
    return redirect(url_for("profiles.edit"))


@profiles_blueprint.route("/bot/register", methods=["POST"])
def bot_register():
    """Register a dedicated bot IP and mint a one-time API token for it, so the
    owner's bot can post via /api/v1/bot/post from that IP."""
    slip = get_slip()
    if not slip:
        flash("You must be logged in to register a bot.")
        return redirect(url_for("slip.landing"))
    import ipaddress
    from model.BotToken import create_bot_token
    raw_ip = (request.form.get("ip") or "").strip()
    label = (request.form.get("label") or "").strip()
    try:
        normalized_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        flash("Enter a valid IPv4 or IPv6 address that your bot will post from.")
        return redirect(url_for("profiles.edit"))
    raw_token, _record = create_bot_token(slip.id, normalized_ip, label)
    # Shown exactly once — the edit page displays it, then it's gone (only the
    # hash is stored).
    session["_new_bot_token"] = raw_token
    flash("Bot credential created. Copy the token now — it will not be shown again.")
    return redirect(url_for("profiles.edit"))


@profiles_blueprint.route("/bot/revoke/<int:token_id>", methods=["POST"])
def bot_revoke(token_id):
    slip = get_slip()
    if not slip:
        flash("You must be logged in to manage bot credentials.")
        return redirect(url_for("slip.landing"))
    from model.BotToken import BotToken
    record = db.session.query(BotToken).filter(
        BotToken.id == token_id, BotToken.slip_id == slip.id
    ).one_or_none()
    if record is not None:
        db.session.delete(record)
        db.session.commit()
        flash("Bot credential revoked.")
    return redirect(url_for("profiles.edit"))


WALLET_LINK_PURPOSE = "profile-link"


@profiles_blueprint.route("/wallet/challenge", methods=["POST"])
def wallet_challenge():
    if not get_slip():
        return jsonify({"error": "Not logged in"}), 403
    _nonce, message = issue_challenge(
        WALLET_LINK_PURPOSE, "link this wallet to your slip"
    )
    return jsonify({"message": message})


@profiles_blueprint.route("/link-wallet", methods=["POST"])
def link_wallet():
    """Attach a wallet to this slip, proven by a signature over a fresh nonce.

    Verification goes through the renderer rather than `eth_account`: that
    import is not present in the runtime image, so this endpoint answered 501
    for every user who ever pressed the button.
    """
    slip = get_slip()
    if not slip:
        return jsonify({"error": "Not logged in"}), 403

    data = request.get_json(silent=True) or {}
    address = data.get("address")
    signature = data.get("signature")

    taken, error = take_challenge(WALLET_LINK_PURPOSE)
    if error:
        return jsonify({"error": error}), 400
    nonce, issued_at = taken

    message = build_message("link this wallet to your slip", nonce, issued_at)
    try:
        recovered = recover_signer(message, signature, address)
    except RuntimeError:
        return jsonify({"error": "Wallet verification is unavailable right now. Try again shortly."}), 502
    if recovered is None:
        return jsonify({"error": "That signature did not verify."}), 400

    # One wallet, one slip: a shared address would make wallet sign-in
    # ambiguous about which account it unlocks.
    owner = slip_for_wallet(recovered)
    if owner is not None and owner.id != slip.id:
        return jsonify({"error": "That wallet is already linked to another slip."}), 409

    profile = db.session.query(Profile).filter(Profile.slip_id == slip.id).one_or_none()
    if not profile:
        profile = Profile(slip_id=slip.id, slug=f"user-{slip.id}")
        db.session.add(profile)
    profile.eth_address = recovered
    db.session.commit()
    return jsonify({"success": True, "address": recovered})


@profiles_blueprint.route("/unlink-wallet", methods=["POST"])
def unlink_wallet():
    slip = get_slip()
    if not slip:
        flash("You must be logged in to manage your wallet.")
        return redirect(url_for("slip.landing"))
    # Removing the wallet while it is the only accepted credential would lock
    # the owner out permanently — there is no password recovery on this site.
    if slip_auth_mode(slip) == AUTH_MODE_WALLET:
        flash("Switch sign-in away from MetaMask-only before unlinking this wallet.")
        return redirect(url_for("profiles.edit"))
    profile = db.session.query(Profile).filter(Profile.slip_id == slip.id).one_or_none()
    if profile is None or not profile.eth_address:
        flash("No wallet is linked to this slip.")
        return redirect(url_for("profiles.edit"))
    profile.eth_address = None
    db.session.commit()
    flash("Wallet unlinked.")
    return redirect(url_for("profiles.edit"))

# The blueprint is registered with url_prefix="/profile", so this path must NOT
# repeat it. It did, and the endpoint was published at
# /profile/profile/<slug>/tip/quote while tip-flow.js correctly asked for
# /profile/<slug>/tip/quote — so the quote endpoint was unreachable from the
# shipped page for as long as it has existed. Caught by loading the real site in
# Firefox; the route test read this decorator string rather than the URL map, so
# it saw the intended path and never noticed the one Flask actually registered.
@profiles_blueprint.route("/<slug>/tip/quote", methods=["POST"])
def tip_quote(slug):
    """What it would cost to tip this creator, and whether a path exists.

    A QUOTE IS NOT AUTHORIZATION. Nothing here signs, moves value, opens a
    channel or writes a row. It reads two things — who, and how much — and
    answers with a description the visitor reads before deciding.

    THE RECIPIENT COMES FROM THE URL, NEVER FROM THE BODY. The slug is resolved
    against application state, so a caller cannot name a wallet, a channel or a
    node of their choosing and have the browser sign against it. For the same
    reason the response carries NO channel identifier: tip-channel.js derives
    the channel itself from the visitor's own wallet address.
    """
    profile = (db.session.query(Profile)
               .filter(Profile.slug == slug)
               .one_or_none())
    if profile is None or not profile.is_public:
        return jsonify({"error": "unknown_profile"}), 404

    slip = get_slip()
    if slip is None:
        return jsonify({"error": "slip_required"}), 401

    from services.pooled_tips import PooledTipError, quote

    payload = request.get_json(silent=True) or request.form
    try:
        quoted = quote(profile.slip, slip, amount=payload.get("amount"))
    except PooledTipError as exc:
        # The message is written to be shown to the visitor.
        return jsonify({"error": "unavailable", "message": str(exc)}), 400

    # The URLs are the server's to name, exactly as the award route decides
    # them: a module that works out what a payment means should not also be
    # deciding where a script lives.
    quoted = dict(
        quoted,
        client_url=url_for("serve_static", path="pof/tip-channel.js"),
        bundle_url=url_for("serve_static", path="pof/chain-bundle.js"),
    )
    return jsonify(quoted)


@profiles_blueprint.route("/u/<slug>")
def view(slug):
    profile = db.session.query(Profile).filter(Profile.slug == slug).one_or_none()
    if not profile:
        return render_template("not-found.html"), 404

    if not profile.is_public:
        slip = get_slip()
        if not slip or slip.id != profile.slip_id:
            return "This profile is private.", 403

    stream = None
    if profile.embed_stream:
        from model.Stream import Stream
        stream = db.session.query(Stream).filter(Stream.slip_id == profile.slip_id).one_or_none()

    # Arcade standing: level, XP, streak, badges and the skill radar. This is
    # what replaced CodePlay's own profile page -- its stats live on the slip's
    # existing profile rather than on a second, parallel one.
    from services.codeplay import profile_summary
    arcade = profile_summary(profile.slip)

    # A node's standing belongs to whoever operates it, so an operator's profile
    # shows the nodes paying out to their wallet. Absent for everyone else
    # rather than shown as zero: most people run none, and a bad-looking score
    # for someone who never opted in would be meaningless.
    from services.reputation import reputation_for_wallet

    reputation = reputation_for_wallet(profile.eth_address) if profile.eth_address else None

    # Awards this person has been given on their posts. Shown as a total rather
    # than per-post because the profile is where recognition accumulates.
    from model.PostAward import totals_for_slip

    awards = totals_for_slip(profile.slip_id)
    return render_template("profile-view.html", profile=profile, stream=stream,
                           arcade=arcade, reputation=reputation, awards=awards)


@profiles_blueprint.route("/u/<slug>/preview")
def preview(slug):
    """Compact profile card for the hover preview shown on a poster's name."""
    profile = db.session.query(Profile).filter(Profile.slug == slug).one_or_none()
    if not profile or not profile.is_public:
        abort(404)
    is_live = False
    if profile.embed_stream:
        from model.Stream import Stream
        stream = db.session.query(Stream).filter(Stream.slip_id == profile.slip_id).one_or_none()
        is_live = bool(stream and stream.is_live)
    return render_template("includes/profile-preview.html", profile=profile, is_live=is_live)


def _place_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "?"


def _place_profile_or_404(slug):
    profile = db.session.query(Profile).filter(Profile.slug == slug).one_or_none()
    if profile is None or not profile.enable_place:
        abort(404)
    if not profile.is_public:
        slip = get_slip()
        if not slip or slip.id != profile.slip_id:
            abort(404)
    return profile


@profiles_blueprint.route("/u/<slug>/place.json")
def place_canvas(slug):
    _place_profile_or_404(slug)
    from services.place import get_canvas
    return jsonify(get_canvas(slug))


@profiles_blueprint.route("/u/<slug>/place", methods=["POST"])
def place_pixel_route(slug):
    _place_profile_or_404(slug)
    from services.place import place_pixel
    data = request.get_json(silent=True) or request.form
    try:
        result = place_pixel(slug, data.get("x"), data.get("y"),
                             data.get("color") or data.get("c"), _place_client_ip())
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify(result), (200 if result.get("ok") else 429)


@profiles_blueprint.route("/u/<slug>/place/recent")
def place_recent(slug):
    """Live feed: pixels placed since ?since=<version>. Each carries `age`
    seconds so the client can blink the ones active painters just placed."""
    _place_profile_or_404(slug)
    from services.place import recent_since, canvas_version
    try:
        since = int(request.args.get("since", "0"))
    except (TypeError, ValueError):
        since = 0
    return jsonify({"version": canvas_version(slug), "pixels": recent_since(slug, since)})


@profiles_blueprint.route("/u/<slug>/place/days")
def place_days(slug):
    profile = _place_profile_or_404(slug)
    from services.place import snapshot_days
    limit = min(60, max(1, getattr(profile, "place_timelapse_days", 7) or 7))
    return jsonify({"days": snapshot_days(slug, limit=limit), "timelapse_days": limit})


@profiles_blueprint.route("/u/<slug>/place/snapshot/<day>")
def place_snapshot(slug, day):
    _place_profile_or_404(slug)
    from services.place import get_snapshot
    snap = get_snapshot(slug, day)
    if snap is None:
        abort(404)
    return jsonify(snap)


@profiles_blueprint.route("/u/<slug>/place/clear", methods=["POST"])
def place_clear_route(slug):
    """Wipe the wall — profile owner or a moderator only."""
    profile = db.session.query(Profile).filter(Profile.slug == slug).one_or_none()
    if profile is None:
        abort(404)
    slip = get_slip()
    from model.Slip import slip_can_moderate
    if not slip or (slip.id != profile.slip_id and not slip_can_moderate(slip=slip)):
        abort(403)
    from services.place import clear_canvas
    return jsonify({"ok": True, "version": clear_canvas(slug)})


@profiles_blueprint.route("/account", methods=["POST"])
def account_update():
    """Change the slip's username and/or password.

    Both were previously unchangeable, which mattered most for the wallet admin:
    the slip was looked up BY NAME (`wallet-admin`), so renaming it did not fail
    — it created a second admin slip on the next sign-in and stranded everything
    attached to the first. That lookup is now by wallet, so the name is free.

    The name is also the public one. There is no separate display name on this
    site, so the moderator list, capcodes and profiles all render the slip name
    — which is exactly why being stuck with "wallet-admin" was wrong.
    """
    from werkzeug.security import check_password_hash, generate_password_hash

    from model.Slip import Slip, get_slip
    from shared import db

    slip = get_slip()
    if slip is None:
        flash("Sign in first.")
        return redirect(url_for("slip.landing"))

    current = request.form.get("current_password") or ""
    new_name = (request.form.get("new_name") or "").strip()
    new_password = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""

    # The current password is required for BOTH changes, not just the password
    # one. A borrowed session that can rename the account can impersonate its
    # owner everywhere the name appears, which is every post they have made.
    #
    # A wallet-authenticated slip has no password the operator ever chose (it is
    # a random hash), so requiring one would lock them out of their own name —
    # the very case this exists to fix. Their session was proven by a signature
    # instead, which is not a weaker proof.
    #
    # Keyed on how THIS SESSION was proven, not on the slip's auth_mode. The
    # first version tested `auth_mode != "wallet"` and did not work for the one
    # account it was written for: the wallet admin is "either", so it was still
    # asked for a password that has never existed. A slip set to "either" can be
    # holding a real password or a random one, and the mode cannot tell them
    # apart — but a session that arrived by signature has already proved
    # ownership, whichever it is.
    from model.Slip import session_proved_by_wallet, slip_allows_password_login

    needs_password = slip_allows_password_login(slip) and not session_proved_by_wallet()
    if needs_password and not check_password_hash(slip.pass_hash, current):
        flash("That is not your current password.")
        return redirect(url_for("profiles.edit"))

    changed = []

    if new_name and new_name != slip.name:
        if len(new_name) > 20:
            flash("Usernames must be 20 characters or fewer.")
            return redirect(url_for("profiles.edit"))
        taken = (
            db.session.query(Slip.id)
            .filter(db.func.lower(Slip.name) == new_name.lower(), Slip.id != slip.id)
            .first()
        )
        if taken is not None:
            # Case-insensitive, because two accounts differing only in case are
            # indistinguishable in every place a name is read.
            flash("That username is already taken.")
            return redirect(url_for("profiles.edit"))
        slip.name = new_name
        changed.append("username")

    if new_password:
        if new_password != confirm:
            flash("The new passwords do not match.")
            return redirect(url_for("profiles.edit"))
        if len(new_password) < 8:
            flash("Use a password of at least 8 characters.")
            return redirect(url_for("profiles.edit"))
        slip.pass_hash = generate_password_hash(new_password)
        changed.append("password")

    if not changed:
        flash("Nothing to change.")
        return redirect(url_for("profiles.edit"))

    db.session.add(slip)
    db.session.commit()
    flash("Updated your %s." % " and ".join(changed))
    return redirect(url_for("profiles.edit"))
