from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

from model.Session import Session
from model.Slip import (
    AUTH_MODE_LABELS,
    AUTH_MODES,
    Slip,
    clear_wallet_admin_session,
    gen_slip,
    get_slip,
    make_session,
    normalize_media_delivery_mode,
    set_slip_auth_mode,
    slip_allows_password_login,
    slip_allows_wallet_login,
    slip_auth_mode,
    slip_can_moderate,
    slip_for_wallet,
    slip_from_id,
    slip_forwards_remote_replies,
    slip_media_delivery_mode,
    slip_is_admin,
    slip_wallet_address,
    viewer_can_moderate,
    viewer_is_admin,
)
from services.wallet_auth import issue_challenge, recover_signer, take_challenge
from shared import app, db


slip_blueprint = Blueprint('slip', __name__, template_folder='template')
slip_blueprint.add_app_template_global(get_slip)
slip_blueprint.add_app_template_global(slip_from_id)
slip_blueprint.add_app_template_global(slip_is_admin)
slip_blueprint.add_app_template_global(slip_can_moderate)
slip_blueprint.add_app_template_global(slip_media_delivery_mode)
slip_blueprint.add_app_template_global(slip_forwards_remote_replies)
slip_blueprint.add_app_template_global(viewer_is_admin)
slip_blueprint.add_app_template_global(viewer_can_moderate)

from model.Report import viewer_moderates_anything
slip_blueprint.add_app_template_global(viewer_moderates_anything)
slip_blueprint.add_app_template_global(slip_auth_mode)
slip_blueprint.add_app_template_global(slip_wallet_address)


def _current_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.environ.get("REMOTE_ADDR") or ""


def _log_failed_slip_login(name):
    app.logger.warning(
        "FAIL2BAN slip-login-failure ip=%s name=%r",
        _current_ip(),
        (name or "")[:128],
    )


@slip_blueprint.route("/")
def landing():
    return render_template("slip.html")


@slip_blueprint.route("/register", methods=["POST"])
def register():
    name = (request.form.get("name") or "").strip()
    password = request.form.get("password") or ""
    if not name or not password:
        flash("Enter a username and password to sign up.")
        return redirect(url_for("slip.landing"))
    if len(name) > 20:
        flash("Usernames must be 20 characters or fewer.")
        return redirect(url_for("slip.landing"))
    if db.session.query(Slip.id).filter(Slip.name == name).first() is not None:
        flash("That username is already taken. Please choose another.")
        return redirect(url_for("slip.landing"))
    slip = gen_slip(name, password)
    try:
        db.session.flush()
    except IntegrityError:
        # Safety net for a race between the check above and the insert.
        db.session.rollback()
        flash("That username is already taken. Please choose another.")
        return redirect(url_for("slip.landing"))
    make_session(slip)
    # The welcome grant. Recorded, not paid: it is claimed later once the
    # account has a wallet and has shown it belongs to a person. Never raises —
    # a missing grant row can be created afterwards, a failed signup cannot.
    from services.signup_grants import record_signup
    record_signup(slip)
    db.session.commit()
    return redirect(url_for("profiles.edit"))


@slip_blueprint.route("/login", methods=["POST"])
def login():
    form_name = request.form["name"]
    password = request.form["password"]
    slip = db.session.query(Slip).filter(Slip.name == form_name).one_or_none()
    if slip:
        if check_password_hash(slip.pass_hash, password):
            # The password is right, but this account asked for wallet-only
            # sign-in. Checked AFTER the hash comparison on purpose: answering
            # before it would turn this into an oracle for which usernames exist
            # and how they log in.
            if not slip_allows_password_login(slip):
                flash("This slip is set to MetaMask-only sign-in. Use \"Sign in with MetaMask\".")
                return redirect(url_for("slip.landing"))
            make_session(slip)
            db.session.commit()
            return redirect(url_for("profiles.edit"))
        else:
            _log_failed_slip_login(form_name)
            flash("Incorrect username or password!")
    else:
        _log_failed_slip_login(form_name)
        flash("Incorrect username or password!")
    return redirect(url_for("slip.landing"))


WALLET_LOGIN_PURPOSE = "slip-login"


@slip_blueprint.route("/wallet/challenge", methods=["POST"])
def wallet_challenge():
    """Mint the message the wallet will sign to prove ownership."""
    _nonce, message = issue_challenge(
        WALLET_LOGIN_PURPOSE, "sign in to your slip"
    )
    return jsonify({"message": message})


@slip_blueprint.route("/wallet/login", methods=["POST"])
def wallet_login():
    """Sign in with a wallet signature over the issued challenge.

    The account is resolved from the address RECOVERED from the signature, never
    from an address the page claims — the latter is just an assertion anyone can
    make.
    """
    payload = request.get_json(silent=True) or {}
    signature = payload.get("signature")
    claimed = payload.get("address")

    taken, error = take_challenge(WALLET_LOGIN_PURPOSE)
    if error:
        return jsonify({"error": error}), 400
    nonce, issued_at = taken

    from services.wallet_auth import build_message

    message = build_message("sign in to your slip", nonce, issued_at)
    try:
        recovered = recover_signer(message, signature, claimed)
    except RuntimeError:
        return jsonify({"error": "Wallet verification is unavailable right now. Try again shortly."}), 502
    if recovered is None:
        _log_failed_slip_login("wallet:%s" % (claimed or "?"))
        return jsonify({"error": "That signature did not verify."}), 403

    slip = slip_for_wallet(recovered)
    if slip is None:
        return jsonify({
            "error": "No slip is linked to %s. Log in with your password first, "
                     "then link this wallet from your profile." % recovered,
        }), 404
    if not slip_allows_wallet_login(slip):
        return jsonify({
            "error": "This slip has wallet sign-in turned off. Enable it in "
                     "your profile's sign-in settings.",
        }), 403

    from model.Slip import AUTH_BY_WALLET
    make_session(slip, method=AUTH_BY_WALLET)
    db.session.commit()
    return jsonify({"ok": True, "redirect": url_for("profiles.edit")})


@slip_blueprint.route("/auth-mode", methods=["POST"])
def auth_mode():
    """Choose which sign-in methods this slip accepts."""
    slip = get_slip()
    if slip is None:
        flash("You must be logged in to change sign-in settings.")
        return redirect(url_for("slip.landing"))
    mode = (request.form.get("auth_mode") or "").strip()
    if mode not in AUTH_MODES:
        flash("Unknown sign-in mode.")
        return redirect(url_for("profiles.edit"))
    try:
        set_slip_auth_mode(slip, mode)
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("profiles.edit"))
    db.session.commit()
    flash("Sign-in method updated: %s." % AUTH_MODE_LABELS[mode])
    return redirect(url_for("profiles.edit"))


@slip_blueprint.route("/unset")
def unset():
    if session.get("session-id"):
        session_id = session["session-id"]
        user_session = db.session.query(Session).filter(Session.id.like(session_id)).one()
        db.session.delete(user_session)
        db.session.commit()
        session.pop("session-id")
    clear_wallet_admin_session()
    return redirect(url_for("slip.landing"))


@slip_blueprint.route("/media-preference", methods=["POST"])
def media_preference():
    slip = get_slip()
    if slip is None:
        flash("You must be logged in to change media delivery settings.")
        return redirect(url_for("slip.landing"))
    slip.media_delivery_mode = normalize_media_delivery_mode(request.form.get("media_delivery_mode"))
    db.session.add(slip)
    db.session.commit()
    flash("Media delivery preference updated.")
    return redirect(request.referrer or url_for("slip.landing"))


def _boolean_preference(value):
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    if normalized in ("1", "true", "yes", "on", "forward"):
        return True
    if normalized in ("0", "false", "no", "off", "local"):
        return False
    raise ValueError("forward_remote_replies must be true or false")


@slip_blueprint.route("/remote-reply-preference", methods=["POST"])
def remote_reply_preference():
    slip = get_slip()
    wants_json = request.is_json or request.accept_mimetypes.best == "application/json"
    if slip is None:
        if wants_json:
            return jsonify({"error": "login_required"}), 401
        flash("You must be logged in to save a reply destination preference.")
        return redirect(url_for("slip.landing"))
    payload = request.get_json(silent=True) if request.is_json else request.form
    try:
        slip.forward_remote_replies = _boolean_preference(
            (payload or {}).get("forward_remote_replies")
        )
    except ValueError as exc:
        if wants_json:
            return jsonify({"error": str(exc)}), 400
        flash(str(exc))
        return redirect(request.referrer or url_for("slip.landing"))
    db.session.add(slip)
    db.session.commit()
    if wants_json:
        return jsonify({"forward_remote_replies": bool(slip.forward_remote_replies)})
    flash("Remote reply preference updated.")
    return redirect(request.referrer or url_for("slip.landing"))
