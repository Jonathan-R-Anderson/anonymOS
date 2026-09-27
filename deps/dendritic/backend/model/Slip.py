import secrets
import uuid

from flask import has_request_context, session
from sqlalchemy import true
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash

from model.Session import Session
from shared import app, db


ADMIN_WALLET_SESSION_KEY = "admin-wallet-address"
DEFAULT_ADMIN_WALLET_ADDRESS = "0xb2b36aad18d7be5d4016267bc4ccec2f12a64b6e"
WALLET_ADMIN_SLIP_NAME = "wallet-admin"
DEFAULT_MEDIA_DELIVERY_MODE = "torrent"
MEDIA_DELIVERY_MODES = {"torrent", "direct"}
DEFAULT_FORWARD_REMOTE_REPLIES = True

# How a slip is allowed to authenticate.
#   password — password only; wallet sign-in refused even if a wallet is linked
#   wallet   — MetaMask only; the password stops working
#   either   — whichever the account holder has to hand
AUTH_MODE_PASSWORD = "password"
AUTH_MODE_WALLET = "wallet"
AUTH_MODE_EITHER = "either"
AUTH_MODES = (AUTH_MODE_PASSWORD, AUTH_MODE_WALLET, AUTH_MODE_EITHER)
# Existing accounts default to password-only. Wallet sign-in is opt-in: some
# users already linked a wallet for other reasons, and silently turning that
# into a second way to log into their account is not a change to make on their
# behalf.
DEFAULT_AUTH_MODE = AUTH_MODE_PASSWORD

AUTH_MODE_LABELS = {
    AUTH_MODE_PASSWORD: "Password only",
    AUTH_MODE_WALLET: "MetaMask wallet only",
    AUTH_MODE_EITHER: "Either password or wallet",
}


def gen_slip(name, password):
    pass_hash = generate_password_hash(password)
    slip = Slip(name=name, pass_hash=pass_hash)
    db.session.add(slip)
    return slip


def get_slip():
    session_id = session.get("session-id")
    if session_id:
        try:
            user_session = db.session.query(Session).filter(Session.id == session_id).one_or_none()
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Failed loading viewer slip session %s", session_id)
            return None
        if user_session is None:
            session.pop("session-id")
            clear_wallet_admin_session()
            return None
        try:
            return db.session.query(Slip).filter(Slip.id == user_session.slip_id).one_or_none()
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Failed loading viewer slip %s", user_session.slip_id)
            return None
    clear_wallet_admin_session()
    return None


def get_slip_bitmask():
    slip = get_slip()
    if slip is None:
        return 0
    bitmask = 1
    if slip_is_admin(slip):
        bitmask |= 2
    if slip_can_moderate(slip) and not slip_is_admin(slip):
        bitmask |= 4
    return bitmask


def slip_from_id(slip_id):
    try:
        return db.session.query(Slip).filter(Slip.id == slip_id).one_or_none()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed loading slip %s", slip_id)
        return None


SESSION_AUTH_KEY = "auth-method"
AUTH_BY_PASSWORD = "password"
AUTH_BY_WALLET = "wallet"


def make_session(slip, method=AUTH_BY_PASSWORD):
    """Start a session, recording HOW it was proven.

    The method matters later: a wallet-created slip has no password anybody ever
    chose (see ensure_wallet_admin_slip — it is a random hash), so asking for
    "your current password" before letting them rename the account or set a real
    one is asking for a string that does not exist. A signature is not a weaker
    proof of ownership than a password, so a wallet-proven session is allowed to
    do what a password-proven one can.

    Defaults to password because that is what an unannotated caller is: the
    dangerous mistake would be defaulting to wallet and skipping the check for a
    session that never proved anything.
    """
    import time as _time
    session_id = uuid.uuid4().hex
    user_session = Session(id=session_id, slip_id=slip.id)
    session["session-id"] = user_session.id
    session[SESSION_AUTH_KEY] = method
    # Persist the cookie and seed the idle-timeout clock (see the per-account
    # auto-logout enforced in app.py's before_request).
    session.permanent = True
    session["la"] = int(_time.time())
    db.session.add(user_session)
    return user_session


def normalize_wallet_address(address):
    if address is None:
        return None
    return address.strip().lower()


def wallet_admin_address():
    return configured_admin_wallet_address()


def configured_admin_wallet_address():
    return normalize_wallet_address(
        app.config.get("ADMIN_WALLET_ADDRESS") or DEFAULT_ADMIN_WALLET_ADDRESS
    )


def clear_wallet_admin_session():
    session.pop(ADMIN_WALLET_SESSION_KEY, None)


def is_wallet_admin_session(address=None):
    target_address = normalize_wallet_address(address) or configured_admin_wallet_address()
    held = normalize_wallet_address(session.get(ADMIN_WALLET_SESSION_KEY))
    # Both empty must NOT compare equal. It cannot happen today, because
    # DEFAULT_ADMIN_WALLET_ADDRESS is a hardcoded non-empty constant — but this
    # function grants moderation (see slip_can_moderate), so if that default
    # ever became empty, `None == None` would quietly make every anonymous
    # visitor a wallet admin. Cheap to rule out, expensive to discover.
    if not target_address or not held:
        return False
    return held == target_address


def session_proved_by_wallet():
    """Whether the current session was established by a signature.

    Two signals, because one of them is new. SESSION_AUTH_KEY is written by
    make_session and is the general answer; ADMIN_WALLET_SESSION_KEY predates it
    and is already sitting in the cookie of anybody signed in as the wallet
    admin right now. Without the second, this change would only take effect
    after they signed out and back in — and the person it was written for is
    exactly the one who would have hit that.
    """
    if session.get(SESSION_AUTH_KEY) == AUTH_BY_WALLET:
        return True
    return is_wallet_admin_session()


def ensure_wallet_admin_slip():
    """The slip the configured admin wallet signs in as.

    Found by the WALLET, not by the name. It used to be looked up as
    `Slip.name == "wallet-admin"`, which quietly made that name permanent: a
    rename did not fail, it created a SECOND admin slip on the next sign-in and
    stranded everything attached to the first — posts, moderation, credits.

    The wallet is the identity. The name is a label the operator should be able
    to change to whatever they are called in public, and now can.
    """
    from model.Profile import Profile

    configured = configured_admin_wallet_address()
    if configured:
        owner = slip_for_wallet(configured)
        if owner is not None:
            # Adopt it: an install that renamed the slip before this fix has a
            # correctly-linked slip under the wrong name, and finding it is the
            # whole point.
            if owner.is_admin is False:
                owner.is_admin = True
                db.session.add(owner)
                db.session.flush()
            return owner

    # Not found by wallet. Either this install predates the wallet link, or the
    # admin slip has never been created.
    slip = db.session.query(Slip).filter(Slip.name == WALLET_ADMIN_SLIP_NAME).one_or_none()
    if slip is None:
        slip = Slip(
            name=WALLET_ADMIN_SLIP_NAME,
            pass_hash=generate_password_hash(secrets.token_hex(32)),
            is_admin=True,
            is_mod=False,
            # AUTH_MODE_EITHER, not the DEFAULT_AUTH_MODE of password-only.
            #
            # The password above is a random 32-byte hex string that is hashed
            # and then discarded -- nobody knows it and nobody can ever know it.
            # Leaving this slip on password-only auth therefore creates an
            # account that CANNOT BE SIGNED INTO BY ANY MEANS: the password is
            # unknowable and slip_allows_wallet_login() refuses the wallet.
            # That is the second half of the bug the linking above fixes, and
            # fixing only one of them still leaves the admin locked out.
            auth_mode=AUTH_MODE_EITHER,
        )
        db.session.add(slip)
        db.session.flush()
    else:
        if slip.is_admin is False:
            slip.is_admin = True
            db.session.add(slip)
        if slip_auth_mode(slip) == AUTH_MODE_PASSWORD:
            # Repairs an install created before the line above existed. Widened
            # to EITHER rather than forced to WALLET: an operator who has since
            # set a real password on this slip keeps it working.
            #
            # Savepointed for the same reason as the wallet link: if the
            # auth_mode column does not exist on this database, the admin must
            # still be able to sign in and fix it.
            try:
                with db.session.begin_nested():
                    slip.auth_mode = AUTH_MODE_EITHER
                    db.session.add(slip)
                    db.session.flush()
            except SQLAlchemyError:
                app.logger.exception("Could not widen auth_mode on slip %s", slip.name)
        db.session.flush()

    # LINK THE WALLET. This used to happen only in the legacy branch above --
    # only for an install that ALREADY had a slip named "wallet-admin" -- so on
    # a fresh install the admin slip was created with no Profile and no
    # eth_address at all, and slip_for_wallet() could never find it.
    #
    # The symptom was confusing because the two sign-in paths disagreed:
    # /admin/login worked, because begin_wallet_admin_session calls this
    # function and does not need the link, while the SITE's "Sign in with
    # MetaMask" answered "No slip is linked to 0x..." for the admin's own
    # wallet, forever. Linking here rather than only in the legacy branch is
    # what makes the two paths agree.
    if configured:
        _link_wallet_to_slip(slip, configured)
    return slip


def _link_wallet_to_slip(slip, address):
    """Attach `address` to `slip`'s profile, creating the profile if needed.

    Never steals an address from another slip. Profile.eth_address is UNIQUE, so
    assigning one that another slip holds would raise on flush and take down
    whatever called us -- which, for this function's main caller, is the admin
    login path. A conflict is logged and left alone: the operator pointing
    ADMIN_WALLET_ADDRESS at a wallet somebody already signs in with is a
    decision only they can resolve.
    """
    from model.Profile import Profile

    holder = slip_for_wallet(address)
    if holder is not None and holder.id != slip.id:
        app.logger.error(
            "ADMIN_WALLET_ADDRESS %s is already linked to slip %s (%s); "
            "leaving it alone. Admin wallet sign-in to slip %s will not work "
            "until the address is freed or the config points elsewhere.",
            address, holder.id, holder.name, slip.name,
        )
        return False

    # SAVEPOINT. Everything below is a convenience for the SITE login; admin
    # login does not need it. Without the savepoint a failure here -- a UNIQUE
    # collision, a column an un-run migration never created -- poisons the whole
    # transaction, and the caller is begin_wallet_admin_session, so the operator
    # is locked out of the admin panel by a fault in a secondary feature. That
    # is the wrong failure to have: admin login is the recovery path.
    try:
        with db.session.begin_nested():
            _write_wallet_link(slip, address)
    except SQLAlchemyError:
        app.logger.exception(
            "Could not link wallet %s to slip %s. Admin sign-in still works; "
            "the SITE's MetaMask sign-in will not find this slip until this is "
            "resolved.", address, slip.name,
        )
        return False
    return True


def _write_wallet_link(slip, address):
    from model.Profile import Profile

    profile = db.session.query(Profile).filter(Profile.slip_id == slip.id).one_or_none()
    if profile is None:
        # `slug` is NOT NULL and UNIQUE, and creating a Profile without it fails
        # with NotNullViolation -- which is what happened in production the first
        # time this ran. The convention is blueprints/profiles.py's
        # "user-{slip.id}"; the suffix loop is for the case where a slip once had
        # a profile under that slug and something else holds it now.
        base = "user-%s" % slip.id
        slug = base
        for n in range(1, 50):
            taken = (
                db.session.query(Profile.id)
                .filter(Profile.slug == slug)
                .first()
            )
            if taken is None:
                break
            slug = "%s-%d" % (base, n)
        db.session.add(Profile(slip_id=slip.id, slug=slug, eth_address=address))
    elif not profile.eth_address:
        profile.eth_address = address
    elif normalize_wallet_address(profile.eth_address) != address:
        # The slip already points at a DIFFERENT wallet. Overwriting would
        # silently move the admin identity; refusing is the safe direction.
        app.logger.error(
            "slip %s is linked to %s but ADMIN_WALLET_ADDRESS is %s; not overwriting.",
            slip.name, profile.eth_address, address,
        )
        return
    db.session.flush()


def begin_wallet_admin_session(address):
    """Start an admin session for a wallet that has already proved itself.

    THE ORDERING RULE: the caller reaches this line only after the signature
    verified and the recovered address matched the configured admin wallet. From
    that point the operator is entitled to a session, and NOTHING optional may
    stand between them and it.

    That is not a general principle, it is a specific one about this function.
    Admin sign-in is the recovery path for a hosted deployment: the logs are
    behind the dashboard, so an operator locked out here cannot see WHY they are
    locked out. A failure in a convenience feature -- linking a wallet to a
    profile, widening an auth mode -- must therefore degrade, not refuse.
    """
    normalized_address = normalize_wallet_address(address)
    if normalized_address != configured_admin_wallet_address():
        raise ValueError("Wallet address is not authorized for admin access")

    try:
        slip = ensure_wallet_admin_slip()
    except SQLAlchemyError:
        # Fall back to a READ-ONLY lookup. ensure_wallet_admin_slip creates and
        # repairs; if any of that fails, an existing admin slip is still a
        # perfectly good thing to sign in as, and refusing would trade a working
        # login for a tidy one.
        db.session.rollback()
        app.logger.exception(
            "ensure_wallet_admin_slip failed; falling back to a read-only lookup")
        slip = (
            db.session.query(Slip)
            .filter(Slip.name == WALLET_ADMIN_SLIP_NAME)
            .one_or_none()
        )
        if slip is None:
            # Nothing to sign in as, and the reason is in the logged exception
            # above. Re-raised so the caller reports it rather than presenting
            # an empty session as success.
            raise

    clear_wallet_admin_session()
    session[ADMIN_WALLET_SESSION_KEY] = normalized_address
    make_session(slip, method=AUTH_BY_WALLET)
    return slip


def slip_wallet_address(slip):
    """The wallet linked to this slip, or None.

    The address lives on Profile (it was already there, unique, with a linking
    flow) rather than being duplicated onto Slip — two columns holding the same
    identity is how they end up disagreeing.
    """
    if slip is None:
        return None
    from model.Profile import Profile

    try:
        row = (
            db.session.query(Profile.eth_address)
            .filter(Profile.slip_id == slip.id)
            .one_or_none()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed loading wallet for slip %s", slip.id)
        return None
    return normalize_wallet_address(row[0]) if row and row[0] else None


def slip_for_wallet(address):
    """The slip that owns `address`, or None."""
    normalized = normalize_wallet_address(address)
    if not normalized:
        return None
    from model.Profile import Profile

    try:
        profile = (
            db.session.query(Profile)
            .filter(db.func.lower(Profile.eth_address) == normalized)
            .one_or_none()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed loading slip for wallet %s", normalized)
        return None
    if profile is None:
        return None
    return slip_from_id(profile.slip_id)


def slip_auth_mode(slip):
    mode = getattr(slip, "auth_mode", None)
    return mode if mode in AUTH_MODES else DEFAULT_AUTH_MODE


def slip_allows_password_login(slip):
    return slip_auth_mode(slip) != AUTH_MODE_WALLET


def slip_allows_wallet_login(slip):
    return slip_auth_mode(slip) in (AUTH_MODE_WALLET, AUTH_MODE_EITHER)


def set_slip_auth_mode(slip, mode):
    """Apply a login policy, refusing the ones that would lock the owner out.

    Wallet-only without a linked wallet leaves no way in at all, and the site
    has no password recovery — so this is a door that cannot be reopened. It is
    refused here rather than in the view so every caller inherits the guard.
    """
    if mode not in AUTH_MODES:
        raise ValueError("Unknown login mode.")
    if mode == AUTH_MODE_WALLET and not slip_wallet_address(slip):
        raise ValueError("Link a wallet before restricting sign-in to MetaMask only.")
    slip.auth_mode = mode
    db.session.add(slip)
    return slip


def slip_is_admin(slip=None):
    slip = slip or get_slip()
    if slip is None or slip.is_admin is False:
        return False
    return is_wallet_admin_session()


def _resolved_board_id(board=None):
    if board is None:
        return None
    if isinstance(board, int):
        return board
    return getattr(board, "id", None)


def slip_moderated_board_ids(slip=None):
    slip = slip or get_slip()
    if slip is None:
        return set()
    try:
        rows = (
            db.session.query(SlipBoardModerator.board_id)
            .filter(SlipBoardModerator.slip_id == slip.id)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed loading moderated boards for slip %s", slip.id)
        return set()
    return {board_id for (board_id,) in rows}


def slip_has_moderation_role(slip=None):
    slip = slip or get_slip()
    if slip is None:
        return False
    return bool(slip.is_mod) or bool(slip_moderated_board_ids(slip))


def slip_can_moderate(slip=None, board=None):
    slip = slip or get_slip()
    if slip is None:
        # A wallet-authenticated sysop can moderate everywhere even without a
        # personal slip session, so the moderation controls always appear for
        # them regardless of how they're browsing.
        return has_request_context() and is_wallet_admin_session()
    if slip_is_admin(slip) or slip.is_mod or (has_request_context() and is_wallet_admin_session()):
        return True
    board_id = _resolved_board_id(board)
    if board_id is None:
        return bool(slip_moderated_board_ids(slip))
    if getattr(board, "owner_slip_id", None) == slip.id:
        return True
    return board_id in slip_moderated_board_ids(slip)


def slip_is_editor(slip=None):
    """Whether this slip may take editorial decisions on stories.

    Deliberately not `slip_can_moderate` — see Slip.is_editor for why the two
    grants are separate. Admins and the wallet-admin session count because
    somebody has to be able to appoint the first editor: an install with no
    editor and nobody able to set the flag is a newsroom that cannot be opened.

    The wallet checks are guarded by has_request_context() because this is also
    called from background passes, where Flask's `session` raises rather than
    quietly returning nothing.
    """
    slip = slip or get_slip()
    if has_request_context() and is_wallet_admin_session():
        return True
    if slip is None:
        return False
    if slip.is_editor:
        return True
    return has_request_context() and slip_is_admin(slip)


def normalize_media_delivery_mode(value):
    mode = (value or "").strip().lower()
    if mode in MEDIA_DELIVERY_MODES:
        return mode
    return DEFAULT_MEDIA_DELIVERY_MODE


def slip_media_delivery_mode(slip=None):
    slip = slip or get_slip()
    if slip is None:
        return DEFAULT_MEDIA_DELIVERY_MODE
    return normalize_media_delivery_mode(getattr(slip, "media_delivery_mode", None))


def slip_forwards_remote_replies(slip=None):
    slip = slip or get_slip()
    if slip is None:
        return DEFAULT_FORWARD_REMOTE_REPLIES
    value = getattr(slip, "forward_remote_replies", None)
    return DEFAULT_FORWARD_REMOTE_REPLIES if value is None else bool(value)


def viewer_is_admin():
    return slip_is_admin()


def viewer_can_moderate(board=None):
    return slip_can_moderate(board=board)


class Slip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    pass_hash = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_mod = db.Column(db.Boolean, nullable=False, default=False)
    # A SEPARATE grant from is_mod, not an alias for it. Moderating a board is
    # removing spam and abuse; approving an article that names a private
    # individual is a publishing decision with legal consequences, and the
    # person you trust to do the first is not automatically the person you want
    # making the second. One human may hold both, which is why they are two
    # columns rather than one rank.
    is_editor = db.Column(db.Boolean, nullable=False, default=False)
    media_delivery_mode = db.Column(db.String(16), nullable=False, default=DEFAULT_MEDIA_DELIVERY_MODE)
    auth_mode = db.Column(
        db.String(16),
        nullable=False,
        default=DEFAULT_AUTH_MODE,
        server_default=DEFAULT_AUTH_MODE,
    )
    forward_remote_replies = db.Column(
        db.Boolean,
        nullable=False,
        default=DEFAULT_FORWARD_REMOTE_REPLIES,
        server_default=true(),
    )


class SlipBoardModerator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id"), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("slip_id", "board_id", name="uq_slip_board_moderator_slip_board"),
    )
