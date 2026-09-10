import re

from flask import url_for

from shared import db

# Imported for its SIDE EFFECT: registering the Media class in SQLAlchemy's
# declarative registry.
#
# `avatar_media` below is declared as db.relationship('Media', ...) -- a STRING,
# which SQLAlchemy resolves from that registry when the Profile mapper is first
# configured. Nothing here imported model.Media, so resolution succeeded only if
# some unrelated module happened to have imported it earlier in the process.
#
# When it did not, EVERY query touching Profile failed with:
#
#     InvalidRequestError: When initializing mapper Mapper[Profile(profile)],
#     expression 'Media' failed to locate a name ('Media')
#
# which is how the admin MetaMask sign-in came to answer "Session creation
# failed": begin_wallet_admin_session -> ensure_wallet_admin_slip -> a Profile
# query -> this error. The failure depended on import order, so it looked
# intermittent and unrelated to wallets.
#
# Media does not import Profile, so this cannot cycle.
from model.Media import Media  # noqa: F401

# Accepts #rgb or #rrggbb.
_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$")
DEFAULT_CHAT_ACCENT = "#b07274"

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey('slip.id'), unique=True, nullable=False)
    eth_address = db.Column(db.String(42), unique=True, nullable=True)
    # Where this author's payment-channel node can be reached, for awards paid
    # over a channel rather than on chain (roadmap P9). Empty is the normal
    # answer and means "no channel path" rather than "no awards" — the great
    # majority of authors have a wallet and nothing else, and they keep the
    # on-chain path.
    channel_endpoint = db.Column(db.String(255), nullable=True)
    # Pooled tipping (roadmap P15). Two booleans and a label — NOT a balance.
    #
    # The pool itself lives in the recipient's own node as a DERIVED VIEW over
    # their bilateral channels (storage-client/internal/channel/pool.go). This
    # server stores whether the owner has switched it on and what to call it, and
    # nothing else: no aggregate, no channel list, no per-tip row. Money stays in
    # the channels, and this database never learns what is in them.
    pool_enabled = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    pool_name = db.Column(db.String(64), nullable=True)
    # Which volunteer node services this creator's tipping, and on what terms
    # (roadmap P15). Two strings and no key.
    #
    # pool_volunteer is the node id the creator authorised, and it is stored so
    # a tipper's browser knows where to send a frame. The ENDPOINT it maps to is
    # channel_endpoint above, which already exists and is already https-only.
    #
    # pool_signing_mode is "mailbox" or "delegate". It is a LABEL for the UI, not
    # an authority: whether a volunteer may actually sign is decided by
    # AxonChannels.canSign and by nothing here. A creator who flips this
    # column without doing the on-chain authorisation gets a volunteer that
    # cannot sign, which is the safe direction to fail.
    pool_volunteer = db.Column(db.String(128), nullable=True)
    pool_signing_mode = db.Column(db.String(16), nullable=True)
    # Where that volunteer's MAILBOX is, which is a different place from
    # channel_endpoint above.
    #
    # channel_endpoint is the RECIPIENT'S OWN node — where a contributor asks
    # for current channel state and proposes a payment. This is the VOLUNTEER —
    # where a contributor leaves a frame when the recipient's node did not
    # answer. Pointing one at the other makes the volunteer reply as though it
    # were a party to the channel, and the payment ends UNKNOWN rather than
    # queued: observed in a real browser run before this field existed.
    #
    # https only, like channel_endpoint, because tip-channel.js refuses to hand
    # a signed proposal to a plain-http mailbox.
    pool_volunteer_endpoint = db.Column(db.String(255), nullable=True)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    is_public = db.Column(db.Boolean, default=True, nullable=False)
    custom_html = db.Column(db.Text, default="", nullable=False)
    custom_css = db.Column(db.Text, default="", nullable=False)
    # When set, the owner's live stream player is embedded on their profile page.
    embed_stream = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    # When set, the owner's name on their thread posts links to this profile
    # (with a hover preview). Off means the name renders as plain text.
    link_on_comments = db.Column(db.Boolean, default=True, nullable=False, server_default="1")
    # When set, an anonymous chat room (#profile-<slug>) is embedded on the
    # profile page; visitors auto-join with a throwaway anon-<digits> nick.
    enable_chat = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    # Profile picture (a Media record). Shown next to the owner's name on posts,
    # comments and uploads when show_avatar is on.
    avatar_media_id = db.Column(db.Integer, db.ForeignKey('media.id'), nullable=True)
    show_avatar = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    # Chatroom appearance chosen by the profile owner. chat_theme is "light" or
    # "dark" (the neutral base palette); chat_accent is a #hex accent colour used
    # for buttons, the owner highlight and member dots. Both are validated on save
    # and surfaced safely for templates via chat_theme_class / chat_accent_css.
    chat_theme = db.Column(db.String(8), default="light", nullable=False, server_default="light")
    chat_accent = db.Column(db.String(7), nullable=True)
    # When set, a collaborative r/place-style pixel wall ("graffiti") is embedded
    # on the profile; visitors can paint pixels on it.
    enable_place = db.Column(db.Boolean, default=False, nullable=False, server_default="0")
    # How many days of daily graffiti-wall snapshots the time-lapse scrubber shows.
    place_timelapse_days = db.Column(db.Integer, default=7, nullable=False, server_default="7")
    # Auto-logout after this many minutes of inactivity (0 = never, the default).
    session_timeout_minutes = db.Column(db.Integer, default=0, nullable=False, server_default="0")

    slip = db.relationship('Slip', backref=db.backref('profile', uselist=False, cascade="all, delete-orphan"))
    avatar_media = db.relationship('Media', foreign_keys=[avatar_media_id])

    @property
    def avatar_url(self):
        if not self.avatar_media_id:
            return None
        return url_for("upload.thumb", media_id=self.avatar_media_id)

    @property
    def chat_theme_class(self):
        """CSS class for the chat container: 'pc-dark' or 'pc-light'."""
        return "pc-dark" if (self.chat_theme or "light") == "dark" else "pc-light"

    @property
    def chat_accent_css(self):
        """The owner's accent colour, validated as a #hex string so it is always
        safe to interpolate into an inline style. Falls back to the site default."""
        value = (self.chat_accent or "").strip()
        return value if _HEX_COLOR_RE.match(value) else DEFAULT_CHAT_ACCENT

    def __repr__(self):
        return f"<Profile {self.slug} (Slip {self.slip_id})>"


def normalize_chat_accent(value):
    """Return a validated #hex accent colour (as given), or None when the input
    is not a valid #rgb / #rrggbb string. Used to sanitize owner input on save."""
    value = (value or "").strip()
    return value if _HEX_COLOR_RE.match(value) else None


def avatar_url_for_slip(slip):
    """Avatar URL for a slip whose owner opted to show it, else None. Accepts a
    Slip object or slip id."""
    if slip is None:
        return None
    slip_id = getattr(slip, "id", slip)
    profile = getattr(slip, "profile", None) if hasattr(slip, "profile") else None
    if profile is None:
        profile = db.session.query(Profile).filter(Profile.slip_id == slip_id).one_or_none()
    if profile is None or not profile.show_avatar or not profile.avatar_media_id:
        return None
    return url_for("upload.thumb", media_id=profile.avatar_media_id)
