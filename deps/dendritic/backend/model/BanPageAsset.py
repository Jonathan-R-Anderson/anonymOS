"""Sysop-configured content for the "annoying" ban page that permanently-banned
visitors are redirected to (inspired by TheAnnoyingSite.com). Each asset is a
kind + a value (a URL, or text for a message). The ban page renders every
enabled asset."""
import datetime as _datetime

from shared import db

BAN_ASSET_KINDS = ("popup", "video", "audio", "image", "message")

# Selectable "extra annoying" browser features (ported from TheAnnoyingSite.com,
# MIT). Each is opt-in per the sysop. Genuinely harmful behaviours from the
# original are deliberately NOT offered: super-logout (attacks the visitor's
# third-party accounts), camera/mic capture + torch (privacy invasion), and
# protocol-handler hijacking (persists in the browser after they leave).
BAN_PAGE_FEATURES = [
    ("popups", "Popup storm", "Spawns popup windows scattered across the screen."),
    ("bounce", "Bouncing windows", "Popups drift and bounce off the screen edges."),
    ("follow_mouse", "Window chases cursor", "A popup follows the mouse pointer around."),
    ("confirm_unload", "Beg them to stay", "\"Are you sure you want to leave?\" prompt when they try to close."),
    ("block_back", "Trap the back button", "Disables Back and floods history so they can't easily leave."),
    ("fullscreen", "Force fullscreen", "Jumps the page to fullscreen on interaction."),
    ("hide_cursor", "Hide the cursor", "Makes the mouse pointer invisible."),
    ("vibrate", "Vibrate device", "Buzzes phones/controllers at random intervals."),
    ("speak", "Creepy text-to-speech", "Reads odd phrases aloud via speech synthesis."),
    ("theramin", "Mouse theremin", "An eerie tone whose pitch/volume tracks the mouse."),
    ("rainbow", "Strobe theme colour", "Flashes the browser theme colour through random colours."),
    ("emoji_url", "Animated emoji URL", "Marches emojis through the address-bar URL."),
    ("alerts", "Alert / print spam", "Pops modal alerts and print dialogs on a timer."),
    ("clipboard_spam", "Hijack the clipboard", "Overwrites whatever they copy with spam."),
    ("pointer_lock", "Lock the pointer", "Captures the mouse pointer."),
    ("downloads", "Junk downloads", "Triggers junk file downloads on interaction."),
    ("device_prompts", "Device permission spam", "Spams Bluetooth/USB/Serial/HID/MIDI prompts (the browser still requires consent for any real access)."),
]
BAN_PAGE_FEATURE_KEYS = {key for key, _label, _desc in BAN_PAGE_FEATURES}

_FEATURES_SETTING = "ban_page_features"
_CSS_SETTING = "ban_page_custom_css"
_HTML_SETTING = "ban_page_custom_html"
_JS_SETTING = "ban_page_custom_js"
_THEME_SETTING = "ban_page_theme"


def enabled_ban_page_features():
    """Set of enabled annoying-feature keys."""
    from model.SiteSetting import get_setting
    raw = get_setting(_FEATURES_SETTING, "") or ""
    return {k.strip() for k in raw.split(",") if k.strip() in BAN_PAGE_FEATURE_KEYS}


def set_ban_page_features(keys):
    from model.SiteSetting import set_setting
    valid = [k for k in (keys or []) if k in BAN_PAGE_FEATURE_KEYS]
    set_setting(_FEATURES_SETTING, ",".join(sorted(set(valid))))


def ban_page_customization():
    """Custom look/behaviour of the ban page (theme + injected CSS/HTML/JS)."""
    from model.SiteSetting import get_setting
    return {
        "theme": (get_setting(_THEME_SETTING, "") or "").strip(),
        "custom_css": get_setting(_CSS_SETTING, "") or "",
        "custom_html": get_setting(_HTML_SETTING, "") or "",
        "custom_js": get_setting(_JS_SETTING, "") or "",
    }


def save_ban_page_customization(theme=None, custom_css=None, custom_html=None, custom_js=None):
    from model.SiteSetting import set_setting
    if theme is not None:
        set_setting(_THEME_SETTING, (theme or "").strip())
    if custom_css is not None:
        set_setting(_CSS_SETTING, custom_css or "")
    if custom_html is not None:
        set_setting(_HTML_SETTING, custom_html or "")
    if custom_js is not None:
        set_setting(_JS_SETTING, custom_js or "")


class BanPageAsset(db.Model):
    __tablename__ = "ban_page_asset"

    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(16), nullable=False)   # popup | video | audio | image | message
    value = db.Column(db.Text, nullable=False)         # a URL, or text for `message`
    enabled = db.Column(db.Boolean, nullable=False, default=True, server_default="1")
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def ban_page_assets(enabled_only=False):
    query = db.session.query(BanPageAsset)
    if enabled_only:
        query = query.filter(BanPageAsset.enabled.is_(True))
    return query.order_by(BanPageAsset.kind.asc(), BanPageAsset.id.asc()).all()


def ban_page_assets_by_kind(enabled_only=True):
    grouped = {kind: [] for kind in BAN_ASSET_KINDS}
    for asset in ban_page_assets(enabled_only=enabled_only):
        grouped.setdefault(asset.kind, []).append(asset.value)
    return grouped


def add_ban_page_asset(kind, value):
    kind = (kind or "").strip().lower()
    value = (value or "").strip()
    if kind not in BAN_ASSET_KINDS or not value:
        return None
    asset = BanPageAsset(kind=kind, value=value)
    db.session.add(asset)
    return asset


def set_ban_page_asset_enabled(asset_id, enabled):
    asset = db.session.query(BanPageAsset).filter(BanPageAsset.id == asset_id).one_or_none()
    if asset is None:
        return False
    asset.enabled = bool(enabled)
    return True


def delete_ban_page_asset(asset_id):
    return bool(
        db.session.query(BanPageAsset)
        .filter(BanPageAsset.id == asset_id)
        .delete(synchronize_session=False)
    )
