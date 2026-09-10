"""Data-driven Warrant Canary for the homepage. All content is admin-managed:
scalar fields live in SiteSetting, the verification timeline is a small table.
Nothing about the notice is hardcoded in the frontend — the component renders
purely from warrant_canary_config()."""
import datetime as _datetime

from shared import db
from model.SiteSetting import get_setting, set_setting

# SiteSetting keys.
K_ENABLED = "warrant_canary_enabled"
K_STATUS = "warrant_canary_status"
K_TITLE = "warrant_canary_title"
K_STATEMENT = "warrant_canary_statement"
K_LAST_UPDATED = "warrant_canary_last_updated"
K_NEXT_UPDATE = "warrant_canary_next_update"
K_SHOW_NEXT = "warrant_canary_show_next_update"
K_THEME = "warrant_canary_theme"
K_SHOW_HISTORY = "warrant_canary_show_history"
K_ACTIVE_LABEL = "warrant_canary_active_label"
K_WARNING_LABEL = "warrant_canary_warning_label"
K_INACTIVE_LABEL = "warrant_canary_inactive_label"

VALID_STATUSES = ("active", "warning", "inactive")
VALID_THEMES = ("auto", "dark", "light")

# Default statement. {lastUpdated}/{nextUpdate} tokens are interpolated at render.
DEFAULT_STATEMENT = (
    "As of {lastUpdated}, this service has never received a secret government "
    "order, National Security Letter, or other legally binding request that "
    "prohibits disclosure to our users.\n\n"
    "This statement is reviewed and reaffirmed regularly."
)


class WarrantCanaryEntry(db.Model):
    __tablename__ = "warrant_canary_entry"

    id = db.Column(db.Integer, primary_key=True)
    entry_date = db.Column(db.String(32), nullable=False)   # YYYY-MM-DD
    status = db.Column(db.String(64), nullable=False)        # e.g. "Verified"
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def _bool(key, default):
    return get_setting(key, "1" if default else "0") == "1"


def _format_date(value):
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return _datetime.datetime.strptime(value, "%Y-%m-%d").strftime("%B %d, %Y")
    except ValueError:
        return value


def warrant_canary_entries():
    try:
        return (
            db.session.query(WarrantCanaryEntry)
            .order_by(WarrantCanaryEntry.entry_date.desc(), WarrantCanaryEntry.id.desc())
            .all()
        )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return []


def add_warrant_canary_entry(entry_date, status):
    entry_date = (entry_date or "").strip()
    status = (status or "").strip()[:64]
    if not entry_date or not status:
        return None
    entry = WarrantCanaryEntry(entry_date=entry_date, status=status)
    db.session.add(entry)
    return entry


def delete_warrant_canary_entry(entry_id):
    return bool(
        db.session.query(WarrantCanaryEntry)
        .filter(WarrantCanaryEntry.id == entry_id)
        .delete(synchronize_session=False)
    )


def warrant_canary_config():
    """Assemble the full, render-ready config for the homepage component."""
    status = (get_setting(K_STATUS, "active") or "active").strip().lower()
    if status not in VALID_STATUSES:
        status = "active"
    theme = (get_setting(K_THEME, "auto") or "auto").strip().lower()
    if theme not in VALID_THEMES:
        theme = "auto"

    labels = {
        "active": (get_setting(K_ACTIVE_LABEL, "Active") or "Active").strip() or "Active",
        "warning": (get_setting(K_WARNING_LABEL, "Attention") or "Attention").strip() or "Attention",
        "inactive": (get_setting(K_INACTIVE_LABEL, "Inactive") or "Inactive").strip() or "Inactive",
    }
    last_updated = (get_setting(K_LAST_UPDATED, "") or "").strip()
    next_update = (get_setting(K_NEXT_UPDATE, "") or "").strip()

    entries = warrant_canary_entries()
    return {
        "enabled": _bool(K_ENABLED, False),
        "status": status,
        "status_class": "wc--" + status,
        "badge_label": labels[status],
        "title": (get_setting(K_TITLE, "Warrant Canary") or "Warrant Canary").strip() or "Warrant Canary",
        "statement": get_setting(K_STATEMENT, DEFAULT_STATEMENT) or DEFAULT_STATEMENT,
        "last_updated": last_updated,
        "last_updated_display": _format_date(last_updated),
        "next_update": next_update,
        "next_update_display": _format_date(next_update),
        "show_next_update": _bool(K_SHOW_NEXT, True),
        "theme": theme,
        "active_label": labels["active"],
        "show_history": _bool(K_SHOW_HISTORY, False),
        "history": [
            {"id": e.id, "date": e.entry_date, "date_display": _format_date(e.entry_date), "status": e.status}
            for e in entries
        ],
    }
