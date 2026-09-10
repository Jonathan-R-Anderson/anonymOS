"""3-strike "illegal content" policy for aggregated source sites.

An operator/mod who finds illegal content in scraped material flags it, which
records a STRIKE against that content's source site (keyed by host). Escalation:

  * STRIKES_PER_BAN strikes  -> a TEMP_BAN_DAYS-day ban on aggregating the site
  * BANS_TO_PERMANENT such bans -> the site is permanently banned

While a site is banned, import_source_thread refuses to import anything from it
(services/aggregator_sync/api.py). State is per-host so it survives re-scrapes.
"""
import datetime as _datetime
from urllib.parse import urlparse

from sqlalchemy import or_

from shared import db

STRIKES_PER_BAN = 3
BANS_TO_PERMANENT = 3
TEMP_BAN_DAYS = 30


def host_of(url):
    """Registrable-ish host for a source URL (lowercased, no creds/port/www)."""
    if not url:
        return None
    try:
        netloc = urlparse(url if "://" in url else "http://" + url).netloc.lower()
    except Exception:
        return None
    netloc = netloc.split("@")[-1].split(":")[0]
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc or None


class SourceModeration(db.Model):
    __tablename__ = "source_moderation"
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False, unique=True, index=True)
    strikes = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    temp_bans = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    banned_until = db.Column(db.DateTime, nullable=True)
    permanent = db.Column(db.Boolean, nullable=False, default=False, server_default="0")
    updated_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )


class SourceStrikeEvent(db.Model):
    __tablename__ = "source_strike_event"
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False, index=True)
    source_url = db.Column(db.Text, nullable=True)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )


def _get(host):
    if not host:
        return None
    return db.session.query(SourceModeration).filter(SourceModeration.host == host).one_or_none()


def is_host_banned(host) -> bool:
    row = _get(host)
    if row is None:
        return False
    if row.permanent:
        return True
    return bool(row.banned_until and _datetime.datetime.utcnow() < row.banned_until)


def ban_status(host):
    row = _get(host) if host else None
    now = _datetime.datetime.utcnow()
    if row is None:
        return {"host": host, "strikes": 0, "temp_bans": 0, "permanent": False,
                "banned_until": None, "active": False}
    active = bool(row.permanent or (row.banned_until and now < row.banned_until))
    return {
        "host": host, "strikes": row.strikes, "temp_bans": row.temp_bans,
        "permanent": row.permanent, "banned_until": row.banned_until, "active": active,
    }


def record_strike(host, source_url=None, reason=None) -> dict:
    """Add one strike and escalate per the policy. Returns the new ban_status."""
    host = (host or "").strip().lower()
    if not host:
        return {}
    row = _get(host)
    if row is None:
        row = SourceModeration(host=host)
        db.session.add(row)
        db.session.flush()
    db.session.add(SourceStrikeEvent(host=host, source_url=(source_url or None), reason=(reason or None)))
    now = _datetime.datetime.utcnow()
    row.updated_at = now
    if not row.permanent:
        row.strikes = (row.strikes or 0) + 1
        if row.strikes >= STRIKES_PER_BAN:
            row.strikes = 0
            row.temp_bans = (row.temp_bans or 0) + 1
            if row.temp_bans >= BANS_TO_PERMANENT:
                row.permanent = True
                row.banned_until = None
            else:
                row.banned_until = now + _datetime.timedelta(days=TEMP_BAN_DAYS)
    db.session.commit()
    return ban_status(host)


def lift_ban(host):
    """Admin override: clear all strikes/bans for a host."""
    host = (host or "").strip().lower()
    row = _get(host)
    if row is None:
        return False
    row.strikes = 0
    row.temp_bans = 0
    row.banned_until = None
    row.permanent = False
    row.updated_at = _datetime.datetime.utcnow()
    db.session.commit()
    return True


def banned_hosts():
    now = _datetime.datetime.utcnow()
    return (
        db.session.query(SourceModeration)
        .filter(or_(SourceModeration.permanent.is_(True), SourceModeration.banned_until > now))
        .order_by(SourceModeration.updated_at.desc())
        .all()
    )


def recent_strike_events(limit=50):
    return (
        db.session.query(SourceStrikeEvent)
        .order_by(SourceStrikeEvent.created_at.desc())
        .limit(limit)
        .all()
    )
