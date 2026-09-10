"""Runtime-security alerts ingested from Falco (falcosecurity/falco).

Falco watches syscalls across every container on the host and POSTs each rule
match to maniwani's token-authed ingest webhook (see blueprints/falco.py). We
persist matches here so the admin panel can surface notifications, filter by
severity, acknowledge, and prune.

Falco itself runs as a privileged container and owns the DETECTION rules; this
table plus the SiteSetting knobs below are maniwani's control surface over what
it KEEPS and SHOWS: ingest on/off, a minimum-severity floor, retention, and an
operator mute-list applied at ingest time (so a noisy rule can be silenced from
the panel without touching Falco's config/restarting it).
"""
import datetime as _datetime
import json as _json

from shared import app, db
from model.SiteSetting import get_setting, set_setting


# --- setting keys (SiteSetting.key is varchar(64); keep these short) --------
INGEST_ENABLED_SETTING = "falco_ingest_enabled"     # "1"/"0"
MIN_PRIORITY_SETTING = "falco_min_priority"          # priority name, e.g. "notice"
RETENTION_DAYS_SETTING = "falco_retention_days"      # int days; 0 = keep forever
MUTED_RULES_SETTING = "falco_muted_rules"            # JSON list of rule names
LAST_ALERT_AT_SETTING = "falco_last_alert_at"        # ISO of newest STORED alert
LAST_INGEST_AT_SETTING = "falco_last_ingest_at"      # ISO of last POST received (even if dropped)

DEFAULT_MIN_PRIORITY = "notice"
DEFAULT_RETENTION_DAYS = 14
MAX_STORED_ALERTS = 5000       # hard cap so an alert flood can't grow the table unbounded

# Falco severity order, most -> least severe. Lower rank = more severe.
PRIORITY_RANK = {
    "emergency": 0, "alert": 1, "critical": 2, "error": 3,
    "warning": 4, "notice": 5, "informational": 6, "info": 6, "debug": 7,
}
PRIORITY_ORDER = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"]


class FalcoAlert(db.Model):
    __tablename__ = "falco_alert"

    id = db.Column(db.Integer, primary_key=True)
    rule = db.Column(db.String(255), nullable=False, default="")
    priority = db.Column(db.String(32), nullable=False, default="")
    priority_rank = db.Column(db.Integer, nullable=False, default=7, index=True)
    output = db.Column(db.Text, nullable=False, default="")
    output_fields = db.Column(db.Text, nullable=True)     # JSON blob (as text)
    source = db.Column(db.String(64), nullable=True)
    tags = db.Column(db.Text, nullable=True)              # comma-joined
    hostname = db.Column(db.String(255), nullable=True)
    container_id = db.Column(db.String(128), nullable=True)
    container_name = db.Column(db.String(255), nullable=True, index=True)
    container_image = db.Column(db.String(512), nullable=True)
    occurred_at = db.Column(db.DateTime, nullable=True)   # Falco's event time
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True)
    acknowledged = db.Column(db.Boolean, nullable=False, default=False, index=True)

    def as_dict(self):
        return {
            "id": self.id,
            "rule": self.rule,
            "priority": self.priority,
            "priority_rank": self.priority_rank,
            "output": self.output,
            "source": self.source,
            "tags": [t for t in (self.tags or "").split(",") if t],
            "hostname": self.hostname,
            "container_id": (self.container_id or "")[:12] or None,
            "container_name": self.container_name,
            "container_image": self.container_image,
            "occurred_at": (self.occurred_at.isoformat() + "Z") if self.occurred_at else None,
            "created_at": (self.created_at.isoformat() + "Z") if self.created_at else None,
            "acknowledged": bool(self.acknowledged),
        }


# --- settings helpers -------------------------------------------------------
def ingest_enabled():
    return str(get_setting(INGEST_ENABLED_SETTING, "1")).strip().lower() not in ("", "0", "false", "no", "off")


def min_priority():
    raw = (get_setting(MIN_PRIORITY_SETTING, DEFAULT_MIN_PRIORITY) or DEFAULT_MIN_PRIORITY).strip().lower()
    return raw if raw in PRIORITY_RANK else DEFAULT_MIN_PRIORITY


def min_priority_rank():
    return PRIORITY_RANK.get(min_priority(), PRIORITY_RANK[DEFAULT_MIN_PRIORITY])


def retention_days():
    raw = get_setting(RETENTION_DAYS_SETTING, str(DEFAULT_RETENTION_DAYS))
    try:
        return max(0, int(str(raw).strip()))
    except (TypeError, ValueError):
        return DEFAULT_RETENTION_DAYS


def muted_rules():
    raw = get_setting(MUTED_RULES_SETTING, "")
    if not raw:
        return []
    try:
        data = _json.loads(raw)
        if isinstance(data, list):
            return [str(x) for x in data]
    except Exception:
        pass
    return []


def set_muted_rules(rules):
    cleaned = sorted({str(r).strip() for r in rules if str(r).strip()})
    set_setting(MUTED_RULES_SETTING, _json.dumps(cleaned))
    return cleaned


def mute_rule(rule):
    if not rule:
        return muted_rules()
    rules = set(muted_rules())
    rules.add(str(rule).strip())
    return set_muted_rules(rules)


def unmute_rule(rule):
    target = (rule or "").strip()
    return set_muted_rules([r for r in muted_rules() if r != target])


def priority_rank_of(priority):
    return PRIORITY_RANK.get((priority or "").strip().lower(), 7)


# --- ingest -----------------------------------------------------------------
def _extract_container(fields):
    if not isinstance(fields, dict):
        return (None, None, None)
    cid = fields.get("container.id") or fields.get("container_id")
    cname = fields.get("container.name") or fields.get("container_name")
    image = (
        fields.get("container.image.repository")
        or fields.get("container.image")
        or fields.get("container.image.tag")
    )
    if cid in ("host", ""):
        cid = None
    if cname in ("host", ""):
        cname = None
    return (cid, cname, image)


def _parse_time(value):
    """Falco emits RFC3339 nanosecond time (e.g. 2026-07-24T16:31:00.123456789Z).
    Trim to microseconds so datetime.fromisoformat accepts it."""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1]
    if "." in text:
        head, frac = text.split(".", 1)
        digits = "".join(ch for ch in frac if ch.isdigit())[:6]
        text = head + (("." + digits) if digits else "")
    try:
        return _datetime.datetime.fromisoformat(text)
    except ValueError:
        return None


def _json_dump(obj):
    try:
        return _json.dumps(obj)[:16000]
    except Exception:
        return None


def record_alert(payload):
    """Persist one Falco alert dict (already JSON-parsed). Returns the row, or
    None if the alert was dropped (ingest off, below the severity floor, or a
    muted rule) or on error. Never raises."""
    if not isinstance(payload, dict):
        return None
    now = _datetime.datetime.utcnow()

    # Best-effort liveness marker — recorded even for dropped/low-severity events
    # so the panel can show "Falco last reported at ...".
    try:
        set_setting(LAST_INGEST_AT_SETTING, now.isoformat())
        db.session.commit()
    except Exception:
        db.session.rollback()

    if ingest_enabled() is False:
        return None

    rule = str(payload.get("rule") or "").strip()
    priority = str(payload.get("priority") or "").strip()
    rank = priority_rank_of(priority)
    if rank > min_priority_rank():
        return None                       # below the configured severity floor
    if rule and rule in set(muted_rules()):
        return None                       # operator-muted rule

    fields = payload.get("output_fields")
    if not isinstance(fields, dict):
        fields = {}
    cid, cname, image = _extract_container(fields)
    tags = payload.get("tags")
    if isinstance(tags, list):
        tags_str = ",".join(str(t) for t in tags) or None
    else:
        tags_str = (str(tags) if tags else None)

    row = FalcoAlert(
        rule=rule[:255],
        priority=priority[:32],
        priority_rank=rank,
        output=str(payload.get("output") or "")[:8000],
        output_fields=_json_dump(fields),
        source=(str(payload.get("source") or "")[:64] or None),
        tags=tags_str,
        hostname=(str(payload.get("hostname") or "")[:255] or None),
        container_id=(str(cid)[:128] if cid else None),
        container_name=(str(cname)[:255] if cname else None),
        container_image=(str(image)[:512] if image else None),
        occurred_at=_parse_time(payload.get("time")),
    )
    try:
        db.session.add(row)
        db.session.flush()
        set_setting(LAST_ALERT_AT_SETTING, (row.created_at or now).isoformat())
        _maybe_prune(row.id)
        db.session.commit()
        return row
    except Exception:
        db.session.rollback()
        app.logger.exception("Falco: failed to record alert")
        return None


def _maybe_prune(latest_id):
    """Opportunistic maintenance: only every ~50th insert, so the common path
    stays a single INSERT."""
    if latest_id is None or (latest_id % 50) != 0:
        return
    purge_expired()
    _trim_to_cap()


def purge_expired():
    days = retention_days()
    if days <= 0:
        return 0
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
    try:
        return db.session.query(FalcoAlert).filter(FalcoAlert.created_at < cutoff).delete(synchronize_session=False) or 0
    except Exception:
        db.session.rollback()
        return 0


def _trim_to_cap():
    try:
        total = db.session.query(FalcoAlert.id).count()
        if total <= MAX_STORED_ALERTS:
            return 0
        overflow = total - MAX_STORED_ALERTS
        old_ids = [
            r[0] for r in db.session.query(FalcoAlert.id)
            .order_by(FalcoAlert.created_at.asc(), FalcoAlert.id.asc())
            .limit(overflow).all()
        ]
        if not old_ids:
            return 0
        return db.session.query(FalcoAlert).filter(FalcoAlert.id.in_(old_ids)).delete(synchronize_session=False) or 0
    except Exception:
        db.session.rollback()
        return 0


# --- queries for the admin panel -------------------------------------------
def recent_alerts(limit=100, priority=None, container=None, unacked_only=False, rule=None):
    query = db.session.query(FalcoAlert)
    if priority:
        p = str(priority).strip().lower()
        if p in PRIORITY_RANK:
            query = query.filter(FalcoAlert.priority_rank <= PRIORITY_RANK[p])
    if container:
        query = query.filter(FalcoAlert.container_name == container)
    if rule:
        query = query.filter(FalcoAlert.rule == rule)
    if unacked_only:
        query = query.filter(FalcoAlert.acknowledged.is_(False))
    try:
        limit = max(1, min(500, int(limit)))
    except (TypeError, ValueError):
        limit = 100
    return query.order_by(FalcoAlert.created_at.desc(), FalcoAlert.id.desc()).limit(limit).all()


def counts_by_priority(days=7):
    since = _datetime.datetime.utcnow() - _datetime.timedelta(days=max(1, days))
    rows = (
        db.session.query(FalcoAlert.priority, db.func.count(FalcoAlert.id))
        .filter(FalcoAlert.created_at >= since)
        .group_by(FalcoAlert.priority)
        .all()
    )
    return {(p or "unknown"): c for (p, c) in rows}


def top_containers(limit=8, days=7):
    since = _datetime.datetime.utcnow() - _datetime.timedelta(days=max(1, days))
    rows = (
        db.session.query(FalcoAlert.container_name, db.func.count(FalcoAlert.id))
        .filter(FalcoAlert.created_at >= since, FalcoAlert.container_name.isnot(None))
        .group_by(FalcoAlert.container_name)
        .order_by(db.func.count(FalcoAlert.id).desc())
        .limit(limit)
        .all()
    )
    return [{"container": c, "count": n} for (c, n) in rows]


def unacknowledged_count():
    return db.session.query(FalcoAlert.id).filter(FalcoAlert.acknowledged.is_(False)).count()


def acknowledge(alert_id, value=True):
    row = db.session.get(FalcoAlert, alert_id)
    if row is None:
        return False
    row.acknowledged = bool(value)
    db.session.commit()
    return True


def acknowledge_all():
    n = db.session.query(FalcoAlert).filter(FalcoAlert.acknowledged.is_(False)).update(
        {"acknowledged": True}, synchronize_session=False
    )
    db.session.commit()
    return n or 0


def delete_alert(alert_id):
    row = db.session.get(FalcoAlert, alert_id)
    if row is None:
        return False
    db.session.delete(row)
    db.session.commit()
    return True


def clear_alerts():
    n = db.session.query(FalcoAlert).delete(synchronize_session=False)
    db.session.commit()
    return n or 0
