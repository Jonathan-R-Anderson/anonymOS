"""One scored request, with the reasons that produced the score.

WHY POSTGRES AND NOT CLICKHOUSE
-------------------------------
The specification asks for a recommendation and offers ClickHouse, RocksDB and
LMDB. The recommendation is Postgres, which is already here — already backed up,
already has a maintenance loop, already understood by whoever debugs this at
three in the morning.

A second datastore is a second thing to operate: its own retention, its own
failure modes, its own disk. This site is run by one person and has already lost
an afternoon to a disk filling up. The volume in question is a few hundred
thousand rows a day with a short retention, which Postgres handles without
noticing; picking a column store for that trades a real operational cost against
a benefit nobody here would measure.

WHAT IS STORED AND WHAT DELIBERATELY IS NOT
-------------------------------------------
The reasons are stored WITH the row, not recomputed on read. A reason
reconstructed later from rules that have since changed is not the reason the
decision used, and an incident review that reads a plausible reconstruction as
fact is worse than one with no explanation at all.

The full request body is NOT stored — only a short prefix, and only when a
signature matched. A security log that quietly accumulates everything people
typed becomes the most sensitive table in the database, which is a strange
outcome for a component meant to reduce risk.
"""

import datetime as _datetime

from shared import db

# Retention. Short on purpose: the value of this data decays fast, and a table
# that grows without bound is the failure this project has already had once.
RETENTION_DAYS = 14


class ThreatEvent(db.Model):
    __tablename__ = "threat_event"

    id = db.Column(db.BigInteger, primary_key=True)

    at = db.Column(db.DateTime, nullable=False,
                   default=_datetime.datetime.utcnow, index=True)

    # The address is stored whole HERE, in the private table, and masked at
    # every point where anything is published. Storing it truncated would make
    # the log useless for the one job it has — telling one client from another —
    # while doing nothing about publication, which is where the risk actually
    # lives.
    address = db.Column(db.String(45), nullable=False, index=True)
    # Derived once at write time. Doing it on read would mean a geoip lookup per
    # row in every dashboard query.
    country = db.Column(db.String(2), nullable=True, index=True)
    asn = db.Column(db.String(32), nullable=True, index=True)

    method = db.Column(db.String(10), nullable=False, default="GET")
    path = db.Column(db.String(512), nullable=False, default="")
    query = db.Column(db.String(512), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    status = db.Column(db.Integer, nullable=True)

    score = db.Column(db.Integer, nullable=False, default=0, index=True)
    band = db.Column(db.String(16), nullable=False, default="safe", index=True)
    # JSON list of {points, why}. Stored, never recomputed.
    reasons = db.Column(db.Text, nullable=False, default="[]")

    # What WOULD have happened. Phase 1 enforces nothing, so this is the whole
    # point of the table: it is how the thresholds get chosen from evidence
    # rather than guessed before any traffic has been seen.
    would_have = db.Column(db.String(16), nullable=False, default="allow", index=True)
    enforced = db.Column(db.Boolean, nullable=False, default=False)

    __table_args__ = (
        db.Index("ix_threat_event_address_at", "address", "at"),
        db.Index("ix_threat_event_band_at", "band", "at"),
    )


def record(features, verdict, status=None, enforced=False):
    """Store one scored request. Never raises — logging must not break serving."""
    import json

    from shared import app

    try:
        reasons = verdict.get("reasons") or []
        event = ThreatEvent(
            address=(features.get("address") or "")[:45],
            country=(features.get("country") or None),
            asn=(features.get("asn") or None),
            method=(features.get("method") or "GET")[:10],
            path=(features.get("path") or "")[:512],
            query=(features.get("query") or None) and features["query"][:512],
            user_agent=(features.get("user_agent") or None) and features["user_agent"][:512],
            status=status,
            score=int(verdict.get("score") or 0),
            band=verdict.get("band") or "safe",
            reasons=json.dumps(reasons),
            would_have=_would_have(verdict),
            enforced=bool(enforced),
        )
        db.session.add(event)
        db.session.commit()
        return event
    except Exception:
        db.session.rollback()
        app.logger.exception("threat log: could not record an event")
        return None


def _would_have(verdict):
    band = verdict.get("band")
    return {"safe": "allow", "monitor": "allow",
            "challenge": "challenge", "block": "block"}.get(band, "allow")


def prune(now=None):
    """Drop events past the retention window. Returns how many went."""
    from shared import app

    cutoff = (now or _datetime.datetime.utcnow()) - _datetime.timedelta(days=RETENTION_DAYS)
    try:
        removed = (db.session.query(ThreatEvent)
                   .filter(ThreatEvent.at < cutoff)
                   .delete(synchronize_session=False))
        db.session.commit()
        return int(removed or 0)
    except Exception:
        db.session.rollback()
        app.logger.exception("threat log: could not prune")
        return 0


def distribution(since=None):
    """Score bands over a window — the number Phase 1 exists to produce.

    Thresholds are meant to be read off this rather than guessed, so it reports
    what each band WOULD have caught rather than what was blocked.
    """
    from sqlalchemy import func

    query = db.session.query(ThreatEvent.band, func.count(ThreatEvent.id))
    if since is not None:
        query = query.filter(ThreatEvent.at >= since)
    counts = {name: 0 for _, _, name in __import__(
        "services.threat_score", fromlist=["BANDS"]).BANDS}
    for band, count in query.group_by(ThreatEvent.band).all():
        counts[band] = int(count)
    return counts


def top_reasons(since=None, limit=15):
    """Which signals are actually firing, most first.

    The tuning instrument: a reason that fires on everything is miscalibrated,
    and one that never fires is dead weight pretending to be defence.
    """
    import json
    from collections import Counter

    query = db.session.query(ThreatEvent.reasons)
    if since is not None:
        query = query.filter(ThreatEvent.at >= since)
    tally = Counter()
    for (raw,) in query.limit(50000).all():
        try:
            for entry in json.loads(raw or "[]"):
                if entry.get("why"):
                    tally[entry["why"]] += 1
        except ValueError:
            continue
    return [{"why": why, "count": count} for why, count in tally.most_common(limit)]
