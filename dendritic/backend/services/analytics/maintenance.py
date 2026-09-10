import datetime as _datetime
import os
import time
import uuid

from sqlalchemy import func, or_, text

import shared
from model.Analytics import (
    AnalyticsAnonProfile,
    AnalyticsDeletion,
    AnalyticsEvent,
    AnalyticsIngestIssue,
    AnalyticsJobState,
    AnalyticsSession,
    AnalyticsUserProfile,
)
from model.Recommendation import CollaborativeSimilarity, RecommendationInteraction, RecommendationLog
from model.Experiment import BehaviorMetricDaily, ExperimentExposure, RecommendationSatisfaction
from model.AdvancedRecommendation import BehaviorSequence, NotificationRecommendation, RecommendationPreference, UserValuePrediction
from shared import db
from services.aggregator_sync.state import (
    _close_raw_connection,
    _open_background_sync_connection,
    _set_connection_autocommit,
)


LOCK_ID = 741313
SESSION_GAP = _datetime.timedelta(minutes=30)
IDENTITY_RETENTION = _datetime.timedelta(days=30)
EVENT_RETENTION = _datetime.timedelta(days=180)
ISSUE_RETENTION = _datetime.timedelta(days=30)
DELETION_LEDGER_RETENTION = _datetime.timedelta(days=30)
_lock_connection = None


def _config_int(name, default):
    try:
        return int(shared.app.config.get(name, os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


def _enabled():
    value = shared.app.config.get("ANALYTICS_MAINTENANCE_ENABLED", True)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("", "0", "false", "no", "off")


def _leader():
    global _lock_connection
    if db.engine.url.get_backend_name() not in ("postgresql", "postgres"):
        return True
    if _lock_connection is not None:
        try:
            cursor = _lock_connection.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            return True
        except Exception:
            try:
                _close_raw_connection(_lock_connection)
            except Exception:
                pass
            _lock_connection = None
    connection = _open_background_sync_connection()
    _set_connection_autocommit(connection, True)
    cursor = connection.cursor()
    cursor.execute(
        "SELECT pg_try_advisory_lock(%s)",
        (_config_int("ANALYTICS_MAINTENANCE_ADVISORY_LOCK_ID", LOCK_ID),),
    )
    acquired = bool(cursor.fetchone()[0])
    cursor.close()
    if acquired:
        _lock_connection = connection
        return True
    _close_raw_connection(connection)
    return False


def _next_month(value):
    return (value.replace(day=28) + _datetime.timedelta(days=4)).replace(day=1)


def _previous_month(value):
    return (value.replace(day=1) - _datetime.timedelta(days=1)).replace(day=1)


def ensure_event_partitions(now=None):
    if db.engine.url.get_backend_name() not in ("postgresql", "postgres"):
        return 0
    today = (now or _datetime.datetime.utcnow()).date().replace(day=1)
    created = 0
    for start in (_previous_month(today), today, _next_month(today), _next_month(_next_month(today))):
        end = _next_month(start)
        name = "analytics_event_%s" % start.strftime("%Y_%m")
        db.session.execute(text(
            "CREATE TABLE IF NOT EXISTS analytics.%s PARTITION OF analytics.analytics_event "
            "FOR VALUES FROM ('%s') TO ('%s')" % (name, start.isoformat(), end.isoformat())
        ))
        created += 1
    db.session.commit()
    return created


def _session_uuid(anonymous_id, started_at):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "maniwani:analytics:%s:%s" % (anonymous_id, started_at.isoformat())))


def sessionize_events(limit=5000):
    events = (
        db.session.query(AnalyticsEvent)
        .filter(AnalyticsEvent.reconstructed_session_id.is_(None))
        .order_by(AnalyticsEvent.anonymous_id.asc(), AnalyticsEvent.event_time.asc(), AnalyticsEvent.event_id.asc())
        .limit(limit)
        .all()
    )
    sessions = {}
    current = None
    for event in events:
        if current is None or current["anonymous_id"] != event.anonymous_id or event.event_time - current["ended_at"] > SESSION_GAP:
            existing = (
                db.session.query(AnalyticsSession)
                .filter(
                    AnalyticsSession.anonymous_id == event.anonymous_id,
                    AnalyticsSession.ended_at >= event.event_time - SESSION_GAP,
                    AnalyticsSession.ended_at <= event.event_time,
                )
                .order_by(AnalyticsSession.ended_at.desc())
                .first()
            )
            if existing is not None:
                current = {
                    "id": existing.id,
                    "anonymous_id": existing.anonymous_id,
                    "slip_id": existing.slip_id or event.slip_id,
                    "started_at": existing.started_at,
                    "ended_at": existing.ended_at,
                    "event_count": existing.event_count,
                    "raw_session_ids": set(existing.raw_session_ids or []),
                    "row": existing,
                }
            else:
                current = {
                    "id": _session_uuid(event.anonymous_id, event.event_time),
                    "anonymous_id": event.anonymous_id,
                    "slip_id": event.slip_id,
                    "started_at": event.event_time,
                    "ended_at": event.event_time,
                    "event_count": 0,
                    "raw_session_ids": set(),
                    "row": None,
                }
            sessions[current["id"]] = current
        current["ended_at"] = max(current["ended_at"], event.event_time)
        current["event_count"] += 1
        current["raw_session_ids"].add(event.session_id)
        event.reconstructed_session_id = current["id"]
    now = _datetime.datetime.utcnow()
    for item in sessions.values():
        row = item["row"] or AnalyticsSession(id=item["id"], anonymous_id=item["anonymous_id"])
        row.slip_id = item["slip_id"]
        row.started_at = item["started_at"]
        row.ended_at = item["ended_at"]
        row.event_count = item["event_count"]
        row.raw_session_ids = sorted(item["raw_session_ids"])
        row.updated_at = now
        db.session.add(row)
    db.session.commit()
    return len(events)


def process_deletions(limit=100):
    rows = (
        db.session.query(AnalyticsDeletion)
        .filter(AnalyticsDeletion.status == "pending")
        .order_by(AnalyticsDeletion.requested_at.asc())
        .limit(limit)
        .all()
    )
    completed = 0
    for deletion in rows:
        try:
            subject_filter = AnalyticsEvent.anonymous_id == deletion.subject_id
            if deletion.slip_id is not None:
                subject_filter = or_(subject_filter, AnalyticsEvent.slip_id == deletion.slip_id)
            db.session.query(AnalyticsEvent).filter(subject_filter).delete(synchronize_session=False)
            session_filter = AnalyticsSession.anonymous_id == deletion.subject_id
            if deletion.slip_id is not None:
                session_filter = or_(session_filter, AnalyticsSession.slip_id == deletion.slip_id)
            db.session.query(AnalyticsSession).filter(session_filter).delete(synchronize_session=False)
            db.session.query(AnalyticsAnonProfile).filter(
                AnalyticsAnonProfile.subject_id == deletion.subject_id
            ).delete(synchronize_session=False)
            if deletion.slip_id is not None:
                db.session.query(AnalyticsUserProfile).filter(
                    AnalyticsUserProfile.slip_id == deletion.slip_id
                ).delete(synchronize_session=False)
            log_filter = RecommendationLog.subject_id == deletion.subject_id
            if deletion.slip_id is not None:
                log_filter = or_(log_filter, RecommendationLog.slip_id == deletion.slip_id)
            db.session.query(RecommendationLog).filter(log_filter).delete(synchronize_session=False)
            exposure_filter = ExperimentExposure.subject_id == deletion.subject_id
            satisfaction_filter = RecommendationSatisfaction.subject_id == deletion.subject_id
            if deletion.slip_id is not None:
                exposure_filter = or_(exposure_filter, ExperimentExposure.slip_id == deletion.slip_id)
                satisfaction_filter = or_(satisfaction_filter, RecommendationSatisfaction.slip_id == deletion.slip_id)
            db.session.query(ExperimentExposure).filter(exposure_filter).delete(synchronize_session=False)
            db.session.query(RecommendationSatisfaction).filter(satisfaction_filter).delete(synchronize_session=False)
            for model in (BehaviorSequence, NotificationRecommendation, RecommendationPreference, UserValuePrediction):
                advanced_filter = model.subject_id == deletion.subject_id
                if deletion.slip_id is not None and hasattr(model, "slip_id"):
                    advanced_filter = or_(advanced_filter, model.slip_id == deletion.slip_id)
                db.session.query(model).filter(advanced_filter).delete(synchronize_session=False)
            interaction_filter = RecommendationInteraction.subject_id == deletion.subject_id
            if deletion.slip_id is not None:
                interaction_filter = or_(interaction_filter, RecommendationInteraction.slip_id == deletion.slip_id)
            removed_interactions = db.session.query(RecommendationInteraction).filter(
                interaction_filter
            ).delete(synchronize_session=False)
            # The aggregate item-item model cannot subtract one subject's
            # contribution. Remove it conservatively; the elected nightly job
            # rebuilds from the remaining consented interaction export.
            if removed_interactions:
                db.session.query(CollaborativeSimilarity).delete(synchronize_session=False)
                model_state = db.session.get(AnalyticsJobState, "phase3_collaborative_refresh")
                if model_state is not None:
                    model_state.status = "pending"
                    model_state.last_completed_at = None
            try:
                import keystore
                redis_client = keystore.make_redis()
                keys = set()
                for pattern in (
                    "analytics:%s:*" % deletion.subject_id,
                    "analytics:*:%s" % deletion.subject_id,
                ):
                    for key in redis_client.scan_iter(match=pattern, count=100):
                        keys.add(key)
                if keys:
                    redis_client.delete(*list(keys))
            except Exception:
                # INTERNAL/dev storage has no analytics keys or scan API.
                if shared.app.config.get("STORE_PROVIDER") == "REDIS":
                    raise
            deletion.status = "complete"
            deletion.completed_at = _datetime.datetime.utcnow()
            deletion.error = None
            db.session.commit()
            completed += 1
        except Exception as exc:
            db.session.rollback()
            deletion = db.session.query(AnalyticsDeletion).filter(AnalyticsDeletion.id == deletion.id).one()
            deletion.status = "error"
            deletion.error = str(exc)[:500]
            db.session.commit()
    return completed


def purge_expired(now=None):
    now = now or _datetime.datetime.utcnow()
    identity_cutoff = now - IDENTITY_RETENTION
    event_cutoff = now - EVENT_RETENTION
    issue_cutoff = now - ISSUE_RETENTION
    ledger_cutoff = now - DELETION_LEDGER_RETENTION
    deidentified_events = (
        db.session.query(AnalyticsEvent)
        .filter(AnalyticsEvent.event_time < identity_cutoff, AnalyticsEvent.slip_id.isnot(None))
        .update({AnalyticsEvent.slip_id: None}, synchronize_session=False)
    )
    deidentified_sessions = (
        db.session.query(AnalyticsSession)
        .filter(AnalyticsSession.ended_at < identity_cutoff, AnalyticsSession.slip_id.isnot(None))
        .update({AnalyticsSession.slip_id: None}, synchronize_session=False)
    )
    expired_events = db.session.query(AnalyticsEvent).filter(AnalyticsEvent.event_time < event_cutoff).delete(synchronize_session=False)
    db.session.query(AnalyticsSession).filter(AnalyticsSession.ended_at < event_cutoff).delete(synchronize_session=False)
    db.session.query(AnalyticsIngestIssue).filter(AnalyticsIngestIssue.occurred_at < issue_cutoff).delete(synchronize_session=False)
    db.session.query(AnalyticsDeletion).filter(
        AnalyticsDeletion.completed_at.isnot(None), AnalyticsDeletion.completed_at < ledger_cutoff
    ).delete(synchronize_session=False)
    db.session.query(AnalyticsAnonProfile).filter(AnalyticsAnonProfile.expires_at < now).delete(synchronize_session=False)
    db.session.query(AnalyticsUserProfile).filter(AnalyticsUserProfile.expires_at < now).delete(synchronize_session=False)
    db.session.query(RecommendationLog).filter(RecommendationLog.expires_at < now).delete(synchronize_session=False)
    db.session.query(RecommendationInteraction).filter(RecommendationInteraction.expires_at < now).delete(synchronize_session=False)
    db.session.query(ExperimentExposure).filter(ExperimentExposure.expires_at < now).delete(synchronize_session=False)
    db.session.query(RecommendationSatisfaction).filter(RecommendationSatisfaction.expires_at < now).delete(synchronize_session=False)
    db.session.query(BehaviorMetricDaily).filter(
        BehaviorMetricDaily.day < (now - _datetime.timedelta(days=730)).date()
    ).delete(synchronize_session=False)
    db.session.query(BehaviorSequence).filter(BehaviorSequence.expires_at < now).delete(synchronize_session=False)
    db.session.query(UserValuePrediction).filter(UserValuePrediction.expires_at < now).delete(synchronize_session=False)
    db.session.query(NotificationRecommendation).filter(NotificationRecommendation.expires_at < now).delete(synchronize_session=False)
    db.session.commit()
    return {"deidentified_events": deidentified_events, "deidentified_sessions": deidentified_sessions, "expired_events": expired_events}


def quality_summary(hours=24, now=None):
    now = now or _datetime.datetime.utcnow()
    since = now - _datetime.timedelta(hours=hours)
    accepted = db.session.query(func.count()).select_from(AnalyticsEvent).filter(AnalyticsEvent.received_time >= since).scalar() or 0
    issues = dict(
        db.session.query(AnalyticsIngestIssue.category, func.sum(AnalyticsIngestIssue.count))
        .filter(AnalyticsIngestIssue.occurred_at >= since)
        .group_by(AnalyticsIngestIssue.category)
        .all()
    )
    schema_rejected = int(issues.get("schema_rejected", 0) or 0)
    denominator = accepted + schema_rejected
    latency = db.session.query(func.avg(
        func.extract("epoch", AnalyticsEvent.received_time - AnalyticsEvent.event_time)
    )).filter(AnalyticsEvent.received_time >= since).scalar() if db.engine.url.get_backend_name() in ("postgresql", "postgres") else None
    return {
        "hours": hours,
        "accepted": int(accepted),
        "issues": {key: int(value) for key, value in issues.items()},
        "schema_valid_percent": round(100.0 * accepted / denominator, 2) if denominator else None,
        "duplicate_rate_percent": round(100.0 * int(issues.get("duplicate", 0) or 0) / max(1, accepted), 2),
        "average_latency_seconds": round(float(latency), 3) if latency is not None else None,
    }


def run_maintenance_cycle():
    ensure_event_partitions()
    deleted = process_deletions()
    sessionized = sessionize_events()
    purged = purge_expired()
    from services.analytics.features import refresh_phase2
    phase2 = refresh_phase2()
    from services.analytics.dashboards import refresh_behavior_rollups
    phase4_rollups = refresh_behavior_rollups()
    return {"deletions": deleted, "sessionized": sessionized, "purged": purged, "phase2": phase2, "phase4_rollups": phase4_rollups}


def _maintenance_loop(app):
    interval = max(60, _config_int("ANALYTICS_MAINTENANCE_INTERVAL_SECONDS", 300))
    while True:
        try:
            with app.app_context():
                if _leader():
                    run_maintenance_cycle()
        except Exception:
            app.logger.exception("analytics: maintenance cycle failed")
            try:
                db.session.rollback()
            except Exception:
                pass
        time.sleep(interval)


def start_analytics_maintenance(app):
    if not _enabled() or app.config.get("TESTING"):
        return None
    return shared.spawn_native_thread(
        target=_maintenance_loop,
        args=(app,),
        name="analytics-maintenance",
        daemon=True,
    )
