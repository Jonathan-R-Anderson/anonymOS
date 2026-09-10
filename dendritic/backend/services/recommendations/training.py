"""Nightly weighted interaction export and item-item collaborative model."""

import datetime as _datetime
import math
import os
import time
from collections import defaultdict

import shared
from model.Analytics import AnalyticsConsent, AnalyticsEvent, AnalyticsJobState
from model.Recommendation import CollaborativeSimilarity, RecommendationInteraction
from services.aggregator_sync.state import (
    _close_raw_connection,
    _open_background_sync_connection,
    _set_connection_autocommit,
)
from services.analytics.features import ACCOUNT_RETENTION, ANON_RETENTION, _effective_event_weight
from shared import db


LOCK_ID = 741314
JOB_NAME = "phase3_collaborative_refresh"
MODEL_VERSION = "item-item-v1"
REFRESH_INTERVAL = _datetime.timedelta(hours=24)
_lock_connection = None


def _config_int(name, default):
    try:
        return int(shared.app.config.get(name, os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


def _enabled():
    value = shared.app.config.get("RECOMMENDER_MAINTENANCE_ENABLED", True)
    return value if isinstance(value, bool) else str(value).strip().lower() not in ("", "0", "false", "no", "off")


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
    cursor.execute("SELECT pg_try_advisory_lock(%s)", (_config_int("RECOMMENDER_ADVISORY_LOCK_ID", LOCK_ID),))
    acquired = bool(cursor.fetchone()[0])
    cursor.close()
    if acquired:
        _lock_connection = connection
        return True
    _close_raw_connection(connection)
    return False


def refresh_interaction_export(now=None):
    now = now or _datetime.datetime.utcnow()
    db.session.query(RecommendationInteraction).delete(synchronize_session=False)
    consent_by_subject = {
        row.subject_id: row
        for row in db.session.query(AnalyticsConsent).filter(
            AnalyticsConsent.analytics.is_(True), AnalyticsConsent.personalization.is_(True)
        ).all()
    }
    aggregates = {}
    query = db.session.query(AnalyticsEvent).filter(
        AnalyticsEvent.anonymous_id.in_(list(consent_by_subject)),
        AnalyticsEvent.content_type.in_(("thread", "video")),
        AnalyticsEvent.content_id.isnot(None),
    )
    for event in query.yield_per(2000):
        if not str(event.content_id).isdigit():
            continue
        direction, weight = _effective_event_weight(event)
        if direction is None:
            continue
        key = (event.anonymous_id, event.content_type, event.content_id)
        item = aggregates.setdefault(key, {"positive": 0.0, "negative": 0.0, "count": 0, "last": event.event_time})
        item[direction] += weight
        item["count"] += 1
        item["last"] = max(item["last"], event.event_time)
    rows = []
    for (subject_id, content_type, content_id), item in aggregates.items():
        consent = consent_by_subject[subject_id]
        retention = ACCOUNT_RETENTION if consent.slip_id is not None else ANON_RETENTION
        expiry = item["last"] + retention
        if expiry <= now:
            continue
        rows.append(RecommendationInteraction(
            subject_id=subject_id,
            content_type=content_type,
            content_id=content_id,
            slip_id=consent.slip_id,
            positive_weight=item["positive"],
            negative_weight=item["negative"],
            net_weight=item["positive"] - item["negative"],
            event_count=item["count"],
            last_event_at=item["last"],
            updated_at=now,
            expires_at=expiry,
        ))
    db.session.add_all(rows)
    db.session.commit()
    return len(rows)


def refresh_item_similarity(now=None):
    now = now or _datetime.datetime.utcnow()
    db.session.query(CollaborativeSimilarity).delete(synchronize_session=False)
    by_subject = defaultdict(list)
    totals = defaultdict(float)
    for row in db.session.query(RecommendationInteraction).filter(RecommendationInteraction.net_weight > 0).all():
        by_subject[row.subject_id].append(row)
        totals[(row.content_type, row.content_id)] += row.net_weight
    pair_scores = defaultdict(float)
    pair_support = defaultdict(int)
    for rows in by_subject.values():
        rows = sorted(rows, key=lambda row: row.net_weight, reverse=True)[:50]
        for source in rows:
            for target in rows:
                if source.content_type == target.content_type and source.content_id == target.content_id:
                    continue
                pair = (source.content_type, source.content_id, target.content_type, target.content_id)
                pair_scores[pair] += min(source.net_weight, target.net_weight)
                pair_support[pair] += 1
    by_source = defaultdict(list)
    for pair, raw_score in pair_scores.items():
        source_key = pair[:2]
        target_key = pair[2:]
        normalized = raw_score / max(1.0, math.sqrt(totals[source_key] * totals[target_key]))
        by_source[source_key].append((normalized, pair, pair_support[pair]))
    output = []
    for candidates in by_source.values():
        for score, pair, support in sorted(candidates, reverse=True)[:100]:
            output.append(CollaborativeSimilarity(
                source_type=pair[0], source_id=pair[1], target_type=pair[2], target_id=pair[3],
                score=round(score, 8), support=support, model_version=MODEL_VERSION, updated_at=now,
            ))
    db.session.add_all(output)
    db.session.commit()
    return len(output)


def refresh_recommendation_model(now=None, force=False):
    now = now or _datetime.datetime.utcnow()
    state = db.session.get(AnalyticsJobState, JOB_NAME)
    if not force and state is not None and state.last_completed_at and now - state.last_completed_at < REFRESH_INTERVAL:
        return {"status": "not_due", "last_completed_at": state.last_completed_at}
    if state is None:
        state = AnalyticsJobState(name=JOB_NAME)
    state.last_started_at = now
    state.status = "running"
    db.session.add(state)
    db.session.commit()
    try:
        if not shared.app.config.get("ANALYTICS_PERSONALIZATION_ENABLED", False):
            interactions = db.session.query(RecommendationInteraction).delete(synchronize_session=False)
            similarities = db.session.query(CollaborativeSimilarity).delete(synchronize_session=False)
            db.session.commit()
        else:
            interactions = refresh_interaction_export(now)
            similarities = refresh_item_similarity(now)
        from services.recommendations.advanced import refresh_phase5
        from services.recommendations.maturity import run_maturity_cycle
        advanced = refresh_phase5(now=now, force=True)
        maturity = run_maturity_cycle(now=now)
        state = db.session.get(AnalyticsJobState, JOB_NAME)
        state.status = "complete"
        state.last_completed_at = now
        state.detail = {
            "interactions": interactions, "similarities": similarities, "model_version": MODEL_VERSION,
            "advanced": advanced, "maturity": maturity,
        }
        db.session.commit()
        return state.detail
    except Exception as exc:
        db.session.rollback()
        state = db.session.get(AnalyticsJobState, JOB_NAME) or AnalyticsJobState(name=JOB_NAME)
        state.status = "error"
        state.detail = {"error": str(exc)[:500]}
        db.session.add(state)
        db.session.commit()
        raise


def _loop(app):
    interval = max(300, _config_int("RECOMMENDER_MAINTENANCE_INTERVAL_SECONDS", 3600))
    while True:
        try:
            with app.app_context():
                if _leader():
                    refresh_recommendation_model()
        except Exception:
            app.logger.exception("recommendations: collaborative refresh failed")
            try:
                db.session.rollback()
            except Exception:
                pass
        time.sleep(interval)


def start_recommendation_maintenance(app):
    if not _enabled() or app.config.get("TESTING"):
        return None
    return shared.spawn_native_thread(target=_loop, args=(app,), name="recommendation-maintenance", daemon=True)
