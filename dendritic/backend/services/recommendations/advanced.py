"""Phase 5 sequence, value, notification, and contextual-bandit baselines."""

import datetime as _datetime
import hashlib
import math
from collections import Counter, defaultdict
from dataclasses import dataclass

from model.AdvancedRecommendation import (
    BehaviorSequence,
    ContextualBanditArm,
    NotificationRecommendation,
    RecommendationPreference,
    UserValuePrediction,
)
from model.Analytics import AnalyticsConsent, AnalyticsEvent, AnalyticsJobState, ContentFeature
from services.analytics.features import ACCOUNT_RETENTION, ANON_RETENTION, cosine_similarity, text_embedding
from shared import app, db


JOB_NAME = "phase5_advanced_refresh"
MODEL_VERSION = "advanced-personalization-v1"
ARMS = ("familiar", "fresh_creator", "new_topic", "cross_format")
POSITIVE = frozenset((
    "recommendation_clicked", "bookmark_added", "follow_added", "video_completed",
    "content_left_viewport", "comment_submitted", "reply_submitted", "share_clicked",
))
NEGATIVE = frozenset(("hide_selected", "not_interested_selected", "report_submitted"))


@dataclass(frozen=True)
class BanditDecision:
    arm: str
    propensity: float
    context_key: str


def _normalize(vector):
    magnitude = math.sqrt(sum(float(value) ** 2 for value in vector))
    return [round(float(value) / magnitude, 8) for value in vector] if magnitude else list(vector)


def _sequence_values(events, features):
    recent_items = []
    topics = []
    vectors = []
    relevant = [event for event in events if event.event_name in POSITIVE and event.content_id][-100:]
    for offset, event in enumerate(reversed(relevant)):
        feature = features.get((event.content_type, event.content_id))
        if feature is None:
            continue
        decay = math.exp(-offset / 12.0)
        recent_items.append({
            "content_type": event.content_type, "content_id": event.content_id,
            "event_name": event.event_name, "event_time": event.event_time.isoformat() + "Z",
        })
        topics.extend((feature.tags or [])[:3] + (feature.keywords or [])[:5])
        vector = feature.multimodal_embedding or feature.embedding or []
        if vector:
            vectors.append([decay * float(value) for value in vector])
    if vectors:
        combined = [sum(vector[index] for vector in vectors) for index in range(len(vectors[0]))]
    else:
        combined = []
    return recent_items[:50], [name for name, _ in Counter(topics).most_common(50)], _normalize(combined), len(relevant)


def refresh_advanced_models(now=None):
    now = now or _datetime.datetime.utcnow()
    if not app.config.get("ANALYTICS_PERSONALIZATION_ENABLED", False):
        removed = 0
        for model in (BehaviorSequence, UserValuePrediction, NotificationRecommendation):
            removed += db.session.query(model).delete(synchronize_session=False)
        db.session.commit()
        return {"sequences": 0, "predictions": 0, "notifications": 0, "removed_while_gated": removed}
    features = {(row.content_type, row.content_id): row for row in db.session.query(ContentFeature).all()}
    consents = db.session.query(AnalyticsConsent).filter(
        AnalyticsConsent.analytics.is_(True), AnalyticsConsent.personalization.is_(True)
    ).all()
    valid = set()
    notification_count = 0
    for consent in consents:
        events = db.session.query(AnalyticsEvent).filter(
            AnalyticsEvent.anonymous_id == consent.subject_id
        ).order_by(AnalyticsEvent.event_time.asc()).all()
        if not events:
            continue
        recent_items, topics, sequence_embedding, used = _sequence_values(events, features)
        retention = ACCOUNT_RETENTION if consent.slip_id is not None else ANON_RETENTION
        expiry = events[-1].event_time + retention
        if expiry <= now:
            continue
        valid.add(consent.subject_id)
        sequence = db.session.get(BehaviorSequence, consent.subject_id) or BehaviorSequence(subject_id=consent.subject_id)
        sequence.slip_id = consent.slip_id
        sequence.recent_items = recent_items
        sequence.recent_topics = topics
        sequence.sequence_embedding = sequence_embedding
        sequence.source_event_count = used
        sequence.model_version = "sasrec-style-hash-v1"
        sequence.updated_at = now
        sequence.expires_at = expiry
        db.session.add(sequence)

        active_days = len({event.event_time.date() for event in events[-500:]})
        positive = sum(event.event_name in POSITIVE for event in events[-500:])
        negative = sum(event.event_name in NEGATIVE for event in events[-500:])
        days_since = max(0.0, (now - events[-1].event_time).total_seconds() / 86400.0)
        churn = 1.0 / (1.0 + math.exp(-(days_since - 7.0) / 3.0))
        constructive = max(0.0, positive - 2.0 * negative)
        value = min(1.0, (math.log1p(active_days) + math.log1p(constructive)) / 8.0)
        prediction = db.session.get(UserValuePrediction, consent.subject_id) or UserValuePrediction(subject_id=consent.subject_id)
        prediction.slip_id = consent.slip_id
        prediction.churn_probability = round(churn, 6)
        prediction.long_term_value = round(value, 6)
        prediction.components = {"active_days": active_days, "positive": positive, "negative": negative, "days_since_active": round(days_since, 3)}
        prediction.updated_at = now
        prediction.expires_at = expiry
        db.session.add(prediction)

        recent_set = {(item["content_type"], item["content_id"]) for item in recent_items}
        candidates = []
        for key, feature in features.items():
            if key in recent_set or not feature.moderation_eligible:
                continue
            similarity = max(0.0, cosine_similarity(sequence_embedding, feature.multimodal_embedding or feature.embedding))
            if similarity > 0:
                candidates.append((similarity, key, feature))
        db.session.query(NotificationRecommendation).filter_by(subject_id=consent.subject_id).delete(synchronize_session=False)
        for score, key, feature in sorted(candidates, reverse=True)[:5]:
            db.session.add(NotificationRecommendation(
                subject_id=consent.subject_id, slip_id=consent.slip_id,
                content_type=key[0], content_id=key[1], score=round(score * (1.0 - 0.25 * churn), 6),
                reason="A new item matches your recent activity", status="pending",
                created_at=now, expires_at=min(expiry, now + _datetime.timedelta(days=7)),
            ))
            notification_count += 1
    for model in (BehaviorSequence, UserValuePrediction):
        for row in db.session.query(model).all():
            if row.subject_id not in valid or row.expires_at <= now:
                db.session.delete(row)
    db.session.commit()
    return {"sequences": len(valid), "predictions": len(valid), "notifications": notification_count, "model_version": MODEL_VERSION}


def refresh_phase5(now=None, force=False):
    now = now or _datetime.datetime.utcnow()
    state = db.session.get(AnalyticsJobState, JOB_NAME)
    if not force and state is not None and state.last_completed_at and now - state.last_completed_at < _datetime.timedelta(hours=24):
        return {"status": "not_due", "last_completed_at": state.last_completed_at}
    state = state or AnalyticsJobState(name=JOB_NAME)
    state.status = "running"
    state.last_started_at = now
    db.session.add(state)
    db.session.commit()
    try:
        detail = refresh_advanced_models(now)
        state = db.session.get(AnalyticsJobState, JOB_NAME)
        state.status = "complete"
        state.last_completed_at = now
        state.detail = detail
        db.session.commit()
        return detail
    except Exception as exc:
        db.session.rollback()
        state = db.session.get(AnalyticsJobState, JOB_NAME) or AnalyticsJobState(name=JOB_NAME)
        state.status = "error"
        state.detail = {"error": str(exc)[:500]}
        db.session.add(state)
        db.session.commit()
        raise


def update_realtime_sequence(events, consent):
    """Update short-term intent immediately after a validated event commit."""
    if not events or consent is None or not consent.personalization or not app.config.get("ANALYTICS_PERSONALIZATION_ENABLED", False):
        return None
    event = events[-1]
    if event.event_name not in POSITIVE or not event.content_id:
        return None
    feature = db.session.query(ContentFeature).filter_by(content_type=event.content_type, content_id=event.content_id).one_or_none()
    if feature is None:
        return None
    row = db.session.get(BehaviorSequence, consent.subject_id) or BehaviorSequence(subject_id=consent.subject_id)
    items = list(row.recent_items or [])
    items.insert(0, {"content_type": event.content_type, "content_id": event.content_id, "event_name": event.event_name, "event_time": event.event_time.isoformat() + "Z"})
    topics = list(feature.tags or [])[:3] + list(feature.keywords or [])[:5] + list(row.recent_topics or [])
    current = row.sequence_embedding or []
    incoming = feature.multimodal_embedding or feature.embedding or []
    combined = incoming if not current else [0.65 * float(a) + 0.35 * float(b) for a, b in zip(incoming, current)]
    row.slip_id = consent.slip_id
    row.recent_items = items[:50]
    row.recent_topics = [name for name, _ in Counter(topics).most_common(50)]
    row.sequence_embedding = _normalize(combined)
    row.source_event_count = int(row.source_event_count or 0) + 1
    row.updated_at = _datetime.datetime.utcnow()
    row.expires_at = row.updated_at + (ACCOUNT_RETENTION if consent.slip_id is not None else ANON_RETENTION)
    db.session.add(row)
    db.session.commit()
    return row


def advanced_viewer_state(subject_id):
    if not subject_id:
        return None, None, None
    return (
        db.session.get(BehaviorSequence, subject_id),
        db.session.get(UserValuePrediction, subject_id),
        db.session.get(RecommendationPreference, subject_id),
    )


def contextual_bandit(subject_id, surface, content_type, session_depth=0, enabled=True):
    context_key = "%s:%s:%s" % (surface, content_type, min(5, max(0, int(session_depth)) // 5))
    if not subject_id or not enabled:
        return BanditDecision("familiar", 1.0, context_key)
    states = {row.arm: row for row in db.session.query(ContextualBanditArm).filter_by(context_key=context_key).all()}
    total = sum(row.pulls for row in states.values())
    scores = {}
    for arm in ARMS:
        row = states.get(arm)
        pulls = row.pulls if row else 0
        mean = row.reward_sum / pulls if row and pulls else 0.0
        scores[arm] = mean + math.sqrt(2.0 * math.log(total + len(ARMS) + 1.0) / (pulls + 1.0))
    greedy = max(ARMS, key=lambda arm: (scores[arm], arm))
    epsilon = max(0.0, min(0.25, float(app.config.get("RECOMMENDER_BANDIT_EPSILON", 0.10))))
    bucket = int(hashlib.sha256((subject_id + context_key + _datetime.datetime.utcnow().strftime("%Y-%m-%dT%H")).encode("utf-8")).hexdigest()[:8], 16) / float(0xFFFFFFFF)
    explore = bucket < epsilon
    if explore:
        index = int(hashlib.sha256((context_key + subject_id).encode("utf-8")).hexdigest()[8:16], 16) % len(ARMS)
        selected = ARMS[index]
    else:
        selected = greedy
    propensity = epsilon / len(ARMS) + ((1.0 - epsilon) if selected == greedy else 0.0)
    return BanditDecision(selected, round(propensity, 6), context_key)


def sequence_affinity(sequence, feature):
    if sequence is None or feature is None:
        return 0.0
    return max(0.0, cosine_similarity(sequence.sequence_embedding, feature.multimodal_embedding or feature.embedding or []))
