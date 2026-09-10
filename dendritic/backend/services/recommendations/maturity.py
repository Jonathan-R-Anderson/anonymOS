"""Phase 5 continuous measurement, fairness, drift, and audit controls."""

import datetime as _datetime
import hashlib
import json
import math
import uuid
from collections import Counter, defaultdict

from model.AdvancedRecommendation import (
    AlgorithmAudit,
    ContextualBanditArm,
    CreatorExposureDaily,
    ModelHealthSnapshot,
)
from model.Analytics import AnalyticsAnonProfile, AnalyticsEvent, AnalyticsUserProfile, ContentFeature
from model.Experiment import BehaviorMetricDaily, ExperimentDefinition, ExperimentExposure, RecommendationSatisfaction
from model.Recommendation import RecommendationLog
from shared import app, db


def _creator_map(content_type, content_ids):
    values = {}
    numeric = [int(value) for value in content_ids if str(value).isdigit()]
    if content_type == "video":
        from model.Video import Video
        for row in db.session.query(Video).filter(Video.id.in_(numeric)).all():
            values[str(row.id)] = str(row.slip_id)
    elif content_type == "thread":
        from model.Thread import Thread
        for row in db.session.query(Thread).filter(Thread.id.in_(numeric)).all():
            creator = None
            if row.posts and row.posts[0].poster is not None:
                from model.Poster import Poster
                poster = db.session.get(Poster, row.posts[0].poster)
                creator = "slip:%s" % poster.slip if poster and poster.slip else "poster:%s" % row.posts[0].poster
            values[str(row.id)] = creator or "unknown"
    return values


def refresh_bandit_rewards(now=None, days=30):
    now = now or _datetime.datetime.utcnow()
    since = now - _datetime.timedelta(days=days)
    logs = db.session.query(RecommendationLog).filter(
        RecommendationLog.created_at >= since, RecommendationLog.bandit_arm.isnot(None)
    ).all()
    request_ids = [row.request_id for row in logs]
    events = db.session.query(AnalyticsEvent).filter(AnalyticsEvent.request_id.in_(request_ids)).all() if request_ids else []
    satisfaction = db.session.query(RecommendationSatisfaction).filter(
        RecommendationSatisfaction.request_id.in_(request_ids)
    ).all() if request_ids else []
    rewards = defaultdict(float)
    for event in events:
        if event.event_name == "recommendation_clicked":
            rewards[event.request_id] += 1.0
        elif event.event_name in ("hide_selected", "not_interested_selected"):
            rewards[event.request_id] -= 1.0
        elif event.event_name == "report_submitted":
            rewards[event.request_id] -= 2.0
    for row in satisfaction:
        rewards[row.request_id] += (row.rating - 3.0) / 2.0
    db.session.query(ContextualBanditArm).delete(synchronize_session=False)
    aggregates = defaultdict(list)
    for log in logs:
        aggregates[(log.policy_context or "unknown", log.bandit_arm)].append(rewards.get(log.request_id, 0.0))
    for (context_key, arm), values in aggregates.items():
        db.session.add(ContextualBanditArm(
            context_key=context_key, arm=arm, pulls=len(values), reward_sum=sum(values),
            reward_square_sum=sum(value * value for value in values), updated_at=now,
        ))
    db.session.commit()
    return len(aggregates)


def refresh_creator_exposure(now=None, days=31):
    now = now or _datetime.datetime.utcnow()
    since = now - _datetime.timedelta(days=days - 1)
    events = db.session.query(AnalyticsEvent).filter(
        AnalyticsEvent.event_time >= since,
        AnalyticsEvent.event_name.in_(("recommendation_impression", "recommendation_viewed")),
        AnalyticsEvent.content_type.in_(("thread", "video")),
        AnalyticsEvent.content_id.isnot(None),
    ).all()
    db.session.query(CreatorExposureDaily).filter(CreatorExposureDaily.day >= since.date()).delete(synchronize_session=False)
    maps = {}
    for content_type in ("thread", "video"):
        ids = {event.content_id for event in events if event.content_type == content_type}
        maps[content_type] = _creator_map(content_type, ids)
    aggregates = defaultdict(lambda: {"impressions": 0, "exploration": 0, "items": set()})
    logs = {row.request_id: row for row in db.session.query(RecommendationLog).filter(
        RecommendationLog.request_id.in_([event.request_id for event in events if event.request_id])
    ).all()} if events else {}
    for event in events:
        creator = maps.get(event.content_type, {}).get(event.content_id, "unknown")
        key = (event.event_time.date(), event.content_type, creator)
        aggregates[key]["impressions"] += 1
        aggregates[key]["items"].add(event.content_id)
        log = logs.get(event.request_id)
        if log and event.position is not None and event.position < len(log.exploration_propensities or []):
            aggregates[key]["exploration"] += int(bool(log.exploration_propensities[event.position]))
    for (day, content_type, creator), values in aggregates.items():
        db.session.add(CreatorExposureDaily(
            day=day, content_type=content_type, creator_id=creator,
            impressions=values["impressions"], exploration_impressions=values["exploration"],
            unique_items=len(values["items"]), updated_at=now,
        ))
    db.session.commit()
    return len(aggregates)


def causal_experiment_estimate(experiment_id, hours=24 * 30, now=None):
    now = now or _datetime.datetime.utcnow()
    since = now - _datetime.timedelta(hours=hours)
    exposures = db.session.query(ExperimentExposure).filter(
        ExperimentExposure.experiment_id == experiment_id,
        ExperimentExposure.exposed_at >= since,
    ).all()
    clicked = {request_id for (request_id,) in db.session.query(AnalyticsEvent.request_id).filter(
        AnalyticsEvent.request_id.in_([row.request_id for row in exposures]),
        AnalyticsEvent.event_name == "recommendation_clicked",
    ).all()} if exposures else set()
    outcomes = defaultdict(list)
    for row in exposures:
        outcomes[row.variant].append(1.0 if row.request_id in clicked else 0.0)
    means = {variant: sum(values) / len(values) for variant, values in outcomes.items() if values}
    baseline_name = "control" if "control" in means else (sorted(means)[0] if means else None)
    effects = {}
    if baseline_name:
        baseline = outcomes[baseline_name]
        for variant, values in outcomes.items():
            if variant == baseline_name:
                continue
            effect = means[variant] - means[baseline_name]
            variance = means[variant] * (1 - means[variant]) / max(1, len(values))
            variance += means[baseline_name] * (1 - means[baseline_name]) / max(1, len(baseline))
            standard_error = math.sqrt(variance)
            effects[variant] = {
                "absolute_effect": round(effect, 6),
                "standard_error": round(standard_error, 6),
                "ci95": [round(effect - 1.96 * standard_error, 6), round(effect + 1.96 * standard_error, 6)],
            }
    return {"experiment_id": experiment_id, "baseline": baseline_name, "sample_by_variant": {key: len(value) for key, value in outcomes.items()}, "mean_by_variant": means, "effects": effects}


def _gini(values):
    values = sorted(max(0.0, float(value)) for value in values)
    total = sum(values)
    if not values or not total:
        return 0.0
    weighted = sum((index + 1) * value for index, value in enumerate(values))
    return (2.0 * weighted) / (len(values) * total) - (len(values) + 1.0) / len(values)


def fairness_summary(days=30, now=None):
    now = now or _datetime.datetime.utcnow()
    since = (now - _datetime.timedelta(days=days)).date()
    rows = db.session.query(CreatorExposureDaily).filter(CreatorExposureDaily.day >= since).all()
    by_creator = Counter()
    discovery = Counter()
    for row in rows:
        by_creator[row.creator_id] += row.impressions
        discovery[row.creator_id] += row.exploration_impressions
    total = sum(by_creator.values())
    top = sum(value for _, value in by_creator.most_common(max(1, math.ceil(len(by_creator) * 0.1))))
    return {
        "creators": len(by_creator), "impressions": total,
        "creator_gini": round(_gini(by_creator.values()), 6),
        "top_10_percent_share": round(top / total, 6) if total else 0.0,
        "creators_with_exploration": sum(value > 0 for value in discovery.values()),
    }


def refresh_privacy_aggregates(now=None, k=5):
    now = now or _datetime.datetime.utcnow()
    topics = Counter()
    for profile in list(db.session.query(AnalyticsUserProfile).all()) + list(db.session.query(AnalyticsAnonProfile).all()):
        topics.update(set((profile.positive_topics or {}).keys()))
    db.session.query(BehaviorMetricDaily).filter_by(
        day=now.date(), dashboard="privacy", metric="k_anonymous_topic_interest"
    ).delete(synchronize_session=False)
    rows = [BehaviorMetricDaily(
        day=now.date(), dashboard="privacy", metric="k_anonymous_topic_interest",
        dimension=topic[:128], value=count, updated_at=now,
    ) for topic, count in topics.items() if count >= k]
    db.session.add_all(rows)
    db.session.commit()
    return len(rows)


def monitor_model_health(now=None):
    now = now or _datetime.datetime.utcnow()
    features = db.session.query(ContentFeature).all()
    current_quality = sum(row.quality_score for row in features) / len(features) if features else 0.0
    previous = db.session.query(ModelHealthSnapshot).order_by(ModelHealthSnapshot.evaluated_at.desc()).first()
    previous_quality = ((previous.feature_drift or {}).get("quality_mean") if previous else current_quality) or 0.0
    drift = abs(current_quality - previous_quality)
    fairness = fairness_summary(now=now)
    violations = []
    if drift > float(app.config.get("RECOMMENDER_FEATURE_DRIFT_MAX", 0.15)):
        violations.append("quality_feature_drift")
    if fairness["creator_gini"] > float(app.config.get("RECOMMENDER_CREATOR_GINI_MAX", 0.80)):
        violations.append("creator_exposure_concentration")
    snapshot = ModelHealthSnapshot(
        model_id="advanced-personalization-v1",
        feature_drift={"quality_mean": round(current_quality, 6), "absolute_change": round(drift, 6)},
        outcome_drift={}, fairness=fairness, violations=violations,
        status="alert" if violations else "healthy", evaluated_at=now,
    )
    db.session.add(snapshot)
    db.session.commit()
    return snapshot


def generate_audit_package(scope="phase5", now=None):
    now = now or _datetime.datetime.utcnow()
    experiments = [{"id": row.id, "status": row.status, "variants": row.variants, "guardrails": row.guardrails} for row in db.session.query(ExperimentDefinition).all()]
    latest_health = db.session.query(ModelHealthSnapshot).order_by(ModelHealthSnapshot.evaluated_at.desc()).first()
    manifest = {
        "scope": scope,
        "generated_at": now.isoformat() + "Z",
        "models": ["linear_baseline_v1", "sasrec-style-hash-v1", "multimodal-hash-64-v1", "contextual-ucb-v1", "survival-value-v1"],
        "experiments": experiments,
        "fairness": fairness_summary(now=now),
        "latest_health": None if latest_health is None else {"status": latest_health.status, "violations": latest_health.violations},
        "privacy": {"personalization_gate": bool(app.config.get("ANALYTICS_PERSONALIZATION_ENABLED", False)), "raw_federated_updates_collected": False},
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    row = AlgorithmAudit(
        id=str(uuid.uuid4()), scope=scope, manifest=manifest,
        checksum=hashlib.sha256(encoded).hexdigest(), status="pending_external_review",
        findings=[], created_at=now,
    )
    db.session.add(row)
    db.session.commit()
    return row


def run_maturity_cycle(now=None):
    now = now or _datetime.datetime.utcnow()
    return {
        "bandit_contexts": refresh_bandit_rewards(now),
        "creator_exposures": refresh_creator_exposure(now),
        "privacy_aggregates": refresh_privacy_aggregates(now),
        "health_status": monitor_model_health(now).status,
    }
