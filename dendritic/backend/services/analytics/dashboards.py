"""Small SSR dashboard rollups over the analytics schema."""

import datetime as _datetime
from collections import Counter, defaultdict

from sqlalchemy import func

from model.Analytics import AnalyticsEvent, AnalyticsIngestIssue, ContentFeature
from model.Experiment import BehaviorMetricDaily, ExperimentDefinition, ExperimentExposure, RecommendationSatisfaction
from model.AdvancedRecommendation import AlgorithmAudit, ModelHealthSnapshot, UserValuePrediction
from model.Recommendation import RecommendationLog
from services.analytics.maintenance import quality_summary
from services.experiments import experiment_snapshot
from services.recommendations.evaluation import offline_evaluation
from services.recommendations.engine import recommendation_quality_summary
from services.recommendations.maturity import causal_experiment_estimate, fairness_summary
from shared import db


NEGATIVE_NAMES = ("hide_selected", "not_interested_selected")


def _event_counts(since):
    rollups = db.session.query(BehaviorMetricDaily.dimension, func.sum(BehaviorMetricDaily.value)).filter(
        BehaviorMetricDaily.dashboard == "product",
        BehaviorMetricDaily.metric == "event_count",
        BehaviorMetricDaily.day >= since.date(),
    ).group_by(BehaviorMetricDaily.dimension).all()
    if rollups:
        return {name: int(value) for name, value in rollups}
    return dict(db.session.query(AnalyticsEvent.event_name, func.count()).filter(
        AnalyticsEvent.event_time >= since
    ).group_by(AnalyticsEvent.event_name).all())


def _daily_active(since):
    rollups = db.session.query(BehaviorMetricDaily).filter(
        BehaviorMetricDaily.dashboard == "executive",
        BehaviorMetricDaily.metric == "active_users",
        BehaviorMetricDaily.day >= since.date(),
    ).order_by(BehaviorMetricDaily.day).all()
    if rollups:
        return [{"label": row.day.isoformat(), "value": int(row.value)} for row in rollups]
    rows = db.session.query(AnalyticsEvent.event_time, AnalyticsEvent.anonymous_id).filter(
        AnalyticsEvent.event_time >= since
    ).all()
    days = defaultdict(set)
    for event_time, subject_id in rows:
        days[event_time.date().isoformat()].add(subject_id)
    return [{"label": day, "value": len(subjects)} for day, subjects in sorted(days.items())]


def refresh_behavior_rollups(now=None, days=31):
    """Rebuild bounded daily dashboard facts; safe to replay after restores."""
    now = now or _datetime.datetime.utcnow()
    since_date = (now - _datetime.timedelta(days=max(1, days) - 1)).date()
    since = _datetime.datetime.combine(since_date, _datetime.time.min)
    db.session.query(BehaviorMetricDaily).filter(BehaviorMetricDaily.day >= since_date).delete(
        synchronize_session=False
    )
    events = db.session.query(AnalyticsEvent).filter(AnalyticsEvent.event_time >= since).all()
    event_counts = Counter()
    active = defaultdict(set)
    clients = Counter()
    for event in events:
        day = event.event_time.date()
        event_counts[(day, event.event_name)] += 1
        active[day].add(event.anonymous_id)
        clients[(day, str((event.client or {}).get("app_version", "unknown")))] += 1
    rows = []
    for (day, name), value in event_counts.items():
        rows.append(BehaviorMetricDaily(day=day, dashboard="product", metric="event_count", dimension=name, value=value, updated_at=now))
    for day, subjects in active.items():
        rows.append(BehaviorMetricDaily(day=day, dashboard="executive", metric="active_users", dimension="all", value=len(subjects), updated_at=now))
    for (day, version), value in clients.items():
        rows.append(BehaviorMetricDaily(day=day, dashboard="data-quality", metric="client_version", dimension=version[:128], value=value, updated_at=now))
    logs = db.session.query(RecommendationLog).filter(RecommendationLog.created_at >= since).all()
    recommendation_counts = Counter()
    for log in logs:
        day = log.created_at.date()
        recommendation_counts[(day, "requests", log.model_id)] += 1
        for source_group in log.ranked_sources or []:
            for source in str(source_group).split("."):
                recommendation_counts[(day, "candidate_source", source)] += 1
        recommendation_counts[(day, "exploration_items", "all")] += sum(
            1 for value in (log.exploration_propensities or []) if value
        )
    for (day, metric, dimension), value in recommendation_counts.items():
        rows.append(BehaviorMetricDaily(day=day, dashboard="recommendation", metric=metric, dimension=str(dimension)[:128], value=value, updated_at=now))
    db.session.add_all(rows)
    db.session.commit()
    return len(rows)


def _base(kind, title, description, window_days):
    return {
        "kind": kind,
        "title": title,
        "description": description,
        "window_days": window_days,
        "cards": [],
        "tables": [],
        "notes": [],
    }


def dashboard_payload(kind, window_days=30, now=None):
    now = now or _datetime.datetime.utcnow()
    since = now - _datetime.timedelta(days=window_days)
    counts = _event_counts(since)
    total_events = sum(counts.values())
    unique_users = db.session.query(func.count(func.distinct(AnalyticsEvent.anonymous_id))).filter(
        AnalyticsEvent.event_time >= since
    ).scalar() or 0
    if kind == "executive":
        result = _base(kind, "Executive behavior dashboard", "Audience, durable value, satisfaction, safety, and recommendation contribution.", window_days)
        satisfaction = db.session.query(func.avg(RecommendationSatisfaction.rating)).filter(
            RecommendationSatisfaction.created_at >= since
        ).scalar()
        churn = db.session.query(func.avg(UserValuePrediction.churn_probability)).scalar()
        long_term_value = db.session.query(func.avg(UserValuePrediction.long_term_value)).scalar()
        recommendation_clicks = counts.get("recommendation_clicked", 0)
        result["cards"] = [
            ("Active users", unique_users),
            ("Meaningful dwell completions", counts.get("deep_read_reached", 0)),
            ("Satisfaction", round(float(satisfaction), 2) if satisfaction is not None else "—"),
            ("Recommendation clicks", recommendation_clicks),
            ("Negative feedback", sum(counts.get(name, 0) for name in NEGATIVE_NAMES)),
            ("Reports", counts.get("report_submitted", 0)),
            ("Predicted churn", round(float(churn), 3) if churn is not None else "—"),
            ("Long-term value", round(float(long_term_value), 3) if long_term_value is not None else "—"),
        ]
        result["tables"].append(("Daily active users", ["Date", "Users"], [[row["label"], row["value"]] for row in _daily_active(since)]))
    elif kind == "product":
        result = _base(kind, "Product behavior dashboard", "Funnels, feature adoption, search, participation, and session composition.", window_days)
        result["cards"] = [
            ("Page views", counts.get("page_view", 0)),
            ("Searches", counts.get("search_submitted", 0)),
            ("Search result clicks", counts.get("search_result_clicked", 0)),
            ("Comments", counts.get("comment_submitted", 0)),
            ("Bookmarks", counts.get("bookmark_added", 0)),
            ("Follows", counts.get("follow_added", 0)),
        ]
        top = sorted(counts.items(), key=lambda row: (-row[1], row[0]))[:20]
        result["tables"].append(("Feature adoption", ["Event", "Count"], [[name, value] for name, value in top]))
    elif kind == "recommendation":
        result = _base(kind, "Recommendation dashboard", "Serving, source coverage, exploration, position bias, experiments, and model quality.", window_days)
        quality = recommendation_quality_summary(hours=window_days * 24)
        evaluation = offline_evaluation(hours=window_days * 24, now=now)
        result["cards"] = [
            ("Requests", quality["requests"]),
            ("Source coverage", "%s%%" % quality["source_coverage_percent"]),
            ("Average latency (ms)", quality["average_latency_ms"] if quality["average_latency_ms"] is not None else "—"),
            ("NDCG", evaluation["ndcg_at_served"] if evaluation["ndcg_at_served"] is not None else "—"),
            ("IPS reward", evaluation["inverse_propensity_reward"] if evaluation["inverse_propensity_reward"] is not None else "—"),
            ("Shadow top-1 agreement", evaluation["shadow_top1_agreement"] if evaluation["shadow_top1_agreement"] is not None else "—"),
        ]
        result["tables"].append(("CTR by position", ["Position", "Impressions", "Clicks", "CTR"], [
            [row["position"], row["impressions"], row["clicks"], row["ctr"]] for row in evaluation["position_bias"]
        ]))
        experiments = db.session.query(ExperimentDefinition).order_by(ExperimentDefinition.id).all()
        result["tables"].append(("Experiments", ["Experiment", "Status", "Sample", "SRM", "Action"], [
            [experiment.id, experiment.status, snapshot["sample_size"], "yes" if snapshot["srm_detected"] else "no", snapshot["action"]]
            for experiment in experiments for snapshot in [experiment_snapshot(experiment, hours=window_days * 24)]
        ]))
        result["tables"].append(("Causal click estimates", ["Experiment", "Baseline", "Effects"], [
            [experiment.id, estimate["baseline"] or "—", estimate["effects"]]
            for experiment in experiments for estimate in [causal_experiment_estimate(experiment.id, hours=window_days * 24, now=now)]
        ]))
        health = db.session.query(ModelHealthSnapshot).order_by(ModelHealthSnapshot.evaluated_at.desc()).first()
        if health is not None:
            result["cards"].append(("Model health", health.status))
            result["tables"].append(("Automated drift and fairness", ["Feature drift", "Fairness", "Violations"], [[health.feature_drift, health.fairness, health.violations]]))
        result["notes"].append(evaluation["limitations"])
    elif kind == "content-health":
        result = _base(kind, "Content-health dashboard", "Creator/topic concentration, freshness, moderation eligibility, and safety outcomes.", window_days)
        features = db.session.query(ContentFeature).all()
        topics = Counter()
        for feature in features:
            topics.update((feature.tags or [])[:3] + (feature.keywords or [])[:3])
        eligible = sum(1 for feature in features if feature.moderation_eligible)
        underexposed = sum(1 for feature in features if feature.engagement_velocity < 1.0)
        result["cards"] = [
            ("Feature rows", len(features)),
            ("Moderation eligible", eligible),
            ("Underexposed content", underexposed),
            ("Reports", counts.get("report_submitted", 0)),
            ("Hides / not interested", sum(counts.get(name, 0) for name in NEGATIVE_NAMES)),
            ("Unique topics", len(topics)),
        ]
        fairness = fairness_summary(window_days, now)
        result["cards"].extend([
            ("Creator exposure Gini", fairness["creator_gini"]),
            ("Creators explored", fairness["creators_with_exploration"]),
        ])
        result["tables"].append(("Topic concentration", ["Topic", "Content rows"], [[name, value] for name, value in topics.most_common(20)]))
    elif kind == "data-quality":
        result = _base(kind, "Data-quality dashboard", "Schema validity, latency, duplication, clock skew, consent, and client coverage.", window_days)
        quality = quality_summary(window_days * 24, now=now)
        client_versions = Counter(dict(db.session.query(
            BehaviorMetricDaily.dimension, func.sum(BehaviorMetricDaily.value)
        ).filter(
            BehaviorMetricDaily.dashboard == "data-quality",
            BehaviorMetricDaily.metric == "client_version",
            BehaviorMetricDaily.day >= since.date(),
        ).group_by(BehaviorMetricDaily.dimension).all()))
        if not client_versions:
            for (client,) in db.session.query(AnalyticsEvent.client).filter(AnalyticsEvent.event_time >= since).all():
                client_versions[str((client or {}).get("app_version", "unknown"))] += 1
        result["cards"] = [
            ("Accepted events", quality["accepted"]),
            ("Schema valid", "%s%%" % quality["schema_valid_percent"] if quality["schema_valid_percent"] is not None else "—"),
            ("Duplicate rate", "%s%%" % quality["duplicate_rate_percent"]),
            ("Average latency (s)", quality["average_latency_seconds"] if quality["average_latency_seconds"] is not None else "—"),
            ("Clock skew", quality["issues"].get("clock_skew", 0)),
            ("Consent rejections", quality["issues"].get("consent_rejected", 0)),
        ]
        result["tables"].append(("Client versions", ["Version", "Events"], [[name, value] for name, value in client_versions.most_common()]))
        result["tables"].append(("Ingest issues", ["Issue", "Count"], [[name, value] for name, value in sorted(quality["issues"].items())]))
        audits = db.session.query(AlgorithmAudit).order_by(AlgorithmAudit.created_at.desc()).limit(20).all()
        result["tables"].append(("Independent audit packages", ["ID", "Scope", "Status", "Checksum"], [
            [row.id, row.scope, row.status, row.checksum] for row in audits
        ]))
    else:
        raise ValueError("unknown dashboard kind")
    result["total_events"] = total_events
    return result
