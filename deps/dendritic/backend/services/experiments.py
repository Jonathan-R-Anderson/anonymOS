"""Consent-gated deterministic experiments and automatic guardrail monitoring."""

import datetime as _datetime
import hashlib
import math
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError

from model.Analytics import AnalyticsEvent
from model.Experiment import (
    ExperimentDefinition,
    ExperimentExposure,
    ExperimentGuardrailSnapshot,
    RecommendationSatisfaction,
)
from model.Recommendation import RecommendationLog
from shared import app, db


EXPOSURE_RETENTION = _datetime.timedelta(days=180)
DEFAULT_EXPERIMENT_ID = "phase4_recommender_v1"
_monitor_thread = None


@dataclass(frozen=True)
class Assignment:
    experiment_id: str
    variant: str
    bucket: int

    @property
    def exposure_id(self):
        return "%s:%s" % (self.experiment_id, self.variant)


def _bucket(*parts):
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return int(digest[:16], 16) % 10000


def ensure_default_experiment(now=None):
    """Install a conservative long-term holdout/control/exploration experiment."""
    if not app.config.get("EXPERIMENTS_ENABLED", True):
        return None
    experiment = db.session.get(ExperimentDefinition, DEFAULT_EXPERIMENT_ID)
    if experiment is not None:
        return experiment
    now = now or _datetime.datetime.utcnow()
    experiment = ExperimentDefinition(
        id=DEFAULT_EXPERIMENT_ID,
        name="Phase 4 recommendation exploration",
        namespace="recommendation_ranking",
        status="running",
        traffic_percent=100.0,
        variants={"holdout": 5.0, "control": 85.0, "exploration": 10.0},
        primary_metrics=["meaningful_dwell", "satisfaction", "return_rate"],
        guardrails={
            "minimum_sample": 200,
            "negative_feedback_rate_max": 0.10,
            "report_rate_max": 0.02,
            "latency_p95_ms_max": 500.0,
            "srm_chi_square_max": 9.21,
            "auto_rollback": True,
        },
        salt="phase4-recommendation-v1",
        long_term_holdout_variant="holdout",
        starts_at=now,
    )
    db.session.add(experiment)
    try:
        db.session.commit()
        return experiment
    except IntegrityError:
        # Another worker can install the same immutable default concurrently.
        db.session.rollback()
        return db.session.get(ExperimentDefinition, DEFAULT_EXPERIMENT_ID)


def assign_experiments(subject_id, now=None):
    """Return at most one stable assignment per namespace."""
    if not subject_id or not app.config.get("EXPERIMENTS_ENABLED", True):
        return []
    now = now or _datetime.datetime.utcnow()
    ensure_default_experiment(now)
    experiments = db.session.query(ExperimentDefinition).filter(
        ExperimentDefinition.status == "running",
        (ExperimentDefinition.starts_at.is_(None) | (ExperimentDefinition.starts_at <= now)),
        (ExperimentDefinition.ends_at.is_(None) | (ExperimentDefinition.ends_at > now)),
    ).order_by(ExperimentDefinition.namespace, ExperimentDefinition.id).all()
    by_namespace = defaultdict(list)
    for experiment in experiments:
        by_namespace[experiment.namespace].append(experiment)
    assignments = []
    for namespace, definitions in by_namespace.items():
        namespace_bucket = _bucket(namespace, subject_id)
        cursor = 0
        selected = None
        for experiment in definitions:
            width = max(0, min(10000, int(round(float(experiment.traffic_percent) * 100))))
            if cursor <= namespace_bucket < cursor + width:
                selected = experiment
                break
            cursor += width
        if selected is None:
            continue
        variant_bucket = _bucket(selected.salt, selected.id, subject_id)
        variant_cursor = 0
        variant = None
        for name, weight in (selected.variants or {}).items():
            width = max(0, int(round(float(weight) * 100)))
            if variant_cursor <= variant_bucket < variant_cursor + width:
                variant = str(name)
                break
            variant_cursor += width
        if variant is not None:
            assignments.append(Assignment(selected.id, variant, variant_bucket))
    return assignments


def log_exposures(assignments, subject_id, slip_id, request_id, surface, now=None):
    if not assignments or not subject_id:
        return 0
    now = now or _datetime.datetime.utcnow()
    for assignment in assignments:
        db.session.add(ExperimentExposure(
            experiment_id=assignment.experiment_id,
            subject_id=subject_id,
            slip_id=slip_id,
            request_id=request_id,
            variant=assignment.variant,
            bucket=assignment.bucket,
            surface=surface,
            exposed_at=now,
            expires_at=now + EXPOSURE_RETENTION,
        ))
    return len(assignments)


def _percentile(values, percentile):
    values = sorted(float(value) for value in values if value is not None)
    if not values:
        return None
    index = max(0, min(len(values) - 1, int(math.ceil(percentile * len(values))) - 1))
    return round(values[index], 3)


def experiment_snapshot(experiment, hours=24, now=None, persist=False):
    now = now or _datetime.datetime.utcnow()
    since = now - _datetime.timedelta(hours=hours)
    exposures = db.session.query(ExperimentExposure).filter(
        ExperimentExposure.experiment_id == experiment.id,
        ExperimentExposure.exposed_at >= since,
    ).all()
    exposure_counts = Counter(row.variant for row in exposures)
    subject_variants = {}
    for row in sorted(exposures, key=lambda value: (value.exposed_at, value.id)):
        subject_variants.setdefault(row.subject_id, row.variant)
    counts = Counter(subject_variants.values())
    sample_size = len(subject_variants)
    request_ids = [row.request_id for row in exposures]
    variant_by_request = {row.request_id: row.variant for row in exposures}
    event_counts = Counter()
    events = []
    logs = []
    satisfaction = []
    if request_ids:
        events = db.session.query(AnalyticsEvent).filter(AnalyticsEvent.request_id.in_(request_ids)).all()
        logs = db.session.query(RecommendationLog).filter(RecommendationLog.request_id.in_(request_ids)).all()
        satisfaction = db.session.query(RecommendationSatisfaction).filter(
            RecommendationSatisfaction.request_id.in_(request_ids)
        ).all()
        event_counts.update(event.event_name for event in events)
    expected_weights = {str(name): float(weight) for name, weight in (experiment.variants or {}).items()}
    total_weight = sum(expected_weights.values()) or 1.0
    chi_square = 0.0
    for variant, weight in expected_weights.items():
        expected = sample_size * weight / total_weight
        if expected > 0:
            chi_square += ((counts.get(variant, 0) - expected) ** 2) / expected
    guardrails = experiment.guardrails or {}
    minimum_sample = int(guardrails.get("minimum_sample", 200))
    metrics = {
        "variant_assignments": dict(counts),
        "variant_exposures": dict(exposure_counts),
        "srm_chi_square": round(chi_square, 4),
        "click_rate": round(event_counts["recommendation_clicked"] / float(sample_size), 6) if sample_size else 0.0,
        "negative_feedback_rate": round(
            (event_counts["not_interested_selected"] + event_counts["hide_selected"]) / float(sample_size), 6
        ) if sample_size else 0.0,
        "report_rate": round(event_counts["report_submitted"] / float(sample_size), 6) if sample_size else 0.0,
        "latency_p95_ms": _percentile([row.latency_ms for row in logs], 0.95),
        "satisfaction_average": round(sum(row.rating for row in satisfaction) / float(len(satisfaction)), 3) if satisfaction else None,
        "satisfaction_responses": len(satisfaction),
    }
    events_by_variant = defaultdict(Counter)
    latency_by_variant = defaultdict(list)
    satisfaction_by_variant = defaultdict(list)
    for event in events:
        events_by_variant[variant_by_request.get(event.request_id, "unknown")][event.event_name] += 1
    for row in logs:
        latency_by_variant[variant_by_request.get(row.request_id, "unknown")].append(row.latency_ms)
    for row in satisfaction:
        satisfaction_by_variant[variant_by_request.get(row.request_id, "unknown")].append(row.rating)
    metrics["by_variant"] = {}
    for variant in expected_weights:
        denominator = exposure_counts.get(variant, 0)
        variant_events = events_by_variant[variant]
        ratings = satisfaction_by_variant[variant]
        metrics["by_variant"][variant] = {
            "exposures": denominator,
            "click_rate": round(variant_events["recommendation_clicked"] / float(denominator), 6) if denominator else 0.0,
            "negative_feedback_rate": round(
                (variant_events["not_interested_selected"] + variant_events["hide_selected"]) / float(denominator), 6
            ) if denominator else 0.0,
            "report_rate": round(variant_events["report_submitted"] / float(denominator), 6) if denominator else 0.0,
            "latency_p95_ms": _percentile(latency_by_variant[variant], 0.95),
            "satisfaction_average": round(sum(ratings) / float(len(ratings)), 3) if ratings else None,
        }
    srm_detected = sample_size >= minimum_sample and chi_square > float(guardrails.get("srm_chi_square_max", 9.21))
    violations = []
    for metric, threshold_key in (
        ("negative_feedback_rate", "negative_feedback_rate_max"),
        ("report_rate", "report_rate_max"),
        ("latency_p95_ms", "latency_p95_ms_max"),
    ):
        value = metrics.get(metric)
        threshold = guardrails.get(threshold_key)
        if sample_size >= minimum_sample and value is not None and threshold is not None and value > float(threshold):
            violations.append({"metric": metric, "value": value, "limit": float(threshold)})
    if srm_detected:
        violations.append({"metric": "sample_ratio_mismatch", "value": metrics["srm_chi_square"], "limit": float(guardrails.get("srm_chi_square_max", 9.21))})
    action = "none"
    if violations and guardrails.get("auto_rollback", True) and experiment.status == "running":
        experiment.status = "rolled_back"
        experiment.rollback_reason = "; ".join(item["metric"] for item in violations)[:500]
        experiment.updated_at = now
        action = "auto_rollback"
    result = {
        "experiment_id": experiment.id,
        "status": experiment.status,
        "sample_size": sample_size,
        "srm_detected": srm_detected,
        "metrics": metrics,
        "violations": violations,
        "action": action,
    }
    if persist:
        db.session.add(ExperimentGuardrailSnapshot(
            experiment_id=experiment.id,
            status=experiment.status,
            sample_size=sample_size,
            srm_detected=srm_detected,
            metrics=metrics,
            violations=violations,
            action=action,
            evaluated_at=now,
        ))
        db.session.commit()
    return result


def monitor_experiments(now=None):
    now = now or _datetime.datetime.utcnow()
    experiments = db.session.query(ExperimentDefinition).filter(
        ExperimentDefinition.status == "running"
    ).all()
    return [experiment_snapshot(experiment, now=now, persist=True) for experiment in experiments]


def _monitor_loop():
    # The app context is entered PER ITERATION, not once around the `while`.
    # Entering it once meant this thread checked out a connection on its first
    # query and never released it — Flask-SQLAlchemy only calls session.remove()
    # on app-context teardown, which never came. That was one connection leaked
    # per worker, for the life of the process, out of a pool of 15.
    while True:
        try:
            with app.app_context():
                from services.singleton_worker import is_maintenance_leader

                # Leader-gated: guardrail evaluation writes snapshot rows, so four
                # workers duplicated every write.
                if is_maintenance_leader():
                    monitor_experiments()
        except Exception:
            try:
                with app.app_context():
                    db.session.rollback()
            except Exception:
                pass
            app.logger.exception("experiments: guardrail monitor failed")
        interval = 900
        try:
            with app.app_context():
                interval = int(app.config.get("EXPERIMENT_MONITOR_INTERVAL_SECONDS", 900))
        except Exception:
            pass
        time.sleep(max(60, interval))


def start_experiment_monitor():
    global _monitor_thread
    if app.config.get("TESTING") or not app.config.get("EXPERIMENT_MONITOR_ENABLED", True) or _monitor_thread is not None:
        return _monitor_thread
    _monitor_thread = threading.Thread(target=_monitor_loop, name="experiment-guardrails", daemon=True)
    _monitor_thread.start()
    return _monitor_thread
