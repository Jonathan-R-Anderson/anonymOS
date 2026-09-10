import datetime as _datetime

from shared import db


UTC_NOW = _datetime.datetime.utcnow


class ExperimentDefinition(db.Model):
    __tablename__ = "experiment_definition"
    __table_args__ = (
        db.Index("ix_experiment_definition_namespace_status", "namespace", "status"),
        {"schema": "analytics"},
    )

    id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    namespace = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(24), nullable=False, default="draft", index=True)
    traffic_percent = db.Column(db.Float, nullable=False, default=0.0)
    variants = db.Column(db.JSON, nullable=False, default=dict)
    primary_metrics = db.Column(db.JSON, nullable=False, default=list)
    guardrails = db.Column(db.JSON, nullable=False, default=dict)
    salt = db.Column(db.String(128), nullable=False)
    long_term_holdout_variant = db.Column(db.String(64), nullable=True)
    starts_at = db.Column(db.DateTime, nullable=True)
    ends_at = db.Column(db.DateTime, nullable=True)
    rollback_reason = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, onupdate=UTC_NOW)


class ExperimentExposure(db.Model):
    __tablename__ = "experiment_exposure"
    __table_args__ = (
        db.UniqueConstraint("experiment_id", "request_id", name="uq_experiment_exposure_request"),
        db.Index("ix_experiment_exposure_variant_time", "experiment_id", "variant", "exposed_at"),
        db.Index("ix_experiment_exposure_subject_time", "subject_id", "exposed_at"),
        {"schema": "analytics"},
    )

    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(
        db.String(64), db.ForeignKey("analytics.experiment_definition.id", ondelete="CASCADE"), nullable=False,
    )
    subject_id = db.Column(db.String(36), nullable=False, index=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    request_id = db.Column(db.String(36), nullable=False)
    variant = db.Column(db.String(64), nullable=False)
    bucket = db.Column(db.Integer, nullable=False)
    surface = db.Column(db.String(64), nullable=False)
    exposed_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class ExperimentGuardrailSnapshot(db.Model):
    __tablename__ = "experiment_guardrail_snapshot"
    __table_args__ = (
        db.Index("ix_experiment_guardrail_experiment_time", "experiment_id", "evaluated_at"),
        {"schema": "analytics"},
    )

    id = db.Column(db.Integer, primary_key=True)
    experiment_id = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(24), nullable=False)
    sample_size = db.Column(db.Integer, nullable=False, default=0)
    srm_detected = db.Column(db.Boolean, nullable=False, default=False)
    metrics = db.Column(db.JSON, nullable=False, default=dict)
    violations = db.Column(db.JSON, nullable=False, default=list)
    action = db.Column(db.String(32), nullable=False, default="none")
    evaluated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)


class RecommendationSatisfaction(db.Model):
    __tablename__ = "recommendation_satisfaction"
    __table_args__ = (
        db.UniqueConstraint("request_id", "subject_id", name="uq_recommendation_satisfaction_request_subject"),
        db.Index("ix_recommendation_satisfaction_time", "created_at"),
        {"schema": "analytics"},
    )

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(36), nullable=False, index=True)
    subject_id = db.Column(db.String(36), nullable=False, index=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    rating = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(64), nullable=True)
    surface = db.Column(db.String(64), nullable=False)
    experiment_ids = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class BehaviorMetricDaily(db.Model):
    __tablename__ = "behavior_metric_daily"
    __table_args__ = (
        db.Index("ix_behavior_metric_daily_dashboard_day", "dashboard", "day"),
        {"schema": "analytics"},
    )

    day = db.Column(db.Date, primary_key=True)
    dashboard = db.Column(db.String(32), primary_key=True)
    metric = db.Column(db.String(64), primary_key=True)
    dimension = db.Column(db.String(128), primary_key=True, default="all")
    value = db.Column(db.Float, nullable=False, default=0.0)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, onupdate=UTC_NOW)
