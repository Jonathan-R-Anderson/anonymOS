import datetime as _datetime

from shared import db


UTC_NOW = _datetime.datetime.utcnow


class BehaviorSequence(db.Model):
    __tablename__ = "behavior_sequence"
    __table_args__ = {"schema": "analytics"}

    subject_id = db.Column(db.String(36), primary_key=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    recent_items = db.Column(db.JSON, nullable=False, default=list)
    recent_topics = db.Column(db.JSON, nullable=False, default=list)
    sequence_embedding = db.Column(db.JSON, nullable=False, default=list)
    source_event_count = db.Column(db.Integer, nullable=False, default=0)
    model_version = db.Column(db.String(64), nullable=False, default="sasrec-style-hash-v1")
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class UserValuePrediction(db.Model):
    __tablename__ = "user_value_prediction"
    __table_args__ = {"schema": "analytics"}

    subject_id = db.Column(db.String(36), primary_key=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    churn_probability = db.Column(db.Float, nullable=False, default=0.0)
    long_term_value = db.Column(db.Float, nullable=False, default=0.0)
    components = db.Column(db.JSON, nullable=False, default=dict)
    model_version = db.Column(db.String(64), nullable=False, default="survival-value-v1")
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class RecommendationPreference(db.Model):
    __tablename__ = "recommendation_preference"
    __table_args__ = {"schema": "analytics"}

    subject_id = db.Column(db.String(36), primary_key=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    muted_topics = db.Column(db.JSON, nullable=False, default=list)
    excluded_creators = db.Column(db.JSON, nullable=False, default=list)
    exploration_enabled = db.Column(db.Boolean, nullable=False, default=True)
    personalization_strength = db.Column(db.Float, nullable=False, default=1.0)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, onupdate=UTC_NOW)


class ContextualBanditArm(db.Model):
    __tablename__ = "contextual_bandit_arm"
    __table_args__ = {"schema": "analytics"}

    context_key = db.Column(db.String(128), primary_key=True)
    arm = db.Column(db.String(32), primary_key=True)
    pulls = db.Column(db.Integer, nullable=False, default=0)
    reward_sum = db.Column(db.Float, nullable=False, default=0.0)
    reward_square_sum = db.Column(db.Float, nullable=False, default=0.0)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)


class NotificationRecommendation(db.Model):
    __tablename__ = "notification_recommendation"
    __table_args__ = (
        db.Index("ix_notification_recommendation_subject_status", "subject_id", "status", "score"),
        {"schema": "analytics"},
    )

    subject_id = db.Column(db.String(36), primary_key=True)
    content_type = db.Column(db.String(32), primary_key=True)
    content_id = db.Column(db.String(128), primary_key=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    score = db.Column(db.Float, nullable=False)
    reason = db.Column(db.String(160), nullable=False)
    status = db.Column(db.String(24), nullable=False, default="pending")
    model_version = db.Column(db.String(64), nullable=False, default="notification-value-v1")
    created_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class CreatorExposureDaily(db.Model):
    __tablename__ = "creator_exposure_daily"
    __table_args__ = (
        db.Index("ix_creator_exposure_daily_type_day", "content_type", "day"),
        {"schema": "analytics"},
    )

    day = db.Column(db.Date, primary_key=True)
    content_type = db.Column(db.String(32), primary_key=True)
    creator_id = db.Column(db.String(128), primary_key=True)
    impressions = db.Column(db.Integer, nullable=False, default=0)
    exploration_impressions = db.Column(db.Integer, nullable=False, default=0)
    unique_items = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)


class ModelHealthSnapshot(db.Model):
    __tablename__ = "model_health_snapshot"
    __table_args__ = (
        db.Index("ix_model_health_snapshot_model_time", "model_id", "evaluated_at"),
        {"schema": "analytics"},
    )

    id = db.Column(db.Integer, primary_key=True)
    model_id = db.Column(db.String(128), nullable=False)
    feature_drift = db.Column(db.JSON, nullable=False, default=dict)
    outcome_drift = db.Column(db.JSON, nullable=False, default=dict)
    fairness = db.Column(db.JSON, nullable=False, default=dict)
    violations = db.Column(db.JSON, nullable=False, default=list)
    status = db.Column(db.String(24), nullable=False, default="healthy")
    evaluated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)


class AlgorithmAudit(db.Model):
    __tablename__ = "algorithm_audit"
    __table_args__ = {"schema": "analytics"}

    id = db.Column(db.String(36), primary_key=True)
    scope = db.Column(db.String(128), nullable=False)
    manifest = db.Column(db.JSON, nullable=False, default=dict)
    checksum = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="pending_external_review")
    reviewer = db.Column(db.String(160), nullable=True)
    findings = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    completed_at = db.Column(db.DateTime, nullable=True)
