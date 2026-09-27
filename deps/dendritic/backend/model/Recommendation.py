import datetime as _datetime

from shared import db


UTC_NOW = _datetime.datetime.utcnow


class RecommendationLog(db.Model):
    __tablename__ = "recommendation_log"
    __table_args__ = (
        db.Index("ix_recommendation_log_subject_time", "subject_id", "created_at"),
        db.Index("ix_recommendation_log_surface_time", "surface", "created_at"),
        {"schema": "analytics"},
    )

    request_id = db.Column(db.String(36), primary_key=True)
    subject_id = db.Column(db.String(36), nullable=True, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True, index=True)
    surface = db.Column(db.String(64), nullable=False)
    content_type = db.Column(db.String(32), nullable=False)
    mode = db.Column(db.String(24), nullable=False)
    model_id = db.Column(db.String(128), nullable=False)
    personalized = db.Column(db.Boolean, nullable=False, default=False)
    candidate_item_ids = db.Column(db.JSON, nullable=False, default=list)
    ranked_item_ids = db.Column(db.JSON, nullable=False, default=list)
    positions = db.Column(db.JSON, nullable=False, default=list)
    scores = db.Column(db.JSON, nullable=False, default=list)
    candidate_sources = db.Column(db.JSON, nullable=False, default=list)
    ranked_sources = db.Column(db.JSON, nullable=False, default=list)
    score_components = db.Column(db.JSON, nullable=False, default=list)
    exclusion_reasons = db.Column(db.JSON, nullable=False, default=dict)
    experiment_ids = db.Column(db.JSON, nullable=False, default=list)
    exploration_propensities = db.Column(db.JSON, nullable=False, default=list)
    explanations = db.Column(db.JSON, nullable=False, default=list)
    shadow_model_id = db.Column(db.String(128), nullable=True)
    shadow_scores = db.Column(db.JSON, nullable=False, default=list)
    objective_scores = db.Column(db.JSON, nullable=False, default=dict)
    policy_context = db.Column(db.String(128), nullable=True)
    bandit_arm = db.Column(db.String(32), nullable=True)
    bandit_propensity = db.Column(db.Float, nullable=True)
    latency_ms = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class RecommendationInteraction(db.Model):
    __tablename__ = "recommendation_interaction"
    __table_args__ = (
        db.Index("ix_recommendation_interaction_subject", "subject_id", "net_weight"),
        db.Index("ix_recommendation_interaction_item", "content_type", "content_id"),
        {"schema": "analytics"},
    )

    subject_id = db.Column(db.String(36), primary_key=True)
    content_type = db.Column(db.String(32), primary_key=True)
    content_id = db.Column(db.String(128), primary_key=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    positive_weight = db.Column(db.Float, nullable=False, default=0.0)
    negative_weight = db.Column(db.Float, nullable=False, default=0.0)
    net_weight = db.Column(db.Float, nullable=False, default=0.0)
    event_count = db.Column(db.Integer, nullable=False, default=0)
    last_event_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class CollaborativeSimilarity(db.Model):
    __tablename__ = "collaborative_similarity"
    __table_args__ = (
        db.Index("ix_collaborative_similarity_source", "source_type", "source_id", "score"),
        db.Index("ix_collaborative_similarity_target", "target_type", "target_id"),
        {"schema": "analytics"},
    )

    source_type = db.Column(db.String(32), primary_key=True)
    source_id = db.Column(db.String(128), primary_key=True)
    target_type = db.Column(db.String(32), primary_key=True)
    target_id = db.Column(db.String(128), primary_key=True)
    score = db.Column(db.Float, nullable=False)
    support = db.Column(db.Integer, nullable=False)
    model_version = db.Column(db.String(64), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
