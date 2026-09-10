import datetime as _datetime

from sqlalchemy import DDL, event, text

from shared import db


UTC_NOW = _datetime.datetime.utcnow


def ensure_analytics_schema():
    if db.engine.url.get_backend_name() in ("postgresql", "postgres"):
        db.session.execute(text("CREATE SCHEMA IF NOT EXISTS analytics"))
        db.session.commit()


def secure_analytics_schema():
    if db.engine.url.get_backend_name() in ("postgresql", "postgres"):
        db.session.execute(text("REVOKE ALL ON SCHEMA analytics FROM PUBLIC"))
        db.session.execute(text("REVOKE ALL ON ALL TABLES IN SCHEMA analytics FROM PUBLIC"))
        db.session.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA analytics REVOKE ALL ON TABLES FROM PUBLIC"))
        db.session.commit()


class AnalyticsConsent(db.Model):
    __tablename__ = "analytics_consent"
    __table_args__ = {"schema": "analytics"}

    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.String(36), nullable=False, unique=True, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="CASCADE"), nullable=True, index=True)
    analytics = db.Column(db.Boolean, nullable=False, default=False)
    personalization = db.Column(db.Boolean, nullable=False, default=False)
    policy_version = db.Column(db.String(32), nullable=False, default="2026-07-19")
    created_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, onupdate=UTC_NOW)
    withdrawn_at = db.Column(db.DateTime, nullable=True)


class AnalyticsEvent(db.Model):
    __tablename__ = "analytics_event"

    # PostgreSQL partitioned unique constraints must include the partition key.
    event_id = db.Column(db.String(36), primary_key=True)
    event_time = db.Column(db.DateTime, primary_key=True)
    received_time = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)
    event_name = db.Column(db.String(64), nullable=False, index=True)
    event_version = db.Column(db.Integer, nullable=False, default=1)
    anonymous_id = db.Column(db.String(36), nullable=False, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True, index=True)
    session_id = db.Column(db.String(64), nullable=False, index=True)
    reconstructed_session_id = db.Column(db.String(36), nullable=True, index=True)
    device_session_id = db.Column(db.String(64), nullable=True)
    page_id = db.Column(db.String(64), nullable=True)
    surface = db.Column(db.String(64), nullable=False)
    content_type = db.Column(db.String(32), nullable=True)
    content_id = db.Column(db.String(128), nullable=True)
    author_id = db.Column(db.String(128), nullable=True)
    position = db.Column(db.Integer, nullable=True)
    request_id = db.Column(db.String(128), nullable=True)
    model_id = db.Column(db.String(64), nullable=True)
    experiment_ids = db.Column(db.JSON, nullable=False, default=list)
    client = db.Column(db.JSON, nullable=False, default=dict)
    context = db.Column(db.JSON, nullable=False, default=dict)
    properties = db.Column(db.JSON, nullable=False, default=dict)
    consent = db.Column(db.JSON, nullable=False, default=dict)

    __table_args__ = (
        db.Index("ix_analytics_event_subject_time", "slip_id", "event_time"),
        db.Index("ix_analytics_event_anon_time", "anonymous_id", "event_time"),
        db.Index("ix_analytics_event_content", "content_type", "content_id"),
        {"postgresql_partition_by": "RANGE (event_time)", "schema": "analytics"},
    )


class AnalyticsSession(db.Model):
    __tablename__ = "analytics_session"
    __table_args__ = {"schema": "analytics"}

    id = db.Column(db.String(36), primary_key=True)
    anonymous_id = db.Column(db.String(36), nullable=False, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True, index=True)
    started_at = db.Column(db.DateTime, nullable=False, index=True)
    ended_at = db.Column(db.DateTime, nullable=False)
    event_count = db.Column(db.Integer, nullable=False, default=0)
    raw_session_ids = db.Column(db.JSON, nullable=False, default=list)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, onupdate=UTC_NOW)


class AnalyticsIngestIssue(db.Model):
    __tablename__ = "analytics_ingest_issue"
    __table_args__ = {"schema": "analytics"}

    id = db.Column(db.Integer, primary_key=True)
    occurred_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)
    category = db.Column(db.String(32), nullable=False, index=True)
    event_name = db.Column(db.String(64), nullable=True)
    count = db.Column(db.Integer, nullable=False, default=1)


class AnalyticsDeletion(db.Model):
    __tablename__ = "analytics_deletion"
    __table_args__ = {"schema": "analytics"}

    id = db.Column(db.String(36), primary_key=True)
    subject_id = db.Column(db.String(36), nullable=False, index=True)
    slip_id = db.Column(db.Integer, nullable=True, index=True)
    requested_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    completed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(16), nullable=False, default="pending")
    error = db.Column(db.String(500), nullable=True)


class ContentFeature(db.Model):
    """Versioned, content-level inputs shared by retrieval and ranking."""

    __tablename__ = "content_feature"
    __table_args__ = (
        db.UniqueConstraint("content_type", "content_id", name="uq_content_feature_item"),
        db.Index("ix_content_feature_eligible_type", "moderation_eligible", "content_type"),
        {"schema": "analytics"},
    )

    id = db.Column(db.Integer, primary_key=True)
    content_type = db.Column(db.String(32), nullable=False)
    content_id = db.Column(db.String(128), nullable=False)
    feature_version = db.Column(db.String(32), nullable=False, default="content-v1")
    source_updated_at = db.Column(db.DateTime, nullable=True)
    keywords = db.Column(db.JSON, nullable=False, default=list)
    tags = db.Column(db.JSON, nullable=False, default=list)
    media = db.Column(db.JSON, nullable=False, default=dict)
    embedding = db.Column(db.JSON, nullable=False, default=list)
    embedding_model = db.Column(db.String(64), nullable=False, default="feature-hash-64-v1")
    multimodal_embedding = db.Column(db.JSON, nullable=False, default=list)
    multimodal_model = db.Column(db.String(64), nullable=False, default="multimodal-hash-64-v1")
    language = db.Column(db.String(16), nullable=False, default="und")
    sentiment_score = db.Column(db.Float, nullable=False, default=0.0)
    sentiment_magnitude = db.Column(db.Float, nullable=False, default=0.0)
    quality_score = db.Column(db.Float, nullable=False, default=0.0)
    report_rate = db.Column(db.Float, nullable=False, default=0.0)
    engagement_velocity = db.Column(db.Float, nullable=False, default=0.0)
    completion_distribution = db.Column(db.JSON, nullable=False, default=dict)
    estimated_duration_seconds = db.Column(db.Integer, nullable=False, default=0)
    moderation_eligible = db.Column(db.Boolean, nullable=False, default=True)
    moderation_reasons = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, onupdate=UTC_NOW, index=True)


class AnalyticsUserProfile(db.Model):
    __tablename__ = "user_profile"
    __table_args__ = {"schema": "analytics"}

    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="CASCADE"), primary_key=True)
    positive_topics = db.Column(db.JSON, nullable=False, default=dict)
    negative_topics = db.Column(db.JSON, nullable=False, default=dict)
    content_type_weights = db.Column(db.JSON, nullable=False, default=dict)
    source_event_count = db.Column(db.Integer, nullable=False, default=0)
    last_event_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class AnalyticsAnonProfile(db.Model):
    __tablename__ = "anon_profile"
    __table_args__ = {"schema": "analytics"}

    subject_id = db.Column(db.String(36), primary_key=True)
    positive_topics = db.Column(db.JSON, nullable=False, default=dict)
    negative_topics = db.Column(db.JSON, nullable=False, default=dict)
    content_type_weights = db.Column(db.JSON, nullable=False, default=dict)
    source_event_count = db.Column(db.Integer, nullable=False, default=0)
    last_event_at = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=UTC_NOW, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class AnalyticsJobState(db.Model):
    __tablename__ = "analytics_job_state"
    __table_args__ = {"schema": "analytics"}

    name = db.Column(db.String(64), primary_key=True)
    last_started_at = db.Column(db.DateTime, nullable=True)
    last_completed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(16), nullable=False, default="pending")
    detail = db.Column(db.JSON, nullable=False, default=dict)


def _month_start(value):
    return value.replace(day=1)


def _next_month(value):
    return (value.replace(day=28) + _datetime.timedelta(days=4)).replace(day=1)


def _previous_month(value):
    return (value.replace(day=1) - _datetime.timedelta(days=1)).replace(day=1)


# Fresh PostgreSQL installs run db.create_all() and stamp Alembic. Give the
# partitioned parent usable current/next partitions in that path as well.
_this_month = _month_start(_datetime.date.today())
for _partition_start in (_previous_month(_this_month), _this_month, _next_month(_this_month)):
    _partition_end = _next_month(_partition_start)
    _partition_name = "analytics_event_%s" % _partition_start.strftime("%Y_%m")
    event.listen(
        AnalyticsEvent.__table__,
        "after_create",
        DDL(
            "CREATE TABLE IF NOT EXISTS analytics.%s PARTITION OF analytics.analytics_event "
            "FOR VALUES FROM ('%s') TO ('%s')"
            % (_partition_name, _partition_start.isoformat(), _partition_end.isoformat())
        ).execute_if(dialect="postgresql"),
    )
event.listen(
    AnalyticsEvent.__table__,
    "after_create",
    DDL("CREATE TABLE IF NOT EXISTS analytics.analytics_event_default PARTITION OF analytics.analytics_event DEFAULT").execute_if(
        dialect="postgresql"
    ),
)
