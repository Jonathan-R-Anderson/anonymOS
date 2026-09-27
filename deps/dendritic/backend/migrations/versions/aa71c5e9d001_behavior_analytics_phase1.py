"""Behavior analytics Phase 1 foundation.

Revision ID: aa71c5e9d001
Revises: f5d9c3b1a2e7
Create Date: 2026-07-19 00:00:00.000000
"""
import datetime as _datetime

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "aa71c5e9d001"
down_revision = "f5d9c3b1a2e7"
branch_labels = None
depends_on = None


def _next_month(value):
    return (value.replace(day=28) + _datetime.timedelta(days=4)).replace(day=1)


def _previous_month(value):
    return (value.replace(day=1) - _datetime.timedelta(days=1)).replace(day=1)


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    postgres = bind.dialect.name == "postgresql"
    schema = "analytics" if postgres else None
    if postgres:
        op.execute("CREATE SCHEMA IF NOT EXISTS analytics")

    if not inspector.has_table("analytics_consent", schema=schema):
        op.create_table(
            "analytics_consent",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("subject_id", sa.String(36), nullable=False, unique=True),
            sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id", ondelete="CASCADE"), nullable=True),
            sa.Column("analytics", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("personalization", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("policy_version", sa.String(32), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("withdrawn_at", sa.DateTime(), nullable=True),
            schema=schema,
        )
        op.create_index("ix_analytics_consent_subject_id", "analytics_consent", ["subject_id"], unique=True, schema=schema)
        op.create_index("ix_analytics_consent_slip_id", "analytics_consent", ["slip_id"], schema=schema)

    if not inspector.has_table("analytics_event", schema=schema):
        kwargs = {"postgresql_partition_by": "RANGE (event_time)"} if postgres else {}
        op.create_table(
            "analytics_event",
            sa.Column("event_id", sa.String(36), nullable=False),
            sa.Column("event_time", sa.DateTime(), nullable=False),
            sa.Column("received_time", sa.DateTime(), nullable=False),
            sa.Column("event_name", sa.String(64), nullable=False),
            sa.Column("event_version", sa.Integer(), nullable=False),
            sa.Column("anonymous_id", sa.String(36), nullable=False),
            sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True),
            sa.Column("session_id", sa.String(64), nullable=False),
            sa.Column("reconstructed_session_id", sa.String(36), nullable=True),
            sa.Column("device_session_id", sa.String(64), nullable=True),
            sa.Column("page_id", sa.String(64), nullable=True),
            sa.Column("surface", sa.String(64), nullable=False),
            sa.Column("content_type", sa.String(32), nullable=True),
            sa.Column("content_id", sa.String(128), nullable=True),
            sa.Column("author_id", sa.String(128), nullable=True),
            sa.Column("position", sa.Integer(), nullable=True),
            sa.Column("request_id", sa.String(128), nullable=True),
            sa.Column("model_id", sa.String(64), nullable=True),
            sa.Column("experiment_ids", sa.JSON(), nullable=False),
            sa.Column("client", sa.JSON(), nullable=False),
            sa.Column("context", sa.JSON(), nullable=False),
            sa.Column("properties", sa.JSON(), nullable=False),
            sa.Column("consent", sa.JSON(), nullable=False),
            sa.PrimaryKeyConstraint("event_id", "event_time"),
            schema=schema,
            **kwargs
        )
        if postgres:
            start = _datetime.date.today().replace(day=1)
            for partition_start in (_previous_month(start), start, _next_month(start)):
                partition_end = _next_month(partition_start)
                name = "analytics_event_%s" % partition_start.strftime("%Y_%m")
                op.execute(
                    "CREATE TABLE IF NOT EXISTS analytics.%s PARTITION OF analytics.analytics_event "
                    "FOR VALUES FROM ('%s') TO ('%s')"
                    % (name, partition_start.isoformat(), partition_end.isoformat())
                )
            op.execute("CREATE TABLE IF NOT EXISTS analytics.analytics_event_default PARTITION OF analytics.analytics_event DEFAULT")
        op.create_index("ix_analytics_event_received_time", "analytics_event", ["received_time"], schema=schema)
        op.create_index("ix_analytics_event_event_name", "analytics_event", ["event_name"], schema=schema)
        op.create_index("ix_analytics_event_anonymous_id", "analytics_event", ["anonymous_id"], schema=schema)
        op.create_index("ix_analytics_event_slip_id", "analytics_event", ["slip_id"], schema=schema)
        op.create_index("ix_analytics_event_session_id", "analytics_event", ["session_id"], schema=schema)
        op.create_index("ix_analytics_event_reconstructed_session_id", "analytics_event", ["reconstructed_session_id"], schema=schema)
        op.create_index("ix_analytics_event_subject_time", "analytics_event", ["slip_id", "event_time"], schema=schema)
        op.create_index("ix_analytics_event_anon_time", "analytics_event", ["anonymous_id", "event_time"], schema=schema)
        op.create_index("ix_analytics_event_content", "analytics_event", ["content_type", "content_id"], schema=schema)

    if not inspector.has_table("analytics_session", schema=schema):
        op.create_table(
            "analytics_session",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("anonymous_id", sa.String(36), nullable=False),
            sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("ended_at", sa.DateTime(), nullable=False),
            sa.Column("event_count", sa.Integer(), nullable=False),
            sa.Column("raw_session_ids", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            schema=schema,
        )
        op.create_index("ix_analytics_session_anonymous_id", "analytics_session", ["anonymous_id"], schema=schema)
        op.create_index("ix_analytics_session_slip_id", "analytics_session", ["slip_id"], schema=schema)
        op.create_index("ix_analytics_session_started_at", "analytics_session", ["started_at"], schema=schema)

    if not inspector.has_table("analytics_ingest_issue", schema=schema):
        op.create_table(
            "analytics_ingest_issue",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("occurred_at", sa.DateTime(), nullable=False),
            sa.Column("category", sa.String(32), nullable=False),
            sa.Column("event_name", sa.String(64), nullable=True),
            sa.Column("count", sa.Integer(), nullable=False),
            schema=schema,
        )
        op.create_index("ix_analytics_ingest_issue_occurred_at", "analytics_ingest_issue", ["occurred_at"], schema=schema)
        op.create_index("ix_analytics_ingest_issue_category", "analytics_ingest_issue", ["category"], schema=schema)

    if not inspector.has_table("analytics_deletion", schema=schema):
        op.create_table(
            "analytics_deletion",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("subject_id", sa.String(36), nullable=False),
            sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("requested_at", sa.DateTime(), nullable=False),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("error", sa.String(500), nullable=True),
            schema=schema,
        )
        op.create_index("ix_analytics_deletion_subject_id", "analytics_deletion", ["subject_id"], schema=schema)
        op.create_index("ix_analytics_deletion_slip_id", "analytics_deletion", ["slip_id"], schema=schema)

    if postgres:
        op.execute("REVOKE ALL ON SCHEMA analytics FROM PUBLIC")
        op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA analytics FROM PUBLIC")
        op.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA analytics REVOKE ALL ON TABLES FROM PUBLIC")


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    schema = "analytics" if bind.dialect.name == "postgresql" else None
    for table in ("analytics_deletion", "analytics_ingest_issue", "analytics_session", "analytics_event", "analytics_consent"):
        if inspector.has_table(table, schema=schema):
            op.drop_table(table, schema=schema)
    if schema:
        op.execute("DROP SCHEMA IF EXISTS analytics")
