"""Behavior content and user features Phase 2.

Revision ID: bc82d6fa2002
Revises: aa71c5e9d001
Create Date: 2026-07-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "bc82d6fa2002"
down_revision = "aa71c5e9d001"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    postgres = bind.dialect.name == "postgresql"
    schema = "analytics" if postgres else None
    if postgres:
        op.execute("CREATE SCHEMA IF NOT EXISTS analytics")

    if not inspector.has_table("content_feature", schema=schema):
        op.create_table(
            "content_feature",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("content_type", sa.String(32), nullable=False),
            sa.Column("content_id", sa.String(128), nullable=False),
            sa.Column("feature_version", sa.String(32), nullable=False),
            sa.Column("source_updated_at", sa.DateTime(), nullable=True),
            sa.Column("keywords", sa.JSON(), nullable=False),
            sa.Column("tags", sa.JSON(), nullable=False),
            sa.Column("media", sa.JSON(), nullable=False),
            sa.Column("embedding", sa.JSON(), nullable=False),
            sa.Column("embedding_model", sa.String(64), nullable=False),
            sa.Column("sentiment_score", sa.Float(), nullable=False),
            sa.Column("sentiment_magnitude", sa.Float(), nullable=False),
            sa.Column("quality_score", sa.Float(), nullable=False),
            sa.Column("report_rate", sa.Float(), nullable=False),
            sa.Column("engagement_velocity", sa.Float(), nullable=False),
            sa.Column("completion_distribution", sa.JSON(), nullable=False),
            sa.Column("estimated_duration_seconds", sa.Integer(), nullable=False),
            sa.Column("moderation_eligible", sa.Boolean(), nullable=False),
            sa.Column("moderation_reasons", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("content_type", "content_id", name="uq_content_feature_item"),
            schema=schema,
        )
        op.create_index("ix_content_feature_eligible_type", "content_feature", ["moderation_eligible", "content_type"], schema=schema)
        op.create_index("ix_content_feature_updated_at", "content_feature", ["updated_at"], schema=schema)

    profile_columns = (
        sa.Column("positive_topics", sa.JSON(), nullable=False),
        sa.Column("negative_topics", sa.JSON(), nullable=False),
        sa.Column("content_type_weights", sa.JSON(), nullable=False),
        sa.Column("source_event_count", sa.Integer(), nullable=False),
        sa.Column("last_event_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    if not inspector.has_table("user_profile", schema=schema):
        op.create_table(
            "user_profile",
            sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id", ondelete="CASCADE"), primary_key=True),
            *profile_columns,
            schema=schema,
        )
        op.create_index("ix_user_profile_updated_at", "user_profile", ["updated_at"], schema=schema)
        op.create_index("ix_user_profile_expires_at", "user_profile", ["expires_at"], schema=schema)

    if not inspector.has_table("anon_profile", schema=schema):
        op.create_table(
            "anon_profile",
            sa.Column("subject_id", sa.String(36), primary_key=True),
            *(
                sa.Column("positive_topics", sa.JSON(), nullable=False),
                sa.Column("negative_topics", sa.JSON(), nullable=False),
                sa.Column("content_type_weights", sa.JSON(), nullable=False),
                sa.Column("source_event_count", sa.Integer(), nullable=False),
                sa.Column("last_event_at", sa.DateTime(), nullable=True),
                sa.Column("updated_at", sa.DateTime(), nullable=False),
                sa.Column("expires_at", sa.DateTime(), nullable=False),
            ),
            schema=schema,
        )
        op.create_index("ix_anon_profile_updated_at", "anon_profile", ["updated_at"], schema=schema)
        op.create_index("ix_anon_profile_expires_at", "anon_profile", ["expires_at"], schema=schema)

    if not inspector.has_table("analytics_job_state", schema=schema):
        op.create_table(
            "analytics_job_state",
            sa.Column("name", sa.String(64), primary_key=True),
            sa.Column("last_started_at", sa.DateTime(), nullable=True),
            sa.Column("last_completed_at", sa.DateTime(), nullable=True),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("detail", sa.JSON(), nullable=False),
            schema=schema,
        )

    if postgres:
        op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA analytics FROM PUBLIC")


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    schema = "analytics" if bind.dialect.name == "postgresql" else None
    for table in ("analytics_job_state", "anon_profile", "user_profile", "content_feature"):
        if inspector.has_table(table, schema=schema):
            op.drop_table(table, schema=schema)
