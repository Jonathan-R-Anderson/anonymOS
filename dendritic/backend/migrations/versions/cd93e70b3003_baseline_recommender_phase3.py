"""Baseline recommender Phase 3.

Revision ID: cd93e70b3003
Revises: bc82d6fa2002
Create Date: 2026-07-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "cd93e70b3003"
down_revision = "bc82d6fa2002"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    postgres = bind.dialect.name == "postgresql"
    schema = "analytics" if postgres else None
    if postgres:
        op.execute("CREATE SCHEMA IF NOT EXISTS analytics")

    content_columns = {column["name"] for column in inspector.get_columns("content_feature", schema=schema)}
    if "language" not in content_columns:
        op.add_column(
            "content_feature",
            sa.Column("language", sa.String(16), nullable=False, server_default="und"),
            schema=schema,
        )

    if not inspector.has_table("recommendation_log", schema=schema):
        op.create_table(
            "recommendation_log",
            sa.Column("request_id", sa.String(36), primary_key=True),
            sa.Column("subject_id", sa.String(36), nullable=True),
            sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True),
            sa.Column("surface", sa.String(64), nullable=False),
            sa.Column("content_type", sa.String(32), nullable=False),
            sa.Column("mode", sa.String(24), nullable=False),
            sa.Column("model_id", sa.String(128), nullable=False),
            sa.Column("personalized", sa.Boolean(), nullable=False),
            sa.Column("candidate_item_ids", sa.JSON(), nullable=False),
            sa.Column("ranked_item_ids", sa.JSON(), nullable=False),
            sa.Column("positions", sa.JSON(), nullable=False),
            sa.Column("scores", sa.JSON(), nullable=False),
            sa.Column("candidate_sources", sa.JSON(), nullable=False),
            sa.Column("ranked_sources", sa.JSON(), nullable=False),
            sa.Column("score_components", sa.JSON(), nullable=False),
            sa.Column("exclusion_reasons", sa.JSON(), nullable=False),
            sa.Column("experiment_ids", sa.JSON(), nullable=False),
            sa.Column("exploration_propensities", sa.JSON(), nullable=False),
            sa.Column("latency_ms", sa.Float(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            schema=schema,
        )
        for name, columns in (
            ("ix_recommendation_log_subject_id", ["subject_id"]),
            ("ix_recommendation_log_slip_id", ["slip_id"]),
            ("ix_recommendation_log_created_at", ["created_at"]),
            ("ix_recommendation_log_expires_at", ["expires_at"]),
            ("ix_recommendation_log_subject_time", ["subject_id", "created_at"]),
            ("ix_recommendation_log_surface_time", ["surface", "created_at"]),
        ):
            op.create_index(name, "recommendation_log", columns, schema=schema)

    if not inspector.has_table("recommendation_interaction", schema=schema):
        op.create_table(
            "recommendation_interaction",
            sa.Column("subject_id", sa.String(36), primary_key=True),
            sa.Column("content_type", sa.String(32), primary_key=True),
            sa.Column("content_id", sa.String(128), primary_key=True),
            sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("positive_weight", sa.Float(), nullable=False),
            sa.Column("negative_weight", sa.Float(), nullable=False),
            sa.Column("net_weight", sa.Float(), nullable=False),
            sa.Column("event_count", sa.Integer(), nullable=False),
            sa.Column("last_event_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            schema=schema,
        )
        op.create_index("ix_recommendation_interaction_subject", "recommendation_interaction", ["subject_id", "net_weight"], schema=schema)
        op.create_index("ix_recommendation_interaction_item", "recommendation_interaction", ["content_type", "content_id"], schema=schema)
        op.create_index("ix_recommendation_interaction_slip_id", "recommendation_interaction", ["slip_id"], schema=schema)
        op.create_index("ix_recommendation_interaction_expires_at", "recommendation_interaction", ["expires_at"], schema=schema)

    if not inspector.has_table("collaborative_similarity", schema=schema):
        op.create_table(
            "collaborative_similarity",
            sa.Column("source_type", sa.String(32), primary_key=True),
            sa.Column("source_id", sa.String(128), primary_key=True),
            sa.Column("target_type", sa.String(32), primary_key=True),
            sa.Column("target_id", sa.String(128), primary_key=True),
            sa.Column("score", sa.Float(), nullable=False),
            sa.Column("support", sa.Integer(), nullable=False),
            sa.Column("model_version", sa.String(64), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            schema=schema,
        )
        op.create_index("ix_collaborative_similarity_source", "collaborative_similarity", ["source_type", "source_id", "score"], schema=schema)
        op.create_index("ix_collaborative_similarity_target", "collaborative_similarity", ["target_type", "target_id"], schema=schema)

    if postgres:
        op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA analytics FROM PUBLIC")


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    schema = "analytics" if bind.dialect.name == "postgresql" else None
    for table in ("collaborative_similarity", "recommendation_interaction", "recommendation_log"):
        if inspector.has_table(table, schema=schema):
            op.drop_table(table, schema=schema)
    content_columns = {column["name"] for column in inspector.get_columns("content_feature", schema=schema)}
    if "language" in content_columns:
        with op.batch_alter_table("content_feature", schema=schema) as batch_op:
            batch_op.drop_column("language")
