"""Experimentation and optimization Phase 4.

Revision ID: de04f81c4004
Revises: cd93e70b3003
Create Date: 2026-07-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "de04f81c4004"
down_revision = "cd93e70b3003"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    postgres = bind.dialect.name == "postgresql"
    schema = "analytics" if postgres else None
    if postgres:
        op.execute("CREATE SCHEMA IF NOT EXISTS analytics")

    recommendation_columns = {
        column["name"] for column in inspector.get_columns("recommendation_log", schema=schema)
    }
    additions = (
        ("explanations", sa.Column("explanations", sa.JSON(), nullable=False, server_default="[]")),
        ("shadow_model_id", sa.Column("shadow_model_id", sa.String(128), nullable=True)),
        ("shadow_scores", sa.Column("shadow_scores", sa.JSON(), nullable=False, server_default="[]")),
    )
    for name, column in additions:
        if name not in recommendation_columns:
            op.add_column("recommendation_log", column, schema=schema)

    if not inspector.has_table("experiment_definition", schema=schema):
        op.create_table(
            "experiment_definition",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("namespace", sa.String(64), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("traffic_percent", sa.Float(), nullable=False),
            sa.Column("variants", sa.JSON(), nullable=False),
            sa.Column("primary_metrics", sa.JSON(), nullable=False),
            sa.Column("guardrails", sa.JSON(), nullable=False),
            sa.Column("salt", sa.String(128), nullable=False),
            sa.Column("long_term_holdout_variant", sa.String(64), nullable=True),
            sa.Column("starts_at", sa.DateTime(), nullable=True),
            sa.Column("ends_at", sa.DateTime(), nullable=True),
            sa.Column("rollback_reason", sa.String(500), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            schema=schema,
        )
        op.create_index("ix_experiment_definition_status", "experiment_definition", ["status"], schema=schema)
        op.create_index("ix_experiment_definition_namespace_status", "experiment_definition", ["namespace", "status"], schema=schema)

    if not inspector.has_table("experiment_exposure", schema=schema):
        definition_fk = "analytics.experiment_definition.id" if postgres else "experiment_definition.id"
        op.create_table(
            "experiment_exposure",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("experiment_id", sa.String(64), sa.ForeignKey(definition_fk, ondelete="CASCADE"), nullable=False),
            sa.Column("subject_id", sa.String(36), nullable=False),
            sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("request_id", sa.String(36), nullable=False),
            sa.Column("variant", sa.String(64), nullable=False),
            sa.Column("bucket", sa.Integer(), nullable=False),
            sa.Column("surface", sa.String(64), nullable=False),
            sa.Column("exposed_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("experiment_id", "request_id", name="uq_experiment_exposure_request"),
            schema=schema,
        )
        for name, columns in (
            ("ix_experiment_exposure_subject_id", ["subject_id"]),
            ("ix_experiment_exposure_slip_id", ["slip_id"]),
            ("ix_experiment_exposure_exposed_at", ["exposed_at"]),
            ("ix_experiment_exposure_expires_at", ["expires_at"]),
            ("ix_experiment_exposure_variant_time", ["experiment_id", "variant", "exposed_at"]),
            ("ix_experiment_exposure_subject_time", ["subject_id", "exposed_at"]),
        ):
            op.create_index(name, "experiment_exposure", columns, schema=schema)

    if not inspector.has_table("experiment_guardrail_snapshot", schema=schema):
        op.create_table(
            "experiment_guardrail_snapshot",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("experiment_id", sa.String(64), nullable=False),
            sa.Column("status", sa.String(24), nullable=False),
            sa.Column("sample_size", sa.Integer(), nullable=False),
            sa.Column("srm_detected", sa.Boolean(), nullable=False),
            sa.Column("metrics", sa.JSON(), nullable=False),
            sa.Column("violations", sa.JSON(), nullable=False),
            sa.Column("action", sa.String(32), nullable=False),
            sa.Column("evaluated_at", sa.DateTime(), nullable=False),
            schema=schema,
        )
        op.create_index("ix_experiment_guardrail_snapshot_experiment_id", "experiment_guardrail_snapshot", ["experiment_id"], schema=schema)
        op.create_index("ix_experiment_guardrail_snapshot_evaluated_at", "experiment_guardrail_snapshot", ["evaluated_at"], schema=schema)
        op.create_index("ix_experiment_guardrail_experiment_time", "experiment_guardrail_snapshot", ["experiment_id", "evaluated_at"], schema=schema)

    if not inspector.has_table("recommendation_satisfaction", schema=schema):
        op.create_table(
            "recommendation_satisfaction",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("request_id", sa.String(36), nullable=False),
            sa.Column("subject_id", sa.String(36), nullable=False),
            sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("rating", sa.Integer(), nullable=False),
            sa.Column("reason", sa.String(64), nullable=True),
            sa.Column("surface", sa.String(64), nullable=False),
            sa.Column("experiment_ids", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("request_id", "subject_id", name="uq_recommendation_satisfaction_request_subject"),
            schema=schema,
        )
        for name, columns in (
            ("ix_recommendation_satisfaction_request_id", ["request_id"]),
            ("ix_recommendation_satisfaction_subject_id", ["subject_id"]),
            ("ix_recommendation_satisfaction_slip_id", ["slip_id"]),
            ("ix_recommendation_satisfaction_time", ["created_at"]),
            ("ix_recommendation_satisfaction_expires_at", ["expires_at"]),
        ):
            op.create_index(name, "recommendation_satisfaction", columns, schema=schema)

    if not inspector.has_table("behavior_metric_daily", schema=schema):
        op.create_table(
            "behavior_metric_daily",
            sa.Column("day", sa.Date(), primary_key=True),
            sa.Column("dashboard", sa.String(32), primary_key=True),
            sa.Column("metric", sa.String(64), primary_key=True),
            sa.Column("dimension", sa.String(128), primary_key=True),
            sa.Column("value", sa.Float(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            schema=schema,
        )
        op.create_index("ix_behavior_metric_daily_dashboard_day", "behavior_metric_daily", ["dashboard", "day"], schema=schema)

    if postgres:
        op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA analytics FROM PUBLIC")


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    schema = "analytics" if bind.dialect.name == "postgresql" else None
    for table in ("behavior_metric_daily", "recommendation_satisfaction", "experiment_guardrail_snapshot", "experiment_exposure", "experiment_definition"):
        if inspector.has_table(table, schema=schema):
            op.drop_table(table, schema=schema)
    recommendation_columns = {
        column["name"] for column in inspector.get_columns("recommendation_log", schema=schema)
    }
    for name in ("shadow_scores", "shadow_model_id", "explanations"):
        if name in recommendation_columns:
            with op.batch_alter_table("recommendation_log", schema=schema) as batch_op:
                batch_op.drop_column(name)
