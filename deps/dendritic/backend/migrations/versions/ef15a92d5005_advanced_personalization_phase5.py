"""Advanced personalization and continuous maturity Phase 5.

Revision ID: ef15a92d5005
Revises: de04f81c4004
Create Date: 2026-07-19 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "ef15a92d5005"
down_revision = "de04f81c4004"
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
    for name, column in (
        ("multimodal_embedding", sa.Column("multimodal_embedding", sa.JSON(), nullable=False, server_default="[]")),
        ("multimodal_model", sa.Column("multimodal_model", sa.String(64), nullable=False, server_default="multimodal-hash-64-v1")),
    ):
        if name not in content_columns:
            op.add_column("content_feature", column, schema=schema)

    recommendation_columns = {column["name"] for column in inspector.get_columns("recommendation_log", schema=schema)}
    for name, column in (
        ("objective_scores", sa.Column("objective_scores", sa.JSON(), nullable=False, server_default="{}")),
        ("policy_context", sa.Column("policy_context", sa.String(128), nullable=True)),
        ("bandit_arm", sa.Column("bandit_arm", sa.String(32), nullable=True)),
        ("bandit_propensity", sa.Column("bandit_propensity", sa.Float(), nullable=True)),
    ):
        if name not in recommendation_columns:
            op.add_column("recommendation_log", column, schema=schema)

    tables = {
        "behavior_sequence": [
            sa.Column("subject_id", sa.String(36), primary_key=True), sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("recent_items", sa.JSON(), nullable=False), sa.Column("recent_topics", sa.JSON(), nullable=False),
            sa.Column("sequence_embedding", sa.JSON(), nullable=False), sa.Column("source_event_count", sa.Integer(), nullable=False),
            sa.Column("model_version", sa.String(64), nullable=False), sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
        ],
        "user_value_prediction": [
            sa.Column("subject_id", sa.String(36), primary_key=True), sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("churn_probability", sa.Float(), nullable=False), sa.Column("long_term_value", sa.Float(), nullable=False),
            sa.Column("components", sa.JSON(), nullable=False), sa.Column("model_version", sa.String(64), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False), sa.Column("expires_at", sa.DateTime(), nullable=False),
        ],
        "recommendation_preference": [
            sa.Column("subject_id", sa.String(36), primary_key=True), sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("muted_topics", sa.JSON(), nullable=False), sa.Column("excluded_creators", sa.JSON(), nullable=False),
            sa.Column("exploration_enabled", sa.Boolean(), nullable=False), sa.Column("personalization_strength", sa.Float(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        ],
        "contextual_bandit_arm": [
            sa.Column("context_key", sa.String(128), primary_key=True), sa.Column("arm", sa.String(32), primary_key=True),
            sa.Column("pulls", sa.Integer(), nullable=False), sa.Column("reward_sum", sa.Float(), nullable=False),
            sa.Column("reward_square_sum", sa.Float(), nullable=False), sa.Column("updated_at", sa.DateTime(), nullable=False),
        ],
        "notification_recommendation": [
            sa.Column("subject_id", sa.String(36), primary_key=True), sa.Column("content_type", sa.String(32), primary_key=True),
            sa.Column("content_id", sa.String(128), primary_key=True), sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("score", sa.Float(), nullable=False), sa.Column("reason", sa.String(160), nullable=False),
            sa.Column("status", sa.String(24), nullable=False), sa.Column("model_version", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False), sa.Column("expires_at", sa.DateTime(), nullable=False),
        ],
        "creator_exposure_daily": [
            sa.Column("day", sa.Date(), primary_key=True), sa.Column("content_type", sa.String(32), primary_key=True),
            sa.Column("creator_id", sa.String(128), primary_key=True), sa.Column("impressions", sa.Integer(), nullable=False),
            sa.Column("exploration_impressions", sa.Integer(), nullable=False), sa.Column("unique_items", sa.Integer(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        ],
        "model_health_snapshot": [
            sa.Column("id", sa.Integer(), primary_key=True), sa.Column("model_id", sa.String(128), nullable=False),
            sa.Column("feature_drift", sa.JSON(), nullable=False), sa.Column("outcome_drift", sa.JSON(), nullable=False),
            sa.Column("fairness", sa.JSON(), nullable=False), sa.Column("violations", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(24), nullable=False), sa.Column("evaluated_at", sa.DateTime(), nullable=False),
        ],
        "algorithm_audit": [
            sa.Column("id", sa.String(36), primary_key=True), sa.Column("scope", sa.String(128), nullable=False),
            sa.Column("manifest", sa.JSON(), nullable=False), sa.Column("checksum", sa.String(64), nullable=False),
            sa.Column("status", sa.String(32), nullable=False), sa.Column("reviewer", sa.String(160), nullable=True),
            sa.Column("findings", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
        ],
    }
    for table_name, columns in tables.items():
        if not inspector.has_table(table_name, schema=schema):
            op.create_table(table_name, *columns, schema=schema)

    indexes = (
        ("behavior_sequence", "ix_behavior_sequence_slip_id", ["slip_id"]),
        ("behavior_sequence", "ix_behavior_sequence_updated_at", ["updated_at"]),
        ("behavior_sequence", "ix_behavior_sequence_expires_at", ["expires_at"]),
        ("user_value_prediction", "ix_user_value_prediction_slip_id", ["slip_id"]),
        ("user_value_prediction", "ix_user_value_prediction_expires_at", ["expires_at"]),
        ("recommendation_preference", "ix_recommendation_preference_slip_id", ["slip_id"]),
        ("notification_recommendation", "ix_notification_recommendation_slip_id", ["slip_id"]),
        ("notification_recommendation", "ix_notification_recommendation_expires_at", ["expires_at"]),
        ("notification_recommendation", "ix_notification_recommendation_subject_status", ["subject_id", "status", "score"]),
        ("creator_exposure_daily", "ix_creator_exposure_daily_type_day", ["content_type", "day"]),
        ("model_health_snapshot", "ix_model_health_snapshot_model_time", ["model_id", "evaluated_at"]),
    )
    inspector = inspect(bind)
    for table_name, index_name, columns in indexes:
        existing = {index["name"] for index in inspector.get_indexes(table_name, schema=schema)}
        if index_name not in existing:
            op.create_index(index_name, table_name, columns, schema=schema)
    if postgres:
        op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA analytics FROM PUBLIC")


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    schema = "analytics" if bind.dialect.name == "postgresql" else None
    for table in (
        "algorithm_audit", "model_health_snapshot", "creator_exposure_daily", "notification_recommendation",
        "contextual_bandit_arm", "recommendation_preference", "user_value_prediction", "behavior_sequence",
    ):
        if inspector.has_table(table, schema=schema):
            op.drop_table(table, schema=schema)
    for table, names in (
        ("recommendation_log", ("bandit_propensity", "bandit_arm", "policy_context", "objective_scores")),
        ("content_feature", ("multimodal_model", "multimodal_embedding")),
    ):
        columns = {column["name"] for column in inspector.get_columns(table, schema=schema)}
        for name in names:
            if name in columns:
                with op.batch_alter_table(table, schema=schema) as batch_op:
                    batch_op.drop_column(name)
