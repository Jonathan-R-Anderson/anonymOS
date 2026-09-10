"""Bind outbound handoffs to adapters and extension event tokens

Revision ID: c4f6b8d0e213
Revises: b3e5a7c9d102
Create Date: 2026-07-26
"""
from alembic import op
import sqlalchemy as sa


revision = "c4f6b8d0e213"
down_revision = "b3e5a7c9d102"
branch_labels = None
depends_on = None


def _columns(table):
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return set()
    return {item["name"] for item in inspector.get_columns(table)}


def upgrade():
    columns = _columns("outbound_reply")
    with op.batch_alter_table("outbound_reply", schema=None) as batch_op:
        if "adapter_id" not in columns:
            batch_op.add_column(sa.Column("adapter_id", sa.String(length=64), nullable=True))
        if "adapter_version" not in columns:
            batch_op.add_column(sa.Column("adapter_version", sa.String(length=32), nullable=True))
        if "event_secret_hash" not in columns:
            batch_op.add_column(sa.Column("event_secret_hash", sa.String(length=64), nullable=True))
        if "event_sequence" not in columns:
            batch_op.add_column(
                sa.Column("event_sequence", sa.Integer(), nullable=False, server_default="0")
            )


def downgrade():
    columns = _columns("outbound_reply")
    with op.batch_alter_table("outbound_reply", schema=None) as batch_op:
        for column in (
            "event_sequence",
            "event_secret_hash",
            "adapter_version",
            "adapter_id",
        ):
            if column in columns:
                batch_op.drop_column(column)
