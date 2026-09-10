"""Add outbound reply idempotency and one-use handoff capabilities

Revision ID: b3e5a7c9d102
Revises: a2d4f6b8c901
Create Date: 2026-07-26
"""
from alembic import op
import sqlalchemy as sa


revision = "b3e5a7c9d102"
down_revision = "a2d4f6b8c901"
branch_labels = None
depends_on = None


def _columns(table):
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table):
        return set()
    return {item["name"] for item in inspector.get_columns(table)}


def _constraints(table):
    inspector = sa.inspect(op.get_bind())
    return {
        item.get("name")
        for item in inspector.get_unique_constraints(table)
        if item.get("name")
    }


def upgrade():
    columns = _columns("outbound_reply")
    with op.batch_alter_table("outbound_reply", schema=None) as batch_op:
        if "body_digest" not in columns:
            batch_op.add_column(sa.Column("body_digest", sa.String(length=64), nullable=True))
        if "idempotency_key" not in columns:
            batch_op.add_column(sa.Column("idempotency_key", sa.String(length=64), nullable=True))
        if "handoff_secret_hash" not in columns:
            batch_op.add_column(sa.Column("handoff_secret_hash", sa.String(length=64), nullable=True))
        if "handoff_expires_at" not in columns:
            batch_op.add_column(sa.Column("handoff_expires_at", sa.DateTime(), nullable=True))
        if "handoff_consumed_at" not in columns:
            batch_op.add_column(sa.Column("handoff_consumed_at", sa.DateTime(), nullable=True))

    if "uq_outbound_reply_poster_idempotency" not in _constraints("outbound_reply"):
        with op.batch_alter_table("outbound_reply", schema=None) as batch_op:
            batch_op.create_unique_constraint(
                "uq_outbound_reply_poster_idempotency",
                ["poster_id", "idempotency_key"],
            )


def downgrade():
    if "uq_outbound_reply_poster_idempotency" in _constraints("outbound_reply"):
        with op.batch_alter_table("outbound_reply", schema=None) as batch_op:
            batch_op.drop_constraint("uq_outbound_reply_poster_idempotency", type_="unique")
    columns = _columns("outbound_reply")
    with op.batch_alter_table("outbound_reply", schema=None) as batch_op:
        for column in (
            "handoff_consumed_at",
            "handoff_expires_at",
            "handoff_secret_hash",
            "idempotency_key",
            "body_digest",
        ):
            if column in columns:
                batch_op.drop_column(column)

