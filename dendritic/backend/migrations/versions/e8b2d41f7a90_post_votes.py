"""Per-slip up/down votes on posts

Revision ID: e8b2d41f7a90
Revises: d7a1c93e5b48
Create Date: 2026-07-26
"""
from alembic import op
import sqlalchemy as sa


revision = "e8b2d41f7a90"
down_revision = "d7a1c93e5b48"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(table):
    return _inspector().has_table(table)


def _indexes(table):
    if not _has_table(table):
        return set()
    return {item["name"] for item in _inspector().get_indexes(table)}


def upgrade():
    if _has_table("post_vote"):
        return
    op.create_table(
        "post_vote",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("post_id", sa.Integer(), nullable=False),
        sa.Column("slip_id", sa.Integer(), nullable=False),
        sa.Column("value", sa.SmallInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["post_id"], ["post.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["slip_id"], ["slip.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        # One vote per slip per post; changing your mind updates the row.
        sa.UniqueConstraint("post_id", "slip_id", name="uq_post_vote_post_slip"),
    )
    indexes = _indexes("post_vote")
    if "ix_post_vote_post_id" not in indexes:
        op.create_index("ix_post_vote_post_id", "post_vote", ["post_id"])
    if "ix_post_vote_slip_id" not in indexes:
        op.create_index("ix_post_vote_slip_id", "post_vote", ["slip_id"])


def downgrade():
    if not _has_table("post_vote"):
        return
    indexes = _indexes("post_vote")
    if "ix_post_vote_slip_id" in indexes:
        op.drop_index("ix_post_vote_slip_id", table_name="post_vote")
    if "ix_post_vote_post_id" in indexes:
        op.drop_index("ix_post_vote_post_id", table_name="post_vote")
    op.drop_table("post_vote")
