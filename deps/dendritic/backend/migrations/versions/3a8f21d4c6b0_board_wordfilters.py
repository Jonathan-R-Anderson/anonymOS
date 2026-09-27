"""Add global and board-scoped wordfilters

Revision ID: 3a8f21d4c6b0
Revises: f026b03e6006
Create Date: 2026-07-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "3a8f21d4c6b0"
down_revision = "f026b03e6006"
branch_labels = None
depends_on = None


def upgrade():
    inspector = inspect(op.get_bind())
    if not inspector.has_table("word_filter"):
        op.create_table(
            "word_filter",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("pattern", sa.String(length=128), nullable=False),
            sa.Column("replacement", sa.String(length=512), nullable=False, server_default=""),
            sa.Column("case_sensitive", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("whole_word", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("is_global", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_by_slip_id", sa.Integer(), nullable=True),
            sa.Column("created_by_sysop", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["created_by_slip_id"], ["slip.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_word_filter_is_global", "word_filter", ["is_global"], unique=False)

    inspector = inspect(op.get_bind())
    if not inspector.has_table("word_filter_board"):
        op.create_table(
            "word_filter_board",
            sa.Column("word_filter_id", sa.Integer(), nullable=False),
            sa.Column("board_id", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(["board_id"], ["board.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["word_filter_id"], ["word_filter.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("word_filter_id", "board_id"),
        )
        op.create_index("ix_word_filter_board_board_id", "word_filter_board", ["board_id"], unique=False)


def downgrade():
    inspector = inspect(op.get_bind())
    if inspector.has_table("word_filter_board"):
        op.drop_index("ix_word_filter_board_board_id", table_name="word_filter_board")
        op.drop_table("word_filter_board")
    inspector = inspect(op.get_bind())
    if inspector.has_table("word_filter"):
        op.drop_index("ix_word_filter_is_global", table_name="word_filter")
        op.drop_table("word_filter")
