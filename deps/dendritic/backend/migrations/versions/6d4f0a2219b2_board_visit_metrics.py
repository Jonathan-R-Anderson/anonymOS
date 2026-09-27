"""Add board visit metrics table

Revision ID: 6d4f0a2219b2
Revises: 0c5d2a7a6c11
Create Date: 2026-04-22 10:15:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "6d4f0a2219b2"
down_revision = "0c5d2a7a6c11"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "board_visit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("board_id", sa.Integer(), nullable=False),
        sa.Column("page_id", sa.String(length=64), nullable=False),
        sa.Column("visitor_token", sa.String(length=64), nullable=False),
        sa.Column("path", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("page_views", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["board_id"], ["board.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("page_id"),
    )
    op.create_index("ix_board_visit_board_started_at", "board_visit", ["board_id", "started_at"], unique=False)
    op.create_index("ix_board_visit_started_at", "board_visit", ["started_at"], unique=False)
    op.create_index("ix_board_visit_visitor_token", "board_visit", ["visitor_token"], unique=False)


def downgrade():
    op.drop_index("ix_board_visit_visitor_token", table_name="board_visit")
    op.drop_index("ix_board_visit_started_at", table_name="board_visit")
    op.drop_index("ix_board_visit_board_started_at", table_name="board_visit")
    op.drop_table("board_visit")
