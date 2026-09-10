"""Add per-board banners

Revision ID: 7a1c2f8b4d9e
Revises: 6d4f0a2219b2
Create Date: 2026-04-22 16:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "7a1c2f8b4d9e"
down_revision = "6d4f0a2219b2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "board_banner",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("board_id", sa.Integer(), nullable=False),
        sa.Column("media_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["board_id"], ["board.id"]),
        sa.ForeignKeyConstraint(["media_id"], ["media.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("media_id"),
    )
    op.create_index("ix_board_banner_board_id", "board_banner", ["board_id"], unique=False)


def downgrade():
    op.drop_index("ix_board_banner_board_id", table_name="board_banner")
    op.drop_table("board_banner")
