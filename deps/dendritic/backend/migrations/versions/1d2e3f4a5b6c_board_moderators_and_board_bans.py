"""Add board moderator assignments and board bans

Revision ID: 1d2e3f4a5b6c
Revises: 8f2c1a6d4b77
Create Date: 2026-04-22 22:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "1d2e3f4a5b6c"
down_revision = "8f2c1a6d4b77"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "slip_board_moderator",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slip_id", sa.Integer(), nullable=False),
        sa.Column("board_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["board_id"], ["board.id"]),
        sa.ForeignKeyConstraint(["slip_id"], ["slip.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slip_id", "board_id", name="uq_slip_board_moderator_slip_board"),
    )
    op.create_index("ix_slip_board_moderator_board_id", "slip_board_moderator", ["board_id"], unique=False)
    op.create_index("ix_slip_board_moderator_slip_id", "slip_board_moderator", ["slip_id"], unique=False)

    op.create_table(
        "board_ban",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("board_id", sa.Integer(), nullable=False),
        sa.Column("ip_address", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by_slip_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["board_id"], ["board.id"]),
        sa.ForeignKeyConstraint(["created_by_slip_id"], ["slip.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("board_id", "ip_address", name="uq_board_ban_board_ip"),
    )
    op.create_index("ix_board_ban_board_id", "board_ban", ["board_id"], unique=False)
    op.create_index("ix_board_ban_ip_address", "board_ban", ["ip_address"], unique=False)


def downgrade():
    op.drop_index("ix_board_ban_ip_address", table_name="board_ban")
    op.drop_index("ix_board_ban_board_id", table_name="board_ban")
    op.drop_table("board_ban")

    op.drop_index("ix_slip_board_moderator_slip_id", table_name="slip_board_moderator")
    op.drop_index("ix_slip_board_moderator_board_id", table_name="slip_board_moderator")
    op.drop_table("slip_board_moderator")
