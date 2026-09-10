"""Per-player daily challenges.

The unique constraint on (slip_id, day) is the feature. Without it a refresh
generates a new challenge, so a player who dislikes today's question reloads
until they get an easy one — a daily challenge that can be rerolled is a slot
machine, and any streak built on it means nothing.

It also caps cost at one generation per player per day, enforced by the database
rather than by remembering to check.

Revision ID: d1e3f5a7b9c2
Revises: c9d1e3f5a7b2
"""

import sqlalchemy as sa
from alembic import op

revision = "d1e3f5a7b9c2"
down_revision = "c9d1e3f5a7b2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "codeplay_daily_challenge",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("aimed_at", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("slip_id", "day", name="uq_codeplay_daily_slip_day"),
    )
    op.create_index("ix_codeplay_daily_challenge_slip_id",
                    "codeplay_daily_challenge", ["slip_id"])
    op.create_index("ix_codeplay_daily_challenge_day",
                    "codeplay_daily_challenge", ["day"])


def downgrade():
    op.drop_index("ix_codeplay_daily_challenge_day", table_name="codeplay_daily_challenge")
    op.drop_index("ix_codeplay_daily_challenge_slip_id", table_name="codeplay_daily_challenge")
    op.drop_table("codeplay_daily_challenge")
