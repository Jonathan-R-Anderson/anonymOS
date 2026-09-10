"""Bug bounties with escrow, and the two-sided ratings that go with them.

escrow_tx is unique for the same reason a store order's tx_hash is: one payment
must not be able to fund two bounties, and the chain would agree the transfer
happened each time it was presented.

The unique constraint on (bounty_id, rater_slip_id) is what keeps a rating a
record of a transaction rather than a review box — one verdict per person per
bounty, enforced by the database rather than by remembering to check.

Revision ID: f3a5b7c9d2e4
Revises: e2f4a6b8c1d3
"""

import sqlalchemy as sa
from alembic import op

revision = "f3a5b7c9d2e4"
down_revision = "e2f4a6b8c1d3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "bounty",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("poster_slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("target", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("reward", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="draft"),
        sa.Column("escrow_tx", sa.String(length=80), nullable=True),
        sa.Column("funded_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("payout_hunter", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("payout_poster", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("settled_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("escrow_tx", name="uq_bounty_escrow_tx"),
    )
    op.create_index("ix_bounty_poster_slip_id", "bounty", ["poster_slip_id"])
    op.create_index("ix_bounty_status", "bounty", ["status"])

    op.create_table(
        "bounty_submission",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("bounty_id", sa.Integer(), sa.ForeignKey("bounty.id"), nullable=False),
        sa.Column("hunter_slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("verdict_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_bounty_submission_bounty_id", "bounty_submission", ["bounty_id"])
    op.create_index("ix_bounty_submission_hunter_slip_id", "bounty_submission", ["hunter_slip_id"])
    op.create_index("ix_bounty_submission_status", "bounty_submission", ["status"])

    op.create_table(
        "bounty_rating",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("bounty_id", sa.Integer(), sa.ForeignKey("bounty.id"), nullable=False),
        sa.Column("rater_slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("rated_slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("comment", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("bounty_id", "rater_slip_id", name="uq_bounty_rating_once"),
    )
    op.create_index("ix_bounty_rating_bounty_id", "bounty_rating", ["bounty_id"])
    op.create_index("ix_bounty_rating_rater_slip_id", "bounty_rating", ["rater_slip_id"])
    op.create_index("ix_bounty_rating_rated_slip_id", "bounty_rating", ["rated_slip_id"])


def downgrade():
    op.drop_table("bounty_rating")
    op.drop_table("bounty_submission")
    op.drop_index("ix_bounty_status", table_name="bounty")
    op.drop_index("ix_bounty_poster_slip_id", table_name="bounty")
    op.drop_table("bounty")
