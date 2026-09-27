"""Awards paid over a payment channel instead of the chain.

An award used to be one ERC-20 transfer, so tx_hash was NOT NULL and unique —
the unique index being the load-bearing part, since without it one real transfer
could be replayed as an award on every post on the board.

A channel-backed award has no transaction at all. That is the point: paying over
a channel is what stops a five-ANON tip costing gas. So tx_hash becomes nullable
and (channel_id, channel_nonce) carries the same guarantee for the new path —
one payment, one award. Postgres treats NULLs as distinct in a unique index, so
the two paths coexist without either weakening the other.

The check constraint is what keeps "either/or" true rather than merely intended.
A row with neither identifier is an award nobody paid for; a row with both is a
claim that two different payments bought the same thing.

channel_award_ledger is the high-water mark per channel — see
model/ChannelAwardLedger.py for why a per-payment receipt is not enough once
payments are free.

This migration and the backend image that needs it must ship in the SAME deploy.
PostAward selects channel_id/channel_nonce, so a backend built from this tree
against a database that has not run this revision does not degrade — it fails at
the first award query. The updater only runs migrations when a file under
backend/migrations/versions/ changed in the deployed range, so a deploy that
carries the new image without carrying this file is the failure to avoid.

Revision ID: f3c9d2a5b7e1
Revises: a1b2c3d4e5f7
"""

import sqlalchemy as sa
from alembic import op

revision = "f3c9d2a5b7e1"
down_revision = "a1b2c3d4e5f7"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("post_award", "tx_hash",
                    existing_type=sa.String(length=80), nullable=True)
    op.add_column("post_award", sa.Column("channel_id", sa.String(length=64), nullable=True))
    op.add_column("post_award", sa.Column("channel_nonce", sa.BigInteger(), nullable=True))
    op.create_index("ix_post_award_channel_id", "post_award", ["channel_id"])
    op.create_unique_constraint(
        "uq_post_award_channel_state", "post_award", ["channel_id", "channel_nonce"])
    op.create_check_constraint(
        "ck_post_award_one_payment_path", "post_award",
        "(tx_hash IS NOT NULL AND channel_id IS NULL)"
        " OR (tx_hash IS NULL AND channel_id IS NOT NULL)",
    )

    op.create_table(
        "channel_award_ledger",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("channel_id", sa.String(length=64), nullable=False),
        sa.Column("recipient_wallet", sa.String(length=42), nullable=False, server_default=""),
        # Wei as a decimal string: 100 ANON is 1e20 and a BigInteger would break
        # after a few gold awards.
        sa.Column("awarded_wei", sa.String(length=80), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("channel_id", name="uq_channel_award_ledger_channel"),
    )
    op.create_index("ix_channel_award_ledger_channel_id", "channel_award_ledger", ["channel_id"])

    # Where an author's node lives. Nullable and empty by default: an author who
    # never sets it keeps the on-chain award path, unchanged.
    op.add_column("profile", sa.Column("channel_endpoint", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("profile", "channel_endpoint")
    op.drop_index("ix_channel_award_ledger_channel_id", table_name="channel_award_ledger")
    op.drop_table("channel_award_ledger")

    op.drop_constraint("ck_post_award_one_payment_path", "post_award", type_="check")
    op.drop_constraint("uq_post_award_channel_state", "post_award", type_="unique")
    op.drop_index("ix_post_award_channel_id", table_name="post_award")
    op.drop_column("post_award", "channel_nonce")
    op.drop_column("post_award", "channel_id")
    # Deliberately NOT restoring NOT NULL on tx_hash. Any channel-backed award
    # recorded while this migration was applied has no transaction to put there,
    # so re-imposing it would either fail or require inventing hashes for real
    # awards. Going back is a schema loosening that stays loose.
    op.alter_column("post_award", "tx_hash",
                    existing_type=sa.String(length=80), nullable=True)
