"""Settled epochs and their claim proofs.

Revision ID: f6a7b8c9d0e1
"""

from alembic import op
import sqlalchemy as sa


revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pof_settlement",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("epoch", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("receipt_root", sa.String(length=66), nullable=False),
        sa.Column("reward_root", sa.String(length=66), nullable=False),
        sa.Column("node_state_root", sa.String(length=66), nullable=False),
        sa.Column("randomness", sa.String(length=66), nullable=False),
        # Decimal wei as text: amounts exceed 64 bits and rounding a reward to
        # fit a column would be a silent theft.
        sa.Column("total_rewards", sa.String(length=80), nullable=False, server_default="0"),
        sa.Column("accepted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejections", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("claims", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("submitted_tx", sa.String(length=80), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_pof_settlement_epoch", "pof_settlement", ["epoch"])


def downgrade():
    op.drop_index("ix_pof_settlement_epoch", table_name="pof_settlement")
    op.drop_table("pof_settlement")
