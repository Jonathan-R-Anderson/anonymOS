"""Node-declared payout addresses.

Revision ID: d4e5f6a7b8c9
"""

from alembic import op
import sqlalchemy as sa


revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pof_payout",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("p2p_public_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("payout", sa.String(length=42), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("signature", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_pof_payout_key", "pof_payout", ["p2p_public_key"])


def downgrade():
    op.drop_index("ix_pof_payout_key", table_name="pof_payout")
    op.drop_table("pof_payout")
