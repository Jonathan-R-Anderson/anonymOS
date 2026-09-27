"""Receipt and assignment relay tables.

Revision ID: e5f6a7b8c9d0
"""

from alembic import op
import sqlalchemy as sa


revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pof_receipt",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        # Unique: re-uploading after a restart is normal and must be a no-op,
        # not a duplicate the aggregator has to dedup again.
        sa.Column("receipt_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("provider_key", sa.String(length=64), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_pof_receipt_epoch", "pof_receipt", ["epoch"])
    op.create_index("ix_pof_receipt_hash", "pof_receipt", ["receipt_hash"])
    op.create_index("ix_pof_receipt_provider", "pof_receipt", ["provider_key"])

    op.create_table(
        "pof_assignment",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("p2p_public_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_pof_assignment_key", "pof_assignment", ["p2p_public_key"])


def downgrade():
    op.drop_index("ix_pof_assignment_key", table_name="pof_assignment")
    op.drop_table("pof_assignment")
    op.drop_index("ix_pof_receipt_provider", table_name="pof_receipt")
    op.drop_index("ix_pof_receipt_hash", table_name="pof_receipt")
    op.drop_index("ix_pof_receipt_epoch", table_name="pof_receipt")
    op.drop_table("pof_receipt")
