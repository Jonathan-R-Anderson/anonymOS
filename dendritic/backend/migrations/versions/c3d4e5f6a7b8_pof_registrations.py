"""Self-service Proof-of-Facilitation node registrations.

Revision ID: c3d4e5f6a7b8
"""

from alembic import op
import sqlalchemy as sa


revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pof_registration",
        sa.Column("id", sa.Integer(), primary_key=True),
        # Unique: NodeRegistry registers a p2p key once, so queueing it twice
        # would only ever produce a KeyAlreadyRegistered revert.
        sa.Column("p2p_public_key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("wallet", sa.String(length=42), nullable=False),
        sa.Column("capabilities", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("endpoint_commitment", sa.String(length=66), nullable=False, server_default=""),
        sa.Column("nonce", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sig_v", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sig_r", sa.String(length=66), nullable=False, server_default=""),
        sa.Column("sig_s", sa.String(length=66), nullable=False, server_default=""),
        sa.Column("p2p_proof", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("tx_hash", sa.String(length=80), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_pof_registration_status", "pof_registration", ["status"])
    op.create_index("ix_pof_registration_key", "pof_registration", ["p2p_public_key"])


def downgrade():
    op.drop_index("ix_pof_registration_key", table_name="pof_registration")
    op.drop_index("ix_pof_registration_status", table_name="pof_registration")
    op.drop_table("pof_registration")
