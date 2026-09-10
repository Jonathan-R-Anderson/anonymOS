"""The welcome grant, and the columns that make a farm visible.

Two unique constraints do the real work. One grant per SLIP stops the same
account claiming twice; one grant per WALLET stops a hundred accounts draining
into one address, which is the shape a farm actually takes. Both are indexes
rather than checks in code, because a check somebody forgets to run is not a
constraint.

network_hash is a salted hash, never an address: grouping signups by network
needs only equality, and this table outlives the reason anybody had for keeping
somebody's IP.

Revision ID: a4b6c8d1e3f5
Revises: f3a5b7c9d2e4
"""

import sqlalchemy as sa
from alembic import op

revision = "a4b6c8d1e3f5"
down_revision = "f3a5b7c9d2e4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "signup_grant",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("credits", sa.BigInteger(), nullable=False, server_default="20"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("network_hash", sa.String(length=64), nullable=True),
        sa.Column("claim_network_hash", sa.String(length=64), nullable=True),
        sa.Column("wallet", sa.String(length=42), nullable=True),
        sa.Column("credit_grant_id", sa.Integer(),
                  sa.ForeignKey("credit_grant.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("note", sa.String(length=255), nullable=False, server_default=""),
        sa.UniqueConstraint("slip_id", name="uq_signup_grant_slip"),
        sa.UniqueConstraint("wallet", name="uq_signup_grant_wallet"),
    )
    op.create_index("ix_signup_grant_status", "signup_grant", ["status"])
    op.create_index("ix_signup_grant_network_hash", "signup_grant", ["network_hash"])
    op.create_index("ix_signup_grant_claim_network_hash", "signup_grant", ["claim_network_hash"])


def downgrade():
    op.drop_index("ix_signup_grant_claim_network_hash", table_name="signup_grant")
    op.drop_index("ix_signup_grant_network_hash", table_name="signup_grant")
    op.drop_index("ix_signup_grant_status", table_name="signup_grant")
    op.drop_table("signup_grant")
