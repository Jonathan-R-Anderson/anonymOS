"""Track signed native-storage client heartbeats.

Revision ID: e6b2c41d8a70
Revises: d4e7a91c2f60
"""

from alembic import op
import sqlalchemy as sa


revision = "e6b2c41d8a70"
down_revision = "d4e7a91c2f60"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "storage_node",
        sa.Column("node_id", sa.String(length=128), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("capacity_bytes", sa.BigInteger(), nullable=False),
        sa.Column("platform", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint("node_id"),
    )
    op.create_index(
        "ix_storage_node_last_seen_at",
        "storage_node",
        ["last_seen_at"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_storage_node_last_seen_at", table_name="storage_node")
    op.drop_table("storage_node")
