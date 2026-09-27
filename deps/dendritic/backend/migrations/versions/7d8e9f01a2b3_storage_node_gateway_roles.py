"""Add verified volunteer-gateway roles to storage heartbeats.

Revision ID: 7d8e9f01a2b3
"""

from alembic import op
import sqlalchemy as sa


revision = "7d8e9f01a2b3"
down_revision = "e2a7c93f1b48"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "storage_node",
        sa.Column("gateway_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "storage_node",
        sa.Column("gateway_verified", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade():
    op.drop_column("storage_node", "gateway_verified")
    op.drop_column("storage_node", "gateway_enabled")
