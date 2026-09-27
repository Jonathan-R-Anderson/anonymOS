"""Whether a node runs the status monitor.

Reported so the admin map can draw the role, and so the operator can see how
many vantage points the status page actually has. A page measured from one
place is barely measured at all — it cannot tell "the site is down" from "the
site is unreachable from that one machine".

Revision ID: a7b9c1d3e5f4
Revises: f6a8b2c4d5e3
"""

import sqlalchemy as sa
from alembic import op

revision = "a7b9c1d3e5f4"
down_revision = "f6a8b2c4d5e3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("storage_node", sa.Column(
        "monitor_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("storage_node", "monitor_enabled")
