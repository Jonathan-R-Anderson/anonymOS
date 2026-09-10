"""Traffic each node moved in its last reporting window.

A WINDOW rather than a lifetime counter. A cumulative counter has to be
differenced against the previous heartbeat to become a rate, and it resets to
zero when the node restarts — which reads as a large negative delta, i.e. as an
enormous burst of traffic exactly when a node is flapping.

Zero-default so existing rows are simply "not reporting" rather than "reporting
nothing", which network_throughput distinguishes by skipping a zero window.

Revision ID: f6a8b2c4d5e3
Revises: e5f7a9b1c3d2
"""

import sqlalchemy as sa
from alembic import op

revision = "f6a8b2c4d5e3"
down_revision = "e5f7a9b1c3d2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("storage_node", sa.Column(
        "traffic_bytes", sa.BigInteger(), nullable=False, server_default="0"))
    op.add_column("storage_node", sa.Column(
        "traffic_requests", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("storage_node", sa.Column(
        "traffic_window_seconds", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    op.drop_column("storage_node", "traffic_window_seconds")
    op.drop_column("storage_node", "traffic_requests")
    op.drop_column("storage_node", "traffic_bytes")
