"""Network throughput over time, so it can be drawn rather than only stated.

The live figure is a sum of what nodes report right now. A graph needs history,
and history has to be written as it happens — it cannot be recovered later from
a number that was only ever instantaneous.

reporting_nodes is stored alongside because without it a dip is unreadable: a
quiet network and a network that stopped reporting draw exactly the same line.

Revision ID: b8c2d4e6f7a9
Revises: a7b9c1d3e5f4
"""

import sqlalchemy as sa
from alembic import op

revision = "b8c2d4e6f7a9"
down_revision = "a7b9c1d3e5f4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "network_traffic_sample",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("bytes_per_second", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("requests_per_second", sa.Float(), nullable=False, server_default="0"),
        sa.Column("reporting_nodes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_nodes", sa.Integer(), nullable=False, server_default="0"),
    )
    # Every query is "the last N hours, in order", and the pruner is the same
    # shape reversed.
    op.create_index("ix_network_traffic_sample_at", "network_traffic_sample", ["at"])


def downgrade():
    op.drop_index("ix_network_traffic_sample_at", table_name="network_traffic_sample")
    op.drop_table("network_traffic_sample")
