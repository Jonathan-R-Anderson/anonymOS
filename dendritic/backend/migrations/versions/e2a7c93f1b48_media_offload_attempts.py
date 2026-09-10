"""count failed DHT offload attempts

Without this the sweep re-selects the same lowest-id rows every pass and never
advances past media whose object was pruned from the store.

Revision ID: e2a7c93f1b48
Revises: d1f4a86b3c27
"""
from alembic import op
import sqlalchemy as sa

revision = "e2a7c93f1b48"
down_revision = "d1f4a86b3c27"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("media", sa.Column("dht_offload_attempts", sa.Integer(),
                                     nullable=False, server_default="0"))


def downgrade():
    op.drop_column("media", "dht_offload_attempts")
