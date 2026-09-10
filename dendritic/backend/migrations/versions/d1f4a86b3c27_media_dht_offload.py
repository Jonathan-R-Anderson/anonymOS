"""track which media have been offloaded to the storage DHT

Set only after a write to the node gateway reads back byte-identically. See
services/storage_offload.py for why offload and reclaim are separate.

Revision ID: d1f4a86b3c27
Revises: c8f3d92a4e15
"""
from alembic import op
import sqlalchemy as sa

revision = "d1f4a86b3c27"
down_revision = "c8f3d92a4e15"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("media", sa.Column("dht_offloaded_at", sa.DateTime(), nullable=True))
    op.create_index("ix_media_dht_offloaded_at", "media", ["dht_offloaded_at"])


def downgrade():
    op.drop_index("ix_media_dht_offloaded_at", table_name="media")
    op.drop_column("media", "dht_offloaded_at")
