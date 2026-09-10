"""storage node egress IP and country-centroid coordinates

Powers the blue storage-node dots on the admin world map. Country-level only.

The peer-to-peer privacy guarantee is unchanged: volunteers still cannot
identify one another, because shard exchange runs over I2P and peers only ever
see a .b32.i2p destination. This records what the heartbeat -- a plain HTTPS
POST -- already reveals to the site operator's web logs.

Revision ID: c8f3d92a4e15
Revises: e6b2c41d8a70
"""
from alembic import op
import sqlalchemy as sa

revision = "c8f3d92a4e15"
down_revision = "e6b2c41d8a70"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("storage_node", sa.Column("last_ip", sa.String(length=64), nullable=True))
    op.add_column("storage_node", sa.Column("country_code", sa.String(length=2), nullable=True))
    op.add_column("storage_node", sa.Column("latitude", sa.Float(), nullable=True))
    op.add_column("storage_node", sa.Column("longitude", sa.Float(), nullable=True))


def downgrade():
    op.drop_column("storage_node", "longitude")
    op.drop_column("storage_node", "latitude")
    op.drop_column("storage_node", "country_code")
    op.drop_column("storage_node", "last_ip")
