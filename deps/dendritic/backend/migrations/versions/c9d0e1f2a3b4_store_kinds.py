"""Digital vs physical store items, and shipping details on orders.

Revision ID: c9d0e1f2a3b4
"""

from alembic import op
import sqlalchemy as sa


revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade():
    # Existing items default to digital: nothing listed so far ships, and
    # defaulting to physical would silently start demanding addresses for them.
    op.add_column("store_item", sa.Column(
        "kind", sa.String(length=16), nullable=False, server_default="digital"))
    op.add_column("store_item", sa.Column(
        "fulfilment_note", sa.Text(), nullable=False, server_default=""))
    op.add_column("store_order", sa.Column(
        "ship_to", sa.Text(), nullable=False, server_default=""))
    op.add_column("store_order", sa.Column("shipped_at", sa.DateTime(), nullable=True))
    op.add_column("store_order", sa.Column("tracking", sa.String(length=140), nullable=True))


def downgrade():
    op.drop_column("store_order", "tracking")
    op.drop_column("store_order", "shipped_at")
    op.drop_column("store_order", "ship_to")
    op.drop_column("store_item", "fulfilment_note")
    op.drop_column("store_item", "kind")
