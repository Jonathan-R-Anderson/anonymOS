"""Credit store: items and orders.

Revision ID: a7b8c9d0e1f2
"""

from alembic import op
import sqlalchemy as sa


revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "store_item",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=140), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        # Cents, not floats: float money is how a price becomes 9.99000001.
        sa.Column("price_usd_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stock", sa.Integer(), nullable=True),
        sa.Column("image_media_id", sa.Integer(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "store_order",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("item_id", sa.Integer(), sa.ForeignKey("store_item.id"), nullable=False),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=True),
        sa.Column("buyer_wallet", sa.String(length=42), nullable=False, server_default=""),
        sa.Column("price_credits", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("price_usd_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        # Unique: one transaction must not be able to pay for two orders.
        sa.Column("tx_hash", sa.String(length=80), nullable=True, unique=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("paid_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_store_order_item", "store_order", ["item_id"])
    op.create_index("ix_store_order_slip", "store_order", ["slip_id"])
    op.create_index("ix_store_order_status", "store_order", ["status"])


def downgrade():
    op.drop_index("ix_store_order_status", table_name="store_order")
    op.drop_index("ix_store_order_slip", table_name="store_order")
    op.drop_index("ix_store_order_item", table_name="store_order")
    op.drop_table("store_order")
    op.drop_table("store_item")
