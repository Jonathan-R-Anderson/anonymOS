"""Card payments for store orders.

The store took the token only, and cards bought the token itself — which is the
wrong way round. A card paying for a physical or digital good is an ordinary
sale; a card buying a first-party token is a token sale, which Stripe lists
under prohibited businesses and which pairs a reversible payment with an
irreversible transfer.

So an order now records which rail paid for it. `tx_hash` was not reused for the
Stripe session: it is unique, and a column that sometimes holds a chain
transaction and sometimes a Checkout session is a column nobody can query.

Revision ID: d4e6f8a0b2c1
Revises: c1a5f70b3d29
"""

import sqlalchemy as sa
from alembic import op

revision = "d4e6f8a0b2c1"
down_revision = "c1a5f70b3d29"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("store_order", sa.Column("stripe_session_id", sa.String(length=120), nullable=True))
    op.create_index("ix_store_order_stripe_session_id", "store_order", ["stripe_session_id"], unique=True)
    # Existing orders were all paid on-chain; naming that explicitly beats
    # leaving them null and making every reader guess what an absent rail means.
    op.add_column("store_order", sa.Column("paid_with", sa.String(length=16), nullable=False,
                                           server_default="credits"))


def downgrade():
    op.drop_column("store_order", "paid_with")
    op.drop_index("ix_store_order_stripe_session_id", table_name="store_order")
    op.drop_column("store_order", "stripe_session_id")
