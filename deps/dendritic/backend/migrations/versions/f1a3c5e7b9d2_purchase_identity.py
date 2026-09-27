"""The two hashes Treasury.releaseOrder takes, stored per purchase.

order_id is keccak256 of the Stripe session id; origin_hash is
keccak256(pepper || buyer ip). Both are hex strings with the 0x prefix, so 66
characters — stored as text rather than binary because every consumer (the
admin console, an eth_getLogs topic, a block explorer link) wants the hex form
and converting in three places to store it in one is the wrong trade.

Both are indexed: looking a purchase up BY its on-chain identifier is the whole
reason they exist — somebody has a topic from a log and needs the row.

Nullable, and older rows stay null. Backfilling is not possible for either:
the session id can be re-hashed, but the buyer's IP was never recorded before
this, and inventing one would be worse than an honest absence.

Revision ID: f1a3c5e7b9d2
Revises: e9c1f4a7b2d6
"""

import sqlalchemy as sa
from alembic import op

revision = "f1a3c5e7b9d2"
down_revision = "e9c1f4a7b2d6"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("credit_purchase", sa.Column("order_id", sa.String(length=66), nullable=True))
    op.add_column("credit_purchase", sa.Column("origin_hash", sa.String(length=66), nullable=True))
    op.create_index("ix_credit_purchase_order_id", "credit_purchase", ["order_id"])
    op.create_index("ix_credit_purchase_origin_hash", "credit_purchase", ["origin_hash"])


def downgrade():
    op.drop_index("ix_credit_purchase_origin_hash", table_name="credit_purchase")
    op.drop_index("ix_credit_purchase_order_id", table_name="credit_purchase")
    op.drop_column("credit_purchase", "origin_hash")
    op.drop_column("credit_purchase", "order_id")
