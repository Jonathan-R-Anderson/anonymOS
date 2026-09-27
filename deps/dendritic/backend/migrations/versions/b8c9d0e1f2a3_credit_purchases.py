"""Credit pack purchases.

Revision ID: b8c9d0e1f2a3
"""

from alembic import op
import sqlalchemy as sa


revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "credit_purchase",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=True),
        sa.Column("wallet", sa.String(length=42), nullable=False, server_default=""),
        sa.Column("credits", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("amount_cents", sa.Integer(), nullable=False, server_default="0"),
        # Unique: Stripe retries webhooks by design, and a retry must not be
        # able to credit the same purchase twice.
        sa.Column("stripe_session_id", sa.String(length=120), nullable=True, unique=True),
        sa.Column("stripe_payment_intent", sa.String(length=120), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("delivery_tx", sa.String(length=80), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("paid_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_credit_purchase_slip", "credit_purchase", ["slip_id"])
    op.create_index("ix_credit_purchase_status", "credit_purchase", ["status"])
    op.create_index("ix_credit_purchase_session", "credit_purchase", ["stripe_session_id"])


def downgrade():
    op.drop_index("ix_credit_purchase_session", table_name="credit_purchase")
    op.drop_index("ix_credit_purchase_status", table_name="credit_purchase")
    op.drop_index("ix_credit_purchase_slip", table_name="credit_purchase")
    op.drop_table("credit_purchase")
