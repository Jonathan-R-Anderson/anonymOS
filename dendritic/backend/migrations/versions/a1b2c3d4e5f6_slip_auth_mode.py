"""Per-slip login policy: password, MetaMask wallet, or either.

Existing rows get "password" so nobody's sign-in changes underneath them —
several accounts already have a wallet linked for other reasons, and that must
not silently become a second way into the account.

Revision ID: a1b2c3d4e5f6
"""

from alembic import op
import sqlalchemy as sa


revision = "a1b2c3d4e5f6"
down_revision = "9f01a2b3c4d5"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "slip",
        sa.Column(
            "auth_mode",
            sa.String(length=16),
            nullable=False,
            server_default="password",
        ),
    )


def downgrade():
    op.drop_column("slip", "auth_mode")
