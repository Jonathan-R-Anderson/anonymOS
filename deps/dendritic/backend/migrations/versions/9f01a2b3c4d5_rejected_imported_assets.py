"""Store source-scoped AI refusals without creating media hash bans.

Revision ID: 9f01a2b3c4d5
"""

from alembic import op
import sqlalchemy as sa


revision = "9f01a2b3c4d5"
down_revision = "8e9f01a2b3c4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "rejected_imported_asset",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_type", sa.String(length=128), nullable=False),
        sa.Column("locator", sa.String(length=2048), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "source_type", "locator", name="uq_rejected_imported_asset_source"
        ),
    )


def downgrade():
    op.drop_table("rejected_imported_asset")
