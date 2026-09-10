"""Add blocked media hash tracking

Revision ID: 8f2c1a6d4b77
Revises: 7a1c2f8b4d9e
Create Date: 2026-04-22 18:40:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "8f2c1a6d4b77"
down_revision = "7a1c2f8b4d9e"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("media", sa.Column("sha256", sa.String(length=64), nullable=True))
    op.create_index("ix_media_sha256", "media", ["sha256"], unique=False)

    op.create_table(
        "blocked_media_hash",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("source_url", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by_slip_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_slip_id"], ["slip.id"]),
        sa.PrimaryKeyConstraint("sha256"),
    )


def downgrade():
    op.drop_table("blocked_media_hash")
    op.drop_index("ix_media_sha256", table_name="media")
    op.drop_column("media", "sha256")
