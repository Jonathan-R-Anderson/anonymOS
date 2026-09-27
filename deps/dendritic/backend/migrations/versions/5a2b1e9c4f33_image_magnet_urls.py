"""Add stored image magnet URLs

Revision ID: 5a2b1e9c4f33
Revises: 2f6c2b9a4d10
Create Date: 2026-04-23 23:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "5a2b1e9c4f33"
down_revision = "2f6c2b9a4d10"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "image_magnet",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("media_id", sa.Integer(), nullable=False),
        sa.Column("magnet_url", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["media_id"], ["media.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("media_id"),
    )


def downgrade():
    op.drop_table("image_magnet")
