"""Add imported media cache mappings

Revision ID: 8c1b7e2a4d55
Revises: 5a2b1e9c4f33
Create Date: 2026-04-25 19:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "8c1b7e2a4d55"
down_revision = "5a2b1e9c4f33"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "imported_media",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("thread_id", sa.Integer(), nullable=False),
        sa.Column("source_post_id", sa.String(length=128), nullable=False),
        sa.Column("media_id", sa.Integer(), nullable=False),
        sa.Column("image_path", sa.String(), nullable=True),
        sa.Column("external_media_url", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["media_id"], ["media.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["thread_id"], ["thread.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("media_id"),
        sa.UniqueConstraint("thread_id", "source_post_id", name="uq_imported_media_thread_source_post"),
    )
    op.create_index("ix_imported_media_thread_id", "imported_media", ["thread_id"], unique=False)


def downgrade():
    op.drop_index("ix_imported_media_thread_id", table_name="imported_media")
    op.drop_table("imported_media")
