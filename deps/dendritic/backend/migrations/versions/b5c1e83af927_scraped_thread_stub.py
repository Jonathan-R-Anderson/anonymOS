"""scraped thread identity stubs for age-bounded retention

What survives when an out-of-window scraped thread's content is purged: the
source triple and a few counters, so a thread that comes back is recognised
instead of re-imported from scratch. See services/scraped_retention.py.

Revision ID: b5c1e83af927
Revises: a3e9d15c72f4
"""
from alembic import op
import sqlalchemy as sa


revision = "b5c1e83af927"
down_revision = "a3e9d15c72f4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scraped_thread_stub",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_type", sa.String(length=128), nullable=False),
        sa.Column("source_name", sa.String(length=64), nullable=True),
        sa.Column("source_thread_id", sa.String(length=128), nullable=False),
        sa.Column("board_id", sa.Integer(), nullable=True),
        sa.Column("last_post_at", sa.DateTime(), nullable=True),
        sa.Column("purged_at", sa.DateTime(), nullable=False),
        sa.Column("post_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("media_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reason", sa.String(length=64), nullable=False, server_default="out_of_window"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_type", "source_name", "source_thread_id",
            name="uq_scraped_stub_source",
        ),
    )
    op.create_index("ix_scraped_thread_stub_last_post_at", "scraped_thread_stub", ["last_post_at"])
    op.create_index("ix_scraped_stub_purged_at", "scraped_thread_stub", ["purged_at"])


def downgrade():
    op.drop_index("ix_scraped_stub_purged_at", table_name="scraped_thread_stub")
    op.drop_index("ix_scraped_thread_stub_last_post_at", table_name="scraped_thread_stub")
    op.drop_table("scraped_thread_stub")
