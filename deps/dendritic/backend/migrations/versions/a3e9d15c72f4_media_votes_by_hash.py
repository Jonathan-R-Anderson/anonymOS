"""media votes keyed by content hash

Votes on a video follow the FILE, not the media row, so a repost arrives
carrying whatever the site already decided about it. See model/MediaVote.py for
why there is deliberately no FK to media.id.

Revision ID: a3e9d15c72f4
Revises: f2c7a9e14b63
"""
from alembic import op
import sqlalchemy as sa


revision = "a3e9d15c72f4"
down_revision = "f2c7a9e14b63"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "media_vote",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("media_hash", sa.String(length=64), nullable=False),
        sa.Column("slip_id", sa.Integer(), nullable=False),
        sa.Column("value", sa.SmallInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["slip_id"], ["slip.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("media_hash", "slip_id", name="uq_media_vote_hash_slip"),
    )
    op.create_index("ix_media_vote_media_hash", "media_vote", ["media_hash"])
    op.create_index("ix_media_vote_slip_id", "media_vote", ["slip_id"])


def downgrade():
    op.drop_index("ix_media_vote_slip_id", table_name="media_vote")
    op.drop_index("ix_media_vote_media_hash", table_name="media_vote")
    op.drop_table("media_vote")
