"""Torrent-hosted /videos feature tables

Adds the ``video`` table (uploader metadata pointing at a reused Media row that
already carries the torrent info-hash and thumbnail) and the ``video_comment``
table backing YouTube-style threaded comments. Both are guarded with has_table
so a database created by db.create_all() is not double-created.

Revision ID: f5d9c3b1a2e7
Revises: e4c8b2a1f7d3
Create Date: 2026-07-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = "f5d9c3b1a2e7"
down_revision = "e4c8b2a1f7d3"
branch_labels = None
depends_on = None


def upgrade():
    inspector = inspect(op.get_bind())

    if not inspector.has_table("video"):
        op.create_table(
            "video",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("slip_id", sa.Integer(), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("tags", sa.String(length=500), nullable=True),
            sa.Column("media_id", sa.Integer(), nullable=False),
            sa.Column("views", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("offloaded", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("keywords", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["slip_id"], ["slip.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["media_id"], ["media.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_video_title", "video", ["title"], unique=False)
        op.create_index("ix_video_created_at", "video", ["created_at"], unique=False)

    if not inspector.has_table("video_comment"):
        op.create_table(
            "video_comment",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("video_id", sa.Integer(), nullable=False),
            sa.Column("parent_id", sa.Integer(), nullable=True),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("author_name", sa.String(length=80), nullable=True),
            sa.Column("tripcode", sa.String(length=120), nullable=True),
            sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["video_id"], ["video.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["parent_id"], ["video_comment.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["slip_id"], ["slip.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_video_comment_video_id", "video_comment", ["video_id"], unique=False
        )
        op.create_index(
            "ix_video_comment_created_at", "video_comment", ["created_at"], unique=False
        )


def downgrade():
    inspector = inspect(op.get_bind())

    if inspector.has_table("video_comment"):
        existing_indexes = {index["name"] for index in inspector.get_indexes("video_comment")}
        if "ix_video_comment_created_at" in existing_indexes:
            op.drop_index("ix_video_comment_created_at", table_name="video_comment")
        if "ix_video_comment_video_id" in existing_indexes:
            op.drop_index("ix_video_comment_video_id", table_name="video_comment")
        op.drop_table("video_comment")

    if inspector.has_table("video"):
        existing_indexes = {index["name"] for index in inspector.get_indexes("video")}
        if "ix_video_created_at" in existing_indexes:
            op.drop_index("ix_video_created_at", table_name="video")
        if "ix_video_title" in existing_indexes:
            op.drop_index("ix_video_title", table_name="video")
        op.drop_table("video")
