"""Persistent news archive.

Revision ID: f026b03e6006
Revises: ef15a92d5005
Create Date: 2026-07-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "f026b03e6006"
down_revision = "ef15a92d5005"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("news_story"):
        return
    columns = {column["name"] for column in inspector.get_columns("news_story")}
    if "fingerprint" not in columns:
        op.add_column("news_story", sa.Column("fingerprint", sa.String(64), nullable=True))
    indexes = {index["name"] for index in inspect(bind).get_indexes("news_story")}
    if "ix_news_story_fingerprint" not in indexes:
        op.create_index("ix_news_story_fingerprint", "news_story", ["fingerprint"], unique=True)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("news_story"):
        return
    indexes = {index["name"] for index in inspector.get_indexes("news_story")}
    if "ix_news_story_fingerprint" in indexes:
        op.drop_index("ix_news_story_fingerprint", table_name="news_story")
    columns = {column["name"] for column in inspect(bind).get_columns("news_story")}
    if "fingerprint" in columns:
        op.drop_column("news_story", "fingerprint")
