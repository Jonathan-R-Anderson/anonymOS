"""Add news article and synthesized story tables

Revision ID: 4b8075b31201
Revises: c4a9dd8d6b11
Create Date: 2026-04-18 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "4b8075b31201"
down_revision = "c4a9dd8d6b11"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "news_article",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.Column("keyword", sa.String(length=255), nullable=True),
        sa.Column("author", sa.String(length=255), nullable=True),
        sa.Column("image_url", sa.String(), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("inserted_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("url"),
    )

    op.create_table(
        "news_story",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("analysis", sa.Text(), nullable=False),
        sa.Column("keywords", sa.String(length=512), nullable=True),
        sa.Column("primary_url", sa.String(), nullable=True),
        sa.Column("primary_source", sa.String(length=255), nullable=True),
        sa.Column("image_url", sa.String(), nullable=True),
        sa.Column("article_count", sa.Integer(), nullable=False),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "news_story_article",
        sa.Column("story_id", sa.Integer(), nullable=False),
        sa.Column("article_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["article_id"], ["news_article.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["story_id"], ["news_story.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("story_id", "article_id"),
    )


def downgrade():
    op.drop_table("news_story_article")
    op.drop_table("news_story")
    op.drop_table("news_article")
