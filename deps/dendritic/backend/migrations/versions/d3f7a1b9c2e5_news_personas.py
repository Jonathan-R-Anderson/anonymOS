"""Add news writer personas and story bylines

Creates the news_persona table (derived satirical writer personalities) and adds
byline + persona_id columns to news_story so each synthesized story records the
persona that wrote it.

Revision ID: d3f7a1b9c2e5
Revises: c9a2f1e4b7d8
Create Date: 2026-07-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = "d3f7a1b9c2e5"
down_revision = "c9a2f1e4b7d8"
branch_labels = None
depends_on = None


def _has_column(inspector, table_name, column_name):
    return column_name in {column["name"] for column in inspector.get_columns(table_name)}


def upgrade():
    inspector = inspect(op.get_bind())

    if not inspector.has_table("news_persona"):
        op.create_table(
            "news_persona",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=120), nullable=False),
            sa.Column("voice", sa.Text(), nullable=False),
            sa.Column("seed_source", sa.String(length=512), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )

    if inspector.has_table("news_story"):
        with op.batch_alter_table("news_story", schema=None) as batch_op:
            if not _has_column(inspector, "news_story", "byline"):
                batch_op.add_column(sa.Column("byline", sa.String(length=120), nullable=True))
            if not _has_column(inspector, "news_story", "persona_id"):
                batch_op.add_column(sa.Column("persona_id", sa.Integer(), nullable=True))
                batch_op.create_foreign_key(
                    "fk_news_story_persona_id_news_persona",
                    "news_persona",
                    ["persona_id"],
                    ["id"],
                    ondelete="SET NULL",
                )


def downgrade():
    inspector = inspect(op.get_bind())

    if inspector.has_table("news_story"):
        with op.batch_alter_table("news_story", schema=None) as batch_op:
            if _has_column(inspector, "news_story", "persona_id"):
                batch_op.drop_constraint("fk_news_story_persona_id_news_persona", type_="foreignkey")
                batch_op.drop_column("persona_id")
            if _has_column(inspector, "news_story", "byline"):
                batch_op.drop_column("byline")

    if inspector.has_table("news_persona"):
        op.drop_table("news_persona")
