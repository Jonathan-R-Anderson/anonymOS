"""Add per-word sentiment learning table

Creates the word_sentiment table that stores a learned sentiment score per
non-stem content word seen in real post text. LM-lexicon words are anchors
(source='lm', fixed score); other words start neutral and converge toward the
average sentiment of the contexts they appear in. The table only holds data, so
this migration just creates it (guarded); it is seeded/filled at runtime.

Revision ID: e4c8b2a1f7d3
Revises: d3f7a1b9c2e5
Create Date: 2026-07-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = "e4c8b2a1f7d3"
down_revision = "d3f7a1b9c2e5"
branch_labels = None
depends_on = None


def upgrade():
    inspector = inspect(op.get_bind())

    if not inspector.has_table("word_sentiment"):
        op.create_table(
            "word_sentiment",
            sa.Column("word", sa.String(length=128), nullable=False),
            sa.Column("stem", sa.String(length=128), nullable=True),
            sa.Column("score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("magnitude", sa.Float(), nullable=False, server_default="0"),
            sa.Column("categories", sa.Text(), nullable=True),
            sa.Column("source", sa.String(length=16), nullable=False, server_default="learned"),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("word"),
        )
        op.create_index("ix_word_sentiment_stem", "word_sentiment", ["stem"], unique=False)


def downgrade():
    inspector = inspect(op.get_bind())

    if inspector.has_table("word_sentiment"):
        existing_indexes = {index["name"] for index in inspector.get_indexes("word_sentiment")}
        if "ix_word_sentiment_stem" in existing_indexes:
            op.drop_index("ix_word_sentiment_stem", table_name="word_sentiment")
        op.drop_table("word_sentiment")
