"""Which school chapters a slip has read.

The unique constraint is the feature: a double-click or a refreshed POST must
not add a second row, because the progress bar counts rows.

Slugs rather than foreign keys, because the curriculum lives in source rather
than in the database — there is no row to point at. A renamed chapter leaves an
orphan that reads as "not yet read", which is the harmless direction.

Revision ID: d7e9f2a4b6c8
Revises: c6d8e1f3a5b7
"""

import sqlalchemy as sa
from alembic import op

revision = "d7e9f2a4b6c8"
down_revision = "c6d8e1f3a5b7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "school_progress",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("subject_slug", sa.String(length=64), nullable=False),
        sa.Column("chapter_slug", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("slip_id", "subject_slug", "chapter_slug",
                            name="uq_school_progress_once"),
    )
    op.create_index("ix_school_progress_slip_id", "school_progress", ["slip_id"])
    op.create_index("ix_school_progress_subject_slug", "school_progress", ["subject_slug"])


def downgrade():
    op.drop_index("ix_school_progress_subject_slug", table_name="school_progress")
    op.drop_index("ix_school_progress_slip_id", table_name="school_progress")
    op.drop_table("school_progress")
