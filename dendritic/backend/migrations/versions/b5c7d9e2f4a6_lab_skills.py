"""Lab skill gauging: question tiers, attempt log, per-box skills, ratings.

The attempt log is the substantive part. LabSolve already records that somebody
got there; without the failures and the timing, every solve looks equally clean
and a skill chart built on solves alone measures persistence and calls it
ability.

lab_question.tier and lab_challenge.skills both default to empty, so the ~330
imported challenges keep working and simply contribute to nobody's chart until
somebody labels them. Guessing a box's skills from its Dockerfile would put
confident wrong labels on all of them at once.

Revision ID: b5c7d9e2f4a6
Revises: a4b6c8d1e3f5
"""

import sqlalchemy as sa
from alembic import op

revision = "b5c7d9e2f4a6"
down_revision = "a4b6c8d1e3f5"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("lab_question",
                  sa.Column("tier", sa.String(length=8), nullable=False, server_default=""))
    op.add_column("lab_challenge",
                  sa.Column("skills", sa.String(length=200), nullable=False, server_default=""))

    op.create_table(
        "lab_attempt",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("challenge_id", sa.Integer(), nullable=False),
        sa.Column("question_id", sa.Integer(),
                  sa.ForeignKey("lab_question.id", ondelete="CASCADE"), nullable=False),
        sa.Column("was_correct", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("minutes_elapsed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_lab_attempt_slip_id", "lab_attempt", ["slip_id"])
    op.create_index("ix_lab_attempt_challenge_id", "lab_attempt", ["challenge_id"])
    op.create_index("ix_lab_attempt_question_id", "lab_attempt", ["question_id"])

    op.create_table(
        "lab_rating",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("challenge_id", sa.Integer(),
                  sa.ForeignKey("lab_challenge.id", ondelete="CASCADE"), nullable=False),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("quality", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("difficulty", sa.String(length=12), nullable=False, server_default=""),
        sa.Column("comment", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("challenge_id", "slip_id", name="uq_lab_rating_once"),
    )
    op.create_index("ix_lab_rating_challenge_id", "lab_rating", ["challenge_id"])
    op.create_index("ix_lab_rating_slip_id", "lab_rating", ["slip_id"])


def downgrade():
    op.drop_table("lab_rating")
    op.drop_index("ix_lab_attempt_question_id", table_name="lab_attempt")
    op.drop_index("ix_lab_attempt_challenge_id", table_name="lab_attempt")
    op.drop_index("ix_lab_attempt_slip_id", table_name="lab_attempt")
    op.drop_table("lab_attempt")
    op.drop_column("lab_challenge", "skills")
    op.drop_column("lab_question", "tier")
