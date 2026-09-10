"""ML competitions, datasets and scored submissions.

Both blobs are deferred columns on the model, so listing pages never load them —
which is the only reason it is reasonable to keep files in the primary database
at all. Sizes are capped in model/MlContest.py rather than by the database:
Postgres will happily accept a 2 GB bytea and the failure would arrive as an
outage rather than as a validation message.

Revision ID: c6d8e1f3a5b7
Revises: b5c7d9e2f4a6
"""

import sqlalchemy as sa
from alembic import op

revision = "c6d8e1f3a5b7"
down_revision = "b5c7d9e2f4a6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ml_dataset",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("licence", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("filename", sa.String(length=160), nullable=False, server_default="data.csv"),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rows", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("columns", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("downloads", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blob", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("slug", name="uq_ml_dataset_slug"),
    )
    op.create_index("ix_ml_dataset_slip_id", "ml_dataset", ["slip_id"])

    op.create_table(
        "ml_competition",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("metric", sa.String(length=16), nullable=False, server_default="accuracy"),
        sa.Column("dataset_id", sa.Integer(), sa.ForeignKey("ml_dataset.id"), nullable=True),
        sa.Column("answer_key", sa.LargeBinary(), nullable=False),
        sa.Column("id_column", sa.String(length=64), nullable=False, server_default="id"),
        sa.Column("target_column", sa.String(length=64), nullable=False, server_default="target"),
        sa.Column("key_rows", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("closes_at", sa.DateTime(), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("slug", name="uq_ml_competition_slug"),
    )
    op.create_index("ix_ml_competition_host_slip_id", "ml_competition", ["host_slip_id"])

    op.create_table(
        "ml_submission",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("competition_id", sa.Integer(),
                  sa.ForeignKey("ml_competition.id", ondelete="CASCADE"), nullable=False),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("public_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("private_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("rows_scored", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("note", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_ml_submission_competition_id", "ml_submission", ["competition_id"])
    op.create_index("ix_ml_submission_slip_id", "ml_submission", ["slip_id"])


def downgrade():
    op.drop_table("ml_submission")
    op.drop_index("ix_ml_competition_host_slip_id", table_name="ml_competition")
    op.drop_table("ml_competition")
    op.drop_index("ix_ml_dataset_slip_id", table_name="ml_dataset")
    op.drop_table("ml_dataset")
