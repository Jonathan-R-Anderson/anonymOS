"""Board sources become per-thread URL submissions

Whole-board / whole-subreddit aggregation is removed. A board source now
identifies one externally hosted thread whose direct URL was submitted in
the board admin form, so ``board_source`` gains a ``source_thread_id``
column. Legacy whole-board source rows have no thread id and are dropped -
threads already imported from them remain until their board prunes them.

Revision ID: f3d82c47a911
Revises: 8c1b7e2a4d55
Create Date: 2026-07-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "f3d82c47a911"
down_revision = "8c1b7e2a4d55"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("DELETE FROM board_source")
    with op.batch_alter_table("board_source", schema=None) as batch_op:
        batch_op.add_column(sa.Column("source_thread_id", sa.String(length=128), nullable=False))
        batch_op.drop_constraint("uq_board_source", type_="unique")
        batch_op.create_unique_constraint(
            "uq_board_source",
            ["board_id", "source_type", "source_name", "source_thread_id"],
        )


def downgrade():
    with op.batch_alter_table("board_source", schema=None) as batch_op:
        batch_op.drop_constraint("uq_board_source", type_="unique")
        batch_op.drop_column("source_thread_id")
        batch_op.create_unique_constraint(
            "uq_board_source",
            ["board_id", "source_type", "source_name"],
        )
