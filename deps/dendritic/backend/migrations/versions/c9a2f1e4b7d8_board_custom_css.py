"""Add board.custom_css

Lets a board owner apply custom CSS to their board's catalog page.

Revision ID: c9a2f1e4b7d8
Revises: b8f4a1c72e93
Create Date: 2026-07-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "c9a2f1e4b7d8"
down_revision = "b8f4a1c72e93"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("board", schema=None) as batch_op:
        batch_op.add_column(sa.Column("custom_css", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("board", schema=None) as batch_op:
        batch_op.drop_column("custom_css")
