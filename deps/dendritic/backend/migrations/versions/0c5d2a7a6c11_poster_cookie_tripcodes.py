"""Add cookie-backed poster identity and tripcodes

Revision ID: 0c5d2a7a6c11
Revises: e1b1e6a9d2c4
Create Date: 2026-04-22 00:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0c5d2a7a6c11"
down_revision = "e1b1e6a9d2c4"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("poster", schema=None) as batch_op:
        batch_op.alter_column("hex_string", existing_type=sa.String(length=4), type_=sa.String(length=16), nullable=False)
        batch_op.add_column(sa.Column("cookie_token", sa.String(length=64), nullable=True))
        batch_op.create_index("ix_poster_thread_cookie_token", ["thread", "cookie_token"], unique=False)

    with op.batch_alter_table("post", schema=None) as batch_op:
        batch_op.add_column(sa.Column("tripcode", sa.String(length=16), nullable=True))


def downgrade():
    with op.batch_alter_table("post", schema=None) as batch_op:
        batch_op.drop_column("tripcode")

    with op.batch_alter_table("poster", schema=None) as batch_op:
        batch_op.drop_index("ix_poster_thread_cookie_token")
        batch_op.drop_column("cookie_token")
        batch_op.alter_column("hex_string", existing_type=sa.String(length=16), type_=sa.String(length=4), nullable=False)
