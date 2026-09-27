"""Add profile.embed_stream toggle

Lets a slip opt into embedding their live stream player on their customizable
profile page.

Revision ID: b8f4a1c72e93
Revises: a7e1c93f52d0
Create Date: 2026-07-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b8f4a1c72e93"
down_revision = "a7e1c93f52d0"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("profile", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("embed_stream", sa.Boolean(), nullable=False, server_default="0")
        )


def downgrade():
    with op.batch_alter_table("profile", schema=None) as batch_op:
        batch_op.drop_column("embed_stream")
