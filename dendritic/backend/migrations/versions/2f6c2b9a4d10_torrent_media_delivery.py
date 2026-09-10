"""Add torrent media metadata and slip delivery preference

Revision ID: 2f6c2b9a4d10
Revises: 1d2e3f4a5b6c
Create Date: 2026-04-23 22:45:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "2f6c2b9a4d10"
down_revision = "1d2e3f4a5b6c"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("media", schema=None) as batch_op:
        batch_op.add_column(sa.Column("torrent_info_hash", sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column("torrent_piece_length", sa.Integer(), nullable=True))
        batch_op.create_index("ix_media_torrent_info_hash", ["torrent_info_hash"], unique=False)

    with op.batch_alter_table("slip", schema=None) as batch_op:
        batch_op.add_column(sa.Column("media_delivery_mode", sa.String(length=16), nullable=True))

    op.execute("UPDATE slip SET media_delivery_mode = 'torrent' WHERE media_delivery_mode IS NULL")

    with op.batch_alter_table("slip", schema=None) as batch_op:
        batch_op.alter_column("media_delivery_mode", existing_type=sa.String(length=16), nullable=False)


def downgrade():
    with op.batch_alter_table("slip", schema=None) as batch_op:
        batch_op.drop_column("media_delivery_mode")

    with op.batch_alter_table("media", schema=None) as batch_op:
        batch_op.drop_index("ix_media_torrent_info_hash")
        batch_op.drop_column("torrent_piece_length")
        batch_op.drop_column("torrent_info_hash")
