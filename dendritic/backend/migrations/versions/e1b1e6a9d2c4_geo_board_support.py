"""Add geo board metadata and display names

Revision ID: e1b1e6a9d2c4
Revises: 4b8075b31201
Create Date: 2026-04-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "e1b1e6a9d2c4"
down_revision = "4b8075b31201"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("board", schema=None) as batch_op:
        batch_op.add_column(sa.Column("display_name", sa.String(length=96), nullable=True))
        batch_op.add_column(sa.Column("board_type", sa.String(length=24), nullable=False, server_default="standard"))
        batch_op.add_column(sa.Column("geo_strategy", sa.String(length=24), nullable=True))
        batch_op.add_column(sa.Column("geo_parent_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("geo_key", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("geo_label", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("geo_latitude", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("geo_longitude", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("geo_radius_miles", sa.Integer(), nullable=True))
        batch_op.create_foreign_key("fk_board_geo_parent_id_board", "board", ["geo_parent_id"], ["id"])


def downgrade():
    with op.batch_alter_table("board", schema=None) as batch_op:
        batch_op.drop_constraint("fk_board_geo_parent_id_board", type_="foreignkey")
        batch_op.drop_column("geo_radius_miles")
        batch_op.drop_column("geo_longitude")
        batch_op.drop_column("geo_latitude")
        batch_op.drop_column("geo_label")
        batch_op.drop_column("geo_key")
        batch_op.drop_column("geo_parent_id")
        batch_op.drop_column("geo_strategy")
        batch_op.drop_column("board_type")
        batch_op.drop_column("display_name")
