"""add short-lived deterministic gateway hostname reservations

Revision ID: 20260727_02
Revises: 20260727_01
"""
from alembic import op
import sqlalchemy as sa

revision = "20260727_02"
down_revision = "20260727_01"
branch_labels = None
depends_on = None


def upgrade():
    # create_all runs before Alembic in this service, so a new installation
    # may already have the table when this migration is stamped.
    bind = op.get_bind()
    if "gateway_hostname_reservations" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "gateway_hostname_reservations",
        sa.Column("node_id", sa.String(length=128), primary_key=True),
        sa.Column("public_ip", sa.String(length=45), nullable=False),
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_gateway_hostname_reservations_public_ip",
        "gateway_hostname_reservations",
        ["public_ip"],
    )
    op.create_index(
        "ix_gateway_hostname_reservations_hostname",
        "gateway_hostname_reservations",
        ["hostname"],
        unique=True,
    )
    op.create_index(
        "ix_gateway_hostname_reservations_expires_at",
        "gateway_hostname_reservations",
        ["expires_at"],
    )


def downgrade():
    op.drop_table("gateway_hostname_reservations")
