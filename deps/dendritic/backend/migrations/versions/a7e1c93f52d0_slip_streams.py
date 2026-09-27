"""Per-slip RTMP stream keys

Adds the ``stream`` table backing per-slip live streaming: each slip owns at
most one stream, identified by an Ethereum-address-shaped account token and a
rotatable secret. Together they form the RTMP stream key the ported RTMP
server (rtmp/) authenticates publishes with.

Revision ID: a7e1c93f52d0
Revises: f3d82c47a911
Create Date: 2026-07-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "a7e1c93f52d0"
down_revision = "f3d82c47a911"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "stream",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slip_id", sa.Integer(), nullable=False),
        sa.Column("stream_account", sa.String(length=64), nullable=False),
        sa.Column("stream_secret", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=120), nullable=True),
        sa.Column("is_live", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_client_ip", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["slip_id"], ["slip.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slip_id", name="uq_stream_slip"),
        sa.UniqueConstraint("stream_account", name="uq_stream_account"),
    )


def downgrade():
    op.drop_table("stream")
