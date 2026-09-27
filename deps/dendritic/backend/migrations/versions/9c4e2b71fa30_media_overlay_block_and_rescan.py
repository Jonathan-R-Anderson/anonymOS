"""media overlay_blocked + rescanned_at

Revision ID: 9c4e2b71fa30
Revises: 3a8f21d4c6b0
Create Date: 2026-07-26

overlay_blocked -- serve an operator-uploaded overlay image instead of the real
bytes to viewers who are not signed into a slip account. NOT NULL with a server
default so the column is populated for the existing rows without a table rewrite
of the NULLs.

rescanned_at -- when the random re-scan sweep last re-checked this file against
the NSFW classifier and ClamAV. Nullable: NULL means "never re-scanned", which is
exactly the set the sweep prioritises, so it must be distinguishable from a real
timestamp. Indexed because the sweep orders by it on every pass.
"""
from alembic import op
import sqlalchemy as sa


revision = "9c4e2b71fa30"
down_revision = "3a8f21d4c6b0"
branch_labels = None
depends_on = None


def _has_column(table, column):
    """Idempotent guard.

    This deployment applies migrations on every container start, and a column may
    already exist if the model was deployed before its migration. Checking is
    cheaper than a failed upgrade that halts startup.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return column in {col["name"] for col in inspector.get_columns(table)}


def upgrade():
    if not _has_column("media", "overlay_blocked"):
        op.add_column(
            "media",
            sa.Column(
                "overlay_blocked",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )
    if not _has_column("media", "rescanned_at"):
        op.add_column("media", sa.Column("rescanned_at", sa.DateTime(), nullable=True))
        op.create_index("ix_media_rescanned_at", "media", ["rescanned_at"])


def downgrade():
    if _has_column("media", "rescanned_at"):
        try:
            op.drop_index("ix_media_rescanned_at", table_name="media")
        except Exception:
            pass
        op.drop_column("media", "rescanned_at")
    if _has_column("media", "overlay_blocked"):
        op.drop_column("media", "overlay_blocked")
