"""Add non-enumerable public hashes for threads and videos.

Revision ID: 8e9f01a2b3c4
"""

import hashlib
import secrets

from alembic import op
import sqlalchemy as sa


revision = "8e9f01a2b3c4"
down_revision = "7d8e9f01a2b3"
branch_labels = None
depends_on = None


def _backfill(table):
    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id FROM %s WHERE public_id IS NULL" % table))
    for (row_id,) in rows:
        value = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        connection.execute(
            sa.text("UPDATE %s SET public_id = :value WHERE id = :id" % table),
            {"value": value, "id": row_id},
        )


def upgrade():
    for table in ("thread", "video"):
        op.add_column(table, sa.Column("public_id", sa.String(length=64), nullable=True))
        _backfill(table)
        op.alter_column(table, "public_id", nullable=False)
        op.create_index("ix_%s_public_id" % table, table, ["public_id"], unique=True)


def downgrade():
    for table in ("video", "thread"):
        op.drop_index("ix_%s_public_id" % table, table_name=table)
        op.drop_column(table, "public_id")
