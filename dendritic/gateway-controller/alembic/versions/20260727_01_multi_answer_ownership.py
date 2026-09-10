"""preserve DNS ownership while enabling multiple address answers

Revision ID: 20260727_01
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "20260727_01"
down_revision = None
branch_labels = None
depends_on = None


def _primary_key(inspector):
    return inspector.get_pk_constraint("managed_dns_records").get("name")


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("managed_dns_records")}
    if "record_type" in columns:
        return
    op.add_column(
        "managed_dns_records",
        sa.Column("record_type", sa.String(length=5), nullable=False, server_default="A"),
    )
    primary_key = _primary_key(sa.inspect(bind))
    if primary_key:
        op.drop_constraint(primary_key, "managed_dns_records", type_="primary")
    op.create_primary_key(
        "pk_managed_dns_records",
        "managed_dns_records",
        ["hostname", "record_type", "answer"],
    )
    op.alter_column("managed_dns_records", "record_type", server_default=None)


def downgrade():
    bind = op.get_bind()
    duplicate = bind.execute(
        sa.text(
            "SELECT hostname FROM managed_dns_records "
            "GROUP BY hostname HAVING count(*) > 1 LIMIT 1"
        )
    ).first()
    if duplicate:
        raise RuntimeError(
            "cannot downgrade multi-answer ownership while a hostname has multiple records"
        )
    primary_key = _primary_key(sa.inspect(bind))
    if primary_key:
        op.drop_constraint(primary_key, "managed_dns_records", type_="primary")
    op.drop_column("managed_dns_records", "record_type")
    op.create_primary_key(
        "pk_managed_dns_records", "managed_dns_records", ["hostname"]
    )
