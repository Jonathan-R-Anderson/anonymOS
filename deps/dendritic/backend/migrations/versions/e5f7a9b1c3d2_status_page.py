"""Status page: monitored components, node probes, daily rollups, incidents.

The probes come from monitor nodes rather than from this server, because a
status page served by the thing it monitors goes quiet at exactly the moment it
is needed. status_day is a rollup incremented as probes arrive, so the 90-day
bar never scans the raw table.

Revision ID: e5f7a9b1c3d2
Revises: d4e6f8a0b2c1
"""

import sqlalchemy as sa
from alembic import op

revision = "e5f7a9b1c3d2"
down_revision = "d4e6f8a0b2c1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "status_component",
        sa.Column("key", sa.String(length=48), primary_key=True),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("probe_url", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("timeout_ms", sa.Integer(), nullable=False, server_default="8000"),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "status_probe",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("component_key", sa.String(length=48), nullable=False),
        sa.Column("node_id", sa.String(length=128), nullable=False),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("detail", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_status_probe_component_key", "status_probe", ["component_key"])
    op.create_index("ix_status_probe_node_id", "status_probe", ["node_id"])
    op.create_index("ix_status_probe_country_code", "status_probe", ["country_code"])
    op.create_index("ix_status_probe_at", "status_probe", ["at"])
    # The two queries that run per page render: "recent probes for this
    # component" and "prune everything older than a week".
    op.create_index("ix_status_probe_component_at", "status_probe", ["component_key", "at"])

    op.create_table(
        "status_day",
        sa.Column("component_key", sa.String(length=48), primary_key=True),
        sa.Column("day", sa.Date(), primary_key=True),
        sa.Column("probes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latency_sum_ms", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("latency_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("worst_latency_ms", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "status_incident",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("component_key", sa.String(length=48), nullable=True),
        sa.Column("impact", sa.String(length=16), nullable=False, server_default="minor"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="investigating"),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_status_incident_component_key", "status_incident", ["component_key"])
    op.create_index("ix_status_incident_status", "status_incident", ["status"])
    op.create_index("ix_status_incident_started_at", "status_incident", ["started_at"])

    op.create_table(
        "status_incident_update",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(),
                  sa.ForeignKey("status_incident.id"), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="investigating"),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_status_incident_update_incident_id",
                    "status_incident_update", ["incident_id"])

    op.create_table(
        "status_report",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("component_key", sa.String(length=48), nullable=True),
        sa.Column("body", sa.String(length=1000), nullable=False, server_default=""),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_status_report_at", "status_report", ["at"])
    op.create_index("ix_status_report_acknowledged", "status_report", ["acknowledged"])


def downgrade():
    op.drop_table("status_report")
    op.drop_table("status_incident_update")
    op.drop_table("status_incident")
    op.drop_table("status_day")
    op.drop_table("status_probe")
    op.drop_table("status_component")
