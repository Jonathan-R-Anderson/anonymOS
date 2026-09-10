"""Compute clusters: N machines running one catalogue workload over one corpus.

A cluster is a parent row plus N ComputeRental UNIT rows, so almost all of this
revision is four nullable columns on compute_rental. That is the design, not an
economy: a unit that is an ordinary rental inherits placement, the node bridge,
verification and provider payment without any of them learning a second row
shape. See model/ComputeCluster.py.

`entrypoint` loses its NOT NULL here. A data-only workload has no entry point of
the submitter's to name — the signed catalogue image ships its own — so the
constraint would force every unit to claim it runs a file that does not exist.
The server default stays, so a language job that omits the column still gets
"main.py" and nothing about the existing path changes.

Note that in production these objects are created by the idempotent DDL block in
app.py (search for compute_cluster there), as the rest of the compute schema is.
This revision exists so the two descriptions of the schema do not diverge, and
so a database built purely from migrations is the same database.

REVISION ID: the filename says a1b2c3d4e5f6, but that identifier was already
taken by a1b2c3d4e5f6_slip_auth_mode.py. Alembic reads the id from this module
and not from the filename, and a duplicate would make every alembic command fail
outright, so the id below is a1b2c3d4e5f7. The filename is left as-is because
other work in flight refers to it.

Revision ID: a1b2c3d4e5f7
Revises: f1a3c5e7b9d2
"""

import sqlalchemy as sa
from alembic import op

revision = "a1b2c3d4e5f7"
down_revision = "f1a3c5e7b9d2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "compute_cluster",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False, server_default=""),
        # Not a language. A cluster runs a signed image over the submitter's
        # data, never the submitter's code.
        sa.Column("workload", sa.String(length=32), nullable=False, server_default="embed"),
        sa.Column("device", sa.String(length=8), nullable=False, server_default="cpu"),
        # What was ASKED FOR, kept rather than counted from the units: if only
        # 6 of 8 could be placed, that difference is the whole explanation.
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("seconds", sa.Integer(), nullable=False, server_default="120"),
        sa.Column("cores", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="queued"),
        # 1.0, not the rental default of 0.25: slice-1 embeddings are bit-exact,
        # so a second run is cheap and the vectors need not rest on one
        # anonymous machine's word. Per cluster because slices 2-5 will not be
        # bit-exact and will have to sample.
        sa.Column("verify_rate", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("credits_paid", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("corpus_lines", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_compute_cluster_slip_id", "compute_cluster", ["slip_id"])
    # What the drainer scans on every pass, and what the user's list orders by.
    op.create_index("ix_compute_cluster_status", "compute_cluster", ["status"])
    op.create_index("ix_compute_cluster_created_at", "compute_cluster", ["created_at"])

    # The unit columns. All nullable: every job that existed before M10 is a
    # language job with none of them set.
    op.add_column("compute_rental",
                  sa.Column("workload", sa.String(length=32), nullable=True))
    op.add_column("compute_rental",
                  sa.Column("cluster_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_compute_rental_cluster", "compute_rental", "compute_cluster",
        ["cluster_id"], ["id"], ondelete="CASCADE")
    op.add_column("compute_rental",
                  sa.Column("shard_index", sa.Integer(), nullable=True))
    # The file the workload produced, not what it printed. stdout is what
    # verification hashes; this is the payload the user came for.
    op.add_column("compute_rental",
                  sa.Column("output_text", sa.Text(), nullable=True))

    op.create_index("ix_compute_rental_cluster_id", "compute_rental", ["cluster_id"])
    op.create_index("ix_compute_rental_workload", "compute_rental", ["workload"])

    op.alter_column("compute_rental", "entrypoint",
                    existing_type=sa.String(length=255),
                    existing_server_default="main.py",
                    nullable=True)


def downgrade():
    # Restore the NOT NULL first, and fill the rows that would violate it. Only
    # cluster units can hold NULL here, and they are about to be deleted with
    # their clusters anyway, but the UPDATE keeps the downgrade from failing on
    # a database where somebody kept one.
    op.execute("UPDATE compute_rental SET entrypoint = 'main.py' WHERE entrypoint IS NULL")
    op.alter_column("compute_rental", "entrypoint",
                    existing_type=sa.String(length=255),
                    existing_server_default="main.py",
                    nullable=False)

    op.drop_index("ix_compute_rental_workload", table_name="compute_rental")
    op.drop_index("ix_compute_rental_cluster_id", table_name="compute_rental")
    op.drop_constraint("fk_compute_rental_cluster", "compute_rental", type_="foreignkey")
    for name in ("output_text", "shard_index", "cluster_id", "workload"):
        op.drop_column("compute_rental", name)

    op.drop_index("ix_compute_cluster_created_at", table_name="compute_cluster")
    op.drop_index("ix_compute_cluster_status", table_name="compute_cluster")
    op.drop_index("ix_compute_cluster_slip_id", table_name="compute_cluster")
    op.drop_table("compute_cluster")
