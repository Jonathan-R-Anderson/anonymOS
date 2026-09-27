"""Rented compute: a queue of user-submitted programs, and their files.

Files are rows rather than one blob column so the inline editor can save a
single file without rewriting the rest, and so a later feature can diff what
changed between attempts.

Two indexes carry the queue itself. (status, priority) is what the scheduler
scans on every pass, and (device, status) is what the per-device wait estimate
counts. Both are read far more often than written — the queue page is polled
every few seconds by everybody watching a job.

Revision ID: e9c1f4a7b2d6
Revises: d7e9f2a4b6c8
"""

import sqlalchemy as sa
from alembic import op

revision = "e9c1f4a7b2d6"
down_revision = "d7e9f2a4b6c8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "compute_rental",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("language", sa.String(length=16), nullable=False, server_default="python"),
        sa.Column("entrypoint", sa.String(length=255), nullable=False, server_default="main.py"),
        sa.Column("stdin_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("device", sa.String(length=8), nullable=False, server_default="cpu"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="queued"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("credits_paid", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stdout", sa.Text(), nullable=False, server_default=""),
        sa.Column("stderr", sa.Text(), nullable=False, server_default=""),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("runtime_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_compute_rental_slip_id", "compute_rental", ["slip_id"])
    op.create_index("ix_compute_rental_created_at", "compute_rental", ["created_at"])
    # The two the queue actually scans.
    op.create_index("ix_compute_rental_status_priority", "compute_rental",
                    ["status", "priority"])
    op.create_index("ix_compute_rental_device_status", "compute_rental",
                    ["device", "status"])

    op.create_table(
        "compute_rental_file",
        sa.Column("id", sa.Integer(), primary_key=True),
        # CASCADE, because a file belonging to a deleted job is not a file, it
        # is an orphan row nobody will ever look at again.
        sa.Column("rental_id", sa.Integer(),
                  sa.ForeignKey("compute_rental.id", ondelete="CASCADE"), nullable=False),
        sa.Column("path", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("rental_id", "path", name="uq_rental_file_path"),
    )
    op.create_index("ix_compute_rental_file_rental_id", "compute_rental_file", ["rental_id"])


def downgrade():
    op.drop_index("ix_compute_rental_file_rental_id", table_name="compute_rental_file")
    op.drop_table("compute_rental_file")
    for name in ("ix_compute_rental_device_status", "ix_compute_rental_status_priority",
                 "ix_compute_rental_created_at", "ix_compute_rental_slip_id"):
        op.drop_index(name, table_name="compute_rental")
    op.drop_table("compute_rental")
