"""Add remote reply forwarding drafts and slip preference

Revision ID: a2d4f6b8c901
Revises: 9c4e2b71fa30
Create Date: 2026-07-26
"""
from alembic import op
import sqlalchemy as sa


revision = "a2d4f6b8c901"
down_revision = "9c4e2b71fa30"
branch_labels = None
depends_on = None


def _has_column(table, column):
    inspector = sa.inspect(op.get_bind())
    return inspector.has_table(table) and column in {
        item["name"] for item in inspector.get_columns(table)
    }


def upgrade():
    if not _has_column("slip", "forward_remote_replies"):
        op.add_column(
            "slip",
            sa.Column(
                "forward_remote_replies",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
        )

    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("outbound_reply"):
        op.create_table(
            "outbound_reply",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("public_id", sa.String(length=32), nullable=False),
            sa.Column("thread_id", sa.Integer(), nullable=False),
            sa.Column("board_id", sa.Integer(), nullable=False),
            sa.Column("poster_id", sa.Integer(), nullable=False),
            sa.Column("slip_id", sa.Integer(), nullable=True),
            sa.Column("source_type", sa.String(length=128), nullable=False),
            sa.Column("source_name", sa.String(length=64), nullable=True),
            sa.Column("source_thread_id", sa.String(length=128), nullable=False),
            sa.Column("source_url", sa.Text(), nullable=False),
            sa.Column("body", sa.String(length=4096), nullable=False),
            sa.Column("subject", sa.String(length=64), nullable=True),
            sa.Column("author_name", sa.String(length=128), nullable=True),
            sa.Column("observed_client_ip", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="ready_for_handoff"),
            sa.Column("transport", sa.String(length=32), nullable=False, server_default="manual_handoff"),
            sa.Column("source_post_id", sa.String(length=128), nullable=True),
            sa.Column("source_post_url", sa.Text(), nullable=True),
            sa.Column("last_error_code", sa.String(length=64), nullable=True),
            sa.Column("last_error_detail", sa.String(length=512), nullable=True),
            sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("handoff_at", sa.DateTime(), nullable=True),
            sa.Column("claimed_submitted_at", sa.DateTime(), nullable=True),
            sa.Column("confirmed_at", sa.DateTime(), nullable=True),
            sa.Column("failed_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["board_id"], ["board.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["poster_id"], ["poster.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["slip_id"], ["slip.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["thread_id"], ["thread.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("public_id"),
        )
        op.create_index("ix_outbound_reply_public_id", "outbound_reply", ["public_id"], unique=True)
        op.create_index("ix_outbound_reply_thread_id", "outbound_reply", ["thread_id"], unique=False)
        op.create_index("ix_outbound_reply_board_id", "outbound_reply", ["board_id"], unique=False)
        op.create_index("ix_outbound_reply_poster_id", "outbound_reply", ["poster_id"], unique=False)
        op.create_index("ix_outbound_reply_slip_id", "outbound_reply", ["slip_id"], unique=False)
        op.create_index("ix_outbound_reply_status", "outbound_reply", ["status"], unique=False)


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("outbound_reply"):
        op.drop_table("outbound_reply")
    if _has_column("slip", "forward_remote_replies"):
        with op.batch_alter_table("slip", schema=None) as batch_op:
            batch_op.drop_column("forward_remote_replies")

