"""Board sidebar: moderator bookmarks + board-level messages to the mods

Adds the board_bookmark table (moderator-curated sidebar links) and lets the
existing report table carry board-level messages: a new `kind` discriminator,
and thread_id becomes nullable because a board message is not about a post.

Revision ID: d7a1c93e5b48
Revises: c4f6b8d0e213
Create Date: 2026-07-26
"""
from alembic import op
import sqlalchemy as sa


revision = "d7a1c93e5b48"
down_revision = "c4f6b8d0e213"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(table):
    return _inspector().has_table(table)


def _columns(table):
    if not _has_table(table):
        return set()
    return {item["name"] for item in _inspector().get_columns(table)}


def _indexes(table):
    if not _has_table(table):
        return set()
    return {item["name"] for item in _inspector().get_indexes(table)}


def upgrade():
    if not _has_table("board_bookmark"):
        op.create_table(
            "board_bookmark",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("board_id", sa.Integer(), nullable=False),
            sa.Column("label", sa.String(length=80), nullable=False),
            sa.Column("url", sa.String(length=500), nullable=False),
            sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("created_by_slip_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(["board_id"], ["board.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["created_by_slip_id"], ["slip.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_board_bookmark_board_id", "board_bookmark", ["board_id"])

    # The sidebar's "here now" figure counts distinct visitors per board within a
    # time window; board_visit only had a unique index on page_id, so that count
    # was a full scan on what is one of the busier tables.
    #
    # CONCURRENTLY on PostgreSQL, and that is not a nicety: board_visit gains a
    # row per page view, so a plain CREATE INDEX locks out writes for as long as
    # the build takes. Migrations run from docker-entrypoint.sh BEFORE uwsgi
    # starts, under `set -e` — so a slow index build here holds the whole site
    # on nginx's 503 page until it finishes. CONCURRENTLY needs its own
    # transaction, hence the autocommit block.
    if _has_table("board_visit") and "ix_board_visit_board_last_seen" not in _indexes("board_visit"):
        bind = op.get_bind()
        if bind.dialect.name == "postgresql":
            with op.get_context().autocommit_block():
                op.execute(
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
                    "ix_board_visit_board_last_seen "
                    "ON board_visit (board_id, last_seen_at)"
                )
        else:
            op.create_index(
                "ix_board_visit_board_last_seen", "board_visit", ["board_id", "last_seen_at"]
            )

    if _has_table("report"):
        report_columns = _columns("report")
        report_indexes = _indexes("report")
        with op.batch_alter_table("report", schema=None) as batch_op:
            if "kind" not in report_columns:
                batch_op.add_column(
                    sa.Column(
                        "kind",
                        sa.String(length=24),
                        nullable=False,
                        server_default="post",
                    )
                )
            # A board message is addressed to the board, not to a post in a
            # thread, so thread_id has to accept NULL.
            batch_op.alter_column(
                "thread_id", existing_type=sa.Integer(), nullable=True
            )
        if "ix_report_kind" not in report_indexes:
            op.create_index("ix_report_kind", "report", ["kind"])


def downgrade():
    if _has_table("board_visit") and "ix_board_visit_board_last_seen" in _indexes("board_visit"):
        op.drop_index("ix_board_visit_board_last_seen", table_name="board_visit")
    if "ix_report_kind" in _indexes("report"):
        op.drop_index("ix_report_kind", table_name="report")
    if _has_table("report"):
        # Reflect BEFORE opening the batch: on SQLite batch_alter_table rebuilds
        # the table, so inspecting from inside it reports a moving target.
        report_columns = _columns("report")
        # Board messages have a NULL thread_id and cannot survive the column
        # going back to NOT NULL; drop them rather than fail the downgrade.
        op.execute(sa.text("DELETE FROM report WHERE thread_id IS NULL"))
        with op.batch_alter_table("report", schema=None) as batch_op:
            batch_op.alter_column(
                "thread_id", existing_type=sa.Integer(), nullable=False
            )
            if "kind" in report_columns:
                batch_op.drop_column("kind")

    if _has_table("board_bookmark"):
        if "ix_board_bookmark_board_id" in _indexes("board_bookmark"):
            op.drop_index("ix_board_bookmark_board_id", table_name="board_bookmark")
        op.drop_table("board_bookmark")
