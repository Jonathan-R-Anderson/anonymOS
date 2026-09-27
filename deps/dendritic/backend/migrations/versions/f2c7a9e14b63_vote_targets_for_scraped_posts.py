"""Make scraped posts votable: thread-scoped vote targets

post_vote originally keyed on post.id, which excluded every imported post — they
have no Post row, only a synthetic id that can collide with a real one. Votes now
key on (thread_id, target_key), where target_key is "p<post_id>" for a local post
and "s<source_post_id>" for a scraped one. post_id stays for local rows so the FK
cascade still cleans up after a deleted post.

Revision ID: f2c7a9e14b63
Revises: e8b2d41f7a90
Create Date: 2026-07-26
"""
from alembic import op
import sqlalchemy as sa


revision = "f2c7a9e14b63"
down_revision = "e8b2d41f7a90"
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


def _constraints(table):
    if not _has_table(table):
        return set()
    try:
        return {c["name"] for c in _inspector().get_unique_constraints(table)}
    except Exception:
        return set()


def _indexes(table):
    if not _has_table(table):
        return set()
    return {item["name"] for item in _inspector().get_indexes(table)}


def upgrade():
    if not _has_table("post_vote"):
        # Nothing to migrate; e8b2d41f7a90 will have created it in the current
        # shape on any database that reaches this point without the table.
        return

    columns = _columns("post_vote")

    # Add the new columns nullable first so existing rows can be backfilled.
    with op.batch_alter_table("post_vote", schema=None) as batch_op:
        if "thread_id" not in columns:
            batch_op.add_column(sa.Column("thread_id", sa.Integer(), nullable=True))
        if "target_key" not in columns:
            batch_op.add_column(sa.Column("target_key", sa.String(length=160), nullable=True))

    # Backfill: every pre-existing row is a local post vote.
    op.execute(sa.text(
        "UPDATE post_vote SET target_key = 'p' || post_id WHERE target_key IS NULL"
    ))
    op.execute(sa.text(
        "UPDATE post_vote SET thread_id = ("
        "  SELECT post.thread FROM post WHERE post.id = post_vote.post_id"
        ") WHERE thread_id IS NULL"
    ))
    # A vote whose post is already gone cannot be given a thread; it is dead
    # weight either way.
    op.execute(sa.text("DELETE FROM post_vote WHERE thread_id IS NULL OR target_key IS NULL"))

    # Drop the old (post_id, slip_id) uniqueness before relaxing post_id — it is
    # wrong now that one slip can hold several votes with a NULL post_id.
    existing_constraints = _constraints("post_vote")
    with op.batch_alter_table("post_vote", schema=None) as batch_op:
        if "uq_post_vote_post_slip" in existing_constraints:
            batch_op.drop_constraint("uq_post_vote_post_slip", type_="unique")
        batch_op.alter_column("thread_id", existing_type=sa.Integer(), nullable=False)
        batch_op.alter_column("target_key", existing_type=sa.String(length=160), nullable=False)
        batch_op.alter_column("post_id", existing_type=sa.Integer(), nullable=True)
        if "uq_post_vote_thread_target_slip" not in existing_constraints:
            batch_op.create_unique_constraint(
                "uq_post_vote_thread_target_slip", ["thread_id", "target_key", "slip_id"]
            )

    if "ix_post_vote_thread_id" not in _indexes("post_vote"):
        op.create_index("ix_post_vote_thread_id", "post_vote", ["thread_id"])


def downgrade():
    if not _has_table("post_vote"):
        return
    # Imported-post votes have no post_id and cannot survive the column going
    # back to NOT NULL.
    op.execute(sa.text("DELETE FROM post_vote WHERE post_id IS NULL"))

    if "ix_post_vote_thread_id" in _indexes("post_vote"):
        op.drop_index("ix_post_vote_thread_id", table_name="post_vote")

    existing_constraints = _constraints("post_vote")
    columns = _columns("post_vote")
    with op.batch_alter_table("post_vote", schema=None) as batch_op:
        if "uq_post_vote_thread_target_slip" in existing_constraints:
            batch_op.drop_constraint("uq_post_vote_thread_target_slip", type_="unique")
        batch_op.alter_column("post_id", existing_type=sa.Integer(), nullable=False)
        if "uq_post_vote_post_slip" not in existing_constraints:
            batch_op.create_unique_constraint("uq_post_vote_post_slip", ["post_id", "slip_id"])
        for column in ("target_key", "thread_id"):
            if column in columns:
                batch_op.drop_column(column)
