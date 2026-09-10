"""Bronze/silver/gold awards on posts.

The unique index on tx_hash is the load-bearing part. An award is only a record
of an on-chain transfer, so without it one real transfer could be replayed as an
award on every post on the board — the chain would agree it happened each time.

post_id cascades on delete: an award is attached to a post, and a deleted post
must not leave rows pointing at nothing.

Revision ID: e2f4a6b8c1d3
Revises: d1e3f5a7b9c2
"""

import sqlalchemy as sa
from alembic import op

revision = "e2f4a6b8c1d3"
down_revision = "d1e3f5a7b9c2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "post_award",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("post_id", sa.Integer(),
                  sa.ForeignKey("post.id", ondelete="CASCADE"), nullable=False),
        sa.Column("giver_slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("recipient_wallet", sa.String(length=42), nullable=False, server_default=""),
        sa.Column("tier", sa.String(length=16), nullable=False, server_default="bronze"),
        sa.Column("credits", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tx_hash", sa.String(length=80), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("tx_hash", name="uq_post_award_tx"),
    )
    op.create_index("ix_post_award_post_id", "post_award", ["post_id"])
    op.create_index("ix_post_award_giver_slip_id", "post_award", ["giver_slip_id"])


def downgrade():
    op.drop_index("ix_post_award_giver_slip_id", table_name="post_award")
    op.drop_index("ix_post_award_post_id", table_name="post_award")
    op.drop_table("post_award")
