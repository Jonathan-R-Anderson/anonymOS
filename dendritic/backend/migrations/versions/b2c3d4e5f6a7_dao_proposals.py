"""DAO proposals and signed votes.

Revision ID: b2c3d4e5f6a7
"""

from alembic import op
import sqlalchemy as sa


revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dao_proposal",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("house", sa.String(length=24), nullable=False, server_default="community"),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("author_slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=True),
        sa.Column("author_wallet", sa.String(length=42), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("closes_at", sa.DateTime(), nullable=False),
        sa.Column("onchain_ref", sa.String(length=80), nullable=True),
    )
    op.create_table(
        "dao_vote",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("proposal_id", sa.Integer(), sa.ForeignKey("dao_proposal.id"), nullable=False),
        sa.Column("slip_id", sa.Integer(), sa.ForeignKey("slip.id"), nullable=False),
        sa.Column("wallet_address", sa.String(length=42), nullable=False),
        sa.Column("choice", sa.String(length=16), nullable=False),
        sa.Column("weight", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signed_message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        # Double-voting is the first thing anyone tries; the schema refuses it
        # rather than relying on the view layer.
        sa.UniqueConstraint("proposal_id", "slip_id", name="uq_dao_vote_proposal_slip"),
    )
    op.create_index("ix_dao_vote_proposal_id", "dao_vote", ["proposal_id"])


def downgrade():
    op.drop_index("ix_dao_vote_proposal_id", table_name="dao_vote")
    op.drop_table("dao_vote")
    op.drop_table("dao_proposal")
