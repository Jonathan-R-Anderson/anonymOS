"""Which volunteer services a creator's pooled tips, and on what terms.

Two nullable strings, and deliberately nothing else. `pool_volunteer` is the
node id the creator picked; the endpoint it resolves to is the existing
`channel_endpoint`, which is already https-only and already the thing tippers
read. `pool_signing_mode` is "mailbox" or "delegate".

THE MODE COLUMN IS A LABEL, NOT AN AUTHORITY. Whether a volunteer may sign is
decided by ChannelManagerV2.canSign and by nothing in this database. Setting
this column to "delegate" without doing the on-chain authorisation produces a
volunteer that cannot sign — which is the safe direction to be wrong in.

No key material, no balance, no channel id: this table learns who a creator
chose, and never what they were paid.

Revision ID: d8f2a6c1e934
Revises: b7e1c4a9f2d3
"""

import sqlalchemy as sa
from alembic import op

revision = "d8f2a6c1e934"
down_revision = "b7e1c4a9f2d3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("profile", sa.Column("pool_volunteer", sa.String(length=128), nullable=True))
    op.add_column("profile", sa.Column("pool_signing_mode", sa.String(length=16), nullable=True))


def downgrade():
    op.drop_column("profile", "pool_signing_mode")
    op.drop_column("profile", "pool_volunteer")
