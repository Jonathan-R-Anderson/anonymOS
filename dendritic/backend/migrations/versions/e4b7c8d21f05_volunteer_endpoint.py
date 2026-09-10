"""Where a creator's chosen volunteer keeps their mailbox.

Separate from `channel_endpoint`, which is the creator's OWN node. They are
different services with different trust: one is asked for channel state and
proposes payments, the other only holds a frame until the creator collects it.
A single field doing both jobs made the volunteer answer as if it were a party
to the channel, and the payment ended UNKNOWN instead of queued.

No financial state: a URL, like the one beside it.

Revision ID: e4b7c8d21f05
Revises: d8f2a6c1e934
"""

import sqlalchemy as sa
from alembic import op

revision = "e4b7c8d21f05"
down_revision = "d8f2a6c1e934"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("profile",
                  sa.Column("pool_volunteer_endpoint", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("profile", "pool_volunteer_endpoint")
