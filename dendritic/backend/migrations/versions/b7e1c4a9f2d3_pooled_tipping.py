"""Pooled tipping: a switch and a label, never a balance — roadmap P15.

WHAT IS AND IS NOT STORED HERE
------------------------------
Two columns. `pool_enabled` is the recipient's own choice, off by default, and
`pool_name` is what they want it called.

There is deliberately NO balance column, no channel list, no per-tip row and no
contributor table. The pool is a DERIVED VIEW computed in the recipient's node
from their bilateral channels; this database learns only that the owner switched
the feature on. Adding a balance here would make the platform a custodian, which
is the one thing P15 exists to avoid.
"""
from alembic import op
import sqlalchemy as sa

revision = "b7e1c4a9f2d3"
down_revision = "f3c9d2a5b7e1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("profile", sa.Column(
        "pool_enabled", sa.Boolean(), nullable=False, server_default="0"))
    op.add_column("profile", sa.Column(
        "pool_name", sa.String(length=64), nullable=True))


def downgrade():
    op.drop_column("profile", "pool_name")
    op.drop_column("profile", "pool_enabled")
