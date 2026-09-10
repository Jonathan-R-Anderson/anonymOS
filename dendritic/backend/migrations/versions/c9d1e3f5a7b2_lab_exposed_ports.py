"""Every container port a lab exposes, not just the primary one.

The importer already computed the whole list — parse_ports() returns it — and
kept one. So a box exposing a web app, a database and a debugger advertised a
single open port, while its destination carried all of them: the page described
the box wrongly, and somebody port-scanning it would find services the page said
were not there.

Empty means "not recorded", NOT "none exposed". Rows imported before this have
an encrypted build context the site cannot re-read, so they keep showing the
primary alone rather than claiming the other ports are closed.

Revision ID: c9d1e3f5a7b2
Revises: b8c2d4e6f7a9
"""

import sqlalchemy as sa
from alembic import op

revision = "c9d1e3f5a7b2"
down_revision = "b8c2d4e6f7a9"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("lab_challenge", sa.Column(
        "exposed_ports", sa.String(length=200), nullable=False, server_default=""))


def downgrade():
    op.drop_column("lab_challenge", "exposed_ports")
