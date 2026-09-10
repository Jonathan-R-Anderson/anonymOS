"""Allow clearnet NNTP peers again, alongside I2P ones.

d4e7a91c2f60 made enabled peers I2P-only so the server could never reveal its
address to a peer. That is the right default and it stays the default — but it
also made federation impossible here, because there is no I2P NNTP peer to
federate WITH and no I2P router this deployment can reach. An anonymity
guarantee on a feature that cannot run protects nobody.

So the constraint is dropped and the choice moves into the open: a peer is
reached over I2P if its host is a .b32.i2p destination and over the clearnet
otherwise, the transport is shown next to every peer, and a clearnet peer is
labelled as one — because the operator adding it needs to know their server's
address is visible to it, and a rule that silently refuses is not the same as a
rule that explains.

Revision ID: c1a5f70b3d29
Revises: c9d0e1f2a3b4
"""

from alembic import op


revision = "c1a5f70b3d29"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade():
    # Postgres names the constraint exactly as the batch operation created it.
    # IF EXISTS because a database created after the constraint was dropped, or
    # from metadata rather than migrations, will not have it.
    op.execute("ALTER TABLE nntp_peer DROP CONSTRAINT IF EXISTS ck_nntp_peer_enabled_i2p_host")
    # Rows the I2P-only migration disabled carry its explanation in last_error,
    # which is now misleading: they were disabled by a rule that no longer
    # exists. Clear the message but leave them disabled — re-enabling somebody's
    # peer on their behalf is not this migration's decision to make.
    op.execute(
        """
        UPDATE nntp_peer
           SET last_error = NULL
         WHERE last_error LIKE 'Disabled by I2P-only migration%'
        """
    )


def downgrade():
    op.execute(
        """
        UPDATE nntp_peer
           SET enabled = false,
               last_error = 'Disabled: this deployment requires I2P peers.'
         WHERE enabled = true
           AND NOT (length(host) = 60 AND lower(host) LIKE '%.b32.i2p')
        """
    )
    with op.batch_alter_table("nntp_peer") as batch:
        batch.create_check_constraint(
            "ck_nntp_peer_enabled_i2p_host",
            "enabled = false OR (length(host) = 60 AND host LIKE '%.b32.i2p')",
        )
