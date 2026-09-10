"""Require I2P destinations for enabled NNTP peers.

Existing clearnet rows cannot be legitimately converted without the remote
node's I2P destination. They are retained for operator reference but disabled,
which guarantees that the application cannot dial them or expose its address.

Revision ID: d4e7a91c2f60
Revises: b5c1e83af927
"""

from alembic import op


revision = "d4e7a91c2f60"
down_revision = "b5c1e83af927"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        """
        UPDATE nntp_peer
           SET host = lower(host)
         WHERE length(host) = 60
           AND lower(host) LIKE '%.b32.i2p'
        """
    )
    op.execute(
        """
        UPDATE nntp_peer
           SET enabled = false,
               last_error = 'Disabled by I2P-only migration; replace with the peer Base32 I2P destination.'
         WHERE enabled = true
           AND NOT (length(host) = 60 AND lower(host) LIKE '%.b32.i2p')
        """
    )
    with op.batch_alter_table("nntp_peer") as batch:
        batch.create_check_constraint(
            "ck_nntp_peer_enabled_i2p_host",
            "enabled = false OR (length(host) = 60 AND host LIKE '%.b32.i2p')",
        )


def downgrade():
    with op.batch_alter_table("nntp_peer") as batch:
        batch.drop_constraint("ck_nntp_peer_enabled_i2p_host", type_="check")
