"""NNTPChan peer configuration.

Route-B (true NNTP peering) only needs ONE reachable bootstrap peer: once we
pull from it, the overchan network's flooding propagation means that peer
already carries the whole mesh's articles, so there is no need to crawl a
directory of sites. Each row is one upstream NNTP node we read from.
"""
import datetime as _datetime

from shared import db
from services.i2p_addresses import is_i2p_host
from services.nntp_hosts import (
    TRANSPORT_CLEARNET, TRANSPORT_I2P, normalize_peer_host,
)


class NntpPeer(db.Model):
    __tablename__ = "nntp_peer"

    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=119)
    use_tls = db.Column(db.Boolean, nullable=False, default=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    last_sync_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.String(500), nullable=True)

    __table_args__ = (
        db.UniqueConstraint("host", "port", name="uq_nntp_peer_host_port"),
    )

    @property
    def transport(self):
        """How this peer is reached. Derived from the host rather than stored,
        so the two can never disagree about the same row."""
        return TRANSPORT_I2P if is_i2p_host(self.host) else TRANSPORT_CLEARNET

    @property
    def is_anonymous(self):
        """Whether reaching this peer hides our address from it."""
        return self.transport == TRANSPORT_I2P


def list_peers(enabled_only=False):
    query = db.session.query(NntpPeer)
    if enabled_only:
        query = query.filter(NntpPeer.enabled.is_(True))
    return query.order_by(NntpPeer.host.asc(), NntpPeer.port.asc()).all()


def add_peer(host, port=119, use_tls=False, description=None):
    host, _transport = normalize_peer_host(host)
    try:
        port = int(port or 119)
    except (TypeError, ValueError):
        raise ValueError("Peer port must be a number.")
    if not (0 < port < 65536):
        raise ValueError("Peer port must be between 1 and 65535.")
    existing = db.session.query(NntpPeer).filter_by(host=host, port=port).one_or_none()
    if existing is not None:
        existing.use_tls = bool(use_tls)
        existing.enabled = True
        if description is not None:
            existing.description = description.strip() or None
        db.session.add(existing)
        return existing
    peer = NntpPeer(
        host=host,
        port=port,
        use_tls=bool(use_tls),
        enabled=True,
        description=(description or "").strip() or None,
    )
    db.session.add(peer)
    return peer


def remove_peer(peer_id):
    peer = db.session.query(NntpPeer).get(peer_id)
    if peer is not None:
        db.session.delete(peer)
    return peer is not None


def record_peer_result(peer, error=None):
    peer.last_sync_at = _datetime.datetime.utcnow()
    peer.last_error = (str(error)[:500] if error else None)
    db.session.add(peer)
