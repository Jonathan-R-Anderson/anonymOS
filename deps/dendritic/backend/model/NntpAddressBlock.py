"""Address blocklist for federated NNTPChan content.

Federated articles have no IP; their identity is expressed by the ed25519
pubkey (X-PubKey-Ed25519), the From address / its domain, and the Path hosts
(the frontends that relayed the article). This is a greenfield deny-list
(nothing like it existed — Ban/BoardBan are exact-IP only) modelled on the
BlockedSourcePost pattern: exact, case-insensitive string match against any of
an article's candidate addresses, enforced at import time so blocked content is
never stored, never rendered, and never seeds/torrents.
"""
import datetime as _datetime

from shared import db


class NntpAddressBlock(db.Model):
    __tablename__ = "nntp_address_block"

    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(255), nullable=False, unique=True, index=True)
    reason = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)


def _normalize(address):
    return (address or "").strip().lower()


def blocked_addresses():
    """Set of every blocked address (normalized). Fails open (empty) on error."""
    try:
        return {
            row.address
            for row in db.session.query(NntpAddressBlock.address).all()
        }
    except Exception:
        return set()


def is_address_blocked(*candidates):
    blocked = blocked_addresses()
    if not blocked:
        return False
    for candidate in candidates:
        norm = _normalize(candidate)
        if norm and norm in blocked:
            return True
    return False


def list_address_blocks():
    return (
        db.session.query(NntpAddressBlock)
        .order_by(NntpAddressBlock.created_at.desc(), NntpAddressBlock.id.desc())
        .all()
    )


def block_address(address, reason=None, created_by_slip_id=None):
    address = _normalize(address)
    if not address:
        raise ValueError("An address (pubkey, From, domain or Path host) is required.")
    existing = db.session.query(NntpAddressBlock).filter_by(address=address).one_or_none()
    if existing is not None:
        if reason:
            existing.reason = reason[:500]
        db.session.add(existing)
        return existing
    row = NntpAddressBlock(
        address=address,
        reason=(reason or "").strip()[:500] or None,
        created_by_slip_id=created_by_slip_id,
    )
    db.session.add(row)
    return row


def unblock_address(block_id):
    row = db.session.query(NntpAddressBlock).get(block_id)
    if row is not None:
        db.session.delete(row)
    return row is not None
