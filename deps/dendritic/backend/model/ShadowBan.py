"""Shadowbans: a poster can keep posting/streaming/uploading, but their content
is hidden from everyone else. Classic semantics — the shadowbanned author still
sees their own content (so they don't realise), enforced by filtering out their
Poster ids for other viewers while a shadowbanned viewer bypasses the shared
cache and keeps their own. Targets the poster's IP and/or account (slip); a
single row can carry both. See services/shadowban_cleanup.py for the 30-day
purge of shadowbanned content."""
import datetime as _datetime

from flask import has_request_context, request
from sqlalchemy import or_

from model.Poster import Poster
from model.Slip import get_slip
from shared import db


def _utcnow():
    return _datetime.datetime.utcnow()


class ShadowBan(db.Model):
    __tablename__ = "shadow_ban"
    id = db.Column(db.Integer, primary_key=True)
    # At least one of ip_address / slip_id is set. Matching is "either".
    ip_address = db.Column(db.String(255), nullable=True, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True, index=True)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)
    # NULL = permanent. Otherwise stops applying once utcnow() passes it.
    expires_at = db.Column(db.DateTime, nullable=True)

    @property
    def is_permanent(self):
        return self.expires_at is None

    @property
    def is_active(self):
        return self.expires_at is None or self.expires_at > _utcnow()


def _active_filter():
    return or_(ShadowBan.expires_at.is_(None), ShadowBan.expires_at > _utcnow())


def _viewer_ip():
    if has_request_context() is False:
        return None
    if "X-Forwarded-For" in request.headers:
        return request.headers.getlist("X-Forwarded-For")[0].split()[-1]
    return request.remote_addr


def active_shadowbans():
    return db.session.query(ShadowBan).filter(_active_filter()).all()


def list_shadowbans():
    """Every shadowban (active first, newest first) for the admin panel."""
    return (
        db.session.query(ShadowBan)
        .order_by(ShadowBan.created_at.desc(), ShadowBan.id.desc())
        .all()
    )


def is_shadowbanned(ip_address=None, slip_id=None):
    conds = []
    if ip_address:
        conds.append(ShadowBan.ip_address == ip_address)
    if slip_id:
        conds.append(ShadowBan.slip_id == slip_id)
    if not conds:
        return False
    return db.session.query(
        db.session.query(ShadowBan.id).filter(_active_filter(), or_(*conds)).exists()
    ).scalar()


def shadowban(ip_address=None, slip_id=None, reason=None, created_by_slip_id=None, expires_at=None):
    """Create or refresh a shadowban for an identity. If an active row already
    covers the same (ip, slip) pair it is updated rather than duplicated."""
    if not ip_address and not slip_id:
        raise ValueError("A shadowban needs an IP address or an account.")
    existing = (
        db.session.query(ShadowBan)
        .filter(
            _active_filter(),
            ShadowBan.ip_address.is_(None) if ip_address is None else (ShadowBan.ip_address == ip_address),
            ShadowBan.slip_id.is_(None) if slip_id is None else (ShadowBan.slip_id == slip_id),
        )
        .first()
    )
    if existing is not None:
        existing.reason = reason
        existing.created_by_slip_id = created_by_slip_id
        existing.expires_at = expires_at
        existing.created_at = _utcnow()
        db.session.add(existing)
        return existing
    entry = ShadowBan(
        ip_address=ip_address,
        slip_id=slip_id,
        reason=reason,
        created_by_slip_id=created_by_slip_id,
        expires_at=expires_at,
    )
    db.session.add(entry)
    return entry


def remove_shadowban(shadowban_id):
    entry = db.session.query(ShadowBan).filter(ShadowBan.id == shadowban_id).one_or_none()
    if entry is not None:
        db.session.delete(entry)
    return entry


# --- Enforcement helpers -------------------------------------------------

def shadowbanned_poster_ids():
    """Poster.id values authored by any active-shadowbanned identity (ip OR slip)."""
    bans = active_shadowbans()
    ips = {b.ip_address for b in bans if b.ip_address}
    slips = {b.slip_id for b in bans if b.slip_id}
    if not ips and not slips:
        return set()
    conds = []
    if ips:
        conds.append(Poster.ip_address.in_(ips))
    if slips:
        conds.append(Poster.slip.in_(slips))
    rows = db.session.query(Poster.id).filter(or_(*conds)).all()
    return {row[0] for row in rows}


def viewer_owned_poster_ids():
    """Poster.id values belonging to the CURRENT viewer (their IP or account)."""
    ip = _viewer_ip()
    slip = get_slip() if has_request_context() else None
    slip_id = slip.id if slip else None
    conds = []
    if ip:
        conds.append(Poster.ip_address == ip)
    if slip_id:
        conds.append(Poster.slip == slip_id)
    if not conds:
        return set()
    rows = db.session.query(Poster.id).filter(or_(*conds)).all()
    return {row[0] for row in rows}


def viewer_is_shadowbanned():
    ip = _viewer_ip()
    slip = get_slip() if has_request_context() else None
    return is_shadowbanned(ip_address=ip, slip_id=slip.id if slip else None)


def hidden_poster_ids():
    """Poster ids to hide from the CURRENT viewer: every shadowbanned poster
    EXCEPT the viewer's own (so the shadowbanned author still sees themselves).
    Returns an empty set when nobody is shadowbanned (near-zero overhead)."""
    banned = shadowbanned_poster_ids()
    if not banned:
        return set()
    return banned - viewer_owned_poster_ids()


def shadowbanned_slip_ids():
    """Account (slip) ids under an active shadowban — used to hide a shadowbanned
    uploader's videos and streams (which are keyed by account, not Poster)."""
    return {b.slip_id for b in active_shadowbans() if b.slip_id}


def hidden_slip_ids():
    """Shadowbanned slip ids to hide from the CURRENT viewer, excluding the
    viewer's own account so a shadowbanned uploader still sees their own content.
    Empty set when nobody is shadowbanned."""
    banned = shadowbanned_slip_ids()
    if not banned:
        return set()
    slip = get_slip() if has_request_context() else None
    if slip is not None:
        banned = banned - {slip.id}
    return banned
