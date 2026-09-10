"""Distance-based image banlist (federated over NNTPChan).

A row is one banned image fingerprint (perceptual, see services/perceptual.py).
A NEW image is blocked when its fingerprint is within the configured Manhattan
distance of ANY non-revoked row here. Local bans (origin='local') are broadcast
to peers; bans learned from peers land here as origin='remote'.

Removals federate too. Removing a ban REVOKES it (excluded from matching) and,
if peers were ever told about it, queues an "unban" broadcast carrying the
fingerprint + exact SHA-256 so remote nodes can test their own banlist and drop
matching entries — undoing a mistaken ban network-wide. A revoked row is kept as
a tombstone so the same fingerprint can't be silently re-ingested.
"""
import datetime as _datetime
import time as _time

from shared import app, db
from services import perceptual
from model.SiteSetting import get_setting


class BannedImageFingerprint(db.Model):
    __tablename__ = "banned_image_fingerprint"

    id = db.Column(db.Integer, primary_key=True)
    algorithm = db.Column(db.String(32), nullable=False, default=perceptual.ALGORITHM)
    dims = db.Column(db.Integer, nullable=False, default=perceptual.DIMS)
    fingerprint = db.Column(db.String(1024), nullable=False, index=True)
    # Exact content hash of the reference image when known (from Media.sha256).
    # Broadcast alongside the fingerprint so peers can match a ban/unban by exact
    # file as well as by perceptual distance.
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    reason = db.Column(db.String(500), nullable=True)
    origin = db.Column(db.String(16), nullable=False, default="local")
    source_message_id = db.Column(db.String(250), nullable=True, index=True)
    broadcasted = db.Column(db.Boolean, nullable=False, default=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    revoke_broadcasted = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)


THRESHOLD_SETTING = "image_distance_threshold"

_CACHE_TTL_SECONDS = 30
_cache = {"at": 0.0, "rows": None}


def distance_threshold():
    raw = get_setting(THRESHOLD_SETTING, str(perceptual.DEFAULT_THRESHOLD))
    try:
        return max(0.0, float(str(raw).strip()))
    except (TypeError, ValueError):
        return perceptual.DEFAULT_THRESHOLD


def invalidate_cache():
    _cache["at"] = 0.0
    _cache["rows"] = None


def _active_vectors():
    """[(id, reason, vector)] for current algo/dims, excluding revoked; cached briefly."""
    now = _time.time()
    if _cache["rows"] is not None and (now - _cache["at"]) < _CACHE_TTL_SECONDS:
        return _cache["rows"]
    rows = []
    try:
        query = (
            db.session.query(BannedImageFingerprint)
            .filter(
                BannedImageFingerprint.algorithm == perceptual.ALGORITHM,
                BannedImageFingerprint.dims == perceptual.DIMS,
                BannedImageFingerprint.revoked.is_(False),
            )
            .all()
        )
        for row in query:
            vector = perceptual.decode_vector(row.fingerprint)
            if vector is not None:
                rows.append((row.id, row.reason, vector))
    except Exception:
        app.logger.exception("banned-fingerprint cache load failed")
        return []
    _cache["rows"] = rows
    _cache["at"] = now
    return rows


def match_vector(vector):
    """Closest non-revoked banned fingerprint within threshold, or None."""
    if not vector:
        return None
    rows = _active_vectors()
    if not rows:
        return None
    threshold = distance_threshold()
    best = None
    for row_id, reason, banned_vector in rows:
        avg = perceptual.average_distance(vector, banned_vector)
        if avg is None:
            continue
        if avg <= threshold and (best is None or avg < best[2]):
            best = (row_id, reason, avg)
    return best


def is_fingerprint_hex_blocked(fingerprint_hex):
    return match_vector(perceptual.decode_vector(fingerprint_hex))


def _live_row_for_fingerprint(fingerprint_hex):
    """Any existing row (revoked or not) with this exact fingerprint."""
    return (
        db.session.query(BannedImageFingerprint)
        .filter(BannedImageFingerprint.fingerprint == fingerprint_hex)
        .first()
    )


def add_local_fingerprint(fingerprint_hex, reason=None, created_by_slip_id=None,
                          sha256=None, algorithm=perceptual.ALGORITHM, dims=perceptual.DIMS):
    """Ban an image locally by fingerprint; queued for broadcast to peers."""
    if perceptual.decode_vector(fingerprint_hex) is None:
        raise ValueError("Invalid image fingerprint.")
    existing = _live_row_for_fingerprint(fingerprint_hex)
    if existing is not None:
        if existing.revoked:
            # Re-ban a previously revoked fingerprint: reactivate + re-broadcast.
            existing.revoked = False
            existing.revoke_broadcasted = False
            existing.broadcasted = False
            existing.origin = "local"
            if reason:
                existing.reason = reason.strip()[:500] or None
            if sha256:
                existing.sha256 = sha256
            db.session.add(existing)
            invalidate_cache()
            return existing
        return None
    row = BannedImageFingerprint(
        algorithm=algorithm, dims=dims, fingerprint=fingerprint_hex,
        sha256=(sha256 or None),
        reason=(reason or "").strip()[:500] or None,
        origin="local", broadcasted=False, created_by_slip_id=created_by_slip_id,
    )
    db.session.add(row)
    invalidate_cache()
    return row


def ingest_remote_fingerprint(fingerprint_hex, algorithm, dims, reason=None,
                              source_message_id=None, sha256=None):
    """Store a fingerprint ban learned from a peer (idempotent)."""
    if perceptual.decode_vector(fingerprint_hex) is None:
        return None
    if source_message_id and remote_ban_seen(source_message_id):
        return None
    if _live_row_for_fingerprint(fingerprint_hex) is not None:
        return None
    row = BannedImageFingerprint(
        algorithm=algorithm or perceptual.ALGORITHM,
        dims=dims or perceptual.DIMS,
        fingerprint=fingerprint_hex,
        sha256=(sha256 or None),
        reason=(reason or "").strip()[:500] or None,
        origin="remote", broadcasted=True, source_message_id=source_message_id,
    )
    db.session.add(row)
    invalidate_cache()
    return row


def revoke_fingerprint(fingerprint_id):
    """Remove a ban: stop matching locally and (if peers knew of it) queue an
    unban broadcast. A never-broadcast local ban is hard-deleted since no peer
    ever saw it. Returns True if a row was affected."""
    row = db.session.query(BannedImageFingerprint).get(fingerprint_id)
    if row is None:
        return False
    if row.origin == "local" and not row.broadcasted:
        db.session.delete(row)
    else:
        row.revoked = True
        row.revoke_broadcasted = False
        db.session.add(row)
    invalidate_cache()
    return True


def apply_unban(fingerprint_hex, sha256=None, algorithm=perceptual.ALGORITHM,
                dims=perceptual.DIMS, source_message_id=None):
    """Revoke local bans that match an unban (exact fingerprint/sha256, or within
    distance of the unbanned fingerprint). If nothing matched, leave a revoked
    tombstone so the unban is remembered even when it arrives BEFORE the ban
    (out-of-order NNTP pulls) and so the message isn't reprocessed. Returns the
    number of rows revoked (0 if only a tombstone was written)."""
    vector = perceptual.decode_vector(fingerprint_hex)
    threshold = distance_threshold()
    revoked = 0
    try:
        candidates = (
            db.session.query(BannedImageFingerprint)
            .filter(BannedImageFingerprint.revoked.is_(False))
            .all()
        )
    except Exception:
        return 0
    for row in candidates:
        hit = False
        if fingerprint_hex and row.fingerprint == fingerprint_hex:
            hit = True
        elif sha256 and row.sha256 and row.sha256 == sha256:
            hit = True
        elif vector is not None and row.algorithm == algorithm and row.dims == dims:
            avg = perceptual.average_distance(vector, perceptual.decode_vector(row.fingerprint))
            if avg is not None and avg <= threshold:
                hit = True
        if hit:
            row.revoked = True
            row.revoke_broadcasted = True  # arrived via a peer's unban; no re-post needed
            db.session.add(row)
            revoked += 1
    if revoked == 0 and vector is not None and _live_row_for_fingerprint(fingerprint_hex) is None:
        # Preemptive tombstone: remembers the unban, dedups the message, and
        # blocks a later re-ban of the same fingerprint from a peer.
        db.session.add(BannedImageFingerprint(
            algorithm=algorithm, dims=dims, fingerprint=fingerprint_hex,
            sha256=(sha256 or None), reason="unbanned",
            origin="remote", broadcasted=True, revoked=True, revoke_broadcasted=True,
            source_message_id=source_message_id,
        ))
    invalidate_cache()
    return revoked


def remote_ban_seen(message_id):
    if not message_id:
        return False
    return (
        db.session.query(BannedImageFingerprint.id)
        .filter(BannedImageFingerprint.source_message_id == message_id)
        .first()
        is not None
    )


def pending_ban_broadcasts():
    return (
        db.session.query(BannedImageFingerprint)
        .filter(
            BannedImageFingerprint.origin == "local",
            BannedImageFingerprint.broadcasted.is_(False),
            BannedImageFingerprint.revoked.is_(False),
        )
        .order_by(BannedImageFingerprint.id.asc())
        .all()
    )


def pending_unban_broadcasts():
    return (
        db.session.query(BannedImageFingerprint)
        .filter(
            BannedImageFingerprint.revoked.is_(True),
            BannedImageFingerprint.revoke_broadcasted.is_(False),
        )
        .order_by(BannedImageFingerprint.id.asc())
        .all()
    )


def mark_broadcasted(row, message_id=None):
    row.broadcasted = True
    if message_id and not row.source_message_id:
        row.source_message_id = message_id
    db.session.add(row)


def mark_revoke_broadcasted(row):
    row.revoke_broadcasted = True
    db.session.add(row)


def list_fingerprints():
    return (
        db.session.query(BannedImageFingerprint)
        .order_by(BannedImageFingerprint.created_at.desc(), BannedImageFingerprint.id.desc())
        .all()
    )
