import datetime as _datetime
import hashlib
import re
from dataclasses import dataclass

from sqlalchemy import select

from shared import db


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class BlockedMediaHashLookup:
    sha256: str
    reason: str = None
    source_url: str = None
    created_at: _datetime.datetime = None
    created_by_slip_id: int = None


class BlockedMediaHash(db.Model):
    sha256 = db.Column(db.String(64), primary_key=True)
    reason = db.Column(db.String(255), nullable=True)
    source_url = db.Column(db.String(1024), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)


def media_sha256_bytes(data) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def normalize_media_hash(raw_value: str) -> str:
    normalized = (raw_value or "").strip().lower()
    if _SHA256_RE.fullmatch(normalized) is None:
        raise ValueError("Media hash must be a 64-character SHA-256 hex string.")
    return normalized


def _read_blocked_media_hash_via_engine(normalized: str):
    engine = getattr(db, "engine", None)
    if engine is None:
        return None

    statement = (
        select(
            BlockedMediaHash.sha256,
            BlockedMediaHash.reason,
            BlockedMediaHash.source_url,
            BlockedMediaHash.created_at,
            BlockedMediaHash.created_by_slip_id,
        )
        .where(BlockedMediaHash.sha256 == normalized)
        .limit(1)
    )

    with engine.connect() as connection:
        row = connection.execute(statement).mappings().first()

    if row is None:
        return None

    return BlockedMediaHashLookup(
        sha256=row["sha256"],
        reason=row["reason"],
        source_url=row["source_url"],
        created_at=row["created_at"],
        created_by_slip_id=row["created_by_slip_id"],
    )


def get_blocked_media_hash(sha256: str):
    normalized = (sha256 or "").strip().lower()
    if not normalized:
        return None
    return _read_blocked_media_hash_via_engine(normalized)


def is_media_hash_blocked(sha256: str) -> bool:
    return get_blocked_media_hash(sha256) is not None


def block_media_hash(raw_hash: str, reason: str = None, source_url: str = None, created_by_slip_id: int = None):
    normalized = normalize_media_hash(raw_hash)
    blocked = (
        db.session.query(BlockedMediaHash)
        .filter(BlockedMediaHash.sha256 == normalized)
        .one_or_none()
    )
    if blocked is None:
        blocked = BlockedMediaHash(
            sha256=normalized,
            reason=(reason or "").strip() or None,
            source_url=(source_url or "").strip() or None,
            created_by_slip_id=created_by_slip_id,
        )
    else:
        if reason is not None:
            blocked.reason = reason.strip() or None
        if source_url is not None:
            blocked.source_url = source_url.strip() or None
        if created_by_slip_id is not None:
            blocked.created_by_slip_id = created_by_slip_id
    db.session.add(blocked)
    return blocked
