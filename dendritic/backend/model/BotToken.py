"""Per-slip bot API credentials: a token bound to a dedicated source IP.

A slip owner registers the IP address their bot posts from and receives a token
(shown once). The bot posting API (blueprints/bot_api.py) requires BOTH a valid
token AND that the request originates from that registered IP. The raw token is
never stored — only its SHA-256 hash, which doubles as the lookup key (the token
is high-entropy random, so an unsalted hash is safe and directly queryable).
"""
import datetime as _datetime
import hashlib

from shared import db

_TOKEN_BYTES = 32  # 32 bytes -> 64 hex chars


def hash_token(raw):
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


class BotToken(db.Model):
    __tablename__ = "bot_token"
    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    ip_address = db.Column(db.String(64), nullable=False)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    label = db.Column(db.String(80), nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )
    last_used_at = db.Column(db.DateTime, nullable=True)
    __table_args__ = (
        db.UniqueConstraint("slip_id", "ip_address", name="uq_bot_token_slip_ip"),
    )


def create_bot_token(slip_id, ip_address, label=None):
    """Create (rotating any existing token for this slip+IP) and return
    (raw_token, BotToken). The raw token is only available here — store the hash."""
    import secrets
    ip_address = (ip_address or "").strip()[:64]
    # One token per (slip, IP): drop any prior one so re-registering rotates it.
    db.session.query(BotToken).filter(
        BotToken.slip_id == slip_id, BotToken.ip_address == ip_address
    ).delete(synchronize_session=False)
    raw = secrets.token_hex(_TOKEN_BYTES)
    record = BotToken(
        slip_id=slip_id,
        ip_address=ip_address,
        token_hash=hash_token(raw),
        label=(label or "").strip()[:80] or None,
    )
    db.session.add(record)
    db.session.commit()
    return raw, record


def bot_token_for(raw_token):
    """Look up a credential by its raw token, or None."""
    raw = (raw_token or "").strip()
    if not raw:
        return None
    return db.session.query(BotToken).filter(
        BotToken.token_hash == hash_token(raw)
    ).one_or_none()


def bot_tokens_for_slip(slip_id):
    return (
        db.session.query(BotToken)
        .filter(BotToken.slip_id == slip_id)
        .order_by(BotToken.created_at.desc())
        .all()
    )


def touch_bot_token(record):
    """Record last-used time; best-effort."""
    try:
        record.last_used_at = _datetime.datetime.utcnow()
        db.session.add(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
