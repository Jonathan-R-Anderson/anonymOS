"""Content-addressed store for embedded NNTP source watermarks.

When a federated article carries its source watermark as embedded bytes (rather
than a URL), we store the image ONCE keyed by its SHA-256 and serve it
same-origin, so attribution is self-contained and survives the origin site
going offline. Deduped: many posts from one source share one row. Kept
lightweight (a small BLOB + a tiny serve route) instead of routing favicons
through the full Media/thumbnail/torrent pipeline.
"""
import datetime as _datetime
import hashlib

from shared import db


MAX_WATERMARK_BYTES = 256 * 1024  # favicons/logos are tiny; reject abusive embeds


class NntpSourceWatermark(db.Model):
    __tablename__ = "nntp_source_watermark"

    sha256 = db.Column(db.String(64), primary_key=True)
    mime = db.Column(db.String(64), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def store_watermark(data, mime):
    """Store watermark bytes (deduped by hash); return its sha256, or None if
    empty / too large / not an image type."""
    if not data or len(data) > MAX_WATERMARK_BYTES:
        return None
    mime = (mime or "").strip().lower() or "application/octet-stream"
    if not mime.startswith("image/"):
        return None
    digest = hashlib.sha256(data).hexdigest()
    if db.session.get(NntpSourceWatermark, digest) is None:
        db.session.add(NntpSourceWatermark(sha256=digest, mime=mime, data=data))
    return digest


def get_watermark(sha256):
    return db.session.get(NntpSourceWatermark, sha256)


def watermark_url_for(sha256):
    """Same-origin URL a stored watermark is served at."""
    return "/nntp-watermark/%s" % sha256
