import datetime as _datetime
import secrets

from shared import db


# The ported RTMP server identifies a stream account by an Ethereum-address
# shaped token (`0x` + 40 hex) — see rtmp/utils/files.py sanitize_eth_address.
# Each slip is assigned a synthetic account of that shape (NOT a real wallet);
# it is only an opaque per-slip stream identifier and storage bucket name.
def generate_stream_account() -> str:
    return "0x" + secrets.token_hex(20)


def generate_stream_secret() -> str:
    return secrets.token_hex(24)


class Stream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="CASCADE"), nullable=False, unique=True)
    # Public account half of the stream key and the on-disk storage bucket.
    stream_account = db.Column(db.String(64), nullable=False, unique=True)
    # Secret half of the stream key; rotating it invalidates the old ingest URL.
    stream_secret = db.Column(db.String(64), nullable=False)
    title = db.Column(db.String(120), nullable=True)
    is_live = db.Column(db.Boolean, nullable=False, default=False)
    last_client_ip = db.Column(db.String(64), nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    @property
    def stream_key(self) -> str:
        """The full RTMP stream key the streamer publishes with."""
        return "%s:%s" % (self.stream_account, self.stream_secret)


def get_or_create_stream_for_slip(slip_id: int) -> "Stream":
    stream = db.session.query(Stream).filter(Stream.slip_id == slip_id).one_or_none()
    if stream is not None:
        return stream
    stream = Stream(
        slip_id=slip_id,
        stream_account=generate_stream_account(),
        stream_secret=generate_stream_secret(),
    )
    db.session.add(stream)
    db.session.flush()
    return stream


def get_stream_by_account(stream_account: str) -> "Stream":
    normalized = (stream_account or "").strip().lower()
    if not normalized:
        return None
    return db.session.query(Stream).filter(Stream.stream_account == normalized).one_or_none()
