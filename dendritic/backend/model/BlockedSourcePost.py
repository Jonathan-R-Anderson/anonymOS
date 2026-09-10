"""Durable blocklist of individual scraped/imported source posts, keyed by
(source_type, source_thread_id, source_post_id).

Scraped post content lives in per-source SQLite scraper databases that are often
mounted read-only, so a moderator "deleting" a scraped post cannot always remove
the underlying SQLite row. This Postgres-backed list records the deletion instead
and is consulted everywhere imported rows are read (thread display + sync), so a
blocked post is hidden regardless of SQLite writability, works for text-only
posts (no media hash to block), and stays hidden if a later scrape re-inserts the
row. Source name is stored for reference but intentionally NOT part of the match
key — thread identity elsewhere ignores source_name too (see aggregator_sync)."""
import datetime as _datetime

from shared import db

# Match services.aggregator_sync.config MAX_IMPORTED_SOURCE_ID_LENGTH (128) and
# MAX_IMPORTED_SOURCE_NAME_LENGTH (64); duplicated here to avoid an import cycle.
_MAX_ID_LEN = 128
_MAX_NAME_LEN = 64


class BlockedSourcePost(db.Model):
    __tablename__ = "blocked_source_post"

    id = db.Column(db.Integer, primary_key=True)
    source_type = db.Column(db.String(_MAX_NAME_LEN), nullable=False)
    source_name = db.Column(db.String(_MAX_NAME_LEN), nullable=True)
    source_thread_id = db.Column(db.String(_MAX_ID_LEN), nullable=False)
    source_post_id = db.Column(db.String(_MAX_ID_LEN), nullable=False)
    reason = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)

    __table_args__ = (
        db.UniqueConstraint(
            "source_type", "source_thread_id", "source_post_id",
            name="uq_blocked_source_post",
        ),
        db.Index("ix_blocked_source_post_thread", "source_type", "source_thread_id"),
    )


def _norm(value):
    return str(value or "").strip()


def block_source_post(source_type, source_name, source_thread_id, source_post_id,
                      reason=None, created_by_slip_id=None):
    """Idempotently record that a scraped post is deleted/hidden. Returns the row
    (existing or new), or None if the identity is incomplete."""
    st = _norm(source_type)[:_MAX_NAME_LEN]
    tid = _norm(source_thread_id)[:_MAX_ID_LEN]
    pid = _norm(source_post_id)[:_MAX_ID_LEN]
    if not st or not tid or not pid:
        return None
    existing = (
        db.session.query(BlockedSourcePost)
        .filter(
            BlockedSourcePost.source_type == st,
            BlockedSourcePost.source_thread_id == tid,
            BlockedSourcePost.source_post_id == pid,
        )
        .one_or_none()
    )
    if existing is not None:
        if reason:
            existing.reason = reason.strip()[:500] or None
        return existing
    row = BlockedSourcePost(
        source_type=st,
        source_name=(_norm(source_name)[:_MAX_NAME_LEN] or None),
        source_thread_id=tid,
        source_post_id=pid,
        reason=((reason or "").strip()[:500] or None),
        created_by_slip_id=created_by_slip_id,
    )
    db.session.add(row)
    return row


def unblock_source_post(source_type, source_thread_id, source_post_id):
    """Remove a block (restore the scraped post). Returns True if a row was removed."""
    st = _norm(source_type)[:_MAX_NAME_LEN]
    tid = _norm(source_thread_id)[:_MAX_ID_LEN]
    pid = _norm(source_post_id)[:_MAX_ID_LEN]
    if not st or not tid or not pid:
        return False
    deleted = (
        db.session.query(BlockedSourcePost)
        .filter(
            BlockedSourcePost.source_type == st,
            BlockedSourcePost.source_thread_id == tid,
            BlockedSourcePost.source_post_id == pid,
        )
        .delete(synchronize_session=False)
    )
    return bool(deleted)


def blocked_source_post_ids(source_type, source_thread_id):
    """Set of blocked source_post_ids for one thread. Session-guarded so a stray
    DB error never breaks thread rendering — worst case nothing is filtered."""
    st = _norm(source_type)[:_MAX_NAME_LEN]
    tid = _norm(source_thread_id)[:_MAX_ID_LEN]
    if not st or not tid:
        return set()
    try:
        rows = (
            db.session.query(BlockedSourcePost.source_post_id)
            .filter(
                BlockedSourcePost.source_type == st,
                BlockedSourcePost.source_thread_id == tid,
            )
            .all()
        )
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return set()
    return {row[0] for row in rows if row[0]}
