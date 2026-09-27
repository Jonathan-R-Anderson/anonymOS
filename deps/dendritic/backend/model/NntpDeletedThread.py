"""Tombstones for federated threads a moderator deleted.

Every imported/published thread has a stable unique identifier — its root
Message-ID (`nntp_article.thread_root`). When such a thread is deleted locally
we record that identifier here; while it's tombstoned, the sync refuses to
re-import the same thread, so a mod's deletion sticks instead of the thread
re-populating on the next pull. Tombstones expire after
`nntpchan_tombstone_days` (default 30; 0 disables the feature) — after that the
thread may return if the peer still carries it.
"""
import datetime as _datetime

from shared import db
from model.SiteSetting import get_setting


TOMBSTONE_DAYS_SETTING = "nntpchan_tombstone_days"
DEFAULT_TOMBSTONE_DAYS = 30


class NntpDeletedThread(db.Model):
    __tablename__ = "nntp_deleted_thread"

    identifier = db.Column(db.String(250), primary_key=True)   # thread root Message-ID
    newsgroup = db.Column(db.String(255), nullable=True)
    deleted_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def tombstone_days():
    raw = get_setting(TOMBSTONE_DAYS_SETTING, str(DEFAULT_TOMBSTONE_DAYS))
    try:
        return max(0, int(str(raw).strip()))
    except (TypeError, ValueError):
        return DEFAULT_TOMBSTONE_DAYS


def tombstone_thread(identifier, newsgroup=None):
    """Record (or refresh) a deleted federated thread. No-op for a blank id."""
    if not identifier:
        return None
    row = db.session.get(NntpDeletedThread, identifier)
    now = _datetime.datetime.utcnow()
    if row is None:
        row = NntpDeletedThread(identifier=identifier, newsgroup=newsgroup, deleted_at=now)
        db.session.add(row)
    else:
        row.deleted_at = now
        if newsgroup:
            row.newsgroup = newsgroup
    return row


def is_thread_tombstoned(identifier):
    """True if this thread was deleted within the retention window."""
    if not identifier:
        return False
    days = tombstone_days()
    if days <= 0:
        return False  # feature disabled
    try:
        row = db.session.get(NntpDeletedThread, identifier)
    except Exception:
        return False
    if row is None or row.deleted_at is None:
        return False
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
    return row.deleted_at >= cutoff


def purge_expired_tombstones():
    """Drop tombstones past the retention window. Returns the count removed."""
    days = tombstone_days()
    if days <= 0:
        return 0
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
    try:
        removed = (
            db.session.query(NntpDeletedThread)
            .filter(NntpDeletedThread.deleted_at < cutoff)
            .delete(synchronize_session=False)
        )
        return removed or 0
    except Exception:
        db.session.rollback()
        return 0


def list_tombstones(limit=200):
    return (
        db.session.query(NntpDeletedThread)
        .order_by(NntpDeletedThread.deleted_at.desc())
        .limit(limit)
        .all()
    )
