"""Retained stats for auto-pruned videos, keyed by the media file's SHA-256.

When a video is auto-deleted for inactivity (services/video_cleanup), its view
count is archived here against the file hash. If the exact same file is later
re-uploaded, the stats are restored — so a video that was pruned only because no
one watched it for a while keeps its history when it comes back."""
import datetime as _datetime

from shared import db


class VideoStatsArchive(db.Model):
    __tablename__ = "video_stats_archive"

    sha256 = db.Column(db.String(64), primary_key=True)
    views = db.Column(db.Integer, nullable=False, default=0)
    title = db.Column(db.String(200), nullable=True)
    archived_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def archive_video_stats(sha256, views, title=None):
    """Upsert archived stats for a file hash, keeping the highest view count seen."""
    sha256 = (sha256 or "").strip().lower()
    if not sha256 or len(sha256) != 64:
        return None
    views = int(views or 0)
    row = db.session.query(VideoStatsArchive).filter(VideoStatsArchive.sha256 == sha256).one_or_none()
    if row is None:
        row = VideoStatsArchive(sha256=sha256, views=views, title=(title or None))
        db.session.add(row)
    else:
        row.views = max(int(row.views or 0), views)
        if title:
            row.title = title
        row.archived_at = _datetime.datetime.utcnow()
    return row


def restore_video_views(sha256):
    """Archived view count for a file hash, or None if nothing is archived.
    The archive row is kept (a re-uploaded file may be pruned and restored again)."""
    sha256 = (sha256 or "").strip().lower()
    if not sha256:
        return None
    try:
        row = db.session.query(VideoStatsArchive).filter(VideoStatsArchive.sha256 == sha256).one_or_none()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return None
    return int(row.views) if row and row.views else None
