"""Prune videos that haven't been watched in a while, to reclaim server space.

A sysop-wide setting (`video_inactivity_delete_days`, default 30) sets how many
days a video may go without being viewed before it is deleted. A video's
"last seen" (`Video.last_seen_at`) is refreshed every time its watch page is
opened, so any view resets the timer. A background thread runs the sweep hourly;
it can also be invoked directly. Setting the limit to 0 disables pruning.
"""
import datetime as _datetime

import shared
from shared import app, db
from model.Video import Video
from model.Media import Media
from model.SiteSetting import get_setting


SETTING_KEY = "video_inactivity_delete_days"
DEFAULT_DAYS = 30
_SWEEP_INTERVAL_SECONDS = 3600


def inactivity_delete_days():
    """The configured limit in days. 0 (or invalid/negative) disables pruning."""
    raw = get_setting(SETTING_KEY, str(DEFAULT_DAYS))
    try:
        days = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_DAYS
    return max(0, days)


def _delete_video(video):
    """Delete a video row (its comments cascade) and its backing media + file.
    Before deletion, archive the view stats against the file hash so a later
    re-upload of the same file restores them."""
    media_id = video.media_id
    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    sha256 = getattr(media, "sha256", None) if media is not None else None
    if sha256:
        try:
            from model.VideoStatsArchive import archive_video_stats
            archive_video_stats(sha256, video.views, video.title)
        except Exception:
            app.logger.exception("Failed archiving stats for pruned video %s", getattr(video, "id", None))
    db.session.delete(video)
    db.session.flush()  # cascade-delete comments before touching the media row
    if media is not None:
        try:
            media.delete_attachment()
        except Exception:
            app.logger.exception("Failed deleting media attachment %s during video prune", media_id)
        db.session.delete(media)


def run_video_cleanup():
    """Delete every video not seen within the retention window. Returns the count."""
    days = inactivity_delete_days()
    if days <= 0:
        return 0
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
    # last_seen_at is set on upload and refreshed on every watch. A NULL value
    # (shouldn't happen after the migration defaults it) is treated as "unknown
    # age" and left alone rather than pruned.
    candidates = (
        db.session.query(Video)
        .filter(Video.last_seen_at.isnot(None), Video.last_seen_at < cutoff)
        .all()
    )
    deleted = 0
    for video in candidates:
        _delete_video(video)
        deleted += 1
    if deleted:
        db.session.commit()
    return deleted


def start_video_cleanup(flask_app):
    def _loop():
        import time as _time
        _time.sleep(45)
        while True:
            try:
                with flask_app.app_context():
                    removed = run_video_cleanup()
                    if removed:
                        flask_app.logger.info("Video cleanup pruned %d unwatched video(s)", removed)
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("Video inactivity cleanup failed")
            _time.sleep(_SWEEP_INTERVAL_SECONDS)

    shared.spawn_native_thread(target=_loop, name="video-cleanup", daemon=True)
