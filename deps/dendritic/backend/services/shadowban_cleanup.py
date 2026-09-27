"""Auto-delete content authored by shadowbanned identities once it ages out.

A shadowbanned user's posts/videos are hidden from everyone else immediately;
this sweep then permanently removes that content once it is older than
`shadowban_delete_days` (default 30). A background thread runs hourly. Setting
the limit to 0 disables deletion (content stays hidden forever instead).
"""
import datetime as _datetime

import shared
from shared import app, db
from model.SiteSetting import get_setting


SETTING_KEY = "shadowban_delete_days"
DEFAULT_DAYS = 30
_SWEEP_INTERVAL_SECONDS = 3600


def shadowban_delete_days():
    """Configured age (days) after which shadowbanned content is deleted.
    0 (or invalid/negative) disables deletion."""
    raw = get_setting(SETTING_KEY, str(DEFAULT_DAYS))
    try:
        return max(0, int(str(raw).strip()))
    except (TypeError, ValueError):
        return DEFAULT_DAYS


def run_shadowban_cleanup():
    """Delete shadowbanned posts + videos older than the retention window.
    Returns the number of items deleted."""
    days = shadowban_delete_days()
    if days <= 0:
        return 0
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
    from sqlalchemy import func
    from model.ShadowBan import shadowbanned_poster_ids, shadowbanned_slip_ids
    from model.Post import Post
    from model.PostRemoval import PostRemoval
    from model.ThreadPosts import ThreadPosts

    deleted = 0

    # --- posts / threads (chan) ---
    poster_ids = shadowbanned_poster_ids()
    if poster_ids:
        post_ids = [
            row[0] for row in (
                db.session.query(Post.id)
                .filter(
                    Post.poster.in_(poster_ids),
                    Post.source_type == "local",
                    Post.datetime < cutoff,
                )
                .all()
            )
        ]
        for post_id in post_ids:
            try:
                post = db.session.query(Post).filter(Post.id == post_id).one_or_none()
                if post is None:
                    continue  # already removed (e.g. its thread was deleted)
                first_id = (
                    db.session.query(func.min(Post.id))
                    .filter(Post.thread == post.thread)
                    .scalar()
                )
                if first_id == post.id:
                    # OP: delete the whole thread rather than leave it headless.
                    ThreadPosts().delete(post.thread)
                else:
                    PostRemoval().delete(post_id)
                deleted += 1
            except Exception:
                db.session.rollback()
                app.logger.exception("Shadowban cleanup failed for post %s", post_id)

    # --- videos ---
    slip_ids = shadowbanned_slip_ids()
    if slip_ids:
        from model.Video import Video
        from services.video_cleanup import _delete_video
        videos = (
            db.session.query(Video)
            .filter(Video.slip_id.in_(slip_ids), Video.created_at < cutoff)
            .all()
        )
        removed_videos = 0
        for video in videos:
            try:
                _delete_video(video)
                removed_videos += 1
            except Exception:
                db.session.rollback()
                app.logger.exception("Shadowban cleanup failed for video %s", getattr(video, "id", None))
        if removed_videos:
            db.session.commit()
            deleted += removed_videos

    return deleted


def start_shadowban_cleanup(flask_app):
    def _loop():
        import time as _time
        _time.sleep(60)
        while True:
            try:
                with flask_app.app_context():
                    removed = run_shadowban_cleanup()
                    if removed:
                        flask_app.logger.info("Shadowban cleanup deleted %d item(s)", removed)
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("Shadowban cleanup failed")
            _time.sleep(_SWEEP_INTERVAL_SECONDS)

    shared.spawn_native_thread(target=_loop, name="shadowban-cleanup", daemon=True)
