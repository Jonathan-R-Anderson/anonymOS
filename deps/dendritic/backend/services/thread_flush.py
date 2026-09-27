"""Flush threads that nobody has directly viewed in a while.

A thread's `last_viewed_at` is refreshed every time its thread page is opened
(a "direct view"). A sysop-wide setting (`thread_unviewed_delete_days`, default
30) sets how long a thread may go with no direct view AND no new activity before
it is deleted — a thread that is still being read or posted to is kept. A
background thread runs the sweep hourly. Setting the limit to 0 disables it.
"""
import datetime as _datetime

from sqlalchemy import func

import shared
from shared import db
from model.Thread import Thread
from model.SiteSetting import get_setting


SETTING_KEY = "thread_unviewed_delete_days"
DEFAULT_DAYS = 30
_SWEEP_INTERVAL_SECONDS = 3600


def unviewed_delete_days():
    """Configured limit in days. 0 (or invalid/negative) disables flushing."""
    raw = get_setting(SETTING_KEY, str(DEFAULT_DAYS))
    try:
        return max(0, int(str(raw).strip()))
    except (TypeError, ValueError):
        return DEFAULT_DAYS


def run_thread_flush():
    """Delete threads with no direct view (and no bump) since the cutoff.
    Returns the number of threads deleted."""
    days = unviewed_delete_days()
    if days <= 0:
        return 0
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
    # last_viewed_at is the direct-view timestamp; fall back to last_updated so a
    # freshly-created (never-yet-viewed) or recently-bumped thread isn't purged.
    candidates = (
        db.session.query(Thread)
        .filter(func.coalesce(Thread.last_viewed_at, Thread.last_updated) < cutoff)
        .all()
    )
    from services.aggregator_sync.media import delete_thread
    deleted = 0
    for thread in candidates:
        try:
            delete_thread(thread)
            deleted += 1
        except Exception:
            db.session.rollback()
            from shared import app
            app.logger.exception("Thread flush failed for thread %s", getattr(thread, "id", None))
    if deleted:
        db.session.commit()
    return deleted


def start_thread_flush(flask_app):
    def _loop():
        import time as _time
        _time.sleep(75)
        while True:
            try:
                with flask_app.app_context():
                    removed = run_thread_flush()
                    if removed:
                        flask_app.logger.info("Thread flush deleted %d unviewed thread(s)", removed)
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("Thread flush failed")
            _time.sleep(_SWEEP_INTERVAL_SECONDS)

    shared.spawn_native_thread(target=_loop, name="thread-flush", daemon=True)
