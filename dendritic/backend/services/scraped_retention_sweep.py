"""Purge scraped threads that have fallen out of the scrape window.

WHAT THIS EXISTS FOR
--------------------
The data node filled to 95% and the object store refused to start, which took all
media down. The dominant consumer was mirrored scraped media that nothing was
ever going to look at again -- threads whose last post was days or weeks old.
Bounding how far back we keep scraped content is what stops that recurring.

Two clocks, both editable in the admin panel (see services/scraped_retention.py):
  * content  -- newest post older than `scraped_thread_max_age_hours` (24) ->
                the thread and its mirrored media are deleted.
  * metadata -- the identity stub left behind is forgotten after
                `scraped_metadata_retention_days` (30).

WHAT IT WILL NOT DO
-------------------
It never deletes a thread that has LOCAL REPLIES. In this schema an imported
thread's Postgres Post rows ARE the replies local users wrote -- the scraped
posts live in the per-source SQLite and are never copied in -- so deleting such
a thread destroys user-authored content that no re-scrape can restore.

A human running "purge this source" from the admin panel may make that trade
deliberately (services/source_purge.py surfaces the count first). An unattended
timer must not. Those threads are counted and logged as `kept_local_replies` so
the exemption is visible rather than silent, and they are small: the disk cost
is the media, and the media of a thread someone is still talking in is not the
problem this sweep is solving.
"""
import datetime as _datetime

from model.ImportedMedia import ImportedMedia
from model.Post import Post
from model.ScrapedThreadStub import ScrapedThreadStub, record_stub
from model.Thread import Thread
from services.scraped_retention import content_cutoff, metadata_cutoff
from shared import app, db


# Bounded so one sweep cannot hold a long transaction or a long lock; the timer
# comes back around and picks up the rest.
MAX_THREADS_PER_SWEEP = 200


def _threads_out_of_window(cutoff, limit=MAX_THREADS_PER_SWEEP):
    return (
        db.session.query(Thread)
        .filter(
            Thread.source_type.isnot(None),
            Thread.source_type != "local",
            Thread.last_updated.isnot(None),
            Thread.last_updated < cutoff,
        )
        .order_by(Thread.last_updated.asc())
        .limit(limit)
        .all()
    )


def _local_reply_counts(thread_ids):
    if not thread_ids:
        return {}
    rows = (
        db.session.query(Post.thread, db.func.count(Post.id))
        .filter(Post.thread.in_(thread_ids))
        .group_by(Post.thread)
        .all()
    )
    return {tid: int(count or 0) for tid, count in rows}


def sweep(dry_run=False):
    """Purge out-of-window scraped threads and expire old stubs.

    Returns a summary dict; never raises into its caller (it runs on a timer).
    """
    summary = {
        "enabled": False, "examined": 0, "purged": 0, "media_deleted": 0,
        "kept_local_replies": 0, "stubs_expired": 0, "errors": 0, "dry_run": bool(dry_run),
    }
    cutoff = content_cutoff()
    if cutoff is None:
        # Age-based purging is switched off. Stub expiry still runs: stubs are
        # meaningless once nothing is being purged, and letting them accumulate
        # forever would be its own slow leak.
        summary["stubs_expired"] = _expire_stubs(dry_run=dry_run)
        return summary

    summary["enabled"] = True
    summary["cutoff"] = cutoff.isoformat()
    try:
        threads = _threads_out_of_window(cutoff)
    except Exception:
        db.session.rollback()
        app.logger.exception("retention sweep: could not list out-of-window threads")
        summary["errors"] += 1
        return summary

    summary["examined"] = len(threads)
    reply_counts = _local_reply_counts([t.id for t in threads])

    from services.aggregator_sync.media import delete_thread

    for thread in threads:
        replies = reply_counts.get(thread.id, 0)
        if replies:
            # See the module docstring: an unattended sweep never destroys
            # user-authored replies.
            summary["kept_local_replies"] += 1
            continue

        media_count = 0
        try:
            media_count = (
                db.session.query(db.func.count(ImportedMedia.id))
                .filter(ImportedMedia.thread_id == thread.id)
                .scalar()
            ) or 0
        except Exception:
            db.session.rollback()
            app.logger.exception("retention sweep: media count failed for thread %s", thread.id)

        if dry_run:
            summary["purged"] += 1
            summary["media_deleted"] += media_count
            continue

        try:
            # Record the identity BEFORE the delete -- afterwards there is
            # nothing left to read the source triple from.
            record_stub(thread, post_count=replies, media_count=media_count,
                        reason="out_of_window")
            delete_thread(thread)      # media, mappings, and cache invalidation
            db.session.commit()
            summary["purged"] += 1
            summary["media_deleted"] += media_count
        except Exception:
            db.session.rollback()
            summary["errors"] += 1
            app.logger.exception("retention sweep: could not purge thread %s", thread.id)

    summary["stubs_expired"] = _expire_stubs(dry_run=dry_run)
    if summary["purged"] or summary["stubs_expired"]:
        app.logger.info(
            "retention sweep: purged %d thread(s) / %d media, kept %d with local replies, "
            "expired %d stub(s)",
            summary["purged"], summary["media_deleted"],
            summary["kept_local_replies"], summary["stubs_expired"],
        )
    return summary


def _expire_stubs(dry_run=False):
    """Forget stubs whose metadata retention has elapsed."""
    cutoff = metadata_cutoff()
    if cutoff is None:
        return 0
    try:
        query = db.session.query(ScrapedThreadStub).filter(
            ScrapedThreadStub.purged_at < cutoff
        )
        if dry_run:
            return query.count()
        removed = query.delete(synchronize_session=False)
        db.session.commit()
        return int(removed or 0)
    except Exception:
        db.session.rollback()
        app.logger.exception("retention sweep: could not expire metadata stubs")
        return 0


def preview():
    """What a sweep would do right now, without doing it. For the admin panel."""
    return sweep(dry_run=True)


# Runs on the same cadence and under the same leader lock as the retirement
# sweep. Leader-gated because it deletes media and commits per thread; four
# uWSGI workers doing that concurrently would contend on the same rows and pin
# four connections doing identical work.
_SWEEP_INTERVAL_SECONDS = 3600


def start_scraped_retention_sweep(flask_app):
    def _loop():
        import time as _time

        # Offset from the retirement sweep so the two do not both wake at boot
        # and fight for the leader lock and the connection pool.
        _time.sleep(300)
        while True:
            try:
                with flask_app.app_context():
                    from services.singleton_worker import is_maintenance_leader

                    if is_maintenance_leader():
                        sweep()
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("Scraped-content retention sweep failed")
            _time.sleep(_SWEEP_INTERVAL_SECONDS)

    import shared as _shared
    _shared.spawn_native_thread(target=_loop, name="scraped-retention-sweep", daemon=True)
