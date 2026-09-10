"""Build a snapshot every hour, without anybody remembering to.

A snapshot that exists because somebody ran a command is a snapshot that is
several days old when it is finally needed. The whole value of the emergency
cache is that the copy is recent, and "recent" is a property of a schedule.

WHY IN-PROCESS AND NOT A CRONJOB
--------------------------------
Because the builder must run inside the serving process. A separate process has
to import the application to get a context, which re-runs the startup DDL
against a live database — that deadlocked the server once already and took the
site down twenty seconds after printing a success message.

ONE BUILDER, NOT ONE PER REPLICA
---------------------------------
An advisory lock, so scaling the backend does not multiply the work. Several
replicas each rendering the whole site every hour would be pure waste, and their
sequence numbers would race — two snapshots claiming the same sequence is the
one thing the rollback defence cannot tolerate.

The randomised delay is from the specification, and it matters for a reason
worth stating: every supporting service refreshing at :00 makes a load spike
that looks exactly like the traffic surge the cache exists to survive.
"""

import random
import threading
import time

from shared import app

# Roadmap default. The build is cheap enough that the interval is chosen for
# freshness rather than cost.
INTERVAL_SECONDS = 3600
# Up to five minutes of jitter, so a fleet does not rebuild in lockstep.
JITTER_SECONDS = 300
# Postgres advisory lock id. Distinct from every other one in this codebase.
ADVISORY_LOCK_ID = 771933

_started = False
_lock = threading.Lock()


def enabled():
    """Off unless explicitly turned on, and never without a publisher key.

    An unsigned snapshot is one no client will serve, so building them on a
    schedule would burn a render of the whole site every hour to produce
    something nobody can use.
    """
    if not app.config.get("SNAPSHOT_TIMER_ENABLED"):
        return False
    try:
        from services.snapshot_key import enabled as signing_enabled

        return signing_enabled()
    except Exception:
        return False


def _hold_leader_lock():
    """True when this replica is the one that should build.

    A session-scoped advisory lock: it is released when the connection goes,
    so a replica that dies does not leave the job wedged until somebody notices.
    """
    from sqlalchemy import text

    from shared import db

    try:
        return bool(db.session.execute(
            text("SELECT pg_try_advisory_lock(:id)"),
            {"id": ADVISORY_LOCK_ID}).scalar())
    except Exception:
        app.logger.exception("snapshot timer: could not take the leader lock")
        return False


def _release_leader_lock():
    from sqlalchemy import text

    from shared import db

    try:
        db.session.execute(text("SELECT pg_advisory_unlock(:id)"),
                           {"id": ADVISORY_LOCK_ID})
    except Exception:
        pass


def _loop():
    # A first build immediately would collide with startup, when the site is
    # still warming caches and a rendered page is not representative.
    time.sleep(120)
    while True:
        delay = INTERVAL_SECONDS + random.randint(0, JITTER_SECONDS)
        try:
            with app.app_context():
                if _hold_leader_lock():
                    try:
                        _build_once()
                    finally:
                        _release_leader_lock()
        except Exception:
            # A failed hour is a stale snapshot, not an outage. The previous
            # one stays active and this tries again next hour.
            app.logger.exception("snapshot timer: build failed")
        time.sleep(delay)


def _build_once():
    from services.snapshot import build_and_publish

    result = build_and_publish()
    if result.get("ok"):
        # Says WHY it rebuilt, not just that it did. "Nothing changed and we
        # rebuilt anyway" and "three pages changed" look identical without this,
        # and the first one is a bug worth noticing.
        app.logger.info(
            "snapshot timer: published sequence %s (%s routes, %s, %s; "
            "%s new object(s), %s reused)",
            result.get("sequence"), result.get("routes"),
            "signed" if result.get("signed") else "UNSIGNED",
            "reissued unchanged" if result.get("content_unchanged") else "content changed",
            result.get("changed_objects"), result.get("unchanged_objects"))
    else:
        app.logger.warning("snapshot timer: refused — %s", result.get("reason"))


def start():
    """Start the hourly builder once per process."""
    global _started
    with _lock:
        if _started or not enabled():
            return False
        _started = True
    # spawn_native_thread, not threading.Thread: gevent.patch_all makes
    # ContextVars greenlet-local, so a plain native thread shares the default
    # context and clobbers Flask's app context across threads. The helper gives
    # each thread its own copy.
    from shared import spawn_native_thread

    spawn_native_thread(target=_loop, name="snapshot-timer", daemon=True)
    app.logger.info("snapshot timer: hourly builds enabled (jitter up to %ds)",
                    JITTER_SECONDS)
    return True
