"""The background pass the newsroom's numbers depend on.

WHY THIS EXISTS AT ALL
----------------------
Two functions were written and nothing called them, which is a specific kind of
broken: the code is right, the tests pass, and the feature does not work.

  * `story_votes.recompute_all()` folds votes into `NewsStory.score`. Without a
    caller, a vote changes a row nobody reads -- the front-page rail orders by a
    score that was last correct when something else happened to rebuild it.
  * `news_rail.refresh()` rebuilds the cached rail. Without a caller, the TTL is
    the only thing that ever repairs a rail, so a rail emptied by a transient
    database failure stays empty for its full life.

WHY THE FRONT PAGE CANNOT DO THIS ITSELF
-----------------------------------------
It is the most-visited route on the site and it is a cached render. This codebase
has already been taken down once by making `/` do work -- an inline news sync
produced 504s on the front page while the API stayed healthy. Recomputing scores
in a request handler would be the same mistake with a different name.

WHY THE INTERVAL IS WHAT IT IS
------------------------------
Vote-driven reordering is EVENTUALLY CONSISTENT BY DESIGN, and that is stated on
the vote endpoint too. Publishing invalidates the rail immediately; voting does
not, because votes arrive at a rate set by whoever is clicking and invalidating
per vote turns a cached front page into an uncached one. Five minutes is short
enough that a story climbing the rail feels responsive and long enough that the
pass is never the reason anything is slow.

The order inside a pass matters: scores first, then the rail, so a rebuild
carries the numbers that were just computed rather than the previous set.
"""

import os
import threading

from shared import db


_INTERVAL_SECONDS = int(os.getenv("NEWSROOM_RECOMPUTE_INTERVAL_SECONDS", "300") or 300)

# Nothing is published at boot, and a pass that runs before the database is
# reachable just logs a failure that looks like a fault.
_FIRST_RUN_DELAY = int(os.getenv("NEWSROOM_RECOMPUTE_FIRST_RUN_DELAY", "120") or 120)

_stop = threading.Event()
_thread = None


def _loop(flask_app):
    _stop.wait(timeout=_FIRST_RUN_DELAY)
    while not _stop.is_set():
        try:
            with flask_app.app_context():
                from services.singleton_worker import is_maintenance_leader

                # Leader-gated: several gevent workers each recomputing the same
                # scores would be wasted work and a write conflict, not a
                # speed-up.
                if is_maintenance_leader():
                    from services import news_rail, story_votes

                    moved = story_votes.recompute_all()

                    # Rebuilt unconditionally, not only when a score moved. The
                    # rail also expires, and a rail emptied by a transient
                    # failure has no other repair path -- that is half of why
                    # this loop exists.
                    news_rail.refresh()

                    if moved:
                        flask_app.logger.info(
                            "newsroom: %d story score(s) recomputed", moved)
        except Exception:
            # A failed pass must never kill the thread. Scores that stop being
            # recomputed are invisible: the site keeps working and the ordering
            # quietly stops meaning anything.
            flask_app.logger.exception("newsroom recompute pass failed")
        finally:
            try:
                with flask_app.app_context():
                    db.session.remove()
            except Exception:
                pass
        _stop.wait(timeout=_INTERVAL_SECONDS)


def start_newsroom_recompute(flask_app):
    """Start the pass. Idempotent, and never raises into startup."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return _thread
    try:
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="newsroom-recompute",
            daemon=True)
        _thread.start()
    except Exception:
        flask_app.logger.exception("could not start the newsroom recompute pass")
    return _thread


def stop_newsroom_recompute():
    _stop.set()
