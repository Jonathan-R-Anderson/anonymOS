"""Runs the retention sweep in the background, on the maintenance leader only.

Same shape as `services/peer_liveness_loop.py`: a daemon thread, gated by
`is_maintenance_leader()` so that four gevent workers do not each try to delete
the same submissions at the same time.

WHY HOURLY AND NOT MORE OFTEN
-----------------------------
Retention here is measured in months and years. An hourly pass makes a deletion
at most an hour late, which is immaterial against a 90-day schedule, and keeps
the sweep off the critical path of anything. A minute-by-minute pass would buy
nothing and would mean the deletion path -- the one piece of this feature that
destroys data irrecoverably -- runs sixty times more often for no benefit.

WHY IT DOES NOT RUN AT STARTUP
------------------------------
A delay before the first pass, for the same reason the peer prober has one: a
process that has just come up may not have a usable object store yet, and a
sweep that cannot reach storage defers every row it looks at. Deferring is safe
but it fills the log with warnings that look like a fault.
"""

import os
import threading

from shared import db


_INTERVAL_SECONDS = int(os.getenv("REPORT_RETENTION_INTERVAL_SECONDS", "3600") or 3600)
_FIRST_RUN_DELAY = int(os.getenv("REPORT_RETENTION_FIRST_RUN_DELAY", "300") or 300)

_stop = threading.Event()
_thread = None


def _loop(flask_app):
    _stop.wait(timeout=_FIRST_RUN_DELAY)
    while not _stop.is_set():
        try:
            with flask_app.app_context():
                from services.singleton_worker import is_maintenance_leader

                if is_maintenance_leader():
                    from services.report_retention import sweep

                    summary = sweep()
                    if summary.get("due"):
                        flask_app.logger.info(
                            "report retention: %d due, %d expired, %d deferred",
                            summary["due"], summary["expired"],
                            summary["deferred"])
        except Exception:
            # Never let a failed sweep kill the thread: retention that stops
            # running silently is how data outlives the policy that promised
            # it would not.
            flask_app.logger.exception("report retention sweep failed")
        finally:
            try:
                with flask_app.app_context():
                    db.session.remove()
            except Exception:
                pass
        _stop.wait(timeout=_INTERVAL_SECONDS)


def start_report_retention(flask_app):
    """Start the sweep. Idempotent, and never raises into startup."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return _thread
    try:
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="report-retention", daemon=True)
        _thread.start()
    except Exception:
        flask_app.logger.exception("could not start the report retention sweep")
    return _thread


def stop_report_retention():
    _stop.set()
