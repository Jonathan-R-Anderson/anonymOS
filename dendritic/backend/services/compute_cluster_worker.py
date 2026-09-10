"""The loop that dispatches clusters, and why it is not the rental drainer.

WHY A SECOND DRAINER
--------------------
`compute_rental_worker` runs one job per device at a time and blocks inside
`_await_remote` for that job's whole timeout. That is the correct shape for a
queue of unrelated jobs: they contend for the same hardware, and running two at
once on one device would oversubscribe it.

It is the wrong shape for a cluster. A cluster's units are N pieces of ONE
request that are meant to be on N different machines simultaneously; drained
serially they take N times as long and land wherever placement happens to send
each one — a cluster in name only. So cluster units are excluded from
`compute_rental.ordered_queue()` and this loop owns them instead, handing a
whole wave to distinct nodes at once (`compute_cluster.dispatch`).

Two drainers over one table is only safe because the split is total: the serial
one skips any job with a cluster_id, this one takes nothing else. If either side
of that ever became partial, both would claim the same row, one would lose the
race, and the submitter would be charged once for two executions.

ONE AT A TIME, AND ONLY THE LEADER
----------------------------------
`uwsgi.ini` runs four worker processes with `lazy-apps = true`, so every
module-level `start_*()` runs four times. Without the maintenance-leader gate
this loop would exist four times over, and four copies dispatching the same
cluster is not a slow site — it is four jobs sent for every one somebody paid
for, on volunteers' hardware.

WHY IT SLEEPS WHEN IDLE AND NOT WHEN BUSY
-----------------------------------------
Same reasoning as the rental drainer: an empty queue is the common case and
polling it costs nothing to nobody, while a cluster that has just been paid for
is somebody watching a page. So it backs off only when there was nothing to do.
"""

import threading

from shared import db

# Idle poll interval. Long enough that an empty queue is free, short enough that
# a cluster submitted into an empty queue starts within a few seconds.
_IDLE_SECONDS = 5

_stop = threading.Event()
_thread = None


def _drain_once(flask_app):
    """Dispatch one cluster. Returns True if any unit was actually sent.

    The return value is what stops a hot loop: a cluster that cannot be
    dispatched — nobody online, every node refusing — reports zero, and the
    caller sleeps rather than retrying the same refusal as fast as the network
    will answer.
    """
    from services.singleton_worker import is_maintenance_leader

    with flask_app.app_context():
        try:
            if not is_maintenance_leader():
                return False
            from services import compute_cluster

            cluster = compute_cluster.next_pending_cluster()
            if cluster is None:
                return False

            dispatched = compute_cluster.dispatch(cluster, flask_app=flask_app)
            flask_app.logger.info(
                "compute cluster: dispatched %d unit(s) of cluster %s (%s)",
                dispatched, getattr(cluster, "id", "?"),
                getattr(cluster, "status", "?"))
            return dispatched > 0
        finally:
            # The session goes back whether units ran, failed, or there was
            # nothing to do. A worker that leaks one holds a connection from a
            # pool sized for request handling, and an idle-in-transaction
            # session is how this site has taken itself down before.
            try:
                db.session.remove()
            except Exception:
                pass


def _loop(flask_app):
    while not _stop.is_set():
        ran = False
        try:
            ran = _drain_once(flask_app)
        except Exception:
            # One bad cluster must not stop every cluster after it. dispatch()
            # already contains per-unit failures; this catches what is outside
            # them — a database blip, a leader-lock error — and tries again
            # after a pause rather than killing the thread.
            flask_app.logger.exception("compute cluster worker failed")
            _stop.wait(timeout=_IDLE_SECONDS)
            continue
        if not ran:
            _stop.wait(timeout=_IDLE_SECONDS)


def start_compute_cluster_workers(flask_app):
    """Start the cluster drainer. Idempotent, never raises into startup."""
    global _thread

    if _thread is not None and _thread.is_alive():
        return _thread
    try:
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(flask_app,),
                                   name="compute-cluster", daemon=True)
        _thread.start()
    except Exception:
        flask_app.logger.exception("could not start the compute cluster worker")
    return _thread


def stop_compute_cluster_workers():
    """For tests: stop the loop."""
    _stop.set()
