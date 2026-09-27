"""The schedule for the I2P peer probe -- and why it is a schedule at all.

THIS MUST NOT RUN IN A REQUEST HANDLER, EVER
--------------------------------------------
The obvious reading of "ping the node before returning it as a peer" is to probe
inside GET /.well-known/syndichan/storage-node.json. That would be the same
mistake, in the same shape, as the inline news sync that once ran inside GET /
and 504'd the front page while the API stayed perfectly healthy.

The numbers here are worse than they were there:

  * an I2P round trip is 0.5-2 SECONDS when everything is warm;
  * a DEAD destination does not fail fast, it waits out the full timeout, and the
    dead ones are exactly the ones being looked for;
  * a node with no live peer refetches that URL every 60 SECONDS, so load peaks
    precisely during the outage the probe is meant to end;
  * nginx sets auth_request off for that location, so there is no challenge and
    no cache in front of it -- every fetch occupies a gevent core for the whole
    handler.

Probing inline would have made the bootstrap endpoint the slowest thing on the
site and taken the network down harder than the stale list did. So the sweep runs
here, the verdict is cached in the peer_liveness table, and the request path does
one indexed read.

Concurrency (in peer_liveness.probe_all) and backgrounding solve two DIFFERENT
problems and both are needed: concurrency makes a sweep cost one timeout instead
of one per dead peer; backgrounding keeps even that quick sweep off an endpoint
every node on the network polls.

VERDICT IN THE DATABASE, NOT IN MEMORY
--------------------------------------
uWSGI runs four workers with lazy-apps. This loop runs in exactly ONE of them
(is_maintenance_leader), while any of the four may serve the bootstrap document,
so an in-process cache would leave three workers unfiltered.
"""

import os
import threading

from shared import db

# One sweep per heartbeat interval, so a verdict is never staler than one beat
# and three strikes span ~15 minutes -- long enough that a peer is not evicted
# for a bad moment. A useful side effect: probing live destinations every five
# minutes keeps their LeaseSets warm in our router, so steady-state probes land
# in the sub-second band and only genuinely dead ones ever burn the full timeout.
_INTERVAL_SECONDS = int(os.getenv("PEER_PROBE_INTERVAL_SECONDS", "300") or 300)

# I2P tunnels are not up at boot. Probing into a router that is still building
# them would score healthy peers as unreachable for the first few minutes.
_FIRST_RUN_DELAY = int(os.getenv("PEER_PROBE_FIRST_RUN_DELAY", "180") or 180)

_stop = threading.Event()
_thread = None


def _loop(flask_app):
    _stop.wait(timeout=_FIRST_RUN_DELAY)
    while not _stop.is_set():
        try:
            with flask_app.app_context():
                from services.singleton_worker import is_maintenance_leader

                if is_maintenance_leader():
                    from services.peer_liveness import sweep

                    summary = sweep()
                    if summary.get("probed"):
                        flask_app.logger.info(
                            "peer liveness: probed %d destinations "
                            "(%d live, %d gone, %d unhealthy, %d withheld)",
                            summary["probed"], summary.get("live", 0),
                            summary.get("gone", 0), summary.get("unhealthy", 0),
                            summary.get("withheld", 0))
        except Exception:
            flask_app.logger.exception("peer liveness sweep failed")
        finally:
            try:
                with flask_app.app_context():
                    db.session.remove()
            except Exception:
                pass
        _stop.wait(timeout=_INTERVAL_SECONDS)


def start_peer_liveness(flask_app):
    """Start the sweep. Idempotent, and never raises into startup."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return _thread
    try:
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="peer-liveness", daemon=True)
        _thread.start()
    except Exception:
        flask_app.logger.exception("could not start the peer liveness sweep")
    return _thread


def stop_peer_liveness():
    _stop.set()
