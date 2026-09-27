"""The timer that keeps the arcade's content on the DHT.

WHY THIS FILE EXISTS AT ALL
---------------------------
services/codeplay_content.publish_to_dht() was written, wired to an admin
button, and described on the admin page as the thing that puts the durable copy
on the network. It had never run: 267 content rows, 0 published snapshots. The
button was the only trigger and nobody had pressed it.

So the lesson is not "add another publisher", it is "a publish path with no
schedule is a publish path that does not happen". This is the schedule.

LEADER-GATED, LIKE EVERY OTHER SWEEP HERE
-----------------------------------------
uWSGI runs several worker processes, so an ungated loop would run one copy per
worker — four simultaneous uploads of the same ten documents, racing on the same
SiteSetting rows. is_maintenance_leader() is the existing lock for exactly this,
and the pattern is copied from services/media_rescan.py rather than reinvented.
"""

import threading

from shared import db

# Hourly. The content changes when somebody edits a collection or a course is
# deployed, neither of which is frequent — and publish() skips documents whose
# digest is unchanged, so a quiet hour costs one hash per document and no
# network traffic at all.
_INTERVAL_SECONDS = 3600

# Long enough for the node bridge and the DHT gateway to be up. Publishing into
# a sidecar that has not finished booting just logs failures for a minute.
_FIRST_RUN_DELAY = 180

_stop = threading.Event()
_thread = None


def _loop(flask_app):
    _stop.wait(timeout=_FIRST_RUN_DELAY)
    while not _stop.is_set():
        try:
            with flask_app.app_context():
                from services.singleton_worker import is_maintenance_leader

                if is_maintenance_leader():
                    from services.arcade_publish import publish_everything
                    result = publish_everything()
                    if result.get("arcade") or result.get("codeplay") or result.get("lab_contexts"):
                        flask_app.logger.info(
                            "arcade publish: %d documents, %d codeplay collections, "
                            "%d lab contexts",
                            len(result.get("arcade") or {}),
                            len(result.get("codeplay") or {}),
                            result.get("lab_contexts") or 0,
                        )
        except Exception:
            flask_app.logger.exception("arcade publish sweep failed")
        finally:
            try:
                with flask_app.app_context():
                    db.session.remove()
            except Exception:
                pass
        _stop.wait(timeout=_INTERVAL_SECONDS)


def start_arcade_publish(flask_app):
    """Start the sweep. Idempotent, and never raises into startup."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return _thread
    try:
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="arcade-publish", daemon=True)
        _thread.start()
    except Exception:
        flask_app.logger.exception("could not start the arcade publish sweep")
    return _thread


def stop_arcade_publish():
    _stop.set()
