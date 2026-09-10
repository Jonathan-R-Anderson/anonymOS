"""The timer that moves finished broadcasts onto the DHT.

Same lesson as services/arcade_publish_loop: a publish path with no schedule is
a publish path that does not happen. services.stream_archive has no other
trigger -- nothing in the RTMP end-of-stream path calls it, deliberately, since
that request comes from the RTMP server and should not block on a multi-hundred
megabyte upload.

LEADER-GATED. uWSGI runs several workers; an ungated loop would run one copy per
worker, and here that means several workers ingesting the SAME recording
concurrently and then racing to delete it. is_maintenance_leader() is the
existing lock for this.
"""

import os
import threading

from shared import db

# OFF BY DEFAULT, pending the node-side write failure.
#
# The gateway closes the connection when storing genuinely unique data past a
# few tens of megabytes -- which is exactly what a video recording is. Every
# earlier "success" was measured with a repeated block that content-addressed
# dedup collapsed to almost nothing, so the store was never doing the work.
#
# Nothing is at risk of deletion while this is off, and nothing was at risk
# while it was on either: publish_one unlinks only after every chunk verifies,
# and these fail. The reason to keep it off is that retrying hundreds of
# megabytes every ten minutes against a node with a 9713-object backfill
# backlog makes an unhealthy node less healthy.
#
# Set STREAM_ARCHIVE_ENABLED=1 to turn it back on once the node stores unique
# blocks reliably.
def enabled():
    return (os.environ.get("STREAM_ARCHIVE_ENABLED") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )

# Recordings only appear when a broadcast ends, and stream_archive skips
# anything still being written, so there is nothing to gain from a tight loop.
_INTERVAL_SECONDS = 600

# Long enough for the DHT gateway sidecar to be up. Ingesting into a gateway
# that has not finished booting fails the readback and leaves the local file --
# harmless, but it logs an error that looks like data loss and is not.
_FIRST_RUN_DELAY = 240

_stop = threading.Event()
_thread = None


def _loop(flask_app):
    _stop.wait(timeout=_FIRST_RUN_DELAY)
    while not _stop.is_set():
        try:
            with flask_app.app_context():
                from services.singleton_worker import is_maintenance_leader

                if is_maintenance_leader():
                    from services.stream_archive import publish_pending
                    result = publish_pending()
                    if result.get("published") or result.get("failed"):
                        flask_app.logger.info(
                            "stream archive: %d published to the DHT, %d failed%s",
                            result.get("published") or 0,
                            result.get("failed") or 0,
                            ", more pending" if result.get("more") else "",
                        )
        except Exception:
            flask_app.logger.exception("stream archive sweep failed")
        finally:
            try:
                with flask_app.app_context():
                    db.session.remove()
            except Exception:
                pass
        _stop.wait(timeout=_INTERVAL_SECONDS)


def start_stream_archive(flask_app):
    """Start the sweep. Idempotent, and never raises into startup."""
    global _thread
    if not enabled():
        flask_app.logger.info(
            "stream archive sweep is off (set STREAM_ARCHIVE_ENABLED=1 to "
            "enable); recordings stay on local disk"
        )
        return None
    if _thread is not None and _thread.is_alive():
        return _thread
    try:
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="stream-archive", daemon=True)
        _thread.start()
    except Exception:
        flask_app.logger.exception("could not start the stream archive sweep")
    return _thread


def stop_stream_archive():
    _stop.set()
