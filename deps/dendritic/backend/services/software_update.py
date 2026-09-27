"""Admin-triggered software updates, without SSH.

The heavy lifting lives in the in-cluster updater (k8s/updater/update.sh): it
pulls from GitHub, builds images, applies manifests, verifies the rollout, and
rolls back to the previous image tags if anything fails. This module is only the
CONTROL SURFACE the admin page talks to.

WHY A FILE DROP AND NOT THE KUBERNETES API
------------------------------------------
The obvious implementation is for the backend to create a Job through the
Kubernetes API. It is also the wrong one here: this backend is the
internet-facing process, and giving it a ServiceAccount that can create Jobs
turns any RCE in the web app into cluster-admin-adjacent access — the updater
mounts the docker and containerd sockets, which is root on the node.

So the backend never talks to the API. It writes a small request file to a
directory the updater watches, and reads a status file the updater publishes.
Worst case, a compromised backend can ask for an update of the code that is
already in GitHub — it cannot describe what runs.

The cost is latency: the request is picked up on the updater's next tick.
"""
import datetime as _datetime
import json
import os
import time as _time
import uuid

from shared import app


# Written by the updater (k8s/updater/update.sh: PUB_DIR). Mounted read-only.
STATUS_DIR = os.environ.get("SOFTWARE_UPDATE_STATUS_DIR", "/deploy")
# Watched by the updater. The only thing this process may write.
REQUEST_DIR = os.environ.get("SOFTWARE_UPDATE_REQUEST_DIR", "/deploy-requests")

STATUS_FILE = "status.json"
FAILURE_LOG = "latest-failure.log"
# The updater writes this on every no-change tick, precisely so "is the updater
# even alive?" is answerable from the browser (k8s/updater/update.sh, finish()).
# A routine tick must NOT overwrite status.json -- the timer fires hundreds of
# times a day and would bury the last real deploy -- so this file is the only
# liveness signal there is.
HEARTBEAT_FILE = "heartbeat.txt"
MAX_LOG_BYTES = 64 * 1024

# The CronJob ticks every minute. Past this, it is not merely between ticks --
# it is suspended, unschedulable, crashing before it can write, or the hostPath
# is not mounted where the backend is reading.
UPDATER_STALE_SECONDS = 5 * 60


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except Exception:
        app.logger.exception("software update: unreadable %s", path)
        return None


def _tail(path, limit=MAX_LOG_BYTES):
    """Last `limit` bytes of a file, or None. Never raises into a request."""
    try:
        size = os.path.getsize(path)
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            if size > limit:
                handle.seek(size - limit)
                handle.readline()  # drop the partial first line
            return handle.read()
    except FileNotFoundError:
        return None
    except Exception:
        app.logger.exception("software update: unreadable %s", path)
        return None


def update_available():
    """True when the control surface is actually wired up.

    False on a plain docker-compose deployment, where there is no updater — the
    admin card then explains that instead of offering a button that does nothing.
    """
    return os.path.isdir(REQUEST_DIR)


def pending_requests():
    """Requests the updater has not consumed yet."""
    try:
        return sorted(
            name for name in os.listdir(REQUEST_DIR)
            if name.startswith("request-") and name.endswith(".json")
        )
    except FileNotFoundError:
        return []
    except Exception:
        app.logger.exception("software update: cannot list %s", REQUEST_DIR)
        return []


def _age_seconds(path):
    """Seconds since path was last written, or None if it does not exist."""
    try:
        return max(0.0, _time.time() - os.path.getmtime(path))
    except FileNotFoundError:
        return None
    except Exception:
        app.logger.exception("software update: cannot stat %s", path)
        return None


def queued_age_seconds():
    """How long the oldest unconsumed request has been waiting."""
    ages = []
    for name in pending_requests():
        age = _age_seconds(os.path.join(REQUEST_DIR, name))
        if age is not None:
            ages.append(age)
    return max(ages) if ages else None


def updater_liveness():
    """Is the updater running at all, and when did it last say so?

    This is the question "Queued" could never answer. A request file sits in
    the directory until the updater deletes it, so a queued state means one of
    two very different things -- the updater is mid-tick, or the updater is not
    running -- and the card showed the same text for both.

    The updater touches heartbeat.txt on every idle tick and rewrites
    status.json on every real run, so the newer of the two is when it was last
    alive.
    """
    ages = [
        age for age in (
            _age_seconds(os.path.join(STATUS_DIR, HEARTBEAT_FILE)),
            _age_seconds(os.path.join(STATUS_DIR, STATUS_FILE)),
        ) if age is not None
    ]
    if not ages:
        return {
            "seen": False, "age_seconds": None, "stale": True,
            "text": _tail(os.path.join(STATUS_DIR, HEARTBEAT_FILE), 4096),
        }
    age = min(ages)
    return {
        "seen": True,
        "age_seconds": int(age),
        "stale": age > UPDATER_STALE_SECONDS,
        "text": _tail(os.path.join(STATUS_DIR, HEARTBEAT_FILE), 4096),
    }


def _describe_age(seconds):
    if seconds is None:
        return "never"
    seconds = int(seconds)
    if seconds < 90:
        return "%ds ago" % seconds
    if seconds < 5400:
        return "%dm ago" % (seconds // 60)
    if seconds < 172800:
        return "%dh ago" % (seconds // 3600)
    return "%dd ago" % (seconds // 86400)


def diagnose(queued, queued_seconds, liveness, state):
    """Plain-language reason the card is showing what it is showing.

    Returns (severity, message). Severity is "info" | "warn" | "error" so the
    card can colour it without re-deriving the logic.
    """
    if not update_available():
        return "warn", (
            "No updater is attached: %s does not exist in this container. "
            "On Kubernetes the request hostPath is not mounted; on plain "
            "docker-compose there is no updater at all." % REQUEST_DIR
        )
    if not liveness["seen"]:
        return "error", (
            "The updater has never published anything to %s. Either it has "
            "not run a single tick yet, or the backend and the updater are "
            "not looking at the same directory." % STATUS_DIR
        )
    if liveness["stale"]:
        return "error", (
            "The updater last checked in %s, but it should tick every minute. "
            "It is suspended, failing before it can write, or not being "
            "scheduled. Nothing queued will be picked up until it runs again."
            % _describe_age(liveness["age_seconds"])
        )
    if queued and queued_seconds is not None and queued_seconds > UPDATER_STALE_SECONDS:
        return "error", (
            "Queued %s, but the updater has ticked since then (%s) without "
            "consuming the request. It is running but cannot see the request "
            "directory -- check that the same hostPath is mounted into the "
            "CronJob." % (
                _describe_age(queued_seconds), _describe_age(liveness["age_seconds"])
            )
        )
    if queued:
        return "info", (
            "Waiting for the next updater tick (it last checked in %s). "
            "The CronJob runs every minute." % _describe_age(liveness["age_seconds"])
        )
    if state == "running":
        return "info", "The updater is working through the deploy now."
    return "info", "Updater alive, last check-in %s." % _describe_age(liveness["age_seconds"])


def cancel_requests():
    """Delete unconsumed request files. Returns (count, message).

    The card disables its button while anything is queued, so a request the
    updater will never consume wedges the control surface permanently. This is
    the way out, and it stays inside the existing trust boundary: the backend
    already owns this directory -- writing it is the entire update channel --
    so removing its own unconsumed request grants nothing new.
    """
    names = pending_requests()
    if not names:
        return 0, "There was nothing queued."
    removed = 0
    for name in names:
        try:
            os.unlink(os.path.join(REQUEST_DIR, name))
            removed += 1
        except FileNotFoundError:
            # The updater consumed it between the listing and here. Fine.
            removed += 1
        except Exception:
            app.logger.exception("software update: cannot remove request %s", name)
    if removed != len(names):
        return removed, "Removed %d of %d queued requests; the rest are not writable." % (
            removed, len(names)
        )
    return removed, "Cleared %d queued request%s." % (removed, "" if removed == 1 else "s")


def request_update(requested_by=None, force=False):
    """Ask the updater to run. Returns (ok, message).

    Idempotent by design: if a request is already queued, this does not stack a
    second one. Two updates racing each other over the same image tags is a good
    way to make rollback ambiguous.
    """
    if not update_available():
        return False, "No updater is attached to this deployment."
    existing = pending_requests()
    if existing:
        return False, "An update is already queued (%s). Waiting for the updater to pick it up." % existing[0]
    status = current_status()
    if (status or {}).get("result") == "running":
        return False, "An update is already running."

    payload = {
        "id": uuid.uuid4().hex,
        "requested_at": _datetime.datetime.utcnow().isoformat() + "Z",
        "requested_by": requested_by or "admin",
        # force=True tells the updater to redeploy even when git HEAD has not
        # moved — the "something is wedged, push the current code again" case.
        "force": bool(force),
    }
    name = "request-%s.json" % payload["id"]
    tmp = os.path.join(REQUEST_DIR, ".%s.tmp" % name)
    final = os.path.join(REQUEST_DIR, name)
    try:
        # Write-then-rename: the updater must never observe a half-written file.
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(tmp, final)
    except Exception:
        app.logger.exception("software update: cannot queue a request")
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return False, "Could not queue the update (the request volume is not writable)."
    return True, "Update queued. The updater picks it up on its next tick."


def current_status():
    """The updater's published status, or None if it has never run."""
    return _read_json(os.path.join(STATUS_DIR, STATUS_FILE))


def failure_log():
    """The error log from the last failed run — the whole point of the feature
    being that this is readable WITHOUT SSH."""
    return _tail(os.path.join(STATUS_DIR, FAILURE_LOG))


# The updater emits ~33 distinct result values (grep 'RESULT=' in
# k8s/updater/update.sh): ok, no_change, adopted, up_to_date, held, no_op,
# build_failed, apply_failed, apply_failed_nginx, import_failed, migrate_failed,
# migration_failed, verify_failed_backend, verify_failed_edge, verify_failed_pvc,
# rollout_failed_<kind>_<name>, rollback_failed, failed_<phase>, and a family of
# halted_* refusals.
#
# This module previously tested `result in ("failed", "rolled_back")` -- two
# strings the updater NEVER emits. So a deploy that failed and rolled back
# rendered as a green "Last update: verify_failed_backend" with the failure log
# suppressed, which is precisely the readable-error-log-without-SSH requirement
# the feature exists to satisfy. Classify by shape, and treat anything
# unrecognised as a failure rather than silently as success.
_OK_RESULTS = frozenset({"ok", "no_change", "adopted", "up_to_date", "no_op", "held"})
_RUNNING_RESULTS = frozenset({"running", "in_progress"})


def classify_result(result):
    """-> "ok" | "running" | "failed" | "unknown". Fails loud, not silent."""
    value = (result or "").strip().lower()
    if not value:
        return "unknown"
    if value in _RUNNING_RESULTS:
        return "running"
    if value in _OK_RESULTS:
        return "ok"
    # Everything else the updater emits is a refusal or a failure:
    # halted_*, *_failed, failed_*, rollback_failed, rolled_back, error, unknown.
    return "failed"


def admin_payload():
    """Everything the admin card renders, in one call."""
    status = current_status() or {}
    queued = pending_requests()
    result = status.get("result")
    state = classify_result(result)
    failed = state == "failed"
    queued_seconds = queued_age_seconds()
    liveness = updater_liveness()
    severity, message = diagnose(bool(queued), queued_seconds, liveness, state)
    return {
        "available": update_available(),
        "queued": bool(queued),
        "queued_count": len(queued),
        "queued_seconds": None if queued_seconds is None else int(queued_seconds),
        "queued_age": _describe_age(queued_seconds) if queued else None,
        "result": result,
        "state": state,
        "running": state == "running",
        "failed": failed,
        "status": status,
        # Liveness is the difference between "waiting a moment" and "waiting
        # forever", which is the whole reason a queued card was unreadable.
        "updater_seen": liveness["seen"],
        "updater_stale": liveness["stale"],
        "updater_age_seconds": liveness["age_seconds"],
        "updater_age": _describe_age(liveness["age_seconds"]),
        "updater_heartbeat": (liveness["text"] or "").strip() or None,
        "diagnosis": message,
        "diagnosis_severity": severity,
        # Where the two sides of the file-drop contract are, so a mount
        # mismatch is visible without shelling into anything.
        "request_dir": REQUEST_DIR,
        "status_dir": STATUS_DIR,
        # Show the log whenever the run did not end well, so an unrecognised
        # result still surfaces its diagnostics instead of hiding them.
        "failure_log": failure_log() if failed else None,
    }
