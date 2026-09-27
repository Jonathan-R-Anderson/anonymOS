"""The loop that actually drains the arcade compute queue.

WHY THIS DID NOT EXIST
----------------------
`compute_rental.run_next()` was written, tested and correct, and nothing ever
called it. So `/arcade/rent` accepted programs, assigned them a queue position,
showed an ETA, and ran none of them — the queue only ever grew. A submitted job
sat at "queued" forever, which from the outside is indistinguishable from the
site being broken, and there was no error anywhere to explain it.

That is the same failure the arcade publisher had (267 rows, 0 published): a
working mechanism with no schedule behind it. The point of this file is the
schedule.

ONE RUNNER AT A TIME, PER DEVICE
--------------------------------
CPU and GPU queues are tracked independently, because they contend for different
hardware and a long GPU job must not hold up CPU work that could run beside it.
Only the devices this site can genuinely execute are drained — see _DEVICES.

Within a device, exactly one worker runs at a time and it is the maintenance
leader. `run_next()` claims a job by flipping it to running and committing
BEFORE handing it to the runner, so two racing workers cannot both take the
same job — but a user charged once for two executions is a bad enough outcome
that the leader lock is worth having as well. Belt and braces on the path where
the failure costs somebody money.

WHY IT SLEEPS WHEN IDLE AND NOT WHEN BUSY
-----------------------------------------
An empty queue is the common case, and polling it every second is pure load on
the database for nothing. A non-empty queue is the case where latency is the
whole product — somebody is watching a spinner. So the loop backs off when
there is nothing to do and loops immediately when there is, which is the
opposite of a fixed interval and the reason this is not a cron.
"""

import threading

from shared import db

# Idle poll interval. Long enough that an empty queue costs nothing, short
# enough that a job submitted into an empty queue starts within a few seconds.
_IDLE_SECONDS = 5

# Devices this site can actually execute.
#
# CPU only, deliberately. `code_runner` is device-blind: it has no GPU
# passthrough, no vendor toolkit, and no way to tell whether the machine it runs
# on has a card at all. Draining the GPU queue through it would run a job
# somebody paid GPU rates for on a CPU and mark it DONE — a wrong answer
# delivered confidently, which is worse than the job never running, because the
# user has no way to tell it happened.
#
# So GPU jobs stay queued until there is a runner that can genuinely serve them
# (a volunteer compute node, or an operator box with a card). `gpu_reason()`
# below is what the queue page shows instead of a silent wait.
_DEVICES = ("cpu",)


def devices():
    """Which queues this deployment can drain.

    With a compute bridge attached, GPU becomes drainable too — a volunteer node
    that offered its card can genuinely serve the work, which is the whole
    reason the bridge exists. Without one, GPU stays queued rather than being
    run on a CPU and reported as done.
    """
    try:
        from services import compute_bridge

        if compute_bridge.enabled():
            return ("cpu", "gpu")
    except Exception:
        pass
    return _DEVICES

# Why GPU work is not running. Shown to anyone with a GPU job queued, because
# "position 1, indefinitely" with no explanation is indistinguishable from the
# site being broken.
GPU_PENDING_REASON = (
    "GPU jobs are queued but not yet executed: this site has no GPU-capable "
    "runner attached. They will run once a GPU provider is connected — nothing "
    "is lost in the meantime, and no credits are spent until a job runs."
)

_stop = threading.Event()
_threads = {}


def _drain_once(flask_app, device):
    """Run at most one job. Returns True if it ran something."""
    from services.singleton_worker import is_maintenance_leader

    with flask_app.app_context():
        try:
            if not is_maintenance_leader():
                return False
            from services.compute_rental import run_next

            job = run_next(device)
            if job is not None:
                flask_app.logger.info(
                    "compute rental: ran %s job %s (%s)",
                    device, getattr(job, "id", "?"), getattr(job, "status", "?"))
                return True
            return False
        finally:
            # The session must go back whether the job ran, failed, or there was
            # nothing to do. A worker that leaks a session holds a connection
            # from a pool sized for request handling, and an idle-in-transaction
            # session is how this site has taken itself down before.
            try:
                db.session.remove()
            except Exception:
                pass


def _loop(flask_app, device):
    while not _stop.is_set():
        ran = False
        try:
            ran = _drain_once(flask_app, device)
        except Exception:
            # Never let one bad job stop the queue forever. run_next already
            # marks a job failed when the runner raises; this catches everything
            # outside that — a database blip, a leader-lock error — and tries
            # again after a pause rather than killing the thread.
            flask_app.logger.exception("compute rental %s worker failed", device)
            _stop.wait(timeout=_IDLE_SECONDS)
            continue
        if not ran:
            _stop.wait(timeout=_IDLE_SECONDS)


def start_compute_rental_workers(flask_app):
    """Start one drainer per device. Idempotent, never raises into startup."""
    for device in devices():
        existing = _threads.get(device)
        if existing is not None and existing.is_alive():
            continue
        try:
            thread = threading.Thread(
                target=_loop, args=(flask_app, device),
                name="compute-rental-%s" % device, daemon=True)
            thread.start()
            _threads[device] = thread
        except Exception:
            flask_app.logger.exception(
                "could not start the %s compute rental worker", device)
    return _threads


def stop_compute_rental_workers():
    """For tests: stop the loops."""
    _stop.set()
