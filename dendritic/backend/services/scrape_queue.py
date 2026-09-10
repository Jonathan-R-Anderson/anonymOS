"""Bounded work queues for remote scrape / import jobs.

WHY THIS EXISTS
---------------
Production outage 2026-07-26:

    sqlalchemy.exc.TimeoutError: QueuePool limit of size 5 overflow 10 reached,
    connection timed out, timeout 30.00
    POST /session/keepalive => generated 0 bytes in 60010 msecs

Nothing was deadlocked — the app was simply oversubscribed. The arithmetic:

  * uWSGI runs `processes = 4`, `gevent = 200` -> up to 800 concurrent greenlets.
  * SQLAlchemy's pool was never sized, so it used the default
    `pool_size=5, max_overflow=10` -> 15 connections PER PROCESS, 60 total.
  * Scrape/import work ran inline and unbounded: every monitored board, every
    source, every thread, every media mirror could hold a connection while it
    waited on a REMOTE network call (a slow imageboard, a Tor circuit rotation,
    the NSFW classifier). A connection held across a 30s fetch is a connection
    no page view can have.

So a burst of scraping starved ordinary requests of connections. They queued 30s
on the pool, raised TimeoutError, and uWSGI killed them at 60s. The site looked
down while every individual component was "fine".

Raising the pool only moves the wall (Postgres 17 ships `max_connections = 100`,
and `maniwani` is the only client, so the whole budget is ~100/4 = 25 per
process). The real fix is to stop scrape work from ever consuming more than a
fixed slice of the process, which is what this module enforces.

THE THREE CAPS
--------------
1. `MAX_WORKERS` — a hard ceiling on scrape jobs executing at once, process-wide.
   No combination of queues can exceed it, so the blast radius of "every site is
   slow today" is a constant, not a function of how many boards are configured.
2. Per-queue caps — each queue (normally one per source_type) gets its own
   concurrency limit, so one dead site cannot occupy every worker and starve the
   others. This is head-of-line blocking avoidance, not extra capacity: the sum
   of the per-queue caps is deliberately allowed to exceed MAX_WORKERS, because
   MAX_WORKERS is the real ceiling and the per-queue caps only carve it up.
3. `db_budget()` — a semaphore over DB *session* use, sized well below the
   engine pool. Even with every worker running, scrape work can hold at most
   `MAX_DB_SLOTS` connections, so page views always have the rest. THIS is the
   cap that actually fixed the outage; the other two keep it from being hit.

Plus a bounded backlog (`MAX_QUEUE_DEPTH`) so a queue cannot grow without limit
when producers outrun consumers.

SHEDDING IS SAFE, AND DELIBERATE
--------------------------------
`submit()` returns False instead of blocking or growing when a queue is full.
That is correct *because every job here is idempotent and re-enqueued by the
next sync cycle* — dropping one is a delay, never a loss. Do not "improve" this
into a blocking put: the caller is often a background sync loop holding a DB
session, and blocking it would reintroduce exactly the starvation this module
exists to prevent. Shed counts are recorded and surfaced in the admin panel so
a persistently full queue is visible rather than silent.

DEDUPE IS LOAD-BEARING
----------------------
The incremental sync loop runs every ~10s and re-proposes the same work each
pass. Without dedupe on `key`, a queue depth of 500 would fill with hundreds of
copies of the same board and the cap would throttle *duplicates* instead of
work. A key that is already queued or in flight is rejected as a duplicate
(counted separately from a shed — it is not backpressure, it is "already
covered").
"""
import os
import threading
import time
from collections import OrderedDict, defaultdict, deque

# --- caps (env-overridable; defaults chosen for the 4-proc / 200-core deploy) ---

def _int_env(name, default, minimum=1):
    try:
        return max(minimum, int(os.getenv(name, "") or default))
    except (TypeError, ValueError):
        return default


# Total scrape jobs running at once, process-wide.
MAX_WORKERS = _int_env("SCRAPE_QUEUE_WORKERS", 4)
# Scrape jobs that may hold a DB session at once. MUST stay well under the
# engine's pool_size + max_overflow, or scraping can still starve requests.
MAX_DB_SLOTS = _int_env("SCRAPE_QUEUE_DB_SLOTS", 3)
# Backlog depth per queue before submit() sheds.
MAX_QUEUE_DEPTH = _int_env("SCRAPE_QUEUE_DEPTH", 256)
# Default per-queue concurrency when a queue is created without an explicit cap.
DEFAULT_QUEUE_CAP = _int_env("SCRAPE_QUEUE_PER_QUEUE", 2)
# A job that overruns this is still allowed to finish, but is logged as slow so
# a wedged remote site is visible in the admin panel.
SLOW_JOB_SECONDS = float(os.getenv("SCRAPE_QUEUE_SLOW_SECONDS", "180") or 180)


class _Job(object):
    __slots__ = ("queue_name", "key", "fn", "label", "enqueued_at", "started_at")

    def __init__(self, queue_name, key, fn, label):
        self.queue_name = queue_name
        self.key = key
        self.fn = fn
        self.label = label or key
        self.enqueued_at = time.time()
        self.started_at = None


class ScrapeQueues(object):
    """Round-robin dispatcher over several bounded queues with a global cap."""

    def __init__(self, max_workers=None, max_db_slots=None, max_depth=None):
        self.max_workers = max_workers or MAX_WORKERS
        self.max_depth = max_depth or MAX_QUEUE_DEPTH
        self._cv = threading.Condition()
        self._queues = OrderedDict()          # name -> deque[_Job]
        self._caps = {}                       # name -> per-queue concurrency cap
        self._inflight = defaultdict(int)     # name -> running count
        self._pending_keys = set()            # dedupe: queued OR running
        self._running = {}                    # key -> _Job (for stats)
        self._order = deque()                 # round-robin cursor over queue names
        self._stats = defaultdict(lambda: defaultdict(int))
        self._threads = []
        self._stop = threading.Event()
        self._started = False
        # Guards DB-session use by workers. Separate from the worker cap so a
        # worker doing pure network I/O does not consume a connection slot.
        self._db_slots = threading.BoundedSemaphore(max_db_slots or MAX_DB_SLOTS)
        self._db_waits = 0
        self._db_wait_seconds = 0.0

    # -- configuration ----------------------------------------------------

    def configure_queue(self, name, cap=None, depth=None):
        """Register a queue (idempotent). Safe to call from any thread."""
        with self._cv:
            if name not in self._queues:
                self._queues[name] = deque()
                self._order.append(name)
            if cap is not None:
                self._caps[name] = max(1, int(cap))
            else:
                self._caps.setdefault(name, DEFAULT_QUEUE_CAP)
            if depth is not None:
                self._stats[name]["max_depth"] = max(1, int(depth))
            self._cv.notify_all()

    def _depth_limit(self, name):
        configured = self._stats[name].get("max_depth")
        return configured or self.max_depth

    # -- producer side ----------------------------------------------------

    def submit(self, queue_name, key, fn, label=None):
        """Enqueue idempotent work. Returns True if accepted.

        False means "already covered" or "shed under backpressure" — both are
        normal and both are counted. Never blocks, never raises.
        """
        if fn is None:
            return False
        key = str(key)
        with self._cv:
            if queue_name not in self._queues:
                # Auto-register rather than dropping work because of ordering.
                self._queues[queue_name] = deque()
                self._order.append(queue_name)
                self._caps.setdefault(queue_name, DEFAULT_QUEUE_CAP)
            if key in self._pending_keys:
                self._stats[queue_name]["duplicate"] += 1
                return False
            queue = self._queues[queue_name]
            if len(queue) >= self._depth_limit(queue_name):
                # Shed. The next sync cycle re-proposes this job.
                self._stats[queue_name]["shed"] += 1
                return False
            queue.append(_Job(queue_name, key, fn, label))
            self._pending_keys.add(key)
            self._stats[queue_name]["submitted"] += 1
            self._cv.notify()
            return True

    # -- consumer side ----------------------------------------------------

    def _next_job(self):
        """Pick a runnable job round-robin. Caller must hold self._cv."""
        checked = 0
        total = len(self._order)
        while checked < total:
            name = self._order[0]
            self._order.rotate(-1)
            checked += 1
            queue = self._queues.get(name)
            if not queue:
                continue
            if self._inflight[name] >= self._caps.get(name, DEFAULT_QUEUE_CAP):
                # This queue is at its own cap; try the next one so a slow site
                # cannot block unrelated sites.
                continue
            job = queue.popleft()
            self._inflight[name] += 1
            job.started_at = time.time()
            self._running[job.key] = job
            return job
        return None

    def _worker(self, flask_app, index):
        while not self._stop.is_set():
            with self._cv:
                job = self._next_job()
                if job is None:
                    # No runnable job: either all queues empty or all at cap.
                    # Timed wait so a per-queue cap freeing up is picked up even
                    # if the notify raced.
                    self._cv.wait(timeout=1.0)
                    continue
            try:
                self._run_job(flask_app, job)
            finally:
                with self._cv:
                    self._inflight[job.queue_name] -= 1
                    self._pending_keys.discard(job.key)
                    self._running.pop(job.key, None)
                    self._cv.notify_all()

    def _run_job(self, flask_app, job):
        started = time.time()
        stats = self._stats[job.queue_name]
        try:
            with flask_app.app_context():
                try:
                    job.fn()
                    stats["completed"] += 1
                finally:
                    # Always return the connection. A worker that leaks a
                    # session here would recreate the original outage one
                    # connection at a time.
                    try:
                        from shared import db

                        db.session.remove()
                    except Exception:
                        pass
        except Exception:
            stats["failed"] += 1
            try:
                flask_app.logger.exception(
                    "scrape queue: job failed (%s/%s)", job.queue_name, job.label
                )
            except Exception:
                pass
        finally:
            elapsed = time.time() - started
            stats["seconds"] = int(stats.get("seconds", 0) + elapsed)
            if elapsed >= SLOW_JOB_SECONDS:
                stats["slow"] += 1
                try:
                    flask_app.logger.warning(
                        "scrape queue: slow job %s/%s took %.0fs",
                        job.queue_name, job.label, elapsed,
                    )
                except Exception:
                    pass

    # -- DB budget --------------------------------------------------------

    def db_budget(self, timeout=30.0):
        """Context manager gating DB-session use by scrape workers.

        Wrap the DB phase of a job, NOT the whole job — the point is that a
        worker waiting on a remote HTTP fetch holds no connection slot.
        """
        return _DbBudget(self, timeout)

    # -- introspection ----------------------------------------------------

    def stats(self):
        with self._cv:
            queues = []
            for name, queue in self._queues.items():
                s = self._stats[name]
                queues.append({
                    "name": name,
                    "depth": len(queue),
                    "depth_limit": self._depth_limit(name),
                    "inflight": self._inflight[name],
                    "cap": self._caps.get(name, DEFAULT_QUEUE_CAP),
                    "submitted": s.get("submitted", 0),
                    "completed": s.get("completed", 0),
                    "failed": s.get("failed", 0),
                    "shed": s.get("shed", 0),
                    "duplicate": s.get("duplicate", 0),
                    "slow": s.get("slow", 0),
                    "seconds": s.get("seconds", 0),
                })
            now = time.time()
            running = [
                {
                    "queue": job.queue_name,
                    "label": job.label,
                    "age_seconds": int(now - (job.started_at or now)),
                }
                for job in self._running.values()
            ]
            return {
                "started": self._started,
                "workers": self.max_workers,
                "inflight_total": sum(self._inflight.values()),
                "db_slots": MAX_DB_SLOTS,
                "db_waits": self._db_waits,
                "db_wait_seconds": int(self._db_wait_seconds),
                "queues": sorted(queues, key=lambda q: q["name"]),
                "running": sorted(running, key=lambda r: -r["age_seconds"]),
            }

    # -- lifecycle --------------------------------------------------------

    def start(self, flask_app):
        with self._cv:
            if self._started:
                return False
            self._started = True
            for index in range(self.max_workers):
                thread = threading.Thread(
                    target=self._worker,
                    args=(flask_app, index),
                    name="scrape-queue-%d" % index,
                    daemon=True,
                )
                self._threads.append(thread)
                thread.start()
        return True

    def stop(self):
        self._stop.set()
        with self._cv:
            self._cv.notify_all()


class _DbBudget(object):
    """Semaphore slot for DB work, with wait accounting."""

    __slots__ = ("_queues", "_timeout", "_acquired")

    def __init__(self, queues, timeout):
        self._queues = queues
        self._timeout = timeout
        self._acquired = False

    def __enter__(self):
        started = time.time()
        self._acquired = self._queues._db_slots.acquire(timeout=self._timeout)
        waited = time.time() - started
        if waited > 0.01:
            self._queues._db_waits += 1
            self._queues._db_wait_seconds += waited
        if not self._acquired:
            # Do not proceed without a slot: that is the whole guarantee.
            raise DbBudgetTimeout(
                "no scrape DB slot within %.1fs" % self._timeout
            )
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._acquired:
            self._acquired = False
            try:
                self._queues._db_slots.release()
            except ValueError:
                pass
        return False


class DbBudgetTimeout(RuntimeError):
    """Raised when scrape work cannot get a DB slot; the job is retried later."""


# Process-wide singleton. Scrape work is only ever done by the sync leader, so
# one dispatcher per process is the right granularity.
queues = ScrapeQueues()


def submit(queue_name, key, fn, label=None):
    return queues.submit(queue_name, key, fn, label=label)


def configure_queue(name, cap=None, depth=None):
    return queues.configure_queue(name, cap=cap, depth=depth)


def db_budget(timeout=30.0):
    return queues.db_budget(timeout=timeout)


def stats():
    return queues.stats()


def start_scrape_queues(flask_app):
    return queues.start(flask_app)


__all__ = [
    "DEFAULT_QUEUE_CAP", "DbBudgetTimeout", "MAX_DB_SLOTS", "MAX_QUEUE_DEPTH",
    "MAX_WORKERS", "ScrapeQueues", "configure_queue", "db_budget", "queues",
    "start_scrape_queues", "stats", "submit",
]
