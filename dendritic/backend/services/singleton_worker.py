"""One shared leader election for the periodic maintenance loops.

WHY
---
`uwsgi.ini` sets `processes = 4` with `lazy-apps = true`, so `app.py` is imported
once per worker after fork and every module-level `start_*()` runs FOUR TIMES.
The aggregator sync loops guard against that with a Postgres advisory lock
(services/aggregator_sync/state.py), but several scraper-facing loops had no gate
at all and therefore ran in all four processes at once:

  * chan-ping             — 25 hosts x 10s timeouts per sweep, x4
  * chan-board-discovery  — remote board scans, x4
  * imported-media-repair — 25 threads/sweep, each re-mirroring media, x4
  * scraped-thread-retire — an HTTP DELETE per dead source, x4
  * experiment-guardrails — x4

That is four times the outbound requests to other people's imageboards, four
concurrent writers racing on the same rows, and four times the DB connections
held while all of it waits on the network.

ONE LOCK, NOT ONE PER LOOP
--------------------------
The obvious fix — copy the advisory-lock dance per loop, as video_offload,
nntpchan.sync, analytics.maintenance and recommendations.training each already do
— would add one more connection per loop. Those locks are held on connections
opened via `pool._creator()`, deliberately OUTSIDE the pool, so the pool cannot
see or reclaim them; five more would quietly eat the connection budget the pool
sizing in shared.py just reserved.

These loops do not need independent leadership, only "don't run me four times",
so they share a single lock on a single connection. Cost: one connection per
cluster, not one per loop.

FAILURE MODE IS DELIBERATE
--------------------------
If the lock cannot be acquired or the DB is briefly unreachable, this returns
False and the caller SKIPS that sweep. These are periodic janitors running every
15-60 minutes; skipping one is invisible, whereas running four copies is what
took the site down. On a non-Postgres backend (dev SQLite) there is only ever one
process, so it returns True.
"""
import os
import threading

from shared import app, db

# Distinct from AGGREGATOR_SYNC_ADVISORY_LOCK_ID (741311) so maintenance
# leadership and sync leadership are independent — they may land in different
# workers, which is fine and spreads the load.
def maintenance_advisory_lock_id() -> int:
    return int(os.getenv("MAINTENANCE_ADVISORY_LOCK_ID", "741312"))


_lock = threading.Lock()
_lock_connection = None
_is_leader = False
_owner_logged = False
_db_down_logged = False


def _helpers():
    """Reuse the sync module's connection plumbing instead of re-deriving it.

    Those helpers encode a real hazard: `pool_pre_ping` issues `SELECT 1` on
    checkout, which opens a transaction, and flipping that connection to
    autocommit afterwards can raise "set_session cannot be used inside a
    transaction" and poison it. Do not replace these with a plain
    `db.engine.connect()`.
    """
    from services.aggregator_sync.state import (
        _close_raw_connection,
        _open_background_sync_connection,
        _set_connection_autocommit,
    )

    return _open_background_sync_connection, _set_connection_autocommit, _close_raw_connection


def is_maintenance_leader() -> bool:
    """True in exactly one process; False in the others.

    Safe to call from several loops and threads concurrently — the connection and
    its bookkeeping are guarded by a mutex, because psycopg2 connections are not
    safe to use from multiple threads at once.
    """
    global _lock_connection, _is_leader, _owner_logged, _db_down_logged

    try:
        backend = db.engine.url.get_backend_name()
    except Exception:
        return False
    if backend not in ("postgresql", "postgres"):
        # SQLite/dev: a single process, so it is trivially the leader.
        return True

    with _lock:
        # Already hold it? Confirm the connection is still alive. An advisory
        # lock is released automatically when its session dies, so a dead
        # connection means leadership must be re-contested, not assumed.
        if _lock_connection is not None:
            try:
                cursor = _lock_connection.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                _db_down_logged = False
                return True
            except Exception:
                _drop_connection_locked()

        open_conn, set_autocommit, close_conn = _helpers()
        raw_connection = None
        try:
            raw_connection = open_conn()
            set_autocommit(raw_connection, True)
            cursor = raw_connection.cursor()
            cursor.execute(
                "SELECT pg_try_advisory_lock(%s)", (maintenance_advisory_lock_id(),)
            )
            row = cursor.fetchone()
            cursor.close()
            acquired = bool(row and row[0])
        except Exception:
            if raw_connection is not None:
                try:
                    close_conn(raw_connection)
                except Exception:
                    pass
            _is_leader = False
            if not _db_down_logged:
                app.logger.warning(
                    "maintenance leader election: database unavailable; skipping this sweep"
                )
                _db_down_logged = True
            return False

        if acquired:
            _lock_connection = raw_connection
            _is_leader = True
            _db_down_logged = False
            if not _owner_logged:
                _owner_logged = True
                app.logger.info(
                    "maintenance loops elected worker pid-%s as leader", os.getpid()
                )
            return True

        # Another worker holds it. Close ours so we do not accumulate idle
        # backends on every check.
        try:
            close_conn(raw_connection)
        except Exception:
            pass
        _is_leader = False
        _db_down_logged = False
        return False


def _drop_connection_locked() -> None:
    """Discard the lock connection. Caller must hold `_lock`."""
    global _lock_connection, _is_leader
    connection, _lock_connection = _lock_connection, None
    _is_leader = False
    if connection is None:
        return
    try:
        _, _, close_conn = _helpers()
        close_conn(connection)
    except Exception:
        pass


def release_maintenance_leadership() -> None:
    """Give up leadership (used by tests and orderly shutdown)."""
    global _owner_logged
    with _lock:
        _drop_connection_locked()
        _owner_logged = False


def is_leader_cached() -> bool:
    """Last known leadership, with no DB round-trip. For status panels only."""
    return _is_leader


__all__ = [
    "is_leader_cached", "is_maintenance_leader", "maintenance_advisory_lock_id",
    "release_maintenance_leadership",
]
