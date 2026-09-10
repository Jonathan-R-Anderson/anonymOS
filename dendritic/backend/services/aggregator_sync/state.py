import collections
import datetime as _datetime
import os
import threading
from typing import Dict

from shared import app, db

from .config import MAX_SYNC_ERROR_LENGTH


_sync_status: Dict = {
    "is_syncing": False,
    "is_leader": None,
    "last_check": None,
    "last_sync_start": None,
    "last_sync_end": None,
    "bg_cycles": 0,
    "per_board": {},
    "log": collections.deque(maxlen=200),
}

_global_sync_lock = threading.RLock()
_background_sync_lock_connection = None
_background_sync_lock_owner = None
_background_sync_db_down_logged = False


def background_sync_advisory_lock_id() -> int:
    return int(os.getenv("AGGREGATOR_SYNC_ADVISORY_LOCK_ID", "741311"))


def _set_connection_autocommit(connection, enabled: bool) -> None:
    target = getattr(connection, "connection", connection)
    if hasattr(target, "autocommit"):
        if enabled and not getattr(target, "autocommit", False):
            try:
                target.rollback()
            except Exception:
                pass
        target.autocommit = enabled


def _open_background_sync_connection():
    """Create a dedicated DBAPI connection for advisory-lock bookkeeping.

    This intentionally bypasses SQLAlchemy's normal pool checkout path.
    `pool_pre_ping` issues `SELECT 1` during checkout, which starts a
    transaction on psycopg2 connections. Flipping that pooled connection into
    autocommit mode afterwards can raise `set_session cannot be used inside a
    transaction` and poison the connection for the rest of the app.
    """
    pool = getattr(db.engine, "pool", None)
    creator = getattr(pool, "_creator", None)
    if callable(creator):
        return creator()

    raw_connection = db.engine.raw_connection()
    detach = getattr(raw_connection, "detach", None)
    if callable(detach):
        detach()
    return raw_connection


def _close_raw_connection(connection) -> None:
    if connection is None:
        return
    target = getattr(connection, "connection", connection)
    close_target = getattr(target, "close", None)
    if callable(close_target):
        close_target()
        return
    connection.close()


def _sync_log(message: str) -> None:
    stamp = _datetime.datetime.now(_datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = "[%s] %s" % (stamp, message)
    _sync_status["log"].append(line)
    app.logger.info("aggregator: %s", message)


def _format_sync_error(exc: Exception) -> str:
    message = str(exc or "").replace("\n", " ").strip()
    if len(message) <= MAX_SYNC_ERROR_LENGTH:
        return message
    return message[: MAX_SYNC_ERROR_LENGTH - 3] + "..."


SCRAPING_PAUSED_SETTING = "scraping-paused"


def scraping_paused() -> bool:
    """Operator kill switch for ALL scraping.

    Read at the top of the leader gate, so every sync path already honours it
    without each loop needing its own check. Backed by a SiteSetting rather than
    an env var or config file: pausing is something you do DURING an incident or
    a database clean-up, and it has to take effect without a redeploy or a
    restart -- a pause that needs a rollout is useless for the case it exists
    for. Fails OPEN (returns False) if the setting cannot be read, because a
    database hiccup silently stopping all crawling is worse than a paused flag
    being briefly ignored.
    """
    try:
        from model.SiteSetting import get_setting

        return str(get_setting(SCRAPING_PAUSED_SETTING, "")).strip().lower() in (
            "1", "true", "yes", "on",
        )
    except Exception:
        return False


def _background_sync_should_run() -> bool:
    global _background_sync_lock_connection, _background_sync_lock_owner
    global _background_sync_db_down_logged

    # Checked BEFORE leader election: a paused instance should not hold the
    # advisory lock either, or the pause would also decide which worker resumes
    # when it is lifted.
    if scraping_paused():
        _sync_status["paused"] = True
        return False
    _sync_status["paused"] = False

    backend = db.engine.url.get_backend_name()
    if backend not in ("postgresql", "postgres"):
        _sync_status["is_leader"] = True
        return True

    if _background_sync_lock_connection is not None:
        try:
            cursor = _background_sync_lock_connection.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            _sync_status["is_leader"] = True
            _background_sync_db_down_logged = False
            return True
        except Exception:
            _drop_background_sync_connection()

    raw_connection = None
    try:
        raw_connection = _open_background_sync_connection()
        _set_connection_autocommit(raw_connection, True)
        cursor = raw_connection.cursor()
        cursor.execute("SELECT pg_try_advisory_lock(%s)", (background_sync_advisory_lock_id(),))
        row = cursor.fetchone()
        cursor.close()
        acquired = bool(row and row[0])
    except Exception:
        if raw_connection is not None:
            try:
                _close_raw_connection(raw_connection)
            except Exception:
                try:
                    raw_connection.invalidate()
                except Exception:
                    try:
                        raw_connection.close()
                    except Exception:
                        pass
        _sync_status["is_leader"] = False
        _drop_background_sync_connection()
        if _background_sync_db_down_logged is False:
            app.logger.warning("Background sync database connection unavailable; will retry")
            _background_sync_db_down_logged = True
        return False

    if acquired:
        _background_sync_lock_connection = raw_connection
        _sync_status["is_leader"] = True
        _background_sync_db_down_logged = False
        owner = "pid-%s" % os.getpid()
        if _background_sync_lock_owner != owner:
            _background_sync_lock_owner = owner
            _sync_log("Worker %s acquired the background sync advisory lock" % owner)
        return True

    _close_raw_connection(raw_connection)
    _sync_status["is_leader"] = False
    _background_sync_db_down_logged = False
    return False


def _drop_background_sync_connection() -> None:
    global _background_sync_lock_connection, _background_sync_lock_owner

    connection = _background_sync_lock_connection
    _background_sync_lock_connection = None
    _background_sync_lock_owner = None
    if connection is None:
        return
    try:
        _close_raw_connection(connection)
    except Exception:
        pass
