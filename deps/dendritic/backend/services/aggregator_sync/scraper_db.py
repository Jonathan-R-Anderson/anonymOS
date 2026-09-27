import datetime as _datetime
import os
import sqlite3
from typing import Optional

import cache
from shared import app

from .config import (
    DEFAULT_EIGHTCHAN_DB,
    DEFAULT_FOURCHAN_DB,
    DEFAULT_GENERIC_SITES_DIR,
    DEFAULT_REDDIT_DB,
    DEFAULT_SEVENCHAN_DB,
    SUPPORTED_SCRAPER_TYPES,
    SYNC_CACHE_KEY_TEMPLATE,
    WATERMARK_CACHE_KEY_TEMPLATE,
)

# Generic sites all live under one container mount, one <host>.db per site.
_GENERIC_CONTAINER_SITES_PATH = "/aggregator-data/generic/sites"
_SCRAPER_DB_CONTAINER_PATHS = {
    "4chan": "/aggregator-data/4chan",
    "8chan": "/aggregator-data/8chan",
    "7chan": "/aggregator-data/7chan",
    "reddit": "/aggregator-data/reddit",
}


# Resolve a scraper database path relative to the Flask app root.
def _default_db_path(relative_path: str) -> str:
    return os.path.join(app.root_path, relative_path)


def configured_aggregator_db_path(source_type: str) -> str:
    if source_type == "4chan":
        return (
            os.getenv("FOURCHAN_AGGREGATOR_DB")
            or app.config.get("FOURCHAN_AGGREGATOR_DB")
            or _default_db_path(DEFAULT_FOURCHAN_DB)
        )
    if source_type == "8chan":
        return (
            os.getenv("EIGHTCHAN_AGGREGATOR_DB")
            or app.config.get("EIGHTCHAN_AGGREGATOR_DB")
            or _default_db_path(DEFAULT_EIGHTCHAN_DB)
        )
    if source_type == "7chan":
        return (
            os.getenv("SEVENCHAN_AGGREGATOR_DB")
            or app.config.get("SEVENCHAN_AGGREGATOR_DB")
            or _default_db_path(DEFAULT_SEVENCHAN_DB)
        )
    if source_type == "reddit":
        return (
            os.getenv("REDDIT_AGGREGATOR_DB")
            or app.config.get("REDDIT_AGGREGATOR_DB")
            or _default_db_path(DEFAULT_REDDIT_DB)
        )
    # Generic aggregated-chan site: source_type IS the remote host, and the shared
    # generic scraper keeps one SQLite file per site (posts.post_id is a global
    # PRIMARY KEY there, so sites cannot share a file without overwriting each
    # other). Mirrors crawler.site_db_path().
    if is_generic_source_type(source_type):
        return os.path.join(generic_site_data_dir(), "%s.db" % source_type)
    raise ValueError("Unsupported source type: %s" % source_type)


def generic_site_data_dir() -> str:
    """Host-side directory holding one <host>.db per monitored generic site."""
    return (
        os.getenv("GENERIC_AGGREGATOR_SITES_DIR")
        or app.config.get("GENERIC_AGGREGATOR_SITES_DIR")
        or _default_db_path(DEFAULT_GENERIC_SITES_DIR)
    )


def scraper_data_dir(source_type: str) -> str:
    """The scraper's DATA_DIR for this source — the root `image_path` is relative to.

    NOT simply dirname(db_path). That coincidence holds only for the four built-ins,
    whose DB sits at the volume root (/aggregator-data/4chan/4chan.db). A generic
    site's DB lives one level down, at <DATA_DIR>/sites/<host>.db, while the crawler
    still writes images to <DATA_DIR>/images/<host>/<board>/... — so using
    dirname(db) resolved every generic asset to .../sites/images/... which never
    exists. It failed as a silent isfile()==False, which disabled banned-hash
    filtering, blocked media purging, and made the mirror re-download every image
    from the remote site.
    """
    if is_generic_source_type(source_type):
        return os.path.abspath(os.path.dirname(generic_site_data_dir().rstrip("/")))
    return os.path.abspath(os.path.dirname(aggregator_db_path(source_type)))


def is_generic_source_type(source_type: str) -> bool:
    """True for a host-keyed generic source (anything that is not a built-in).

    Requires a dot so a typo'd built-in name is still an error rather than being
    silently treated as a hostname and pointed at a nonexistent DB.
    """
    value = (source_type or "").strip().lower()
    if not value or value in SUPPORTED_SCRAPER_TYPES or value == "local":
        return False
    return "." in value and "/" not in value and " " not in value


def _resolved_container_db_path(source_type: str, db_path: str) -> str:
    normalized = str(db_path or "").strip()
    if not normalized.startswith("/data/"):
        return normalized
    container_prefix = _SCRAPER_DB_CONTAINER_PATHS.get(source_type)
    if not container_prefix and is_generic_source_type(source_type):
        container_prefix = _GENERIC_CONTAINER_SITES_PATH
    if not container_prefix:
        return normalized
    relative_suffix = normalized[len("/data/"):].lstrip("/")
    return os.path.join(container_prefix, relative_suffix)


# Open a scraper SQLite database in read-only mode.
def _open_scraper_db(db_path: str, immutable: bool = False) -> sqlite3.Connection:
    normalized_path = db_path.replace("\\", "/")
    uri = "file:%s?mode=ro" % normalized_path
    if immutable:
        uri += "&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# Detect SQLite readonly errors that warrant an immutable retry.
def _is_sqlite_readonly_error(exc: Exception) -> bool:
    return "readonly database" in str(exc).lower()


# Read a scraper database and retry with immutable mode when needed.
def _read_scraper_db(db_path: str, reader):
    last_error = None
    for immutable in (False, True):
        connection = None
        try:
            connection = _open_scraper_db(db_path, immutable=immutable)
            return reader(connection)
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            last_error = exc
            if immutable or _is_sqlite_readonly_error(exc) is False:
                raise
        finally:
            if connection is not None:
                connection.close()
    if last_error is not None:
        raise last_error
    raise sqlite3.OperationalError("Could not read scraper database: %s" % db_path)


# Detect corruption-style SQLite errors from scraper databases.
def _is_sqlite_corruption_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "database disk image is malformed",
            "malformed",
            "file is not a database",
            "file is encrypted or is not a database",
            "not a database",
        )
    )


# Return whether the scraper database contains the named table.
def _sqlite_table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


# Return the set of column names for a scraper table.
def _sqlite_table_columns(connection: sqlite3.Connection, table_name: str):
    if _sqlite_table_exists(connection, table_name) is False:
        return set()
    escaped_name = table_name.replace('"', '""')
    rows = connection.execute('PRAGMA table_info("%s")' % escaped_name).fetchall()
    return {str(row["name"]) for row in rows}


# Resolve which posts column stores the source name for this scraper.
def _scraper_posts_source_column(connection: sqlite3.Connection, source_type: str) -> str:
    post_columns = _sqlite_table_columns(connection, "posts")
    if source_type == "reddit" and "subreddit" in post_columns and "board" not in post_columns:
        return "subreddit"
    if "board" in post_columns:
        return "board"
    if "subreddit" in post_columns:
        return "subreddit"
    raise sqlite3.OperationalError("posts table is missing a board/subreddit source column")


# Detect the legacy Reddit scraper schema that splits posts and comments.
def _reddit_uses_universal_schema(connection: sqlite3.Connection) -> bool:
    post_columns = _sqlite_table_columns(connection, "posts")
    return "subreddit" in post_columns and "board" not in post_columns and "id" in post_columns


def _normalize_source_name(value) -> str:
    return str(value or "").strip()


def _thread_source_name_candidates(
    connection: sqlite3.Connection,
    source_type: str,
    source_thread_id: str,
    preferred_source_name: Optional[str] = None,
):
    preferred = _normalize_source_name(preferred_source_name)
    candidates = [preferred] if preferred else []

    if source_type == "reddit" and _reddit_uses_universal_schema(connection):
        return candidates

    source_column = _scraper_posts_source_column(connection, source_type)
    rows = connection.execute(
        (
            "SELECT DISTINCT {source_column} AS source_name "
            "FROM posts WHERE thread_id = ?"
        ).format(source_column=source_column),
        (str(source_thread_id),),
    ).fetchall()
    discovered = []
    for row in rows:
        normalized = _normalize_source_name(row["source_name"])
        if normalized and normalized not in discovered:
            discovered.append(normalized)

    if preferred and preferred in discovered:
        return candidates
    if len(discovered) == 1:
        actual_source_name = discovered[0]
        if actual_source_name not in candidates:
            candidates.append(actual_source_name)
    return candidates


# Read configured source rows from whichever table a scraper exposes.
def _configured_source_rows(connection: sqlite3.Connection, source_type: str):
    if _sqlite_table_exists(connection, "sources"):
        return connection.execute("SELECT name FROM sources ORDER BY name").fetchall()
    if source_type == "reddit" and _sqlite_table_exists(connection, "subreddits"):
        return connection.execute("SELECT name FROM subreddits ORDER BY name").fetchall()
    return []


# Return the newest non-empty timestamp from a set of candidates.
def _max_timestamp(*values):
    filtered = [value for value in values if value]
    if not filtered:
        return None
    return max(filtered)


# Resolve the database path for a configured scraper type.
def aggregator_db_path(source_type: str) -> str:
    return _resolved_container_db_path(source_type, configured_aggregator_db_path(source_type))


def list_source_thread_ids(source_type: str, source_name: str, limit: int = 200):
    """Thread ids the crawler currently holds for one source board/subreddit.

    Newest-activity first, so a capped whole-board import takes the live threads
    rather than an arbitrary slice. Returns [] when the scraper DB is missing or
    unreadable -- callers treat that as "nothing to import yet", not an error.

    Backs the whole-board import (BoardSource.source_thread_id == "*").
    """
    name = _normalize_source_name(source_name)
    if not name:
        return []
    try:
        db_path = aggregator_db_path(source_type)
    except ValueError:
        return []
    if not db_path or not os.path.exists(db_path):
        # EXPECTED, not an error: the crawler creates <host>.db on its first
        # successful pass, so a whole-board source whose site has never been
        # crawled has no file yet. 16 of the 21 configured generic sites are in
        # that state, and letting them fall through to the `except` below logged
        # 40 ERROR-level tracebacks per sync cycle (every 10s via
        # _sync_board_incremental) — which buried the real errors.
        #
        # Returning [] here is exactly what the except-branch already did, so the
        # caller's `expansion_incomplete` prune guard behaves identically. That
        # guard is what stops an empty expansion from mass-deleting imported
        # threads, so this must keep returning an EMPTY LIST and never raise.
        app.logger.debug(
            "no scraper database yet for %s:%s (%s); nothing to import",
            source_type, source_name, db_path,
        )
        return []

    def _reader(connection):
        if not _sqlite_table_exists(connection, "posts"):
            return []
        if source_type == "reddit" and _reddit_uses_universal_schema(connection):
            rows = connection.execute(
                """
                SELECT CAST(id AS TEXT) AS thread_id
                FROM posts
                WHERE subreddit = ?
                ORDER BY COALESCE(created_utc, scraped_at) DESC
                LIMIT ?
                """,
                (name, int(limit)),
            ).fetchall()
        else:
            source_column = _scraper_posts_source_column(connection, source_type)
            rows = connection.execute(
                (
                    "SELECT CAST(thread_id AS TEXT) AS thread_id, MAX(scraped_at) AS last_seen "
                    "FROM posts WHERE {source_column} = ? AND thread_id IS NOT NULL "
                    "GROUP BY thread_id ORDER BY last_seen DESC LIMIT ?"
                ).format(source_column=source_column),
                (name, int(limit)),
            ).fetchall()
        seen, ids = set(), []
        for row in rows:
            thread_id = _normalize_source_name(row["thread_id"])
            if thread_id and thread_id not in seen:
                seen.add(thread_id)
                ids.append(thread_id)
        return ids

    try:
        return _read_scraper_db(db_path, _reader) or []
    except Exception as exc:
        # Contention is expected while the crawler writes and deserves one visible
        # line, not a traceback; anything else is a real fault (corrupt file,
        # EACCES) and keeps its traceback. Note sqlite returns the SAME message
        # ("unable to open database file") for a missing file, a missing parent
        # directory and a permissions failure, so os.path.exists above — not
        # message matching — is what distinguishes "never crawled".
        if "database is locked" in str(exc).lower():
            app.logger.warning(
                "scraper database busy while enumerating %s:%s: %s",
                source_type, source_name, exc,
            )
        else:
            app.logger.exception(
                "could not enumerate %s:%s threads for whole-board import",
                source_type, source_name,
            )
        return []


def source_thread_health(source_type: str, source_name: str = None):
    """Per-thread failure state from a crawler's own `thread_failures` table.

    Returns {(board, thread_id): {failure_count, last_error, last_failed_at,
    gone}} where `gone` means the recorded error looks like the thread no longer
    exists (404 / not found / deleted). Empty dict when the scraper DB or the
    table is unavailable — callers must treat "no data" as "no opinion" and
    never retire on it.

    Read directly rather than through a new crawler endpoint: the crawler already
    maintains this table and maniwani already opens these DBs read-only, so this
    needs no scraper-side change or version coupling.
    """
    try:
        db_path = aggregator_db_path(source_type)
    except ValueError:
        return {}
    if not os.path.exists(db_path):
        return {}

    def _reader(connection):
        if not _sqlite_table_exists(connection, "thread_failures"):
            return {}
        columns = _sqlite_table_columns(connection, "thread_failures")
        if not {"board", "thread_id", "failure_count"} <= columns:
            return {}
        sql = "SELECT board, thread_id, failure_count, last_error, last_failed_at FROM thread_failures"
        params = ()
        if source_name:
            sql += " WHERE board = ?"
            params = (_normalize_source_name(source_name),)
        out = {}
        for row in connection.execute(sql, params).fetchall():
            error_text = (row["last_error"] or "").lower()
            out[(str(row["board"]), str(row["thread_id"]))] = {
                "failure_count": int(row["failure_count"] or 0),
                "last_error": row["last_error"],
                "last_failed_at": row["last_failed_at"],
                # A 404/not-found/deleted thread will never come back; anything
                # else (timeouts, 403/429 blocks, parse errors) may be transient
                # and must NOT be treated as gone.
                "gone": any(
                    marker in error_text
                    for marker in ("404", "not found", "no longer exists", "deleted")
                ),
            }
        return out

    try:
        return _read_scraper_db(db_path, _reader) or {}
    except Exception:
        app.logger.debug("could not read thread_failures for %s", source_type, exc_info=True)
        return {}


# Return the current background sync interval in seconds.
def sync_interval_seconds() -> int:
    return app.config.get("AGGREGATOR_SYNC_INTERVAL", 300)


# Load the last full-sync timestamp for a board from cache.
def _load_sync_timestamp(board_id: int) -> Optional[_datetime.datetime]:
    raw_timestamp = cache.Cache().get(SYNC_CACHE_KEY_TEMPLATE % board_id)
    if raw_timestamp is None:
        return None
    try:
        return _datetime.datetime.fromisoformat(raw_timestamp)
    except ValueError:
        return None


# Store the last full-sync timestamp for a board in cache.
def _store_sync_timestamp(board_id: int, timestamp: _datetime.datetime) -> None:
    cache.Cache().set(SYNC_CACHE_KEY_TEMPLATE % board_id, timestamp.isoformat())


# Load the incremental import watermark for a scraper source.
def _get_watermark(source_type: str, source_name: str) -> Optional[str]:
    return cache.Cache().get(WATERMARK_CACHE_KEY_TEMPLATE % (source_type, source_name))


# Persist the incremental import watermark for a scraper source.
def _set_watermark(source_type: str, source_name: str, ts: str) -> None:
    cache.Cache().set(WATERMARK_CACHE_KEY_TEMPLATE % (source_type, source_name), ts)


# Read the newest scraped timestamp available for a scraper source.
def _scraper_latest_scraped_at(source_type: str, source_name: str) -> Optional[str]:
    try:
        db_path = aggregator_db_path(source_type)
    except ValueError:
        return None
    if not os.path.exists(db_path):
        return None
    try:
        def _reader(conn):
            if source_type == "reddit" and _reddit_uses_universal_schema(conn):
                post_latest_row = conn.execute(
                    "SELECT MAX(scraped_at) FROM posts WHERE subreddit = ?",
                    (source_name,),
                ).fetchone()
                post_latest = post_latest_row[0] if post_latest_row and post_latest_row[0] else None
                comment_latest = None
                if _sqlite_table_exists(conn, "comments"):
                    comment_latest_row = conn.execute(
                        """
                        SELECT MAX(c.scraped_at)
                        FROM comments c
                        JOIN posts p ON p.id = c.post_id
                        WHERE p.subreddit = ?
                        """,
                        (source_name,),
                    ).fetchone()
                    comment_latest = (
                        comment_latest_row[0]
                        if comment_latest_row and comment_latest_row[0]
                        else None
                    )
                return _max_timestamp(post_latest, comment_latest)
            row = conn.execute(
                "SELECT MAX(scraped_at) FROM posts WHERE %s = ?"
                % _scraper_posts_source_column(conn, source_type),
                (source_name,),
            ).fetchone()
            return row[0] if row and row[0] else None

        return _read_scraper_db(db_path, _reader)
    except Exception:
        return None


# Return whether a scraper source has content newer than its watermark.
def _source_has_new_content(source_type: str, source_name: str) -> bool:
    latest = _scraper_latest_scraped_at(source_type, source_name)
    if not latest:
        return False
    watermark = _get_watermark(source_type, source_name)
    return watermark is None or latest > watermark


# Summarize per-scraper database health and source activity for the admin UI.
def get_aggregator_db_stats() -> dict:
    result = {}
    for source_type in SUPPORTED_SCRAPER_TYPES:
        try:
            configured_db_path = configured_aggregator_db_path(source_type)
            db_path = aggregator_db_path(source_type)
        except ValueError:
            continue
        if not os.path.exists(db_path):
            result[source_type] = {
                "unavailable": True,
                "db_path": db_path,
                "configured_db_path": configured_db_path,
            }
            continue
        try:
            # Collect per-source row counts and freshness data from this scraper database.
            def _reader(conn):
                if source_type == "reddit" and _reddit_uses_universal_schema(conn):
                    thread_rows = conn.execute(
                        """
                        SELECT subreddit AS source_name,
                               COUNT(*) AS thread_count,
                               MAX(scraped_at) AS last_scraped
                        FROM posts
                        WHERE subreddit IS NOT NULL
                        GROUP BY subreddit
                        ORDER BY subreddit
                        """
                    ).fetchall()
                    comment_rows = []
                    if _sqlite_table_exists(conn, "comments"):
                        comment_rows = conn.execute(
                            """
                            SELECT p.subreddit AS source_name,
                                   COUNT(*) AS comment_count,
                                   MAX(c.scraped_at) AS last_scraped
                            FROM comments c
                            JOIN posts p ON p.id = c.post_id
                            WHERE p.subreddit IS NOT NULL
                            GROUP BY p.subreddit
                            ORDER BY p.subreddit
                            """
                        ).fetchall()
                    configured_sources = _configured_source_rows(conn, source_type)
                    total_posts = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
                    if _sqlite_table_exists(conn, "comments"):
                        total_posts += conn.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
                    return {
                        "thread_rows": thread_rows,
                        "comment_rows": comment_rows,
                        "configured_sources": configured_sources,
                        "total_posts": total_posts,
                    }

                source_column = _scraper_posts_source_column(conn, source_type)
                rows = conn.execute(
                    """
                    SELECT {source_column} AS source_name,
                           COUNT(*) AS thread_count,
                           (SELECT COUNT(*) FROM posts p2 WHERE p2.{source_column} = p.{source_column}) AS post_count,
                           MAX(scraped_at) AS last_scraped
                    FROM posts p
                    WHERE post_id = thread_id AND {source_column} IS NOT NULL
                    GROUP BY {source_column}
                    ORDER BY {source_column}
                    """.format(source_column=source_column)
                ).fetchall()
                configured_sources = _configured_source_rows(conn, source_type)
                total_posts = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
                return {
                    "rows": rows,
                    "configured_sources": configured_sources,
                    "total_posts": total_posts,
                }

            payload = _read_scraper_db(db_path, _reader)
            configured_sources = payload.get("configured_sources", []) or []
            merged_sources = {}
            for row in payload.get("rows", []) or []:
                merged_sources[str(row["source_name"])] = {
                    "source_name": row["source_name"],
                    "thread_count": row["thread_count"] or 0,
                    "post_count": row["post_count"] or 0,
                    "last_scraped": row["last_scraped"],
                }
            for row in payload.get("thread_rows", []) or []:
                merged_sources[str(row["source_name"])] = {
                    "source_name": row["source_name"],
                    "thread_count": row["thread_count"] or 0,
                    "post_count": row["thread_count"] or 0,
                    "last_scraped": row["last_scraped"],
                }
            for row in payload.get("comment_rows", []) or []:
                source_name = str(row["source_name"])
                source_stats = merged_sources.setdefault(source_name, {
                    "source_name": source_name,
                    "thread_count": 0,
                    "post_count": 0,
                    "last_scraped": None,
                })
                source_stats["post_count"] += row["comment_count"] or 0
                source_stats["last_scraped"] = _max_timestamp(
                    source_stats.get("last_scraped"),
                    row["last_scraped"],
                )
            for source_row in configured_sources:
                source_name = str(source_row["name"])
                merged_sources.setdefault(source_name, {
                    "source_name": source_name,
                    "thread_count": 0,
                    "post_count": 0,
                    "last_scraped": None,
                })
            result[source_type] = {
                "total_posts": payload["total_posts"],
                "db_path": db_path,
                "configured_db_path": configured_db_path,
                "sources": [merged_sources[name] for name in sorted(merged_sources)],
            }
        except Exception as exc:
            result[source_type] = {
                "error": str(exc),
                "db_path": db_path,
                "configured_db_path": configured_db_path,
            }
    return result
