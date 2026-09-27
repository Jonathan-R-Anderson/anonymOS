import datetime as _datetime
import json
import os
import sqlite3
import time as _time
from typing import Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import and_

from model.BlockedMediaHash import BlockedMediaHash, block_media_hash, get_blocked_media_hash, media_sha256_bytes
from model.BlockedSourcePost import block_source_post, blocked_source_post_ids
from model.Post import Post
from model.Thread import Thread
import shared
from shared import app, db
from thread import invalidate_board_cache

from services.aggregator_sync.config import (
    MAX_IMPORTED_SOURCE_ID_LENGTH,
    MAX_IMPORTED_SOURCE_NAME_LENGTH,
    SUPPORTED_SCRAPER_TYPES,
    WHOLE_BOARD_THREAD_ID,
    whole_board_thread_limit,
)
from services.aggregator_sync.media import (
    delete_thread,
    invalidate_thread_cache,
    sync_imported_thread_media,
)
from services.aggregator_sync.assets import resolve_scraper_asset_path
from services.aggregator_sync.scraper_db import (
    _is_sqlite_corruption_error,
    _is_sqlite_readonly_error,
    _load_sync_timestamp,
    _open_scraper_db,
    _reddit_uses_universal_schema,
    _read_scraper_db,
    _scraper_latest_scraped_at,
    _scraper_posts_source_column,
    _set_watermark,
    _sqlite_table_exists,
    _thread_source_name_candidates,
    _source_has_new_content,
    _store_sync_timestamp,
    aggregator_db_path,
    get_aggregator_db_stats,
    is_generic_source_type,
    list_source_thread_ids,
    sync_interval_seconds,
)
from services.aggregator_sync.state import (
    _background_sync_should_run,
    _format_sync_error,
    _global_sync_lock,
    _sync_log,
    _sync_status,
)
from services.aggregator_sync.text import (
    _clip_imported_text,
    imported_row_datetime,
    normalize_source_url,
    row_value,
)
from services.thread_retention import trim_board_threads as _trim_board_threads


def _run_with_session_retry(label: str, operation):
    for attempt in range(2):
        try:
            return operation()
        except Exception as exc:
            if attempt == 0 and shared.is_retryable_session_error(exc):
                app.logger.warning("%s hit a retryable SQLAlchemy session error; resetting session and retrying once", label)
                shared.reset_sqlalchemy_session(dispose_engine=True)
                continue
            raise


def _cleanup_session_after_error(exc: Exception) -> None:
    if shared.is_retryable_session_error(exc):
        shared.reset_sqlalchemy_session(dispose_engine=True)
        return
    try:
        db.session.rollback()
    except Exception:
        pass
    try:
        db.session.remove()
    except Exception:
        pass


def _end_read_transaction():
    """Close the implicit transaction opened by a read.

    SQLAlchemy autobegins on the first SELECT and does not end it until someone
    commits or rolls back. Both helpers below produce a WORK LIST that the
    caller then spends minutes acting on -- scraper HTTP with a 5s timeout per
    source, across ~25 source types. Holding the read transaction open for that
    long is what wedged production: the session sat `idle in transaction` with
    wait_event=Client while app.py's startup `ALTER TABLE ... ADD COLUMN`
    queued behind its ACCESS SHARE lock for ACCESS EXCLUSIVE, and every
    subsequent SELECT queued behind the DDL. 81 connections deep, the pool was
    exhausted and the site served 503s until the session was terminated by hand.

    A rollback (not a commit) because these reads write nothing, and it must
    never raise into a caller that is only trying to list work.
    """
    try:
        db.session.rollback()
    except Exception:
        app.logger.exception("aggregator sync: could not end the read transaction")


def _all_board_ids():
    from model.Board import Board

    ids = [row[0] for row in db.session.query(Board.id).all()]
    _end_read_transaction()
    return ids


def _board_ids_with_sources():
    from model.BoardSource import BoardSource

    ids = [
        row[0]
        for row in (
            db.session.query(BoardSource.board_id)
            .filter(BoardSource.source_type != "local")
            .distinct()
            .all()
        )
    ]
    # Do not hold a transaction across the scraper HTTP the caller is about to
    # do with this list -- see _end_read_transaction().
    _end_read_transaction()
    return ids

# Return a JSON-safe snapshot of the current aggregator sync state.
def get_sync_status() -> dict:
    """Return a JSON-serialisable snapshot of the current sync status."""
    per_board = {
        str(k): dict(v)
        for k, v in _sync_status["per_board"].items()
    }
    try:
        from model.Board import Board

        boards = db.session.query(Board).all()
        for board in boards:
            source_labels = [
                "%s:%s:%s" % (source.source_type, source.source_name, source.source_thread_id)
                for source in board.sources
                if is_syncable_source_type(source.source_type)
            ]
            if not source_labels:
                continue
            board_status = per_board.setdefault(str(board.id), {})
            board_status.setdefault("board_name", board.name)
            board_status["sources"] = source_labels
            board_status.setdefault("syncing", False)
    except Exception:
        app.logger.exception("Could not hydrate sync status from configured board sources")
    return {
        "is_syncing": _sync_status["is_syncing"],
        "is_leader": _sync_status["is_leader"],
        "last_check": _sync_status["last_check"],
        "last_sync_start": _sync_status["last_sync_start"],
        "last_sync_end": _sync_status["last_sync_end"],
        "bg_cycles": _sync_status["bg_cycles"],
        "per_board": per_board,
        "log": list(_sync_status["log"]),
    }



# Run a full sync for one board when it is forced or due.
def sync_board_if_due(board, force: bool = False) -> bool:
    with _global_sync_lock:
        active_sources = [source for source in board.sources if is_syncable_source_type(source.source_type) and not source.retired]
        if len(active_sources) == 0:
            return False

        source_labels = ["%s:%s:%s" % (s.source_type, s.source_name, s.source_thread_id) for s in active_sources]

        # Make sure a status entry exists for this board even before a sync runs
        board_status = _sync_status["per_board"].setdefault(board.id, {})
        board_status.setdefault("board_name", board.name)
        board_status["sources"] = source_labels

        now = _datetime.datetime.utcnow()
        last_synced = _load_sync_timestamp(board.id)
        interval = sync_interval_seconds()

        if force is False and last_synced is not None:
            age = (now - last_synced).total_seconds()
            if age < interval:
                # Record next-due time so the UI can show a countdown
                next_due = last_synced + _datetime.timedelta(seconds=interval)
                board_status["last_synced"] = last_synced.isoformat()
                board_status["next_sync_due"] = next_due.isoformat()
                return False

        _sync_log("Starting sync for board /%s/ (sources: %s)" % (board.name, ", ".join(source_labels)))
        board_status["syncing"] = True
        board_status["last_error"] = None
        _sync_status["is_syncing"] = True
        _sync_status["last_sync_start"] = now.isoformat()

        try:
            changed, threads_added, threads_bumped = sync_board_sources(board)
        except Exception as exc:
            formatted_error = _format_sync_error(exc)
            board_status["last_error"] = formatted_error
            _sync_log("Error syncing /%s/: %s" % (board.name, formatted_error))
            raise
        finally:
            board_status["syncing"] = False
            _sync_status["is_syncing"] = False

        finish = _datetime.datetime.utcnow()
        next_due = finish + _datetime.timedelta(seconds=interval)
        board_status["last_synced"] = finish.isoformat()
        board_status["next_sync_due"] = next_due.isoformat()
        board_status["last_threads_added"] = threads_added
        board_status["last_threads_bumped"] = threads_bumped
        board_status["total_threads_added"] = board_status.get("total_threads_added", 0) + threads_added
        board_status["total_threads_bumped"] = board_status.get("total_threads_bumped", 0) + threads_bumped
        _sync_status["last_sync_end"] = finish.isoformat()
        _store_sync_timestamp(board.id, finish)

        _sync_log(
            "Finished sync for /%s/: %d thread(s) added, %d thread(s) updated" % (
                board.name, threads_added, threads_bumped)
        )
        return changed


# Run due full-sync work across a sequence of boards.
def sync_boards_if_due(boards: Iterable[object], force: bool = False) -> bool:
    changed = False
    for board in boards:
        if sync_board_if_due(board, force=force):
            changed = True
    return changed


# Publish a new-thread event after an external source creates a thread.
def _publish_new_thread(thread: Thread) -> None:
    try:
        import keystore
        client = keystore.Pubsub()
        client.publish("new-thread", json.dumps({
            "thread": thread.id,
            "board": thread.board,
        }))
    except Exception:
        app.logger.exception("Failed to publish new-thread event for thread %s", thread.id)


# Publish a bump-thread event after imported content updates a thread.
def _publish_bump_thread(thread: Thread) -> None:
    try:
        import keystore
        client = keystore.Pubsub()
        client.publish("bump-thread", json.dumps({
            "thread": thread.id,
            "board": thread.board,
        }))
    except Exception:
        app.logger.exception("Failed to publish bump-thread event for thread %s", thread.id)


def _open_scraper_db_write(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def _row_source_post_id(row) -> Optional[str]:
    return _clip_imported_text(row_value(row, "post_id"), MAX_IMPORTED_SOURCE_ID_LENGTH)


def _drop_blocked_source_post_rows(source_type: str, source_thread_id: str, post_rows: Sequence[object]):
    """Drop rows for posts a moderator has deleted (durable Postgres blocklist),
    so a blocked scraped post is never re-imported/synced regardless of whether
    the read-only scraper SQLite row could be physically removed."""
    if not post_rows:
        return post_rows
    blocked_ids = blocked_source_post_ids(source_type, source_thread_id)
    if not blocked_ids:
        return post_rows
    return [row for row in post_rows if _row_source_post_id(row) not in blocked_ids]


def _local_post_count(thread_id: int) -> int:
    return (
        db.session.query(Post.id)
        .filter(Post.thread == thread_id)
        .count()
    )


def _thread_rows_from_conn(connection, source_type: str, source_name: str, source_thread_id: str):
    if source_type == "reddit" and _reddit_uses_universal_schema(connection):
        op = connection.execute(
            """
            SELECT id AS post_id, id AS thread_id, NULL AS parent_post_id,
                   title AS subject, selftext AS body_text, author,
                   CASE
                       WHEN permalink LIKE '/%' THEN 'https://redlib.catsarch.com' || permalink
                       WHEN permalink LIKE 'https://www.reddit.com/%' THEN REPLACE(permalink, 'https://www.reddit.com', 'https://redlib.catsarch.com')
                       WHEN permalink LIKE 'https://reddit.com/%' THEN REPLACE(permalink, 'https://reddit.com', 'https://redlib.catsarch.com')
                       WHEN permalink LIKE 'https://old.reddit.com/%' THEN REPLACE(permalink, 'https://old.reddit.com', 'https://redlib.catsarch.com')
                       WHEN url LIKE 'https://www.reddit.com/%' THEN REPLACE(url, 'https://www.reddit.com', 'https://redlib.catsarch.com')
                       WHEN url LIKE 'https://reddit.com/%' THEN REPLACE(url, 'https://reddit.com', 'https://redlib.catsarch.com')
                       WHEN url LIKE 'https://old.reddit.com/%' THEN REPLACE(url, 'https://old.reddit.com', 'https://redlib.catsarch.com')
                       ELSE COALESCE(permalink, url)
                   END AS url,
                   image_url,
                   NULL AS image_path,
                   CASE
                       WHEN permalink LIKE '/%' THEN 'https://redlib.catsarch.com' || permalink
                       WHEN permalink LIKE 'https://www.reddit.com/%' THEN REPLACE(permalink, 'https://www.reddit.com', 'https://redlib.catsarch.com')
                       WHEN permalink LIKE 'https://reddit.com/%' THEN REPLACE(permalink, 'https://reddit.com', 'https://redlib.catsarch.com')
                       WHEN permalink LIKE 'https://old.reddit.com/%' THEN REPLACE(permalink, 'https://old.reddit.com', 'https://redlib.catsarch.com')
                       ELSE permalink
                   END AS permalink,
                   score,
                   upvote_ratio,
                   num_comments,
                   post_type,
                   flair,
                   is_nsfw,
                   COALESCE(created_utc, scraped_at) AS activity_at,
                   scraped_at
            FROM posts
            WHERE subreddit = ? AND CAST(id AS TEXT) = ?
            LIMIT 1
            """,
            (source_name, source_thread_id),
        ).fetchone()
        comments = []
        if _sqlite_table_exists(connection, "comments"):
            comments = connection.execute(
                """
                SELECT c.comment_id AS post_id,
                       c.post_id AS thread_id,
                       REPLACE(REPLACE(c.parent_id, 't1_', ''), 't3_', '') AS parent_post_id,
                       NULL AS subject,
                       c.body AS body_text,
                       c.author,
                       NULL AS url,
                       NULL AS image_url,
                       NULL AS image_path,
                       NULL AS permalink,
                       c.score AS score,
                       NULL AS upvote_ratio,
                       NULL AS num_comments,
                       'comment' AS post_type,
                       NULL AS flair,
                       0 AS is_nsfw,
                       COALESCE(c.created_utc, c.scraped_at) AS activity_at,
                       c.scraped_at AS scraped_at
                FROM comments c
                WHERE CAST(c.post_id AS TEXT) = ?
                ORDER BY COALESCE(c.created_utc, c.scraped_at) ASC, c.comment_id ASC
                """,
                (source_thread_id,),
            ).fetchall()
        if op is not None:
            return dict(op), [dict(op)] + [dict(row) for row in comments]
        if comments:
            placeholder = {
                "post_id": source_thread_id,
                "thread_id": source_thread_id,
                "parent_post_id": None,
                "subject": "[removed]",
                "body_text": "[removed by moderation]",
                "author": "[removed]",
                "url": None,
                "image_url": None,
                "image_path": None,
                "permalink": None,
                "score": None,
                "upvote_ratio": None,
                "num_comments": len(comments),
                "post_type": "self",
                "flair": None,
                "is_nsfw": 0,
                "activity_at": row_value(comments[-1], "activity_at"),
                "scraped_at": row_value(comments[0], "scraped_at"),
            }
            return placeholder, [placeholder] + [dict(row) for row in comments]
        return None, []

    source_column = _scraper_posts_source_column(connection, source_type)
    source_name_candidates = _thread_source_name_candidates(
        connection,
        source_type,
        source_thread_id,
        source_name,
    ) or ([str(source_name or "").strip()] if source_name else [])
    thread_row = None
    resolved_source_name = None
    for candidate_source_name in source_name_candidates:
        thread_row = connection.execute(
            (
                "SELECT * FROM posts WHERE {source_column} = ? AND thread_id = ? AND post_id = thread_id "
                "ORDER BY scraped_at DESC, post_id DESC LIMIT 1"
            ).format(source_column=source_column),
            (candidate_source_name, source_thread_id),
        ).fetchone()
        if thread_row is not None:
            resolved_source_name = candidate_source_name
            break
    if thread_row is None:
        for candidate_source_name in source_name_candidates:
            thread_row = connection.execute(
                (
                    "SELECT * FROM posts WHERE {source_column} = ? AND thread_id = ? "
                    "ORDER BY scraped_at ASC, post_id ASC LIMIT 1"
                ).format(source_column=source_column),
                (candidate_source_name, source_thread_id),
            ).fetchone()
            if thread_row is not None:
                resolved_source_name = candidate_source_name
                break
    if thread_row is None:
        return None, []
    post_rows = connection.execute(
        (
            "SELECT * FROM posts WHERE thread_id = ? AND {source_column} = ? "
            "ORDER BY scraped_at ASC, post_id ASC"
        ).format(source_column=source_column),
        (source_thread_id, resolved_source_name),
    ).fetchall()
    return dict(thread_row), [dict(row) for row in post_rows]


def _source_row_media_hash(source_type: str, row) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    image_path = row_value(row, "image_path")
    if not image_path:
        return None, None, None
    resolved = resolve_scraper_asset_path(source_type, image_path)
    if resolved is None:
        return None, None, None
    _data_dir, _relative_path, absolute_path = resolved
    if os.path.isfile(absolute_path) is False:
        return None, None, absolute_path
    with open(absolute_path, "rb") as asset_file:
        return media_sha256_bytes(asset_file.read()), normalize_source_url(
            row_value(row, "image_url") or row_value(row, "url") or row_value(row, "permalink")
        ), absolute_path


def _ban_source_asset_fingerprint(absolute_path, sha256, reason, acting_slip_id):
    """Also ban the image by PERCEPTUAL fingerprint, not only its exact SHA-256.

    An exact-hash ban is defeated by a single re-encode, a rescale or one changed
    pixel — which is precisely what happens when the same image is reposted across
    chans. services/perceptual.py already derives a distance-comparable
    fingerprint and model/BannedImageFingerprint matches new uploads against it,
    but the ban action never populated it, so only byte-identical copies were ever
    caught.

    Best-effort: a fingerprint we cannot compute must not abort the ban, because
    the exact hash has already been recorded by then.
    """
    if not absolute_path or not os.path.isfile(absolute_path):
        return None
    try:
        from model.BannedImageFingerprint import add_local_fingerprint
        from services import perceptual

        with open(absolute_path, "rb") as asset_file:
            data = asset_file.read()
        computed = perceptual.compute_fingerprint(data)
        if not computed:
            # Not a still image (video/audio) or undecodable: exact hash only.
            return None
        algorithm, dims, fingerprint_hex = computed
        add_local_fingerprint(
            fingerprint_hex,
            reason=reason,
            created_by_slip_id=acting_slip_id,
            sha256=sha256,
            algorithm=algorithm,
            dims=dims,
        )
        return fingerprint_hex
    except Exception:
        app.logger.exception(
            "could not compute a perceptual fingerprint for %s", absolute_path
        )
        return None


def _purge_imported_media_for_source_post(thread, source_post_id):
    """Delete OUR stored copy of an imported post's media.

    Recording the hash stops the image coming back, but it does nothing about the
    copy already mirrored into Postgres + the object store. Banning an image has to
    remove it, not merely stop displaying it — the row, the Media record and the
    stored bytes all go. _delete_imported_media_mapping handles all three
    (including media.delete_attachment()).

    Independent of whether the scraper's own SQLite row could be deleted: that DB
    is opened read-only by design, and the BlockedSourcePost/BlockedMediaHash
    entries are what stop a surviving remote row from being re-imported.
    """
    from model.ImportedMedia import ImportedMedia

    from .media import _delete_imported_media_mapping

    mapping = (
        db.session.query(ImportedMedia)
        .filter(
            ImportedMedia.thread_id == thread.id,
            ImportedMedia.source_post_id == str(source_post_id),
        )
        .one_or_none()
    )
    if mapping is None:
        return False
    _delete_imported_media_mapping(mapping)
    return True


def _delete_source_row_asset(source_type: str, row) -> None:
    image_path = row_value(row, "image_path")
    if not image_path:
        return
    resolved = resolve_scraper_asset_path(source_type, image_path)
    if resolved is None:
        return
    _data_dir, _relative_path, absolute_path = resolved
    try:
        if os.path.isfile(absolute_path):
            os.remove(absolute_path)
    except OSError:
        app.logger.exception("Failed deleting cached scraper asset %s", absolute_path)


def _filtered_source_rows_after_purge(post_rows: Sequence[object], rows_to_purge: Sequence[object]):
    purged_post_ids = {
        _row_source_post_id(row)
        for row in rows_to_purge
        if _row_source_post_id(row)
    }
    filtered_rows = [
        dict(row)
        for row in post_rows
        if _row_source_post_id(row) not in purged_post_ids
    ]
    representative_row = dict(filtered_rows[0]) if filtered_rows else None
    return representative_row, filtered_rows


def _purge_source_posts(source_type: str, source_name: str, source_thread_id: str, rows_to_purge: Sequence[object]):
    if not rows_to_purge:
        return None, []
    db_path = aggregator_db_path(source_type)
    connection = None
    try:
        connection = _open_scraper_db_write(db_path)
        if source_type == "reddit" and _reddit_uses_universal_schema(connection):
            for row in rows_to_purge:
                source_post_id = _row_source_post_id(row)
                if not source_post_id:
                    continue
                if source_post_id == source_thread_id:
                    connection.execute("DELETE FROM posts WHERE CAST(id AS TEXT) = ?", (source_thread_id,))
                else:
                    connection.execute(
                        "DELETE FROM comments WHERE CAST(post_id AS TEXT) = ? AND comment_id = ?",
                        (source_thread_id, source_post_id),
                    )
        else:
            source_column = _scraper_posts_source_column(connection, source_type)
            for row in rows_to_purge:
                source_post_id = _row_source_post_id(row)
                if not source_post_id:
                    continue
                connection.execute(
                    (
                        "DELETE FROM posts WHERE {source_column} = ? AND thread_id = ? AND post_id = ?"
                    ).format(source_column=source_column),
                    (source_name, source_thread_id, source_post_id),
                )
        connection.commit()
        refreshed_thread_row, refreshed_post_rows = _thread_rows_from_conn(
            connection,
            source_type,
            source_name,
            source_thread_id,
        )
    finally:
        if connection is not None:
            connection.close()

    for row in rows_to_purge:
        _delete_source_row_asset(source_type, row)

    return refreshed_thread_row, refreshed_post_rows


def _purge_blocked_source_rows(source_type: str, source_name: str, source_thread_id: str, post_rows: Sequence[object]):
    if not post_rows:
        return None, []
    try:
        blocked_hash_exists = db.session.query(BlockedMediaHash.sha256).first() is not None
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        return dict(post_rows[0]), [dict(row) for row in post_rows]
    if blocked_hash_exists is False:
        return dict(post_rows[0]), [dict(row) for row in post_rows]
    blocked_rows = []
    seen_paths = {}
    seen_hashes = {}
    for row in post_rows:
        media_hash, _target_url, absolute_path = _source_row_media_hash(source_type, row)
        if absolute_path and absolute_path in seen_paths:
            media_hash = seen_paths[absolute_path]
        elif absolute_path:
            seen_paths[absolute_path] = media_hash
        if not media_hash:
            continue
        is_blocked = seen_hashes.get(media_hash)
        if is_blocked is None:
            try:
                is_blocked = get_blocked_media_hash(media_hash) is not None
            except Exception:
                try:
                    db.session.rollback()
                except Exception:
                    pass
                return dict(post_rows[0]), [dict(row) for row in post_rows]
            seen_hashes[media_hash] = is_blocked
        if is_blocked:
            blocked_rows.append(row)
    if not blocked_rows:
        return dict(post_rows[0]), [dict(row) for row in post_rows]
    _sync_log(
        "Purging %d blocked media post(s) from %s:%s thread %s"
        % (len(blocked_rows), source_type, source_name, source_thread_id)
    )
    try:
        return _purge_source_posts(source_type, source_name, source_thread_id, blocked_rows)
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
        if _is_sqlite_readonly_error(exc) is False:
            raise
        app.logger.warning(
            "Scraper DB for %s:%s thread %s is read-only; filtering %d blocked row(s) in memory",
            source_type,
            source_name,
            source_thread_id,
            len(blocked_rows),
        )
        return _filtered_source_rows_after_purge(post_rows, blocked_rows)


def purge_imported_source_post(
    thread: Thread,
    source_post_id: str,
    block_media: bool = False,
    reason: Optional[str] = None,
    acting_slip_id: Optional[int] = None,
):
    if thread.source_type == "local" or not thread.source_thread_id:
        raise ValueError("That thread is not backed by imported scraper content.")
    normalized_post_id = _clip_imported_text(source_post_id, MAX_IMPORTED_SOURCE_ID_LENGTH)
    if not normalized_post_id:
        raise ValueError("Imported source post could not be identified.")

    db_path = aggregator_db_path(thread.source_type)
    if os.path.exists(db_path) is False:
        raise ValueError("The source scraper database is unavailable for this thread.")

    def _reader(connection):
        return _thread_rows_from_conn(
            connection,
            thread.source_type,
            thread.source_name,
            thread.source_thread_id,
        )

    thread_row, post_rows = _read_scraper_db(db_path, _reader)
    target_row = None
    for row in post_rows:
        if _row_source_post_id(row) == normalized_post_id:
            target_row = row
            break
    if target_row is None:
        raise ValueError("Imported source post %s was not found." % normalized_post_id)

    blocked_hash = None
    blocked_fingerprint = None
    purged_local_media = False
    if block_media:
        blocked_hash, source_url, absolute_path = _source_row_media_hash(thread.source_type, target_row)
        if not blocked_hash:
            raise ValueError("This imported post does not have a locally cached image to block.")
        ban_reason = (
            reason
            or "Blocked imported image from thread %d post %s" % (thread.id, normalized_post_id)
        )
        # TWO hashes, deliberately: the exact SHA-256 catches the identical file,
        # and the perceptual fingerprint catches re-encoded / rescaled reposts that
        # an exact hash cannot.
        block_media_hash(
            blocked_hash,
            reason=ban_reason,
            source_url=source_url,
            created_by_slip_id=acting_slip_id,
        )
        blocked_fingerprint = _ban_source_asset_fingerprint(
            absolute_path, blocked_hash, ban_reason, acting_slip_id
        )
        # PURGE our stored copy rather than just hiding it. The hashes above are
        # what keep it out in future; leaving the mirrored Media row and its object
        # in place would mean a "banned" image was still sitting in the database.
        purged_local_media = _purge_imported_media_for_source_post(thread, normalized_post_id)

    # Record the deletion in a durable Postgres blocklist keyed by post id. This
    # is what makes deletion work regardless of the scraper SQLite DB being
    # read-only, hides text-only posts (which have no media hash to block), and
    # keeps the post hidden if a later scrape re-inserts the row into SQLite.
    block_source_post(
        thread.source_type,
        thread.source_name,
        thread.source_thread_id,
        normalized_post_id,
        reason=(reason or "Deleted imported post %s from thread %d" % (normalized_post_id, thread.id)),
        created_by_slip_id=acting_slip_id,
    )

    purged_source_posts = True
    try:
        refreshed_thread_row, refreshed_post_rows = _purge_source_posts(
            thread.source_type,
            thread.source_name,
            thread.source_thread_id,
            [target_row],
        )
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
        if _is_sqlite_readonly_error(exc) is False:
            raise
        # SQLite is read-only, so the physical row stays — but the Postgres
        # blocklist above hides it everywhere imported rows are read. Filter it
        # out in memory here so the counts / last_updated below reflect the
        # deletion. No longer an error: the delete still takes effect.
        purged_source_posts = False
        app.logger.warning(
            "Scraper DB for %s:%s thread %s is read-only; source post %s hidden via blocklist without purging SQLite rows",
            thread.source_type,
            thread.source_name,
            thread.source_thread_id,
            normalized_post_id,
        )
        refreshed_thread_row, refreshed_post_rows = _filtered_source_rows_after_purge(post_rows, [target_row])

    latest_local_post_row = (
        db.session.query(Post.datetime)
        .filter(Post.thread == thread.id)
        .order_by(Post.datetime.desc())
        .first()
    )
    latest_local_post = latest_local_post_row[0] if latest_local_post_row else None
    deleted_thread = False
    if not refreshed_post_rows:
        if latest_local_post is None:
            delete_thread(thread)
            deleted_thread = True
        else:
            thread.last_updated = latest_local_post
            db.session.add(thread)
    else:
        desired_last_updated = None
        for row in refreshed_post_rows:
            row_dt = imported_row_datetime(row, fallback=None)
            if row_dt is not None and (desired_last_updated is None or row_dt > desired_last_updated):
                desired_last_updated = row_dt
        if latest_local_post is not None and (desired_last_updated is None or latest_local_post > desired_last_updated):
            desired_last_updated = latest_local_post
        desired_url = normalize_source_url(row_value(refreshed_thread_row, "permalink") or row_value(refreshed_thread_row, "url"))
        if desired_url:
            thread.source_url = desired_url
        if desired_last_updated is not None:
            thread.last_updated = desired_last_updated
        db.session.add(thread)

    invalidate_thread_cache(thread.id)
    invalidate_board_cache(thread.board)
    return {
        "blocked_sha256": blocked_hash,
        # Perceptual hash, so the caller can tell the operator that near-duplicate
        # reposts are covered too — not just byte-identical files.
        "blocked_fingerprint": blocked_fingerprint,
        # Whether OUR mirrored copy (ImportedMedia + Media + stored object) was
        # actually deleted, as distinct from purged_source_posts, which is about the
        # crawler's read-only SQLite row.
        "purged_local_media": purged_local_media,
        "deleted_thread": deleted_thread,
        "remaining_source_posts": len(refreshed_post_rows),
        "purged_source_posts": purged_source_posts,
    }


# Import every thread URL submitted for a board and prune withdrawn ones.

def is_syncable_source_type(source_type: str) -> bool:
    """Whether this source_type has a scraper we can read.

    The built-in four, plus any host-keyed generic aggregated-chan site. Every
    place that used to compare against SUPPORTED_SCRAPER_TYPES must go through
    here, or a generic source is silently skipped by sync and never imports.
    """
    return source_type in SUPPORTED_SCRAPER_TYPES or is_generic_source_type(source_type)


def sync_board_sources(board) -> Tuple[bool, int, int]:
    """Returns (changed, threads_added, threads_bumped)."""
    changed = False
    new_thread_ids = []
    bumped_thread_ids = []

    # Boards fed by our own NNTP protocol are exempt from scraping: the peer
    # pushes its posts to us, so scraping the same site would import duplicates
    # and fight the sync. Checked here (not only at submission time) so a board
    # that gets peered AFTER its sources were configured also stops scraping.
    # Deliberately does NOT prune already-imported threads -- turning on NNTP
    # should stop new scraping, not delete history.
    try:
        from board_sources import nntp_newsgroups_for_board
        newsgroups = nntp_newsgroups_for_board(board.id)
    except Exception:
        newsgroups = []
    if newsgroups:
        _sync_log(
            "Skipping scrape of /%s/: syncing over NNTP (%s)."
            % (board.name, ", ".join(newsgroups))
        )
        return False, 0, 0

    configured_threads = []
    # A whole-board source ("*") that we cannot currently enumerate must NOT be
    # treated as "no threads configured": the prune below deletes every imported
    # thread missing from this list, so an unreadable crawler DB would wipe the
    # board and re-import it next cycle. Track that and skip pruning instead.
    expansion_incomplete = False
    uncrawled_sources = []
    # TWO lists, because "still configured" and "still worth fetching" are
    # different questions:
    #   configured_threads  -> what the PRUNE may keep. Includes RETIRED sources.
    #   importable_threads  -> what we actually re-fetch. Excludes retired.
    # Conflating them made retirement destructive: retiring a dead source removed
    # it from configured_threads, so the prune saw its imported thread as "no
    # longer submitted" and delete_thread() wiped the Thread, its ImportedMedia and
    # the mirrored Media — while the retire sweep logged "(imported content kept)".
    # The has_local_posts guard does not save it: import_source_thread creates no
    # local Post rows. Retirement must stop FETCHING, never stop KEEPING.
    importable_threads = []
    for source in board.sources:
        if not is_syncable_source_type(source.source_type):
            continue
        if not source.source_thread_id:
            continue
        source_thread_id = str(source.source_thread_id)
        if source_thread_id != WHOLE_BOARD_THREAD_ID:
            configured_threads.append((source.source_type, source.source_name, source_thread_id))
            if not source.retired:
                importable_threads.append(
                    (source.source_type, source.source_name, source_thread_id)
                )
            continue
        if source.retired:
            # A retired whole-board source keeps whatever it already imported, but
            # is not expanded or re-fetched.
            for (already_imported_id,) in (
                db.session.query(Thread.source_thread_id)
                .filter(
                    Thread.board == board.id,
                    Thread.source_type == source.source_type,
                    Thread.source_name == source.source_name,
                )
                .all()
            ):
                if already_imported_id:
                    configured_threads.append(
                        (source.source_type, source.source_name, str(already_imported_id))
                    )
            continue
        discovered = list_source_thread_ids(
            source.source_type, source.source_name, whole_board_thread_limit()
        )
        if not discovered:
            # Collected and logged ONCE per board below, not per source: 40 of the
            # configured whole-board sources are on sites the crawler has never
            # touched, and one line each per cycle flooded the 200-line sync-log
            # ring buffer shown in the admin panel, pushing out everything useful.
            expansion_incomplete = True
            uncrawled_sources.append((source.source_type, source.source_name))
            continue
        _sync_log(
            "Whole-board source %s:%s expanded to %d thread(s) for /%s/."
            % (source.source_type, source.source_name, len(discovered), board.name)
        )
        for discovered_id in discovered:
            configured_threads.append((source.source_type, source.source_name, discovered_id))
            importable_threads.append((source.source_type, source.source_name, discovered_id))
        # ALSO treat everything already imported from this source as configured.
        #
        # The expansion is a MOVING WINDOW (newest whole_board_thread_limit()
        # threads by scraped_at). The prune below deletes every imported thread
        # absent from configured_threads, so without this an already-imported
        # thread that drifts out of the window is deleted — and re-imported if it
        # drifts back. Any source with more threads than the limit therefore
        # churned its whole local copy away: 28chan.org (189 crawled threads vs a
        # limit of 100) lost all 40 of its imported threads, while 0xfdb.xyz (23,
        # under the limit) was untouched.
        #
        # Ageing out imported threads is thread_retention.trim_board_threads' job,
        # not the prune's. The prune exists to drop sources an operator REMOVED.
        for (already_imported_id,) in (
            db.session.query(Thread.source_thread_id)
            .filter(
                Thread.board == board.id,
                Thread.source_type == source.source_type,
                Thread.source_name == source.source_name,
            )
            .all()
        ):
            if already_imported_id:
                configured_threads.append(
                    (source.source_type, source.source_name, str(already_imported_id))
                )

    if uncrawled_sources:
        labels = ["%s:%s" % pair for pair in uncrawled_sources]
        shown = ", ".join(labels[:6])
        if len(labels) > 6:
            shown += " and %d more" % (len(labels) - 6)
        _sync_log(
            "%d whole-board source(s) for /%s/ have no crawled threads yet (%s); "
            "skipping prune this cycle."
            % (len(labels), board.name, shown)
        )
        # An uncrawled source that ALREADY HAS imported threads is a different and
        # far more serious condition than one that has simply never run: it means
        # the scraper database DISAPPEARED for a site whose content we are still
        # serving — an unmounted or recreated aggregator volume, or a renamed file.
        # That is precisely the situation in which the prune would delete the whole
        # archive, so it must be loud. Without this, the os.path.exists() shortcut
        # in list_source_thread_ids (added to stop 240 tracebacks/min for
        # never-crawled sites) would also silence this genuine fault down to DEBUG.
        try:
            uncrawled_types = {source_type for source_type, _ in uncrawled_sources}
            with_content = (
                db.session.query(Thread.source_type, db.func.count(Thread.id))
                .filter(Thread.board == board.id, Thread.source_type.in_(uncrawled_types))
                .group_by(Thread.source_type)
                .all()
            )
            for source_type, thread_count in with_content:
                if thread_count:
                    app.logger.warning(
                        "scraper database for %s is missing, but /%s/ still has %d "
                        "imported thread(s) from it - check the aggregator volume. "
                        "Pruning is disabled for this board until it returns.",
                        source_type, board.name, thread_count,
                    )
        except Exception:
            app.logger.debug(
                "could not check for vanished scraper databases on /%s/",
                board.name, exc_info=True,
            )
    if not expansion_incomplete and _prune_unsubmitted_source_threads(board, configured_threads):
        changed = True

    grouped_thread_ids = {}
    for source_type, source_name, source_thread_id in importable_threads:
        grouped_thread_ids.setdefault((source_type, source_name), set()).add(source_thread_id)

    for (source_type, source_name), thread_ids in sorted(grouped_thread_ids.items()):
        _sync_log(
            "Importing %d submitted %s:%s thread(s) into /%s/ ..."
            % (len(thread_ids), source_type, source_name, board.name)
        )
        wm = _scraper_latest_scraped_at(source_type, source_name)
        thread_events, had_errors = sync_single_source(
            board,
            source_type,
            source_name,
            thread_ids,
        )
        if wm and had_errors is False:
            _set_watermark(source_type, source_name, wm)
        source_new = 0
        source_bumped = 0
        if thread_events:
            changed = True
            db.session.commit()
            invalidate_board_cache(board.id)
            for thread_id, is_new in thread_events:
                if is_new:
                    new_thread_ids.append(thread_id)
                    source_new += 1
                    thread = db.session.query(Thread).get(thread_id)
                    if thread:
                        _publish_new_thread(thread)
                else:
                    bumped_thread_ids.append(thread_id)
                    source_bumped += 1
                    thread = db.session.query(Thread).get(thread_id)
                    if thread:
                        _publish_bump_thread(thread)
        _sync_log(
            "%s:%s → %d new thread(s), %d updated thread(s)" % (
                source_type, source_name, source_new, source_bumped)
        )

    if trim_board_threads(board):
        changed = True
    if changed:
        db.session.commit()
        invalidate_board_cache(board.id)

    return changed, len(new_thread_ids), len(bumped_thread_ids)


# Trim a board down to its retention limit and report whether anything was removed.
def trim_board_threads(board, protected_thread_ids=None) -> bool:
    return len(_trim_board_threads(board, protected_thread_ids=protected_thread_ids)) > 0


# Delete imported threads whose URLs are no longer submitted for this board.
def _prune_unsubmitted_source_threads(board, configured_threads) -> bool:
    # Identity must match import_source_thread(), which locates an existing
    # thread by (board, source_type, source_thread_id) — NOT source_name. Keying
    # the prune on source_name too meant a thread whose stored source_name no
    # longer matched the configured one (e.g. a re-derived/clipped name) was
    # deleted here and then re-created fresh by the importer, wiping its local
    # replies. source_thread_id is also clipped on the stored thread, so clip the
    # configured id the same way before comparing.
    configured = {
        (source_type, _clip_imported_text(str(source_thread_id), MAX_IMPORTED_SOURCE_ID_LENGTH))
        for source_type, source_name, source_thread_id in configured_threads
    }
    imported_threads = (
        db.session.query(Thread)
        .filter(Thread.board == board.id)
        .filter(Thread.source_type != "local")
        .all()
    )
    removed_any = False
    for thread in imported_threads:
        key = (thread.source_type, str(thread.source_thread_id or ""))
        if key in configured:
            continue
        # Never destroy a thread that carries local user replies. Deleting it
        # (and re-importing on the next sync) would wipe those replies — this is
        # the "edited a post and the whole thread got recopied" bug. Keep it;
        # import_source_thread still matches it by source_thread_id and updates
        # it in place.
        has_local_posts = (
            db.session.query(Post.id).filter(Post.thread == thread.id).first() is not None
        )
        if has_local_posts:
            _sync_log(
                "Keeping imported %s:%s thread %s on /%s/ (has local replies; not pruning)"
                % (thread.source_type, thread.source_name, thread.source_thread_id, board.name)
            )
            continue
        _sync_log(
            "Removing imported %s:%s thread %s from /%s/ (URL no longer submitted)"
            % (thread.source_type, thread.source_name, thread.source_thread_id, board.name)
        )
        delete_thread(thread)
        removed_any = True
    return removed_any


# Import a set of submitted threads for one scraper source from its SQLite database.
def sync_single_source(board, source_type: str, source_name: str, thread_ids, incremental: bool = False) -> Tuple[List[Tuple[int, bool]], bool]:
    """Returns (thread_events, had_errors) for an import of submitted threads.

    Only the explicitly submitted *thread_ids* are read from the scraper DB.
    When *incremental* is True the per-source watermark is advanced afterwards
    so the fast loop can skip sources without new content.
    """
    db_path = aggregator_db_path(source_type)
    if os.path.exists(db_path) is False:
        return [], False

    # Snapshot the scraper's current max timestamp BEFORE reading rows so that
    # any rows the scraper writes concurrently get picked up next time.
    new_watermark = _scraper_latest_scraped_at(source_type, source_name) if incremental else None

    try:
        # Read the submitted threads from the scraper DB and import each one in isolation.
        def _reader(connection):
            events = []
            had_errors = False
            for thread_row, post_rows in source_threads(connection, source_type, source_name, thread_ids):
                savepoint = db.session.begin_nested()
                try:
                    result = import_source_thread(board, source_type, source_name, thread_row, post_rows)
                    savepoint.commit()
                except Exception as exc:
                    had_errors = True
                    try:
                        savepoint.rollback()
                    except Exception:
                        pass
                    source_thread_id = _clip_imported_text(thread_row["thread_id"], MAX_IMPORTED_SOURCE_ID_LENGTH)
                    board_status = _sync_status["per_board"].setdefault(board.id, {})
                    board_status["board_name"] = board.name
                    board_status["last_error"] = _format_sync_error(
                        Exception(
                            "Thread import failed for %s:%s thread %s: %s"
                            % (source_type, source_name, source_thread_id, exc)
                        )
                    )
                    _sync_log(
                        "Skipping %s:%s thread %s for /%s/: %s"
                        % (source_type, source_name, source_thread_id, board.name, exc)
                    )
                    continue
                if result is not None:
                    events.append(result)
            return events, had_errors

        events, had_errors = _read_scraper_db(db_path, _reader)
        if incremental and new_watermark and had_errors is False:
            _set_watermark(source_type, source_name, new_watermark)
        return events, had_errors
    except sqlite3.DatabaseError as exc:
        if _is_sqlite_corruption_error(exc):
            board_status = _sync_status["per_board"].setdefault(board.id, {})
            board_status["board_name"] = board.name
            board_status["last_error"] = (
                _format_sync_error(
                    Exception("Scraper DB read failed for %s:%s: %s" % (source_type, source_name, exc))
                )
            )
            _sync_log(
                "Skipping %s:%s for /%s/ because scraper DB %s appears corrupt: %s"
                % (source_type, source_name, board.name, db_path, exc)
            )
            return [], True
        raise


# Yield thread rows and their post rows for the submitted thread ids.
def source_threads(connection, source_type: str, source_name: str, thread_ids):
    """Yield ``(thread_row, post_rows)`` pairs for the submitted thread ids.

    The scraper DB is never enumerated wholesale - only threads whose direct
    URL was submitted for a board are read from it.
    """
    if not is_syncable_source_type(source_type):
        raise ValueError("Unsupported source type: %s" % source_type)

    requested_ids = sorted({str(thread_id) for thread_id in (thread_ids or []) if thread_id})
    for source_thread_id in requested_ids:
        representative_row, post_rows = _thread_rows_from_conn(
            connection,
            source_type,
            source_name,
            source_thread_id,
        )
        if not post_rows:
            continue
        representative_row, post_rows = _purge_blocked_source_rows(
            source_type,
            source_name,
            source_thread_id,
            post_rows,
        )
        if not post_rows:
            continue
        post_rows = _drop_blocked_source_post_rows(source_type, source_thread_id, post_rows)
        if not post_rows:
            continue
        representative_row = post_rows[0]
        yield representative_row, post_rows


# One favicon-fetch attempt per source_type per process (avoid re-hitting a
# site that has no usable favicon on every imported thread).
_FAVICON_ATTEMPTED = set()


def _fetch_favicon_png(host):
    """Fetch a site's favicon and return it as PNG bytes, or None. Tries the
    homepage's <link rel=icon> then /favicon.ico; converts (incl. multi-size
    .ico) to a single PNG via Pillow. Best-effort, network-bound."""
    import io
    import re
    from urllib.parse import urljoin
    import requests
    from PIL import Image

    headers = {"User-Agent": "Mozilla/5.0 (compatible; SyndichanFaviconBot/1.0)"}
    candidates = []
    for scheme in ("https://", "http://"):
        base = scheme + host + "/"
        try:
            resp = requests.get(base, timeout=8, headers=headers)
        except Exception:
            continue
        if resp.ok and resp.text:
            for tag in re.findall(r"<link\b[^>]*>", resp.text, re.IGNORECASE):
                if re.search(r'rel\s*=\s*["\'][^"\']*icon', tag, re.IGNORECASE):
                    href = re.search(r'href\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
                    if href:
                        candidates.append(urljoin(base, href.group(1)))
            candidates.append(urljoin(base, "/favicon.ico"))
            break
    if not candidates:
        candidates = ["https://%s/favicon.ico" % host, "http://%s/favicon.ico" % host]

    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.get(url, timeout=8, headers=headers)
            if not r.ok or not r.content:
                continue
            img = Image.open(io.BytesIO(r.content))
            try:
                if getattr(img, "n_frames", 1) > 1:
                    best, best_area = None, -1
                    for i in range(img.n_frames):
                        img.seek(i)
                        area = img.size[0] * img.size[1]
                        if area > best_area:
                            best, best_area = img.copy(), area
                    img = best or img
            except Exception:
                pass
            out = io.BytesIO()
            img.convert("RGBA").save(out, format="PNG")
            data = out.getvalue()
            if data:
                return data
        except Exception:
            continue
    return None


def ensure_source_favicon_watermark(source_type, source_url):
    """If this source has no watermark yet, grab the source site's favicon,
    convert it to PNG, store it, and set it as the watermark overlaid on that
    source's imported posts. One attempt per source per process; never raises."""
    if not source_type or source_type in _FAVICON_ATTEMPTED:
        return
    try:
        from source_watermarks import source_watermark_media_id, replace_source_watermark
        from model.SourceModeration import host_of
        if source_watermark_media_id(source_type):
            _FAVICON_ATTEMPTED.add(source_type)
            return
        host = host_of(source_url)
        if not host:
            return
        _FAVICON_ATTEMPTED.add(source_type)
        png = _fetch_favicon_png(host)
        if not png:
            return
        import io
        from model.Media import storage
        media = storage.save_attachment(io.BytesIO(png), content_type="image/png")
        if media is not None and getattr(media, "id", None):
            replace_source_watermark(source_type, media.id)
            _sync_log("Derived %s watermark from %s favicon (media %s)" % (source_type, host, media.id))
    except Exception:
        pass


# Create or update one imported thread's metadata row in PostgreSQL.
# Post content is read directly from SQLite at display time — nothing is copied into PostgreSQL.
def import_source_thread(board, source_type: str, source_name: str, thread_row, post_rows: Sequence) -> Optional[Tuple[int, bool]]:
    source_thread_id = _clip_imported_text(thread_row["thread_id"], MAX_IMPORTED_SOURCE_ID_LENGTH)
    # 3-strike policy: never import (or refresh) content from a site currently
    # under an aggregation ban for illegal content. See model/SourceModeration.py.
    _source_url = normalize_source_url(row_value(thread_row, "permalink") or row_value(thread_row, "url"))
    try:
        from model.SourceModeration import host_of, is_host_banned
        if is_host_banned(host_of(_source_url)):
            return None
    except Exception:
        pass
    # First time we import from this source, derive its post watermark from the
    # site's favicon (best-effort, one attempt per source per process).
    ensure_source_favicon_watermark(source_type, _source_url)
    existing_thread = (
        db.session.query(Thread)
        .filter(
            and_(
                Thread.board == board.id,
                Thread.source_type == source_type,
                Thread.source_thread_id == source_thread_id,
            )
        )
        .first()
    )
    created_thread = existing_thread is None

    # Prefer source-native post times so thread ordering reflects real activity
    # rather than the scraper's per-source crawl batches.
    last_updated = None
    for row in post_rows:
        row_dt = imported_row_datetime(row, fallback=None)
        if row_dt is not None and (last_updated is None or row_dt > last_updated):
            last_updated = row_dt
    if last_updated is None:
        last_updated = _datetime.datetime.utcnow()

    # SCRAPE WINDOW. Do not claim a remote thread that is already stale -- there
    # is no point mirroring its images just so the retention sweep can delete
    # them an hour later. Only NEW threads are gated: an existing thread going
    # stale is the sweep's business, and it protects threads that local users
    # have replied to, which this early return knows nothing about.
    if created_thread:
        from services.scraped_retention import is_within_window

        if not is_within_window(last_updated):
            app.logger.debug(
                "scrape window: skipping %s:%s:%s (newest post %s is outside the window)",
                source_type, source_name, source_thread_id, last_updated,
            )
            # Bare None, matching the banned-host skip above: the caller tests
            # `if result is not None`, so a (None, False) tuple would sail past
            # that guard and be appended to `events` as a thread with no id.
            return None

    if created_thread:
        existing_thread = Thread(
            board=board.id,
            views=0,
            source_type=source_type,
            source_name=_clip_imported_text(source_name, MAX_IMPORTED_SOURCE_NAME_LENGTH),
            source_thread_id=source_thread_id,
            source_url=normalize_source_url(row_value(thread_row, "permalink") or row_value(thread_row, "url")),
            last_updated=last_updated,
        )
        db.session.add(existing_thread)
        db.session.flush()
        trim_board_threads(board, protected_thread_ids={existing_thread.id})
        db.session.flush()
        sync_imported_thread_media(existing_thread, source_type, post_rows)
        invalidate_thread_cache(existing_thread.id)
        return (existing_thread.id, True)

    latest_local_post_row = (
        db.session.query(Post.datetime)
        .filter(Post.thread == existing_thread.id)
        .order_by(Post.datetime.desc())
        .first()
    )
    latest_local_post = latest_local_post_row[0] if latest_local_post_row else None
    desired_last_updated = last_updated
    if latest_local_post is not None and latest_local_post > desired_last_updated:
        desired_last_updated = latest_local_post

    changed = False
    desired_url = normalize_source_url(row_value(thread_row, "permalink") or row_value(thread_row, "url"))
    if existing_thread.source_url != desired_url:
        existing_thread.source_url = desired_url
        changed = True
    if existing_thread.last_updated != desired_last_updated:
        existing_thread.last_updated = desired_last_updated
        changed = True
    media_changed = sync_imported_thread_media(existing_thread, source_type, post_rows)
    if changed or media_changed:
        db.session.add(existing_thread)
        db.session.flush()
        invalidate_thread_cache(existing_thread.id)
        return (existing_thread.id, False)
    return None


# Import only content newer than the stored watermark for a board.
def _sync_board_incremental(board) -> None:
    """Import only content newer than the watermark for each of a board's sources.

    This is the fast path: no stale-thread removal, no trimming.  Those are
    handled by the periodic full sync.  We only commit if something actually
    changed so idle boards are free.
    """
    new_thread_ids = []
    bumped_thread_ids = []

    grouped_thread_ids = {}
    for source in board.sources:
        if not is_syncable_source_type(source.source_type) or not source.source_thread_id or source.retired:
            continue
        source_thread_id = str(source.source_thread_id)
        if source_thread_id != WHOLE_BOARD_THREAD_ID:
            grouped_thread_ids.setdefault(
                (source.source_type, source.source_name), set()
            ).add(source_thread_id)
            continue
        # A whole-board source must be expanded here too, not just in the full
        # sync. Passing "*" through as a literal thread id asks the crawler for a
        # thread named "*", finds nothing, and silently imports nothing — which is
        # why monitored boards accumulated hundreds of scraped posts that never
        # appeared locally, while individual-thread sources kept working.
        #
        # No prune guard is needed here (unlike sync_board_sources): this function
        # never calls _prune_unsubmitted_source_threads, so an empty expansion just
        # means "nothing to import yet" and cannot delete anything.
        discovered = list_source_thread_ids(
            source.source_type, source.source_name, whole_board_thread_limit()
        )
        if not discovered:
            continue
        grouped_thread_ids.setdefault(
            (source.source_type, source.source_name), set()
        ).update(str(thread_id) for thread_id in discovered)

    for (source_type, source_name), thread_ids in sorted(grouped_thread_ids.items()):
        if not _source_has_new_content(source_type, source_name):
            continue
        thread_events, _had_errors = sync_single_source(
            board, source_type, source_name, thread_ids, incremental=True
        )
        for thread_id, is_new in thread_events:
            if is_new:
                new_thread_ids.append(thread_id)
            else:
                bumped_thread_ids.append(thread_id)

    if not new_thread_ids and not bumped_thread_ids:
        return

    db.session.commit()
    invalidate_board_cache(board.id)

    for thread_id in new_thread_ids:
        thread = db.session.query(Thread).get(thread_id)
        if thread:
            _publish_new_thread(thread)
            _sync_log("Incremental: new thread %d in /%s/" % (thread_id, board.name))

    for thread_id in bumped_thread_ids:
        thread = db.session.query(Thread).get(thread_id)
        if thread:
            _publish_bump_thread(thread)


# Start the periodic full-sync and incremental-sync background loops.
def start_background_sync(flask_app) -> None:
    """
    Spawn a long-running gevent greenlet that periodically syncs all boards
    with external sources.  Each iteration re-checks sync_interval_seconds()
    so the config value can be changed at runtime.  Errors are logged and the
    loop continues rather than crashing the worker.

    Also re-registers all existing board sources with the scrapers on startup
    so that scraper container restarts don't require a main-app restart to
    resume crawling.
    """
    from model.Board import Board

    # Re-register submitted board threads with scraper services after startup.
    def _register_all_sources():
        """Push every submitted thread to the appropriate scraper on startup."""
        try:
            import scraper_client
            boards = db.session.query(Board).all()
            triples = []
            for board in boards:
                for source in board.sources:
                    if not is_syncable_source_type(source.source_type) or not source.source_thread_id or source.retired:
                        continue
                    # A whole-board follow is not a thread. Registering "*" as a
                    # thread id makes the crawler answer 400, and register_thread
                    # used to treat that as "storage is broken" and POST /reset —
                    # wiping the crawler's active boards so nothing crawled at all.
                    if str(source.source_thread_id) == WHOLE_BOARD_THREAD_ID:
                        continue
                    triples.append((source.source_type, source.source_name, source.source_thread_id))
            if triples:
                flask_app.logger.info(
                    "aggregator_sync: re-registering %d submitted thread(s) with scrapers", len(triples)
                )
                scraper_client.sync_all_threads(triples)
        except Exception:
            flask_app.logger.exception("aggregator_sync: startup source registration failed")

    # Run the slow full-sync loop that handles pruning and retention work.
    def _periodic_loop():
        """Full sync every few minutes: stale-thread removal, trimming, etc."""
        # Give the scrapers a moment to finish their own startup before we
        # bombard them with registration calls.
        _time.sleep(10)
        with flask_app.app_context():
            if _background_sync_should_run():
                _register_all_sources()
        while True:
            _time.sleep(60)
            try:
                with flask_app.app_context():
                    try:
                        if _background_sync_should_run():
                            _sync_status["last_check"] = _datetime.datetime.utcnow().isoformat()
                            _sync_status["bg_cycles"] += 1
                            board_ids = _run_with_session_retry(
                                "Background aggregator board enumeration",
                                _all_board_ids,
                            )
                            for board_id in board_ids:
                                board = db.session.query(Board).get(board_id)
                                if board is None:
                                    continue
                                with _global_sync_lock:
                                    sync_board_if_due(board)
                    except Exception as exc:
                        _cleanup_session_after_error(exc)
                        flask_app.logger.exception("Background aggregator sync failed")
            except Exception:
                flask_app.logger.exception("Background aggregator sync: unexpected loop error")

    # Run the fast incremental loop that publishes fresh imported threads quickly.
    def _continuous_loop():
        """Incremental sync every 10 s: publish new threads as soon as the scraper writes them."""
        _time.sleep(15)  # let the periodic loop run first
        while True:
            _time.sleep(10)
            try:
                with flask_app.app_context():
                    try:
                        if _background_sync_should_run():
                            board_ids = _run_with_session_retry(
                                "Continuous aggregator board enumeration",
                                _board_ids_with_sources,
                            )
                            for board_id in board_ids:
                                board = db.session.query(Board).get(board_id)
                                if board is None:
                                    continue
                                with _global_sync_lock:
                                    try:
                                        _sync_board_incremental(board)
                                    except Exception as exc:
                                        _cleanup_session_after_error(exc)
                                        flask_app.logger.exception(
                                            "Incremental sync failed for board %s", board_id
                                        )
                    except Exception as exc:
                        _cleanup_session_after_error(exc)
                        flask_app.logger.exception("Continuous sync loop failed")
            except Exception:
                flask_app.logger.exception("Continuous sync: unexpected loop error")

    shared.spawn_native_thread(target=_periodic_loop, name="aggregator-sync-periodic", daemon=True)
    shared.spawn_native_thread(target=_continuous_loop, name="aggregator-sync-continuous", daemon=True)
