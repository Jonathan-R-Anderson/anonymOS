"""Purge everything imported from one scraped source.

DESTRUCTIVE. Removes every imported thread that came from a given source_type
(and optionally one remote board within it), across every local board, plus the
ImportedMedia mappings and mirrored Media rows those threads owned.

Deliberately two-phase: `purge_preview()` counts exactly what would go, and
`purge_source()` does it. The admin UI shows the preview in the confirmation, so
"purge this source" is never a blind click — including how many LOCAL user replies
would be destroyed with it, which is the part that cannot be undone by re-scraping.

Local replies: an imported thread's Postgres Post rows are the LOCAL replies
users wrote (the scraped posts live in the per-source SQLite DB and are never
copied in). Deleting the thread cascades those away. A purge is explicitly "remove
this source's content", so it does delete them — but the count is surfaced first,
and `keep_threads_with_replies=True` skips exactly those threads.
"""
from model.BoardSource import BoardSource
from model.ImportedMedia import ImportedMedia
from model.Post import Post
from model.Thread import Thread
from shared import app, db


def _thread_query(source_type, source_name=None):
    query = db.session.query(Thread).filter(Thread.source_type == source_type)
    if source_name:
        query = query.filter(Thread.source_name == source_name)
    return query


def purge_preview(source_type, source_name=None):
    """Exactly what purge_source() would remove. Read-only."""
    source_type = (source_type or "").strip()
    if not source_type or source_type == "local":
        return None
    threads = _thread_query(source_type, source_name).all()
    thread_ids = [t.id for t in threads]

    local_posts = 0
    threads_with_replies = 0
    if thread_ids:
        rows = (
            db.session.query(Post.thread, db.func.count(Post.id))
            .filter(Post.thread.in_(thread_ids))
            .group_by(Post.thread)
            .all()
        )
        for _thread_id, count in rows:
            local_posts += count or 0
            if count:
                threads_with_replies += 1

    media_count = 0
    if thread_ids:
        media_count = (
            db.session.query(db.func.count(ImportedMedia.id))
            .filter(ImportedMedia.thread_id.in_(thread_ids))
            .scalar()
        ) or 0

    sources = (
        db.session.query(db.func.count(BoardSource.id))
        .filter(BoardSource.source_type == source_type)
    )
    if source_name:
        sources = sources.filter(BoardSource.source_name == source_name)

    boards = sorted({t.board for t in threads})
    return {
        "source_type": source_type,
        "source_name": source_name,
        "threads": len(threads),
        "local_posts": local_posts,
        "threads_with_replies": threads_with_replies,
        "imported_media": media_count,
        "board_sources": sources.scalar() or 0,
        "boards": boards,
    }


def purge_source(source_type, source_name=None, remove_sources=True,
                 keep_threads_with_replies=False):
    """Delete imported content for one source. Returns a summary dict.

    remove_sources -- also delete the BoardSource rows, so it stops being scraped
        and sync does not simply re-import everything on the next pass. Almost
        always what you want; without it a purge is undone within minutes.
    keep_threads_with_replies -- skip threads carrying local user replies.
    """
    source_type = (source_type or "").strip()
    if not source_type or source_type == "local":
        return {"threads": 0, "media": 0, "sources": 0, "skipped": 0}

    from services.aggregator_sync.media import delete_thread

    threads = _thread_query(source_type, source_name).all()
    deleted_threads = deleted_media = skipped = 0
    board_ids = set()

    for thread in threads:
        if keep_threads_with_replies:
            has_local = (
                db.session.query(Post.id).filter(Post.thread == thread.id).first() is not None
            )
            if has_local:
                skipped += 1
                continue
        board_ids.add(thread.board)
        # Count mappings before the cascade takes them.
        deleted_media += (
            db.session.query(db.func.count(ImportedMedia.id))
            .filter(ImportedMedia.thread_id == thread.id)
            .scalar()
        ) or 0
        try:
            # delete_thread handles cache invalidation and the media/mapping
            # teardown; going through it keeps a purge consistent with every
            # other thread deletion path.
            delete_thread(thread)
            deleted_threads += 1
        except Exception:
            db.session.rollback()
            app.logger.exception("purge: could not delete imported thread %s", thread.id)

    removed_sources = 0
    if remove_sources:
        source_query = db.session.query(BoardSource).filter(
            BoardSource.source_type == source_type
        )
        if source_name:
            source_query = source_query.filter(BoardSource.source_name == source_name)
        removed_sources = source_query.delete(synchronize_session=False)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("purge: commit failed for %s", source_type)
        raise

    for board_id in board_ids:
        try:
            from thread import invalidate_board_cache
            invalidate_board_cache(board_id)
        except Exception:
            pass

    app.logger.warning(
        "PURGED source %s%s: %d thread(s), %d media mapping(s), %d source row(s), %d skipped",
        source_type, ("/%s" % source_name) if source_name else "",
        deleted_threads, deleted_media, removed_sources, skipped,
    )
    return {
        "threads": deleted_threads,
        "media": deleted_media,
        "sources": removed_sources,
        "skipped": skipped,
    }


__all__ = ["purge_preview", "purge_source"]
