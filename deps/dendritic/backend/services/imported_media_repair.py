"""Validate imported threads against their source, and repair what is wrong.

Two distinct failure modes, with different owners:

  * THE SOURCE ROW ITSELF IS DEFICIENT — the crawler stored the post with an empty
    body or no image_url. That happened wholesale on vichan sites: BODY_SELECTORS
    lacked `div.body` so every body imported empty, and the OP's file lives in a
    <div class="files"> SIBLING of div.post.op so no OP image was ever captured.
    maniwani cannot fix this; only a RE-SCRAPE can, and `upsert_post` does
    `ON CONFLICT(post_id) DO UPDATE SET body_text=..., image_url=...`, so one
    re-fetch overwrites the bad row. This module asks the crawler to re-fetch the
    thread now (register_thread fetches immediately) rather than waiting out the
    per-thread monitor backoff, which reaches a full day.
  * THE SOURCE IS FINE BUT maniwani NEVER MIRRORED THE IMAGE — see below.

Imported post BODIES are never copied into Postgres; they are read live from the
per-source SQLite at render time. So fixing the crawler row fixes the displayed
text with no further work here. Only MEDIA is materialised locally, which is why
media is the only thing this module stores.

THE MEDIA HALF — re-mirror imported posts whose image is missing.

Why that is needed: `sync_board_sources` skips a source entirely when its
watermark shows no new content (`_source_has_new_content`). That is the right
call for post text — but it means a post whose image failed to mirror the first
time (remote 500, timeout, a URL that 404'd, a rate-limited site, the NSFW
classifier being down under fail-closed) is NEVER retried. The post stays
permanently imported-without-its-image once the thread goes quiet.

This sweep finds those posts and re-runs the normal media pipeline for their
thread, bypassing the watermark. It deliberately reuses
`sync_imported_thread_media`, so repaired images go through exactly the same
gates as a first import — banned-hash, perceptual fingerprint, ClamAV, and the
**NSFW classifier** (per-board, via `_nsfw_board_for_thread`). No image reaches
storage through a path that skips scanning.

Cheap to run: a thread is only touched when a source row that HAS an image has no
ImportedMedia mapping, so a fully-mirrored thread costs one scraper-DB read.
"""
import datetime as _datetime
import threading

from model.ImportedMedia import ImportedMedia
from model.Thread import Thread
from model.SiteSetting import get_setting
from shared import app, db

SETTING_KEY = "imported_media_repair_enabled"
BATCH_SETTING_KEY = "imported_media_repair_batch"
DEFAULT_BATCH = 25
_SWEEP_INTERVAL_SECONDS = 900

_thread = None
_lock = threading.Lock()
_stop = threading.Event()


def repair_enabled():
    raw = (get_setting(SETTING_KEY, "") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def repair_batch():
    raw = (get_setting(BATCH_SETTING_KEY, "") or "").strip()
    try:
        return max(1, min(int(raw), 500)) if raw else DEFAULT_BATCH
    except ValueError:
        return DEFAULT_BATCH


def _source_rows_for_thread(thread):
    """(thread_row, post_rows) for one imported thread, or (None, []) on failure."""
    from services.aggregator_sync.api import _thread_rows_from_conn
    from services.aggregator_sync.scraper_db import _read_scraper_db, aggregator_db_path

    try:
        db_path = aggregator_db_path(thread.source_type)
    except ValueError:
        return None, []

    def _reader(connection):
        return _thread_rows_from_conn(
            connection, thread.source_type, thread.source_name, str(thread.source_thread_id)
        )

    try:
        return _read_scraper_db(db_path, _reader)
    except Exception:
        app.logger.debug(
            "media repair: could not read source rows for thread %s", thread.id, exc_info=True
        )
        return None, []


def _rows_missing_media(thread, source_rows):
    """Source rows that carry an image but have no ImportedMedia mapping."""
    from services.aggregator_sync.text import row_value

    mapped = {
        str(source_post_id)
        for (source_post_id,) in db.session.query(ImportedMedia.source_post_id)
        .filter(ImportedMedia.thread_id == thread.id)
        .all()
    }
    missing = []
    for row in source_rows:
        if row is None:
            continue
        # Only rows the SOURCE says have an image. A text-only post legitimately
        # has no media and must not be retried forever.
        has_image = bool(row_value(row, "image_url")) or bool(row_value(row, "image_path"))
        if not has_image:
            continue
        source_post_id = row_value(row, "post_id")
        if source_post_id is None:
            continue
        if str(source_post_id) not in mapped:
            missing.append(row)
    return missing


def repair_thread(thread):
    """Re-mirror any missing images on one imported thread.

    Returns the number of source rows that were missing media before the run.
    """
    from services.aggregator_sync.media import sync_imported_thread_media

    thread_row, post_rows = _source_rows_for_thread(thread)
    source_rows = ([thread_row] if thread_row is not None else []) + list(post_rows or [])
    if not source_rows:
        return 0
    missing = _rows_missing_media(thread, source_rows)
    if not missing:
        return 0
    app.logger.info(
        "media repair: thread %s (%s:%s:%s) missing %d image(s); re-mirroring",
        thread.id, thread.source_type, thread.source_name, thread.source_thread_id, len(missing),
    )
    try:
        # The normal pipeline: mirrors what is missing, and every byte goes
        # through the same upload gates including the NSFW classifier.
        sync_imported_thread_media(thread, thread.source_type, source_rows)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("media repair failed for thread %s", thread.id)
        return 0
    return len(missing)


def run_imported_media_repair(limit=None):
    """Sweep imported threads for missing images. Returns (threads, images)."""
    if not repair_enabled():
        return 0, 0
    limit = limit or repair_batch()
    threads = (
        db.session.query(Thread)
        .filter(Thread.source_type != "local")
        # Newest first: a thread that just imported is the most likely to have a
        # transient media failure worth retrying, and the most visible.
        .order_by(Thread.last_updated.desc())
        .limit(limit)
        .all()
    )
    repaired_threads = repaired_images = 0
    for thread in threads:
        try:
            count = repair_thread(thread)
        except Exception:
            db.session.rollback()
            app.logger.exception("media repair crashed for thread %s", thread.id)
            continue
        if count:
            repaired_threads += 1
            repaired_images += count
    if repaired_images:
        app.logger.info(
            "media repair: re-mirrored %d image(s) across %d thread(s)",
            repaired_images, repaired_threads,
        )
    return repaired_threads, repaired_images


def _loop(flask_app):
    with flask_app.app_context():
        while not _stop.is_set():
            # Leader-gated: this is the heaviest of the periodic loops (it
            # re-mirrors media, so ClamAV + NSFW + a remote fetch per image) and
            # it ran in all four workers at once, racing on the same rows.
            try:
                from services.singleton_worker import is_maintenance_leader

                leader = is_maintenance_leader()
            except Exception:
                leader = False
            try:
                # Source first: a re-scrape may be what makes the image exist at
                # all, and the media repair on the next sweep then mirrors it.
                if leader:
                    run_imported_content_validate()
            except Exception:
                flask_app.logger.exception("imported content validation failed")
            try:
                if leader:
                    run_imported_media_repair()
            except Exception:
                flask_app.logger.exception("imported media repair sweep failed")
            finally:
                try:
                    db.session.remove()
                except Exception:
                    pass
            _stop.wait(timeout=_SWEEP_INTERVAL_SECONDS)


def start_imported_media_repair(flask_app):
    """Start the periodic repair sweep once per process."""
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="imported-media-repair", daemon=True
        )
        _thread.start()
        return True


__all__ = [
    "BATCH_SETTING_KEY", "MAX_RESCRAPE_PER_SWEEP", "RESCRAPE_SETTING_KEY",
    "SETTING_KEY", "repair_batch", "repair_enabled", "repair_thread",
    "request_rescrape", "rescrape_enabled", "run_imported_content_validate",
    "run_imported_media_repair", "source_row_issues", "start_imported_media_repair",
]


# ---------------------------------------------------------------------------
# Source-side validation: is the crawler's stored row 1:1 with the live thread?
# ---------------------------------------------------------------------------
# Runs in the same sweep as the media repair. Where the media repair fixes
# maniwani's copy, this fixes the CRAWLER's copy by forcing a re-fetch — the only
# thing that can repair an empty body or a missing image_url at the source.

RESCRAPE_SETTING_KEY = "imported_rescrape_enabled"
_RESCRAPE_MARK_KEY = "imported_rescrape_marks"
# Cap re-fetch requests per sweep: each one makes the crawler hit the remote site.
MAX_RESCRAPE_PER_SWEEP = 10


def rescrape_enabled():
    raw = (get_setting(RESCRAPE_SETTING_KEY, "") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def source_row_issues(thread, source_rows):
    """What is wrong with the CRAWLER's stored rows for this thread.

    Only reports things a re-scrape could plausibly fix, so a genuinely text-only
    or image-less thread is not flagged forever.
    """
    from services.aggregator_sync.text import row_value

    issues = []
    if not source_rows:
        return ["no source rows at all"]

    op_id = str(thread.source_thread_id)
    op_row = None
    for row in source_rows:
        if row is not None and str(row_value(row, "post_id")) == op_id:
            op_row = row
            break

    if op_row is None:
        issues.append("OP row missing from the scraper DB")
    else:
        if not (row_value(op_row, "body_text") or "").strip():
            issues.append("OP body empty")

    # A thread where NOTHING has a body is the vichan div.body symptom, not a
    # coincidence — flag it even when the OP itself is legitimately image-only.
    bodies = sum(
        1 for row in source_rows
        if row is not None and (row_value(row, "body_text") or "").strip()
    )
    if bodies == 0 and len(source_rows) > 1:
        issues.append("no post in the thread has any body text")

    return issues


def _rescrape_marks():
    import json
    try:
        return json.loads(get_setting(_RESCRAPE_MARK_KEY, "") or "{}") or {}
    except Exception:
        return {}


def _mark_rescraped(thread_id):
    """Remember we already asked for a re-fetch, so one bad thread is not
    re-requested every sweep forever."""
    import json
    from model.SiteSetting import set_setting
    marks = _rescrape_marks()
    marks[str(thread_id)] = _datetime.datetime.utcnow().isoformat()
    # Bounded: keep the most recent 500 marks.
    if len(marks) > 500:
        for key in sorted(marks, key=marks.get)[: len(marks) - 500]:
            marks.pop(key, None)
    set_setting(_RESCRAPE_MARK_KEY, json.dumps(marks))
    db.session.commit()



def _nudge_monitored_board(thread):
    """Ask the shared generic scraper to re-crawl this thread's board now.

    Re-POSTing the monitored board sets the crawler's crawl_trigger, so the
    monitored-board pass runs immediately with the site bound — instead of waiting
    out the cycle interval. Idempotent on the crawler side (duplicate entries are
    deduped), so this is safe to call repeatedly.
    """
    import scraper_client
    from model.BoardSource import BoardSource

    site_url = (
        db.session.query(BoardSource.source_site)
        .filter(
            BoardSource.source_type == thread.source_type,
            BoardSource.source_site.isnot(None),
        )
        .limit(1)
        .scalar()
    )
    if not site_url:
        return False
    return scraper_client.add_monitored_board(
        thread.source_type, thread.source_name, site=site_url
    )


def request_rescrape(thread, issues):
    """Ask the crawler to re-fetch this thread now. Returns True if requested."""
    import scraper_client

    if str(thread.source_thread_id) == "*":
        return False

    # For a generic aggregated-chan source, poking POST /threads would enqueue the
    # thread in the shared scraper's site-less monitor pool and it would be fetched
    # against the placeholder BASE_URL. Those sites are re-crawled every cycle by
    # the monitored-board pass anyway (with the site bound), so the correct action
    # is to nudge that pass, not to register a thread.
    from services.aggregator_sync.scraper_db import is_generic_source_type
    if is_generic_source_type(thread.source_type):
        ok = _nudge_monitored_board(thread)
        if ok:
            app.logger.info(
                "content validate: nudged %s /%s/ to re-crawl (%s)",
                thread.source_type, thread.source_name, "; ".join(issues),
            )
            _mark_rescraped(thread.id)
        return bool(ok)

    ok = scraper_client.register_thread(
        thread.source_type, thread.source_name, str(thread.source_thread_id)
    )
    if ok:
        app.logger.info(
            "content validate: asked %s to re-fetch %s:%s (%s)",
            thread.source_type, thread.source_name, thread.source_thread_id,
            "; ".join(issues),
        )
        _mark_rescraped(thread.id)
    return bool(ok)


def run_imported_content_validate(limit=None, force=False):
    """Validate imported threads' SOURCE rows and request re-scrapes.

    Returns (checked, rescrape_requested). Threads already asked to re-fetch are
    skipped unless force=True, so a site that simply has no body text does not
    generate an endless stream of requests.
    """
    if not rescrape_enabled() and not force:
        return 0, 0
    limit = limit or repair_batch()
    marks = {} if force else _rescrape_marks()
    threads = (
        db.session.query(Thread)
        .filter(Thread.source_type != "local")
        .order_by(Thread.last_updated.desc())
        .limit(limit)
        .all()
    )
    checked = requested = 0
    for thread in threads:
        if requested >= MAX_RESCRAPE_PER_SWEEP:
            break
        if str(thread.id) in marks:
            continue
        thread_row, post_rows = _source_rows_for_thread(thread)
        source_rows = ([thread_row] if thread_row is not None else []) + list(post_rows or [])
        checked += 1
        issues = source_row_issues(thread, source_rows)
        if not issues:
            continue
        try:
            if request_rescrape(thread, issues):
                requested += 1
        except Exception:
            db.session.rollback()
            app.logger.exception("content validate: re-scrape request failed for %s", thread.id)
    if requested:
        app.logger.info(
            "content validate: checked %d thread(s), requested %d re-fetch(es)",
            checked, requested,
        )
    return checked, requested
