"""Retire scraped source threads that have gone dead, so the crawler stops
spending requests on them.

Two independent signals, whichever fires first:

  * GONE / persistently failing (fast) -- the crawler's own `thread_failures`
    table says this thread 404s or has failed N times in a row. A 404 thread is
    never coming back, so waiting out the staleness window below just wastes
    requests. Read via scraper_db.source_thread_health().
  * STALE (slow) -- no new content within `scraped_thread_retire_days`. This is
    the catch-all: it also covers threads that are locked/closed/archived, which
    stop producing posts without ever erroring.

RETIRING NEVER DELETES CONTENT. It sets BoardSource.retired (so sync and
re-registration skip it) and unregisters the thread from the scraper (so it stops
being fetched). Already-imported threads and posts stay exactly where they are.

If a submitted source thread produces no new content within
`scraped_thread_retire_days` (default 3) — i.e. its imported thread stops being
bumped, which is what happens when the source link is deleted, pruned, or
Liveness for the stale check is read from the imported Thread's last_updated; a
source that never imported anything falls back to when it was submitted. Setting
`scraped_thread_retire_days` to 0 disables the stale check (the gone check still
runs). A background thread runs the sweep hourly.
"""
import datetime as _datetime

import shared
from shared import app, db
from model.BoardSource import BoardSource
from model.Thread import Thread
from model.SiteSetting import get_setting
from services.aggregator_sync.config import WHOLE_BOARD_THREAD_ID
from services.aggregator_sync.scraper_db import source_thread_health


SETTING_KEY = "scraped_thread_retire_days"
DEFAULT_DAYS = 3
# Consecutive crawl failures before a thread is considered dead even when the
# error is not an explicit 404. High enough that a blocked/rate-limited or
# briefly-unreachable site does not lose its sources.
FAILURE_SETTING_KEY = "scraped_thread_retire_failures"
DEFAULT_FAILURES = 8
# Errors that mean "the site is blocking us", not "this thread is dead".
_BLOCK_MARKERS = (
    "403", "429", "forbidden", "too many requests", "rate limit",
    "cloudflare", "challenge", "captcha", "blocked",
)
_SWEEP_INTERVAL_SECONDS = 3600


def retire_days():
    """Days with no new content before a source thread is retired. 0 disables."""
    raw = get_setting(SETTING_KEY, str(DEFAULT_DAYS))
    try:
        return max(0, int(str(raw).strip()))
    except (TypeError, ValueError):
        return DEFAULT_DAYS


def retire_failure_threshold():
    """Consecutive failures before a thread is retired. 0 disables that check."""
    raw = (get_setting(FAILURE_SETTING_KEY, "") or "").strip()
    try:
        return max(0, int(raw)) if raw else DEFAULT_FAILURES
    except ValueError:
        return DEFAULT_FAILURES


def _dead_reason(source, health, failure_threshold):
    """Why this source should stop being scraped, or None to keep it.

    Only consults the crawler's failure table — the staleness check is separate.
    Whole-board sources ("*") are never retired here: they are a standing
    instruction to follow a board, not one thread that can 404.
    """
    if not health or failure_threshold <= 0:
        return None
    if str(source.source_thread_id) == WHOLE_BOARD_THREAD_ID:
        return None
    entry = health.get((str(source.source_name), str(source.source_thread_id)))
    if not entry:
        return None
    if entry.get("gone"):
        return "gone (%s)" % (str(entry.get("last_error") or "404")[:80])
    # A block is the SITE refusing us, not a dead thread. Retiring on it would
    # drop every source for a Cloudflare-walled or rate-limiting site the moment
    # it starts pushing back, and they would all have to be re-added by hand.
    # Only staleness may retire these.
    error_text = str(entry.get("last_error") or "").lower()
    if any(marker in error_text for marker in _BLOCK_MARKERS):
        return None
    if int(entry.get("failure_count") or 0) >= failure_threshold:
        return "failed %d times in a row (%s)" % (
            entry["failure_count"], str(entry.get("last_error") or "")[:60]
        )
    return None


def run_scraped_thread_retire():
    """Retire (stop monitoring) every dead source thread. Returns the count.

    Content is never deleted — see the module docstring.
    """
    days = retire_days()
    failure_threshold = retire_failure_threshold()
    if days <= 0 and failure_threshold <= 0:
        return 0
    cutoff = (
        _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
        if days > 0 else None
    )
    sources = (
        db.session.query(BoardSource)
        .filter(BoardSource.retired.is_(False))
        .all()
    )
    # One read per (source_type, board) rather than per thread.
    health_cache = {}

    def _health_for(source):
        key = (source.source_type, source.source_name)
        if key not in health_cache:
            try:
                health_cache[key] = source_thread_health(source.source_type, source.source_name)
            except Exception:
                health_cache[key] = {}
        return health_cache[key]

    retired = 0
    for source in sources:
        reason = _dead_reason(source, _health_for(source), failure_threshold)
        if reason is not None:
            _retire_source(source, reason)
            retired += 1
            continue
        if cutoff is None:
            continue
        thread = (
            db.session.query(Thread)
            .filter(
                Thread.board == source.board_id,
                Thread.source_type == source.source_type,
                Thread.source_thread_id == str(source.source_thread_id),
            )
            .first()
        )
        last_active = (thread.last_updated if (thread and thread.last_updated is not None)
                       else source.created_at)
        if last_active is None or last_active >= cutoff:
            continue  # still fresh (or age unknown) — keep monitoring
        if str(source.source_thread_id) == WHOLE_BOARD_THREAD_ID:
            continue  # a whole-board follow has no single thread to go stale
        _retire_source(source, "no new content in %d day(s)" % days)
        retired += 1
    if retired:
        db.session.commit()
    return retired


def _retire_source(source, reason):
    """Stop scraping one source thread. Does NOT touch imported content."""
    try:
        from scraper_client import unregister_thread
        unregister_thread(source.source_type, source.source_name, str(source.source_thread_id))
    except Exception:
        app.logger.exception(
            "Failed unregistering dead source %s/%s/%s",
            source.source_type, source.source_name, source.source_thread_id,
        )
    source.retired = True
    db.session.add(source)
    app.logger.info(
        "Retired source %s:%s:%s — %s (imported content kept)",
        source.source_type, source.source_name, source.source_thread_id, reason,
    )


def start_scraped_thread_retire(flask_app):
    def _loop():
        import time as _time
        _time.sleep(90)
        while True:
            try:
                with flask_app.app_context():
                    from services.singleton_worker import is_maintenance_leader

                    # Leader-gated: it issues one HTTP DELETE per dead source
                    # inside an open transaction, so four workers meant four
                    # connections pinned across the same sequence of calls.
                    removed = run_scraped_thread_retire() if is_maintenance_leader() else 0
                    if removed:
                        flask_app.logger.info("Retired %d dead scraped source thread(s)", removed)
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("Scraped-thread retirement sweep failed")
            _time.sleep(_SWEEP_INTERVAL_SECONDS)

    shared.spawn_native_thread(target=_loop, name="scraped-thread-retire", daemon=True)
