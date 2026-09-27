"""Age-bounded scraping: how far back we claim threads, and what survives a purge.

TWO SEPARATE CLOCKS, AND THEY ARE NOT THE SAME THING
----------------------------------------------------
1. `scraped_thread_max_age_hours` (default 24) -- the SCRAPE WINDOW. A remote
   thread is only worth claiming while it is alive. Once its newest post is
   older than this, it stops being imported and its imported CONTENT is purged:
   posts, bodies, and mirrored media. This is the setting that bounds disk.

2. `scraped_metadata_retention_days` (default 30) -- how long the small
   IDENTITY STUB outlives the content. When a purged thread pops back up
   (a bumped 4chan thread, a re-crawled board), the stub is how we recognise it
   as something we already had rather than importing it from scratch and
   re-downloading every image.

The stub is deliberately tiny: the source triple, the last-seen timestamp, and
counters. It is metadata ABOUT a thread, not the thread. Keeping 30 days of
stubs costs kilobytes; keeping 30 days of content costs the 48G that filled the
data node.

WHY AN EXPLICIT STUB TABLE RATHER THAN "JUST KEEP THE THREAD ROW"
-----------------------------------------------------------------
Keeping the Thread row and deleting its posts leaves an empty thread rendering
in catalogs and counted in board statistics -- a ghost. The stub lives in its
own table, is never rendered, and is consulted only by the importer.

Both values are editable in the admin panel (Admin -> Scrapers -> Retention).
Setting the window to 0 disables age-based purging entirely.
"""
import datetime as _datetime

from model.SiteSetting import get_setting
from shared import app


MAX_AGE_SETTING = "scraped_thread_max_age_hours"
DEFAULT_MAX_AGE_HOURS = 24

METADATA_SETTING = "scraped_metadata_retention_days"
DEFAULT_METADATA_DAYS = 30

# Guard rails. A window of a few minutes would purge threads faster than the
# crawler can import them, producing a permanent import/purge loop.
MIN_MAX_AGE_HOURS = 1
MAX_MAX_AGE_HOURS = 24 * 365


def _int_setting(key, default, minimum, maximum):
    raw = (get_setting(key, "") or "").strip()
    if not raw:
        return default
    try:
        value = int(float(raw))
    except (TypeError, ValueError):
        app.logger.warning("scraped retention: %s is not a number (%r); using %d", key, raw, default)
        return default
    if value <= 0:
        return 0                      # explicit "disabled"
    return max(minimum, min(maximum, value))


def max_age_hours():
    """Newest-post age beyond which a scraped thread is purged. 0 disables."""
    return _int_setting(MAX_AGE_SETTING, DEFAULT_MAX_AGE_HOURS, MIN_MAX_AGE_HOURS, MAX_MAX_AGE_HOURS)


def metadata_retention_days():
    """How long an identity stub outlives the purged content. 0 disables."""
    return _int_setting(METADATA_SETTING, DEFAULT_METADATA_DAYS, 1, 3650)


def content_cutoff(now=None):
    """Threads whose newest post predates this are out of the scrape window.

    None when age-based purging is disabled, which callers must treat as
    "purge nothing" rather than as a cutoff of now().
    """
    hours = max_age_hours()
    if hours <= 0:
        return None
    return (now or _datetime.datetime.utcnow()) - _datetime.timedelta(hours=hours)


def metadata_cutoff(now=None):
    """Stubs last seen before this are forgotten completely. None disables."""
    days = metadata_retention_days()
    if days <= 0:
        return None
    return (now or _datetime.datetime.utcnow()) - _datetime.timedelta(days=days)


def is_within_window(newest_post_at, now=None):
    """Should this remote thread be imported/kept at all?

    A thread with NO known timestamp is kept: "we do not know how old it is" is
    not evidence that it is stale, and treating unknown as stale would purge
    every thread a source reports without dates.
    """
    cutoff = content_cutoff(now=now)
    if cutoff is None or newest_post_at is None:
        return True
    return newest_post_at >= cutoff
