import os


SYNC_CACHE_KEY_TEMPLATE = "board-source-sync-%d"
WATERMARK_CACHE_KEY_TEMPLATE = "agg-wm-%s-%s"

DEFAULT_FOURCHAN_DB = "board_aggregators/fourchan_aggregator_plus/data/4chan.db"
DEFAULT_EIGHTCHAN_DB = "board_aggregators/fourchan_aggregator_plus/data/8chan.db"
DEFAULT_SEVENCHAN_DB = "board_aggregators/fourchan_aggregator_plus/data/7chan.db"
DEFAULT_REDDIT_DB = "reddit-aggregator/data/reddit.db"
# Generic aggregated-chan sites: one <host>.db per site, written by the shared
# generic scraper container (see its GENERIC_SITE_DATA_DIR).
DEFAULT_GENERIC_SITES_DIR = "board_aggregators/fourchan_aggregator_plus/data/sites"

MAX_IMPORTED_BODY_LENGTH = 4096
MAX_IMPORTED_SUBJECT_LENGTH = 64
MAX_IMPORTED_AUTHOR_LENGTH = 128
MAX_IMPORTED_SOURCE_ID_LENGTH = 128
MAX_IMPORTED_SOURCE_NAME_LENGTH = 64
MAX_SYNC_ERROR_LENGTH = 512

SUPPORTED_SCRAPER_TYPES = ("4chan", "8chan", "7chan", "reddit")

# A BoardSource with this source_thread_id means "import the whole source board",
# i.e. every thread the crawler currently holds for that board/subreddit, rather
# than one submitted thread. Set by the admin board-monitoring UI.
WHOLE_BOARD_THREAD_ID = "*"


def whole_board_thread_limit():
    """Cap on threads pulled in per whole-board source, newest activity first.

    Bounds both the import work per cycle and how many imported threads a single
    monitored board can put on a local board.
    """
    return max(1, int(os.getenv("WHOLE_BOARD_THREAD_LIMIT", "100")))

DEFAULT_MIRROR_REQUEST_DELAY_SECONDS = 4.0
DEFAULT_MIRROR_MAX_RETRIES = 5
DEFAULT_MIRROR_RETRY_BACKOFF_SECONDS = 20.0
FALLBACK_IMAGE_PATH = os.path.join("resources", "missing_media_placeholder.png")
DEFAULT_MIRROR_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari"
)


def mirror_request_delay_seconds():
    return float(os.getenv("MIRROR_REQUEST_DELAY_SECONDS", str(DEFAULT_MIRROR_REQUEST_DELAY_SECONDS)))


def mirror_max_retries():
    return max(1, int(os.getenv("MIRROR_MAX_RETRIES", str(DEFAULT_MIRROR_MAX_RETRIES))))


def mirror_retry_backoff_seconds():
    return float(os.getenv("MIRROR_RETRY_BACKOFF_SECONDS", str(DEFAULT_MIRROR_RETRY_BACKOFF_SECONDS)))


def mirror_inline_sleep_budget_seconds():
    """Total seconds a single mirror may SLEEP while a DB transaction is open.

    Mirroring happens inside `begin_nested()` (api.py) and while _global_sync_lock
    is held, so every second slept here is a second a pooled connection cannot be
    used by a page view. With MIRROR_MAX_RETRIES=4 and
    MIRROR_RETRY_BACKOFF_SECONDS=30 the backoff is 30 + 60 + 90 = 180 SECONDS of
    sleeping inside that transaction for one dead URL — a large part of why the
    connection pool was being exhausted.

    Exceeding the budget is not data loss: the mirror simply gives up for this
    pass and services/imported_media_repair.py retries it on a later sweep,
    outside this transaction. Long backoffs still happen, just not while holding a
    connection.
    """
    return max(0.0, float(os.getenv("MIRROR_INLINE_SLEEP_BUDGET_SECONDS", "5")))


def mirror_user_agent():
    return os.getenv("MIRROR_USER_AGENT", DEFAULT_MIRROR_USER_AGENT)
