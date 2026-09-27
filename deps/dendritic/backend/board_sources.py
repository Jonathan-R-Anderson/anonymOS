import re
from typing import Iterable, List, Sequence, Tuple
from urllib.parse import urlparse

from model.BoardSource import BoardSource
from shared import db


DEFAULT_MAX_THREADS = 100
DEFAULT_MIMETYPES = "image/jpeg|image/png|image/gif|image/webp|video/webm"
SUPPORTED_SOURCE_TYPES = ("4chan", "8chan", "7chan", "reddit")
SOURCE_TOKEN_SPLIT = re.compile(r"[\n,]+")

# Direct thread URL path patterns for each supported source type.
REDDIT_THREAD_PATH = re.compile(r"^/r/([A-Za-z0-9_\-]+)/comments/([A-Za-z0-9]+)(?:/|$)")
FOURCHAN_THREAD_PATH = re.compile(r"^/([A-Za-z0-9_\-]+)/thread/(\d+)(?:[/.]|$)")
CHAN_RES_THREAD_PATH = re.compile(r"^/([A-Za-z0-9_\-]+)/res/(\d+)(?:\.x?html?)?(?:[/#?]|$)")
COMPACT_SOURCE_LINE = re.compile(r"^([A-Za-z0-9]+):([A-Za-z0-9_\-]+):([A-Za-z0-9]+)$")

CANONICAL_THREAD_URL_TEMPLATES = {
    "reddit": "https://www.reddit.com/r/%s/comments/%s/",
    "4chan": "https://boards.4chan.org/%s/thread/%s",
    "8chan": "https://8chan.moe/%s/res/%s.html",
    "7chan": "https://7chan.org/%s/res/%s.html",
}


def normalize_source_type(raw_source_type: str) -> str:
    source_type = raw_source_type.strip().lower()
    if source_type in ("8chan", "eightchan"):
        return "8chan"
    if source_type in ("7chan", "sevenchan"):
        return "7chan"
    if source_type in ("4chan", "fourchan"):
        return "4chan"
    if source_type in ("reddit", "r"):
        return "reddit"
    raise ValueError("Unsupported source type: %s" % raw_source_type)


def normalize_source_name(source_type: str, raw_name: str) -> str:
    source_name = raw_name.strip().strip("/")
    return source_name.lower()


def _source_type_for_host(hostname: str) -> str:
    host = (hostname or "").lower()
    if "4chan" in host or "4channel" in host:
        return "4chan"
    if "8chan" in host or "8kun" in host:
        return "8chan"
    if "7chan" in host:
        return "7chan"
    if "reddit" in host or "redlib" in host or "troddit" in host or "libreddit" in host:
        return "reddit"
    return ""


def parse_source_line(line: str) -> Tuple[str, str, str]:
    """Parse one submitted thread URL into (source_type, source_name, source_thread_id).

    Only direct thread URLs are accepted - whole boards and subreddits can no
    longer be aggregated. A compact ``type:board:thread_id`` form is also
    understood so stored configs stay grep-able.
    """
    value = line.strip()
    if not value:
        raise ValueError("Empty source value")

    compact = COMPACT_SOURCE_LINE.match(value)
    if compact is not None:
        source_type = normalize_source_type(compact.group(1))
        source_name = normalize_source_name(source_type, compact.group(2))
        return source_type, source_name, compact.group(3).lower()

    parsed = urlparse(value if "//" in value else "https://" + value)
    if not parsed.hostname:
        raise ValueError("Unsupported source format (expected a direct thread URL): %s" % value)
    path = parsed.path or ""

    reddit_match = REDDIT_THREAD_PATH.match(path)
    host_type = _source_type_for_host(parsed.hostname)

    # Reddit thread paths are unambiguous, so accept them from any mirror host.
    if reddit_match is not None and host_type in ("", "reddit"):
        return "reddit", reddit_match.group(1).lower(), reddit_match.group(2).lower()

    if host_type == "4chan":
        thread_match = FOURCHAN_THREAD_PATH.match(path)
        if thread_match is not None:
            return "4chan", thread_match.group(1).lower(), thread_match.group(2)
    if host_type in ("8chan", "7chan"):
        thread_match = CHAN_RES_THREAD_PATH.match(path)
        if thread_match is not None:
            return host_type, thread_match.group(1).lower(), thread_match.group(2)

    raise ValueError(
        "Unsupported source format: %s (submit the direct URL of a thread, "
        "for example https://boards.4chan.org/g/thread/12345678 or "
        "https://www.reddit.com/r/example/comments/abc123/)" % value
    )


def parse_source_config(source_config: str) -> List[Tuple[str, str, str]]:
    parsed_sources = []
    seen = set()
    for raw_token in SOURCE_TOKEN_SPLIT.split(source_config or ""):
        token = raw_token.strip()
        if not token:
            continue
        source = parse_source_line(token)
        if source in seen:
            continue
        seen.add(source)
        parsed_sources.append(source)
    return parsed_sources


def canonical_thread_url(source_type: str, source_name: str, source_thread_id: str) -> str:
    template = CANONICAL_THREAD_URL_TEMPLATES.get(source_type)
    if template is None:
        raise ValueError("Unsupported source type: %s" % source_type)
    return template % (source_name, source_thread_id)


# Why a source may not be scraped into a board. Both are surfaced to the person
# submitting the URL as a real page (see boards.import_thread), never as a
# silently-dropped submission.
SCRAPE_BLOCK_BANNED = "banned"
SCRAPE_BLOCK_NNTP = "nntp"


def nntp_newsgroups_for_board(board_id) -> List[str]:
    """Enabled NNTP newsgroups syncing into this board (empty if none)."""
    try:
        from model.NntpGroupMap import NntpGroupMap
        rows = (
            db.session.query(NntpGroupMap.newsgroup)
            .filter(NntpGroupMap.board_id == board_id, NntpGroupMap.enabled.is_(True))
            .order_by(NntpGroupMap.newsgroup.asc())
            .all()
        )
        return [newsgroup for (newsgroup,) in rows]
    except Exception:
        return []


def scrape_block_reason(board, source_type: str, source_name: str, source_thread_id: str):
    """Return a reason dict if this source must NOT be scraped into ``board``.

    Two exemptions, checked in this order:

    1. The board already receives posts over our own NNTP protocol, i.e. the
       remote site pushes to us. Scraping it as well would duplicate content the
       peer is already syncing, so the whole board is exempt from scraping.
    2. The source's host is under a 3-strike illegal-content aggregation ban.

    Returns None when the source is eligible.
    """
    newsgroups = nntp_newsgroups_for_board(board.id)
    if newsgroups:
        return {
            "code": SCRAPE_BLOCK_NNTP,
            "newsgroups": newsgroups,
            "board_name": board.name,
        }

    try:
        source_url = canonical_thread_url(source_type, source_name, source_thread_id)
    except ValueError:
        source_url = ""
    try:
        from model.SourceModeration import ban_status, host_of, is_host_banned
        host = host_of(source_url)
        if host and is_host_banned(host):
            return {
                "code": SCRAPE_BLOCK_BANNED,
                "host": host,
                "status": ban_status(host),
                "board_name": board.name,
            }
    except Exception:
        # Never let a moderation-lookup failure block a legitimate submission.
        return None
    return None


def _is_whole_board_source(source) -> bool:
    from services.aggregator_sync.config import WHOLE_BOARD_THREAD_ID
    return str(getattr(source, "source_thread_id", "") or "") == WHOLE_BOARD_THREAD_ID


def format_source_config(sources: Iterable[BoardSource]) -> str:
    """The board-settings textarea: one direct thread URL per line.

    Whole-board ("*") rows are EXCLUDED, and that is load-bearing in two
    directions. replace_board_sources documents this as an invariant and refuses
    to delete anything the textarea cannot express, which is what keeps a plain
    Save from wiping whole-board scrape config (and, through the pruner, the
    imported threads with it).

    It also has to hold for the form to work at all: "*" is truthy, so this used
    to render it into the URL template as
    https://boards.4chan.org/a/thread/* — which parse_source_line rightly
    rejects, since it is not a thread URL. The textarea therefore came
    pre-loaded with a value that failed validation, and every save of such a
    board was refused, including changes that had nothing to do with sources
    (the thread limit, the mimetype list, the rules). Whole-board sources are
    managed from the board-monitoring UI, not here; they are surfaced read-only
    on the settings page via whole_board_source_labels().
    """
    return "\n".join(
        canonical_thread_url(source.source_type, source.source_name, source.source_thread_id)
        for source in sources
        if source.source_type in SUPPORTED_SOURCE_TYPES
        and source.source_thread_id
        and not _is_whole_board_source(source)
    )


def whole_board_source_labels(sources: Iterable[BoardSource]) -> List[str]:
    """Human-readable labels for the whole-board sources feeding a board.

    Shown read-only on the settings page so an owner can see why threads keep
    arriving even though the source textarea does not list them.
    """
    return sorted(
        source_label(source.source_type, source.source_name)
        for source in sources
        if _is_whole_board_source(source)
    )


def replace_board_sources(board, parsed_sources: Sequence[Tuple[str, str, str]]) -> None:
    current_sources = {
        (source.source_type, source.source_name, source.source_thread_id): source
        for source in board.sources
    }
    desired_sources = set(parsed_sources)

    # WHOLE_BOARD_THREAD_ID lives in services.aggregator_sync.config; imported
    # lazily because board_sources is imported very early by blueprints/models and
    # a top-level import risks a cycle.
    from services.aggregator_sync.config import WHOLE_BOARD_THREAD_ID

    for key, source in current_sources.items():
        if key in desired_sources:
            continue
        # ONLY delete what the submitted form could actually express.
        #
        # `desired_sources` comes from a textarea rendered by
        # format_source_config(), which emits ONLY SUPPORTED_SOURCE_TYPES
        # ("4chan", "8chan", "7chan", "reddit"). Every generic aggregated-chan
        # source — 21 hosts / ~90 rows in production — and every whole-board "*"
        # row is therefore ABSENT from that textarea, so treating "absent" as
        # "the operator removed it" deleted scrape configuration nobody touched.
        # Merely opening a board's settings and pressing Save wiped it.
        #
        # And it did not stop at configuration: with the BoardSource gone, the next
        # sync no longer lists those threads in `configured_threads`, so
        # _prune_unsubmitted_source_threads deletes the imported threads too — and
        # its has_local_posts escape does not help, because imported threads carry
        # no local Post rows. One Save could destroy a host's entire archive.
        if source.source_type not in SUPPORTED_SOURCE_TYPES:
            continue
        if str(source.source_thread_id or "") == WHOLE_BOARD_THREAD_ID:
            continue
        db.session.delete(source)

    for source_type, source_name, source_thread_id in parsed_sources:
        if (source_type, source_name, source_thread_id) not in current_sources:
            db.session.add(BoardSource(
                board_id=board.id,
                source_type=source_type,
                source_name=source_name,
                source_thread_id=source_thread_id,
            ))


def source_label(source_type: str, source_name: str, source_thread_id: str = None) -> str:
    if source_type == "reddit":
        base = "reddit /r/%s" % source_name
    elif source_type in ("4chan", "8chan", "7chan"):
        base = "%s /%s/" % (source_type, source_name)
    else:
        return source_type
    if source_thread_id:
        return "%s thread %s" % (base, source_thread_id)
    return base
