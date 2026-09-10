import datetime as _datetime
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from .config import (
    MAX_IMPORTED_AUTHOR_LENGTH,
    MAX_IMPORTED_BODY_LENGTH,
    MAX_IMPORTED_SOURCE_ID_LENGTH,
    MAX_IMPORTED_SOURCE_NAME_LENGTH,
    MAX_IMPORTED_SUBJECT_LENGTH,
    SUPPORTED_SCRAPER_TYPES,
)

REPLY_REGEXP = r"(>>|&gt;&gt;)([0-9]+)"


# Represent a reply edge discovered in imported scraper content.
@dataclass(frozen=True)
class ImportedReply:
    reply_from: int
    reply_to: int


# Read a column from a scraper row while tolerating missing keys.
def row_value(row, key: str, default=None):
    if key in row.keys():
        return row[key]
    return default


def _normalize_imported_datetime(value) -> Optional[_datetime.datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, _datetime.datetime):
        if value.tzinfo is not None:
            return value.astimezone(_datetime.timezone.utc).replace(tzinfo=None)
        return value

    text = str(value).strip()
    if text == "":
        return None

    # Accept unix timestamps when scrapers expose them numerically.
    if re.fullmatch(r"\d{10}(?:\.\d+)?", text):
        return _datetime.datetime.utcfromtimestamp(float(text))
    if re.fullmatch(r"\d{13}", text):
        return _datetime.datetime.utcfromtimestamp(int(text) / 1000.0)

    iso_candidate = text.replace("Z", "+00:00")
    try:
        parsed = _datetime.datetime.fromisoformat(iso_candidate)
        if parsed.tzinfo is not None:
            return parsed.astimezone(_datetime.timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        pass

    # Normalize imageboard-style dates such as "04/20/26(Sun)12:34:56".
    normalized = re.sub(r"\([^)]*\)", " ", text)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    for fmt in (
        "%m/%d/%y %H:%M:%S",
        "%m/%d/%y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d %H:%M:%S UTC",
    ):
        try:
            return _datetime.datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    return None


def imported_row_datetime(row, fallback=None) -> _datetime.datetime:
    for key in ("activity_at", "created_utc", "created_at", "datetime", "created_text", "scraped_at"):
        parsed = _normalize_imported_datetime(row_value(row, key))
        if parsed is not None:
            return parsed
    if fallback is not None:
        return fallback
    return _datetime.datetime.utcnow()


# Return the OP subject for imported thread rows.
def thread_subject(row, source_type: str) -> Optional[str]:
    if source_type in SUPPORTED_SCRAPER_TYPES and str(row["post_id"]) == str(row["thread_id"]):
        return _clip_imported_text(row_value(row, "subject"), MAX_IMPORTED_SUBJECT_LENGTH)
    return None


# Strip NUL bytes and clamp imported text to the requested length.
def _clip_imported_text(value, max_length: int) -> Optional[str]:
    if value is None:
        return None
    return str(value).replace("\x00", "")[:max_length]


# Normalize an imported source URL for storage.
def normalize_source_url(url: Optional[str]) -> Optional[str]:
    return _normalize_http_url(url)


# Normalize an imported external media URL for storage.
def normalize_external_media_url(url: Optional[str]) -> Optional[str]:
    return _normalize_http_url(url)


# Accept only absolute HTTP(S) URLs and normalize protocol-relative links.
def _normalize_http_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    if url.startswith("//"):
        url = "https:" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return url


# Format one imported source post reference as a local chan-style reply marker.
def _translated_reply_marker(source_reply_id: str, source_post_id_map) -> str:
    local_reply_id = source_post_id_map.get(source_reply_id)
    if local_reply_id is None:
        return ">>ext-%s" % source_reply_id
    return ">>%s" % local_reply_id


# Prefix Reddit comments with a chan-style reply marker for their parent.
def _prepend_reddit_parent_reply(body_text: str, parent_post_id, source_post_id_map) -> str:
    clipped_parent_id = _clip_imported_text(parent_post_id, MAX_IMPORTED_SOURCE_ID_LENGTH)
    if not clipped_parent_id:
        return body_text

    translated_parent = _translated_reply_marker(clipped_parent_id, source_post_id_map)
    stripped_body = (body_text or "").lstrip()
    if stripped_body.startswith(translated_parent):
        return body_text or ""

    if body_text:
        return translated_parent + "\n" + body_text
    return translated_parent


# Rewrite imported reply markers to point at local post IDs when possible.
def translate_imported_body(
    body_text: str,
    source_post_id_map,
    source_type: Optional[str] = None,
    parent_post_id=None,
) -> str:
    import re

    # Translate one imported reply reference into its local equivalent.
    def _replace_reply(match):
        source_reply_id = match.group(2)
        return _translated_reply_marker(source_reply_id, source_post_id_map)

    translated = re.sub(REPLY_REGEXP, _replace_reply, body_text or "")
    if source_type == "reddit":
        translated = _prepend_reddit_parent_reply(translated, parent_post_id, source_post_id_map)
    return translated


# Translate and clamp an imported post body for Maniwani storage.
def _translated_imported_body(row, source_post_id_map, source_type: Optional[str] = None) -> str:
    translated = translate_imported_body(
        row_value(row, "body_text", "") or "",
        source_post_id_map,
        source_type=source_type,
        parent_post_id=row_value(row, "parent_post_id"),
    )
    return _clip_imported_text(translated, MAX_IMPORTED_BODY_LENGTH) or ""


# Collect reply edges implied by imported body text and parent pointers.
def imported_replies(post, row, source_post_id_map):
    import re

    replies = []
    body_text = row_value(row, "body_text", "") or ""
    for match in re.finditer(REPLY_REGEXP, body_text):
        reply_source_id = match.group(2)
        local_reply_id = source_post_id_map.get(reply_source_id)
        if local_reply_id is None:
            continue
        replies.append(ImportedReply(reply_from=post.id, reply_to=local_reply_id))

    parent_source_id = _clip_imported_text(
        row_value(row, "parent_post_id"),
        MAX_IMPORTED_SOURCE_ID_LENGTH,
    )
    if parent_source_id:
        local_parent_id = source_post_id_map.get(parent_source_id)
        if local_parent_id is not None:
            replies.append(ImportedReply(reply_from=post.id, reply_to=local_parent_id))

    return replies
