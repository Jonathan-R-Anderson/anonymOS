"""Parse an overchan/netnews article into a structured post.

NNTPChan article format (doc/developer/protocol.md):
  Message-ID: <{random}{timestamp}@{frontend}>
  Newsgroups: overchan.<board>
  From: name <addr@host>
  Date: RFC5322 date
  Subject: ...
  Path: frontend!frontend!...        (relay hosts, '!' separated)
  References: <root-msgid> [<ancestor> ...]   (absent/empty => root/OP)
  X-Sage: (presence => do not bump)
  X-PubKey-Ed25519: 64 hex   / X-Signature-Ed25519-SHA512: 128 hex
Body is text/plain OR multipart/mixed with base64 attachments
(Content-Disposition: attachment; filename="...").
"""
import datetime as _datetime
import email
import email.utils
import mimetypes
import re


_MID_RE = re.compile(r"<[^<>]+>")


class ParsedArticle(object):
    def __init__(self):
        self.message_id = None
        self.newsgroup = None
        self.newsgroups = []
        self.references = []
        self.thread_root = None
        self.subject = ""
        self.from_name = None
        self.from_addr = None
        self.pubkey = None
        self.path_hosts = []
        self.posted_at = None
        self.sage = False
        self.body_text = ""
        self.attachments = []  # list of (filename, content_type, bytes)
        self.source_label = None          # X-Source-Label: origin site name
        self.source_watermark_url = None  # X-Source-Watermark: origin favicon URL
        self.source_watermark_bytes = None  # embedded watermark image bytes
        self.source_watermark_mime = None   # embedded watermark image mimetype

    @property
    def is_root(self):
        return not self.references


def _clean_message_id(raw):
    if not raw:
        return None
    match = _MID_RE.search(raw)
    if match:
        return match.group(0).strip()
    raw = raw.strip()
    return raw or None


def _parse_references(raw):
    if not raw:
        return []
    return _MID_RE.findall(raw)


def _parse_date(raw):
    if not raw:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    # Store naive UTC to match the rest of the codebase (utcnow()).
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(_datetime.timezone.utc).replace(tzinfo=None)
    return parsed


def _ext_for(content_type):
    return mimetypes.guess_extension(content_type or "") or ".bin"


def _extract_body(msg):
    text_parts = []
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = (part.get_content_type() or "").lower()
            disposition = (part.get("Content-Disposition") or "").lower()
            filename = part.get_filename()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is None:
                continue
            is_text = content_type.startswith("text/") and "attachment" not in disposition and not filename
            if is_text:
                charset = part.get_content_charset() or "utf-8"
                try:
                    text_parts.append(payload.decode(charset, "replace"))
                except LookupError:
                    text_parts.append(payload.decode("utf-8", "replace"))
            else:
                name = filename or ("attachment" + _ext_for(content_type))
                attachments.append((name, content_type or "application/octet-stream", payload))
    else:
        try:
            payload = msg.get_payload(decode=True)
        except Exception:
            payload = None
        if payload is not None:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text_parts.append(payload.decode(charset, "replace"))
            except LookupError:
                text_parts.append(payload.decode("utf-8", "replace"))
    return "\n".join(text_parts).strip(), attachments


def parse_article(raw_bytes):
    """Parse raw article bytes into a ParsedArticle, or None if unusable."""
    if not raw_bytes:
        return None
    try:
        # compat32 (default, no policy=) keeps get_payload(decode=True)/walk().
        msg = email.message_from_bytes(raw_bytes)
    except Exception:
        return None

    article = ParsedArticle()
    article.message_id = _clean_message_id(msg.get("Message-ID"))
    if not article.message_id:
        return None

    article.newsgroups = [
        g.strip() for g in (msg.get("Newsgroups") or "").split(",") if g.strip()
    ]
    overchan = [g for g in article.newsgroups if g.startswith("overchan.")]
    article.newsgroup = (
        overchan[0] if overchan else (article.newsgroups[0] if article.newsgroups else None)
    )

    article.references = _parse_references(msg.get("References"))
    article.thread_root = article.references[0] if article.references else article.message_id

    article.subject = (msg.get("Subject") or "").strip()
    from_name, from_addr = email.utils.parseaddr(msg.get("From") or "")
    article.from_name = (from_name or "").strip() or None
    article.from_addr = (from_addr or "").strip() or None

    pubkey = (msg.get("X-PubKey-Ed25519") or msg.get("X-Pubkey-Ed25519") or "").strip().lower()
    article.pubkey = pubkey or None

    article.posted_at = _parse_date(msg.get("Date"))
    article.sage = msg.get("X-Sage") is not None

    # Source watermark (site favicon URL + label) for attribution of federated
    # content. Header names are case-insensitive; only http(s) URLs are trusted.
    article.source_label = (msg.get("X-Source-Label") or "").strip()[:128] or None
    watermark = (msg.get("X-Source-Watermark") or "").strip()
    if watermark.lower().startswith(("http://", "https://")):
        article.source_watermark_url = watermark[:1024]

    path = (msg.get("Path") or "").strip()
    article.path_hosts = [h for h in re.split(r"[!,\s]+", path) if h and h != "!"]

    article.body_text, article.attachments = _extract_body(msg)

    # An embedded source watermark travels as an image part whose filename
    # carries the "source-watermark" token; pull it out of the content
    # attachments so it isn't imported as the post's image.
    kept = []
    for filename, content_type, data in article.attachments:
        if (filename and "source-watermark" in filename.lower()
                and content_type.startswith("image/") and article.source_watermark_bytes is None):
            article.source_watermark_bytes = data
            article.source_watermark_mime = content_type
        else:
            kept.append((filename, content_type, data))
    article.attachments = kept
    return article
