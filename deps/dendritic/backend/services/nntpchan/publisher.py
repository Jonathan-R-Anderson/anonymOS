"""Outbound content federation: publish local posts to the NNTP hub.

maniwani's inbound side pulls overchan.* and imports articles; this is the
missing outbound side so two instances actually SHARE board content. When
enabled, local posts on a board that has a newsgroup mapping are POSTed to that
newsgroup as overchan articles (text + base64 attachment), threaded via
References. The other instance pulls and imports them exactly like any overchan
article.

Dedup uses the same nntp_article ledger as the inbound path: a published post
gets a ledger row keyed by its generated Message-ID, so (a) the origin server
skips it when it pulls its own article back, and (b) replies can reference their
thread's OP Message-ID. A post is "already published or imported" iff it has an
nntp_article row for its id — so genuinely-local, not-yet-federated posts are
exactly the ones without one.
"""
import base64
import calendar
import email.utils
import mimetypes
import secrets
import time
from collections import OrderedDict

from shared import app, db
from model.SiteSetting import get_setting
from model.NntpGroupMap import list_group_maps
from model.NntpArticle import NntpArticle, record_article
from model.Post import Post
from model.Thread import Thread
from model.Media import Media, storage
from services.nntpchan.client import NNTPError


PUBLISH_SETTING = "nntp_publish_content"
FLOOR_SETTING = "nntp_publish_min_post_id"
SOURCE_LABEL_SETTING = "nntpchan_source_label"          # this site's display name
# ONE watermark image, given as EITHER an absolute URL or a local file path.
# Whatever it is, a shrunk copy is embedded in the article (self-contained on
# the receiver); additionally, if it's a URL we send it as the X-Source-Watermark
# header (a lightweight fallback for receivers that don't read embedded parts).
SOURCE_WATERMARK_SETTING = "nntpchan_source_watermark_url"
_MAX_EMBED_BYTES = 256 * 1024
_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_embed_cache = {"source": None, "value": None}
# Small batch: each publish base64-encodes media and POSTs it, which is heavy;
# a large batch in one cycle starves the web workers. Drains over cycles.
MAX_PER_CYCLE = 8


def _watermark_source():
    return (get_setting(SOURCE_WATERMARK_SETTING, "") or "").strip()


def _is_url(value):
    return value.lower().startswith(("http://", "https://"))


def _shrink_watermark(raw):
    """Downscale any image to a tiny PNG watermark so a full logo embeds cheaply.
    Returns (bytes, 'image/png') or None."""
    try:
        import io
        from PIL import Image
        with Image.open(io.BytesIO(raw)) as image:
            image = image.convert("RGBA")
            image.thumbnail((64, 64))
            out = io.BytesIO()
            image.save(out, "PNG")
            data = out.getvalue()
        if data and len(data) <= _MAX_EMBED_BYTES:
            return data, "image/png"
    except Exception:
        if raw and len(raw) <= _MAX_EMBED_BYTES:  # Pillow missing/undecodable
            return raw, "image/png"
    return None


def _load_watermark_raw(source):
    """Raw bytes of the watermark image, fetched (URL) or read (path)."""
    if _is_url(source):
        try:
            import requests
            resp = requests.get(source, timeout=(3, 8), stream=True)
            if resp.status_code == 200:
                data = resp.raw.read(_MAX_SOURCE_BYTES + 1, decode_content=True)
                return data or None
        except Exception:
            app.logger.warning("NNTPChan: could not fetch watermark URL %s", source)
        return None
    try:
        with open(source, "rb") as handle:
            return handle.read(_MAX_SOURCE_BYTES + 1)
    except Exception:
        app.logger.warning("NNTPChan: could not read watermark file %s", source)
        return None


def _embed_watermark_bytes():
    """(bytes, 'image/png') to embed, downscaled. Sourced from the single
    watermark setting (URL fetched, or local path read). Cached per source."""
    source = _watermark_source()
    if not source:
        return None
    if _embed_cache["source"] == source:
        return _embed_cache["value"]
    raw = _load_watermark_raw(source)
    value = _shrink_watermark(raw) if (raw and len(raw) <= _MAX_SOURCE_BYTES) else None
    _embed_cache["source"] = source
    _embed_cache["value"] = value
    return value


def publishing_enabled():
    return str(get_setting(PUBLISH_SETTING, "0")).strip().lower() not in ("", "0", "false", "no", "off")


def _floor():
    try:
        return int(str(get_setting(FLOOR_SETTING, "0")).strip())
    except (TypeError, ValueError):
        return 0


def _node_id():
    from services.nntpchan.banlist import _node_id as node_id
    return node_id()


def _board_newsgroups():
    index = {}
    for group_map in list_group_maps(enabled_only=True):
        index.setdefault(group_map.board_id, []).append(group_map.newsgroup)
    return index


def _clean_header(value):
    return (value or "").replace("\r", " ").replace("\n", " ").strip()


def _has_article(post_id):
    return (
        db.session.query(NntpArticle.id)
        .filter(NntpArticle.local_post_id == post_id)
        .first()
        is not None
    )


def _op_message_id(thread_id):
    row = (
        db.session.query(NntpArticle)
        .filter(NntpArticle.local_thread_id == thread_id, NntpArticle.is_op.is_(True))
        .first()
    )
    return row.message_id if row else None


def _source_watermark(post):
    """(watermark_url, label) to attribute this post's origin. A post that
    already carries federated attribution keeps it (so a re-federated post still
    points at its true origin); otherwise stamp this server's configured
    identity (label defaults to the node id)."""
    existing_url = getattr(post, "source_watermark_url", None)
    existing_label = getattr(post, "source_watermark_label", None)
    if existing_url or existing_label:
        return existing_url, existing_label
    label = (get_setting(SOURCE_LABEL_SETTING, "") or "").strip() or _node_id()
    source = _watermark_source()
    # Only emit the URL header when the single watermark source is actually a
    # URL; a local-path source is delivered purely as the embedded image.
    url = source if (source and _is_url(source)) else None
    return url, label


def _build_article(post, newsgroups, reference_mid=None):
    node = _node_id()
    message_id = "<mw%d-%s@%s>" % (post.id, secrets.token_hex(6), node)
    ts = calendar.timegm(post.datetime.timetuple()) if post.datetime else time.time()

    headers = OrderedDict()
    headers["Message-ID"] = message_id
    headers["Newsgroups"] = ",".join(newsgroups)
    headers["From"] = "%s <anon@%s>" % (_clean_header(post.author_name) or "Anonymous", node)
    headers["Subject"] = _clean_header(post.subject)
    headers["Date"] = email.utils.formatdate(ts, usegmt=True)
    if reference_mid:
        headers["References"] = reference_mid
    headers["Path"] = node
    # Source attribution watermark so the receiving instance can show viewers
    # where the post came from (e.g. this site's favicon). A post that was itself
    # scraped keeps its ORIGINAL source's watermark; otherwise we stamp this
    # server's configured identity.
    watermark_url, watermark_label = _source_watermark(post)
    if watermark_label:
        headers["X-Source-Label"] = _clean_header(watermark_label)
    if watermark_url:
        headers["X-Source-Watermark"] = _clean_header(watermark_url)
    headers["MIME-Version"] = "1.0"

    body_text = post.body or ""

    def _b64(raw):
        enc = base64.b64encode(raw).decode("ascii")
        return "\r\n".join(enc[i:i + 76] for i in range(0, len(enc), 76))

    # Assemble MIME parts: the text body, the optional content attachment, and
    # the optional EMBEDDED source watermark (a dedicated inline image part the
    # receiver stores locally so attribution survives us going offline).
    parts = [([
        "Content-Type: text/plain; charset=UTF-8",
        "Content-Transfer-Encoding: 8bit",
    ], body_text)]

    media = db.session.query(Media).get(post.media) if post.media else None
    if media is not None:
        try:
            data = storage.read_attachment_bytes(media.id, media.ext)
        except Exception:
            app.logger.exception("NNTPChan publish: could not read media %s", media.id)
            data = None
        if data:
            parts.append(([
                "Content-Type: %s" % (media.mimetype or "application/octet-stream"),
                "Content-Transfer-Encoding: base64",
                'Content-Disposition: attachment; filename="%d.%s"' % (media.id, media.ext or "bin"),
            ], _b64(data)))

    embed = _embed_watermark_bytes()
    if embed:
        wm_data, wm_mime = embed
        wm_ext = mimetypes.guess_extension(wm_mime) or ".png"
        parts.append(([
            "Content-Type: %s" % wm_mime,
            "Content-Transfer-Encoding: base64",
            'Content-Disposition: inline; filename="source-watermark%s"' % wm_ext,
        ], _b64(wm_data)))

    if len(parts) == 1:
        headers["Content-Type"] = "text/plain; charset=UTF-8"
        body = body_text
    else:
        boundary = "mw-%s" % secrets.token_hex(8)
        headers["Content-Type"] = 'multipart/mixed; boundary="%s"' % boundary
        chunks = []
        for part_headers, payload in parts:
            chunks.append("--%s" % boundary)
            chunks.extend(part_headers)
            chunks.append("")
            chunks.append(payload)
        chunks.append("--%s--" % boundary)
        body = "\r\n".join(chunks)

    return message_id, headers, body


def _publish_post(client, post, board_newsgroups):
    thread = db.session.query(Thread).get(post.thread)
    if thread is None:
        return False
    newsgroups = board_newsgroups.get(thread.board)
    if not newsgroups:
        return False

    op = (
        db.session.query(Post)
        .filter(Post.thread == thread.id)
        .order_by(Post.datetime.asc(), Post.id.asc())
        .first()
    )
    is_op = op is not None and op.id == post.id

    reference_mid = None
    thread_root = None
    if not is_op:
        op_mid = _op_message_id(thread.id)
        if op_mid is None and op is not None and not _has_article(op.id):
            # Publish the OP first so the reply has a thread to attach to on the
            # far side — even if the OP predates the publish floor.
            _publish_post(client, op, board_newsgroups)
            op_mid = _op_message_id(thread.id)
        if op_mid is None:
            return False
        reference_mid = op_mid
        thread_root = op_mid

    message_id, headers, body = _build_article(post, newsgroups, reference_mid=reference_mid)
    if thread_root is None:
        thread_root = message_id  # OP is its own root
    client.post_article(headers, body)  # raises NNTPError if the peer refuses
    record_article(message_id, newsgroups[0], thread_root, thread.id, post.id, is_op)
    return True


def publish_pending(client):
    """POST not-yet-federated local posts on mapped boards. Returns count posted.

    Stops (without committing further) if the peer refuses a POST, so the rest
    retry next cycle. Idempotent: published posts carry an nntp_article row and
    are never re-selected.
    """
    if not publishing_enabled():
        return 0
    board_newsgroups = _board_newsgroups()
    if not board_newsgroups:
        return 0

    published_subquery = (
        db.session.query(NntpArticle.local_post_id)
        .filter(NntpArticle.local_post_id.isnot(None))
    )
    posts = (
        db.session.query(Post)
        .join(Thread, Post.thread == Thread.id)
        .filter(Thread.board.in_(list(board_newsgroups.keys())))
        .filter(Thread.source_type == "local")     # never re-federate scraped content
        .filter(Post.id > _floor())
        .filter(~Post.id.in_(published_subquery))
        .order_by(Post.id.asc())
        .limit(MAX_PER_CYCLE)
        .all()
    )
    posted = 0
    for post in posts:
        try:
            if _publish_post(client, post, board_newsgroups):
                posted += 1
        except NNTPError as exc:
            app.logger.warning("NNTPChan publish: peer refused POST (%s); will retry", exc)
            break
        except Exception:
            db.session.rollback()
            app.logger.exception("NNTPChan publish: failed for post %s", post.id)
        time.sleep(0)  # release the GIL so web workers keep serving
    if posted:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("NNTPChan publish: commit failed")
    return posted
