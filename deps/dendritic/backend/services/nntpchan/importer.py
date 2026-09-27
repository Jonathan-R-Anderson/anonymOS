"""Import a parsed overchan article as local Thread/Post/Media rows.

Design choice: imported articles become ORDINARY local posts (source_type
stays "local"), so every existing surface — catalog, thread view, firehose,
board-list thumbnails, the live-update poll/distributed sync, and moderation —
treats them with no special-casing. Provenance + dedup live entirely in the
NntpArticle ledger.

Two moderation guarantees the operator asked for:
  * Address blocklist: an article whose pubkey / From / From-domain / any Path
    host is blocked is dropped before anything is stored.
  * Image auto-block: attachment bytes go through storage.save_attachment,
    whose SHA-256 check raises BlockedMediaError for banned hashes (and for
    failed magic-byte/AV checks) — we drop the media, and if that leaves the
    post with no text, we drop the whole post.
"""
import datetime as _datetime
import hashlib

from shared import app, db
from model.Board import Board
from model.Thread import Thread
from model.Post import Post, MAX_BODY_LENGTH
from model.Poster import Poster
from model.Media import BlockedMediaError, storage
from services.seedbox import seed_media_background
from services.aggregator_sync.media import _MirrorFile
from services.thread_retention import make_room_for_new_thread
from model.NntpArticle import is_message_seen, record_article, thread_for_root
from model.NntpAddressBlock import is_address_blocked


def article_addresses(article):
    """Every identifier an operator might block an article by."""
    candidates = []
    if article.pubkey:
        candidates.append(article.pubkey)
    if article.from_addr:
        candidates.append(article.from_addr)
        if "@" in article.from_addr:
            candidates.append(article.from_addr.rsplit("@", 1)[-1])
    for host in article.path_hosts:
        candidates.append(host)
    # de-dup while preserving order
    seen = set()
    ordered = []
    for candidate in candidates:
        norm = (candidate or "").strip().lower()
        if norm and norm not in seen:
            seen.add(norm)
            ordered.append(norm)
    return ordered


def _poster_hex(article):
    seed = (article.pubkey or article.from_addr or article.message_id or "nntp").encode("utf-8", "replace")
    return hashlib.sha1(seed).hexdigest()[:16]


def _save_media(article, board=None):
    """Store the first usable attachment; None if none/blocked. Hash-block fires here."""
    from model.Media import _sniff_attachment_mimetype
    for filename, content_type, data in article.attachments:
        if not data:
            continue
        # Federated attachments are frequently MISLABELED (e.g. a PNG screenshot
        # named ".jpg" and declared image/jpeg). save_attachment trusts the
        # declared type and its magic-byte check then rejects the image as a
        # content/signature mismatch — which is why pulled posts had no images.
        # Trust the actual magic bytes: sniff the real type and store with it.
        # Genuinely-bogus content still sniffs to None/text and is dropped by the
        # signature/AV checks, so this doesn't weaken upload security.
        sniffed = _sniff_attachment_mimetype(data[:512])
        effective_type = sniffed or content_type
        try:
            media = storage.save_attachment(
                _MirrorFile(filename, effective_type, data),
                content_type=effective_type,
                # Peer-supplied bytes go through the NSFW filter like any upload;
                # `board` lets the destination board's toggle apply, and None
                # falls back to the stricter site-wide policy.
                nsfw_board=board,
            )
        except BlockedMediaError as exc:
            nsfw_score = getattr(exc, "nsfw_score", None)
            app.logger.info(
                "NNTPChan: dropped attachment on %s (%s)",
                article.message_id,
                ("NSFW filter, score %.2f" % float(nsfw_score)) if nsfw_score is not None
                else "banned hash/fingerprint/AV",
            )
            continue
        except Exception:
            app.logger.exception("NNTPChan: attachment save failed on %s", article.message_id)
            continue
        db.session.flush()
        try:
            seed_media_background(
                media.id,
                storage.get_attachment_fetch_url(media.id, media.ext),
                media_ext=media.ext,
                expected_info_hash=media.torrent_info_hash,
                piece_length=media.torrent_piece_length,
            )
        except Exception:
            app.logger.exception("NNTPChan: seed_media_background failed for media %s", media.id)
        return media.id
    return None


REQUIRE_WATERMARK_SETTING = "nntpchan_require_watermark"


def require_watermark():
    from model.SiteSetting import get_setting
    return str(get_setting(REQUIRE_WATERMARK_SETTING, "0")).strip().lower() not in ("", "0", "false", "no", "off")


def _resolve_watermark(article):
    """URL for this post's source watermark: an EMBEDDED image is stored once
    (deduped by hash) and served same-origin so attribution survives the origin
    going offline; otherwise fall back to the provided (http/https) URL."""
    data = getattr(article, "source_watermark_bytes", None)
    if data:
        try:
            from model.NntpSourceWatermark import store_watermark, watermark_url_for
            digest = store_watermark(data, getattr(article, "source_watermark_mime", None))
            if digest:
                db.session.flush()
                return watermark_url_for(digest)
        except Exception:
            app.logger.exception("NNTPChan: failed storing embedded watermark for %s", article.message_id)
    return getattr(article, "source_watermark_url", None)


def import_article(article, board_id):
    """Import one article into board_id.

    Returns: 'imported' | 'skipped' (already seen) | 'blocked' (address/hash)
             | 'deferred' (reply whose OP is not imported yet) | 'error'.
    """
    if is_message_seen(article.message_id):
        return "skipped"

    if is_address_blocked(*article_addresses(article)):
        # Record so we don't reprocess, but store nothing.
        record_article(article.message_id, article.newsgroup, article.thread_root, None, None, False)
        return "blocked"

    # Policy: optionally require every federated post to carry a source
    # watermark (embedded image or URL). Off by default so it doesn't silently
    # drop content from peers that don't send one yet.
    if require_watermark() and not (
        getattr(article, "source_watermark_bytes", None)
        or getattr(article, "source_watermark_url", None)
    ):
        record_article(article.message_id, article.newsgroup, article.thread_root, None, None, False)
        app.logger.info("NNTPChan: dropped %s — required source watermark missing", article.message_id)
        return "blocked"

    # Don't re-import a thread a moderator deleted here (within the retention
    # window). NOT recorded in the ledger, so it can return once the tombstone
    # expires and the peer still carries it.
    from model.NntpDeletedThread import is_thread_tombstoned
    if is_thread_tombstoned(article.thread_root):
        return "blocked"

    is_op = article.is_root

    if is_op:
        board = db.session.query(Board).get(board_id)
        if board is None:
            return "error"
        thread = Thread(board=board_id, views=0)
        db.session.add(thread)
        db.session.flush()
        try:
            make_room_for_new_thread(board)
        except Exception:
            app.logger.exception("NNTPChan: make_room_for_new_thread failed for board %s", board_id)
        thread_id = thread.id
    else:
        thread_id = thread_for_root(article.thread_root)
        if thread_id is None:
            # OP not imported yet; leave unrecorded so a later sync retries once
            # its root has landed.
            return "deferred"
        thread = db.session.query(Thread).get(thread_id)
        if thread is None:
            return "deferred"

    poster = Poster(
        hex_string=_poster_hex(article),
        ip_address=((article_addresses(article) or ["nntp"])[0])[:255],
        thread=thread_id,
        slip=None,
        country_code=None,
    )
    db.session.add(poster)
    db.session.flush()

    _nsfw_board = None
    try:
        from model.Board import Board
        _nsfw_board = db.session.query(Board).get(board_id) if board_id else None
    except Exception:
        _nsfw_board = None  # fall back to the site-wide policy (stricter)
    media_id = _save_media(article, board=_nsfw_board)

    body = (article.body_text or "").strip()
    if not body and media_id is None:
        # Nothing left to show (e.g. the only content was a hash-blocked image).
        if is_op:
            db.session.delete(thread)
        db.session.delete(poster)
        db.session.flush()
        record_article(article.message_id, article.newsgroup, article.thread_root, None, None, False)
        return "blocked"

    subject = (article.subject or "").strip() or None
    if subject:
        subject = subject[:64]
    tripcode = ("!" + article.pubkey[:10]) if article.pubkey else None

    post = Post(
        body=(body or "(no text)")[:MAX_BODY_LENGTH],
        subject=subject,
        thread=thread_id,
        poster=poster.id,
        media=media_id,
        spoiler=False,
        author_name=(article.from_name or None),
        tripcode=tripcode,
        datetime=(article.posted_at or _datetime.datetime.utcnow()),
        # Source attribution watermark (embedded image stored locally, else URL).
        source_watermark_url=_resolve_watermark(article),
        source_watermark_label=getattr(article, "source_label", None),
    )
    db.session.add(post)
    db.session.flush()

    if is_op or not article.sage:
        thread.last_updated = post.datetime
        db.session.add(thread)

    record_article(
        article.message_id, article.newsgroup, article.thread_root,
        thread_id, post.id, is_op,
    )
    return "imported"
