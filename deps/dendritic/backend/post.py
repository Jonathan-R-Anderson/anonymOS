"""
This module is responsible for creating posts out of post data.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Optional, Tuple, Set, List

from flask import g, request

from board_access import get_board_or_404
from cache import Cache
from captcha import validate_submission
import keystore
from model.Ban import get_ban, get_board_ban
from model.Board import Board
from model.Media import BlockedMediaError, Media, resolve_attachment_content_type, storage
from services.seedbox import seed_media_background
from model.Poster import Poster
from model.Post import Post, MAX_BODY_LENGTH
from model.Reply import Reply, REPLY_REGEXP
from model.SubmissionError import SubmissionError
from model.Thread import Thread
from model.ThreadPosts import thread_posts_cache_key
from model.Slip import get_slip, slip_can_moderate, slip_is_admin
from model.UrlBlocklist import (
    AUTOBAN_REASON as URL_BLOCKLIST_AUTOBAN_REASON,
    REJECTION_MESSAGE as URL_BLOCKLIST_REJECTION_MESSAGE,
    autoban_duration as url_blocklist_autoban_duration,
    autoban_enabled as url_blocklist_autoban_enabled,
    find_match as find_url_blocklist_match,
    record_hit as record_url_blocklist_hit,
)
from model.WordFilter import apply_word_filters
from shared import app, db


POSTER_COOKIE_NAME = "maniwani_poster"
POSTER_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 5


class InvalidMimeError(Exception):
    "Error to be thrown when the mimetype is invalid for an attachment."


def _tripcode_secret() -> bytes:
    configured_secret = app.config.get("TRIPCODE_SECRET") or app.secret_key or "maniwani-tripcode"
    if isinstance(configured_secret, bytes):
        return configured_secret
    return str(configured_secret).encode("utf-8")


def _short_hash(raw_digest: bytes, width: int) -> str:
    return base64.b64encode(raw_digest, altchars=b".-").decode("ascii").rstrip("=")[:width]


def build_tripcode(secret: str, secure_salt: Optional[str] = None) -> Optional[str]:
    normalized_secret = (secret or "").strip()
    if not normalized_secret:
        return None
    if secure_salt:
        payload = ("%s\x1f%s" % (normalized_secret, secure_salt.strip())).encode("utf-8")
        digest = hmac.new(_tripcode_secret(), payload, hashlib.sha256).digest()
        return "!!" + _short_hash(digest, 12)
    digest = hashlib.sha1(normalized_secret.encode("utf-8")).digest()
    return "!" + _short_hash(digest, 10)


def parse_poster_name(raw_name: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    normalized = (raw_name or "").strip()
    if not normalized:
        return (None, None)

    display_name = normalized
    tripcode = None
    hash_index = normalized.find("#")
    if hash_index != -1:
        display_name = normalized[:hash_index].strip()
        trip_input = normalized[hash_index + 1:]
        secure_index = trip_input.find("##")
        secure_salt = None
        if secure_index != -1:
            secure_salt = trip_input[secure_index + 2:].strip()
            trip_input = trip_input[:secure_index]
        tripcode = build_tripcode(trip_input, secure_salt=secure_salt)

    display_name = display_name[:128].strip() or None
    return (display_name, tripcode)


def _normalize_poster_cookie(raw_token: Optional[str]) -> Optional[str]:
    if not raw_token:
        return None
    token = str(raw_token).strip().lower()
    if re.fullmatch(r"[a-f0-9]{32,64}", token) is None:
        return None
    return token


def get_or_create_poster_cookie_token() -> str:
    token = _normalize_poster_cookie(request.cookies.get(POSTER_COOKIE_NAME))
    if token is None:
        token = secrets.token_hex(16)
    g.poster_cookie_token = token
    return token


def apply_pending_poster_cookie(response):
    token = getattr(g, "poster_cookie_token", None)
    if not token:
        return response
    if _normalize_poster_cookie(request.cookies.get(POSTER_COOKIE_NAME)) == token:
        return response
    response.set_cookie(
        POSTER_COOKIE_NAME,
        token,
        max_age=POSTER_COOKIE_MAX_AGE,
        httponly=True,
        secure=bool(getattr(request, "is_secure", False)),
        samesite="Lax",
    )
    return response


def _poster_digest(thread_id: int, cookie_token: str) -> str:
    payload = ("%s:%s" % (thread_id, cookie_token)).encode("utf-8")
    return hmac.new(_tripcode_secret(), payload, hashlib.sha256).hexdigest().upper()


def _poster_hex_for_thread(thread_id: int, cookie_token: str, poster_id: Optional[int] = None) -> str:
    digest = _poster_digest(thread_id, cookie_token)
    for width in (6, 8, 10, 12):
        candidate = digest[:width]
        existing = (
            db.session.query(Poster)
            .filter_by(thread=thread_id, hex_string=candidate)
            .first()
        )
        if existing is None or existing.id == poster_id or existing.cookie_token == cookie_token:
            return candidate

    suffix = 1
    while True:
        candidate = "%s-%X" % (digest[:10], suffix)
        existing = (
            db.session.query(Poster)
            .filter_by(thread=thread_id, hex_string=candidate)
            .first()
        )
        if existing is None or existing.id == poster_id or existing.cookie_token == cookie_token:
            return candidate
        suffix += 1


def get_ip_address() -> str:
    "Returns the current IP address of the user."

    from services.client_ip import get_client_ip
    return get_client_ip()


def _resolve_country(ip: str) -> Optional[str]:
    "Best-effort IP -> country; never raises so it can't block posting."
    try:
        from services.geoip import country_for_ip
        return country_for_ip(ip)
    except Exception:
        return None


def get_or_update_poster(thread_id: int, ip: str) -> Tuple[Poster, bool]:
    """
    Returns the current poster (creating one if it doesn't exist) and whether
    this poster is the last poster in the current thread.
    """

    cookie_token = get_or_create_poster_cookie_token()
    poster = (
        db.session.query(Poster)
        .filter_by(thread=thread_id, cookie_token=cookie_token)
        .first()
    )

    if poster is None:
        poster = (
            db.session.query(Poster)
            .filter_by(thread=thread_id, ip_address=ip, cookie_token=None)
            .first()
        )
        if poster is None:
            poster = (
                db.session.query(Poster)
                .filter_by(thread=thread_id, ip_address=ip, cookie_token="")
                .first()
            )
        if poster is not None:
            poster.cookie_token = cookie_token

    if poster is None:
        poster_hex = _poster_hex_for_thread(thread_id, cookie_token)
        poster = Poster(
            hex_string=poster_hex,
            ip_address=ip,
            thread=thread_id,
            cookie_token=cookie_token,
            country_code=_resolve_country(ip),
        )
        db.session.add(poster)
        db.session.flush()

        return (poster, False)

    if poster.ip_address != ip:
        poster.ip_address = ip
        poster.country_code = _resolve_country(ip)
    elif not poster.country_code:
        poster.country_code = _resolve_country(ip)
    if poster.cookie_token != cookie_token:
        poster.cookie_token = cookie_token
    desired_hex = _poster_hex_for_thread(thread_id, cookie_token, poster_id=poster.id)
    if poster.hex_string != desired_hex:
        poster.hex_string = desired_hex
    db.session.add(poster)

    last_post = (
        db.session.query(Post)
        .filter_by(thread=thread_id)
        .order_by(Post.id.desc())
        .first()
    )

    if last_post is None or last_post.poster != poster.id:
        return (poster, False)
    return (poster, True)


def update_poster_slip(poster: Poster, args: dict, board=None) -> None:
    "Updates the current poster with a slip if necessary."

    slip = get_slip()
    if slip is None:
        return
    if slip_is_admin(slip) or (args.get("useslip") is True and slip_can_moderate(slip, board=board)):
        poster.slip = slip.id
        db.session.add(poster)


def _enforce_nsfw_for_board(media, board, board_id: int) -> None:
    """Reject already-stored media that this board's NSFW filter disallows.

    This is the authoritative gate for post attachments. It runs on the STORED
    score rather than re-classifying, which is what closes the pre-upload bypass:
    the browser sends the file to /upload/media before a board is chosen, so
    Media.save_attachment had no board policy to apply at the time.
    """
    from services import nsfw as nsfw_service

    score = getattr(media, "nsfw_score", None)
    if nsfw_service.score_blocks(score, board):
        raise SubmissionError(nsfw_service.rejection_message(score), board_id)
    # Nothing was scored, the filter is on, and this board demands filtering:
    # only refuse when the operator has opted into fail-closed, matching the
    # policy Media.save_attachment applies.
    if (
        score is None
        and media.mimetype
        and media.mimetype.startswith("image/")
        and nsfw_service.is_enabled()
        and nsfw_service.board_filters_nsfw(board)
        and nsfw_service.fail_closed()
    ):
        raise SubmissionError(
            "This image could not be checked by the NSFW filter, so it was not posted. "
            "Try again shortly.",
            board_id,
        )


def get_media_id(board_id: int) -> int:
    "Get the media ID for this request, or None if no media was uploaded."

    # Loaded lazily: a text-only post must not pay for a Board query it never uses.
    def _board():
        return db.session.query(Board).filter_by(id=board_id).one()

    # Accept a media_id from a prior /upload/media call (JS pre-upload path)
    pre_uploaded = request.form.get("media_id", "").strip()
    if pre_uploaded:
        try:
            media_id = int(pre_uploaded)
        except ValueError:
            raise SubmissionError("Invalid media_id", board_id)
        media = db.session.query(Media).filter_by(id=media_id).one_or_none()
        if media is None:
            raise SubmissionError("Pre-uploaded media not found", board_id)
        board = _board()
        if re.match(board.mimetypes, media.mimetype) is None:
            raise InvalidMimeError(media.mimetype, board_id)
        _enforce_nsfw_for_board(media, board, board_id)
        return media_id

    f = request.files.get("media")
    if not f or not f.filename:
        return None

    # Check the mimetype
    mimetype = resolve_attachment_content_type(f)
    board = _board()

    if re.match(board.mimetypes, mimetype) is None:
        db.session.rollback()
        raise InvalidMimeError(mimetype, board_id)

    try:
        # Direct (non-JS) upload: the board IS known here, so the NSFW filter can
        # apply this board's policy inline and refuse before anything is stored.
        media = storage.save_attachment(f, content_type=mimetype, nsfw_board=board)
        seed_media_background(
            media.id,
            storage.get_attachment_fetch_url(media.id, media.ext),
            media_ext=media.ext,
            expected_info_hash=media.torrent_info_hash,
            piece_length=media.torrent_piece_length,
        )
        return media.id
    except BlockedMediaError as exc:
        db.session.rollback()
        raise SubmissionError(str(exc), board_id)


def get_replies(post_id: int, body: str) -> Set[Reply]:
    "Returns a list of Reply objects for this post (unique IDs)."

    ids = set()
    iterator = re.finditer(REPLY_REGEXP, body)

    if not iterator:
        return []

    for match in iterator:
        # match.group(2) == the post ID
        ids.add(int(match.group(2)))
    if not ids:
        return []

    existing_ids = {
        row[0]
        for row in (
            db.session.query(Post.id)
            .filter(Post.id.in_(ids))
            .all()
        )
    }
    return [
        Reply(reply_from=post_id, reply_to=reply_id)
        for reply_id in ids
        if reply_id in existing_ids
    ]

def publish_thread(thread: Thread, post: Post, replies: List[Reply], bumped: bool = True) -> None:
    """
    Publish a new post to the pub-sub system, also invalidating the cache in
    the process.  When bumped is True the catalog is also notified so clients
    can reorder the thread grid in real time.
    """

    client = keystore.Pubsub()
    client.publish("new-post", json.dumps({
        "thread": thread.id,
        "post": post.id,
    }))
    if bumped:
        client.publish("bump-thread", json.dumps({
            "thread": thread.id,
            "board": thread.board,
        }))
    for reply in replies:
        client.publish("new-reply", json.dumps({
            "thread": post.thread,
            "post": post.id,
            "reply_to": reply.reply_to,
        }))


def invalidate_posts(thread: Thread, replies: List[Reply]):
    "Invalidates the respective cache pages after a post has been created."

    cache = Cache()
    cache.invalidate(thread_posts_cache_key(thread.id))
    theme_list = app.config.get("THEME_LIST") or ("stock", "harajuku", "wildride")
    for theme in theme_list:
        render_cache_key = "thread-%d-%s-render" % (thread.id, theme)
        cache.invalidate(render_cache_key)

    reply_ids = list(map(lambda r: r.reply_to, replies))
    # Single-column query() rows are Row objects, not scalars — unpack the id
    # (and dedupe, since several replies can target the same thread) before
    # building the cache key, which formats it with %d.
    thread_id_rows = (
        db.session.query(Post.thread)
        .filter(Post.id.in_(reply_ids))
        .distinct()
        .all()
    )
    for (thread_id,) in thread_id_rows:
        cache.invalidate(thread_posts_cache_key(thread_id))


def prepare_submission(thread: Thread, args: dict, include_media: bool = True):
    """Apply the posting gates shared by local and outbound replies."""
    board_id = thread.board
    board = get_board_or_404(board_id)
    # API-only boards reject every posting path EXCEPT the authenticated bot API,
    # which sets g.bot_api_authorized just before calling here. This is the single
    # funnel all posts (thread OPs and replies, web and generic JSON API) pass
    # through, so one check covers them all.
    if getattr(board, "api_only", False) and not getattr(g, "bot_api_authorized", False):
        raise SubmissionError(
            "This board only accepts posts through its bot API (see the FAQ).",
            board_id,
        )
    if board.is_geo_root:
        raise SubmissionError(
            "This nearby board only routes you into a local area board. Open the resolved local board instead.",
            board_id,
        )
    # Authorized bot API posts (token + registered IP, see blueprints/bot_api.py)
    # are already vetted and send no CAPTCHA — skip the human CAPTCHA gate for
    # them. Every other posting path still validates normally.
    if not getattr(g, "bot_api_authorized", False):
        validate_submission(board_id, args)

    # Wordfilters are submission-time transforms. Store and publish only the
    # filtered text so API, SSE, catalog and thread views all agree.
    args["body"] = apply_word_filters(args.get("body") or "", board_id)
    if args.get("subject") is not None:
        args["subject"] = apply_word_filters(args.get("subject") or "", board_id)

    body = args["body"]
    if len(body) > MAX_BODY_LENGTH:
        raise SubmissionError(
            "Post body is too long: %d characters (the maximum is %d)."
            % (len(body), MAX_BODY_LENGTH),
            board_id,
        )
    if len(args.get("subject") or "") > 64:
        raise SubmissionError(
            "Post subject is too long after wordfilters (the maximum is 64 characters).",
            board_id,
        )

    ip = get_ip_address()
    ban = get_ban(ip)
    if ban is not None:
        ban_reason = (" Reason: %s" % ban.reason) if ban.reason else ""
        raise SubmissionError("You are banned from posting.%s" % ban_reason, board_id)
    board_ban = get_board_ban(board_id, ip)
    if board_ban is not None:
        ban_reason = (" Reason: %s" % board_ban.reason) if board_ban.reason else ""
        raise SubmissionError("You are banned from posting on this board.%s" % ban_reason, board_id)

    # Spam URL blocklist. Checked on the wordfiltered body+subject (i.e. exactly
    # what would be stored) so a wordfilter cannot smuggle a blocked domain past
    # this gate, and before any Poster/Media row is created so a rejected spam
    # post leaves nothing behind. Applies to the bot API too: an authenticated
    # bot is exempt from the CAPTCHA, not from spam filtering.
    blocklist_match = find_url_blocklist_match(args.get("body"), args.get("subject"))
    if blocklist_match is not None:
        entry_id, matched_pattern = blocklist_match
        record_url_blocklist_hit(entry_id)
        app.logger.info(
            "blocked spam post on board %s from %s (blocklist entry %s: %r)",
            board_id, ip, entry_id, matched_pattern,
        )
        if url_blocklist_autoban_enabled():
            try:
                from model.Ban import ban_ip, expiry_from_duration
                ban_ip(
                    ip,
                    URL_BLOCKLIST_AUTOBAN_REASON,
                    expires_at=expiry_from_duration(url_blocklist_autoban_duration()),
                )
                db.session.commit()
            except Exception:
                db.session.rollback()
                app.logger.exception("blocklist autoban failed for %s", ip)
        raise SubmissionError(URL_BLOCKLIST_REJECTION_MESSAGE, board_id)

    poster, flooding = get_or_update_poster(thread.id, ip)

    update_poster_slip(poster, args, board=thread.board)

    media_id = get_media_id(board_id) if include_media else None
    author_name, tripcode = parse_poster_name(args.get("name"))

    return {
        "board": board,
        "poster": poster,
        "flooding": flooding,
        "media_id": media_id,
        "author_name": author_name,
        "tripcode": tripcode,
    }


def create_post(thread: Thread, args: dict) -> Post:
    "Creates a new post from the given data."

    board_id = thread.board
    prepared = prepare_submission(thread, args, include_media=True)
    poster = prepared["poster"]
    flooding = prepared["flooding"]

    post = Post(
        body=args["body"],
        subject=args["subject"],
        thread=thread.id,
        poster=poster.id,
        media=prepared["media_id"],
        spoiler=args["spoiler"],
        author_name=prepared["author_name"],
        tripcode=prepared["tripcode"],
    )
    db.session.add(post)
    db.session.flush()

    replies = get_replies(post.id, post.body)
    for reply in replies:
        db.session.add(reply)

    if not flooding:
        # bump the thread if the last poster isn't the same
        thread.last_updated = post.datetime
        db.session.add(thread)

    db.session.flush()
    db.session.commit()

    publish_thread(thread, post, replies, bumped=not flooding)
    invalidate_posts(thread, replies)
    # Learn per-word sentiment from the new post's body in real time. Guarded and
    # fire-and-forget: a failure here must never break posting.
    try:
        from model.WordSentiment import score_and_learn_text
        score_and_learn_text(post.body)
    except Exception:
        app.logger.exception("word sentiment learning failed for post %s", post.id)
    # import here to prevent a circular import
    # TODO: fix circular import with NewPost
    from thread import invalidate_board_cache
    invalidate_board_cache(board_id)

    try:
        from services.analytics import emit_server_event
        emit_server_event(
            "reply_submitted",
            surface="thread",
            content_type="post",
            content_id=post.id,
            properties={"interaction_type": "create"},
        )
    except Exception:
        app.logger.exception("analytics event failed for post %s", post.id)

    return post
