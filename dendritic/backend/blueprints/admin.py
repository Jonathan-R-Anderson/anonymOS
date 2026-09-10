import datetime as _datetime
import json
import mimetypes
import os
import secrets
import time
from functools import wraps

import requests
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from flask import Blueprint, abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for

import cache
from board_access import get_board_by_name_or_404, get_board_or_404, get_post_thread_board_or_404, get_thread_and_board_or_404
from model.Ban import Ban, ban_ip, ban_ip_for_board, unban_ip
from model.Ban import BoardBan
from model.BlockedMediaHash import BlockedMediaHash, block_media_hash, normalize_media_hash
from model.CaptchaChallenge import (
    CaptchaChallenge,
    add_questions_to_challenge,
    create_challenge,
    remove_question,
)
from captcha.anime import QUESTIONS_PER_CHALLENGE
from services.board_cleanup import inactivity_delete_days
from services.csrf import csrf_protect
from services.video_cleanup import inactivity_delete_days as _video_inactivity_delete_days
from board_sources import DEFAULT_MIMETYPES as DEFAULT_BOARD_MIMETYPES
from model.Board import Board
from model.BoardBanner import BoardBanner
from model.BoardVisit import BoardVisit
from model.BoardSource import BoardSource
from model.FrontPageUpdate import (
    create_front_page_update,
    delete_front_page_update,
    recent_front_page_updates,
)
from model.BanPageAsset import (
    BAN_ASSET_KINDS,
    add_ban_page_asset,
    ban_page_assets,
    delete_ban_page_asset,
)
from model.WarrantCanary import (
    VALID_STATUSES as WC_STATUSES,
    VALID_THEMES as WC_THEMES,
    add_warrant_canary_entry,
    delete_warrant_canary_entry,
    warrant_canary_config,
)
import model.WarrantCanary as _wc
from model.ImageMagnet import ImageMagnet
from model.ImportedMedia import ImportedMedia
from model.Media import BlockedMediaError, Media, storage
from model.Poster import Poster
from model.Post import Post
from model.PostRemoval import PostRemoval
from model.Reply import Reply
from model.SiteSetting import get_setting, set_setting
from model.Slip import (
    WALLET_ADMIN_SLIP_NAME,
    Slip,
    SlipBoardModerator,
    begin_wallet_admin_session,
    configured_admin_wallet_address,
    get_slip,
    slip_can_moderate,
    slip_is_admin,
)
from model.ThreadPosts import ThreadPosts
from model.Thread import Thread, tags as thread_tags
from model.WordFilter import WordFilter, create_word_filter
from board_sources import SUPPORTED_SOURCE_TYPES, format_source_config, replace_board_sources
from services.analytics.maintenance import quality_summary
from services.analytics.dashboards import dashboard_payload
from services.analytics.features import feature_quality_summary
from services.recommendations.engine import recommendation_quality_summary
from services.recommendations.maturity import generate_audit_package
from model.AdvancedRecommendation import AlgorithmAudit
from source_watermarks import (
    clear_source_watermark,
    replace_source_watermark,
    source_display_name,
    source_watermark_image_url,
    source_watermark_summary,
)
from shared import app, db
from thread import invalidate_board_cache


admin_blueprint = Blueprint("admin", __name__, template_folder="template")

ADMIN_CHALLENGE_SESSION_KEY = "admin-wallet-challenge"
ADMIN_CHALLENGE_ISSUED_AT_KEY = "admin-wallet-issued-at"
ADMIN_CHALLENGE_TTL = 300
FRONT_PAGE_SETTING_KEY = "front_page_html"
DEFAULT_GREETING_PATH = "deploy-configs/index-greeting.html"
BOARD_METRICS_WINDOW_DAYS = 30
ALLOWED_WATERMARK_IMAGE_MIMETYPES = {
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
}


@app.context_processor
def _admin_shell_context():
    """`admin_site_map` and `admin_url()` for templates/admin-shell.html.

    A context processor rather than something each view passes, because the
    whole point is that no admin screen can forget to have navigation. A view
    that omitted it would render a page with no way out, which is exactly the
    failure being fixed.

    `admin_url` resolves an endpoint to a URL and returns None when it does not
    exist, so a renamed route makes one nav entry disappear instead of raising
    BuildError on every admin page.
    """
    from services.admin_nav import DASHBOARD_SECTIONS, SITE_MAP

    def admin_url(endpoint_name):
        try:
            return url_for(endpoint_name)
        except Exception:
            return None

    # Supplied here rather than by each view for the same reason as the map:
    # every admin screen shows who is signed in, and a view that has to remember
    # to pass it is a view that will eventually forget. An explicit
    # render_template kwarg still wins, so the dashboard's own value is
    # unaffected.
    from model.Slip import ADMIN_WALLET_SESSION_KEY

    return {
        "admin_site_map": SITE_MAP,
        "admin_dashboard_sections": DASHBOARD_SECTIONS,
        "admin_url": admin_url,
        "admin_wallet_address": session.get(ADMIN_WALLET_SESSION_KEY),
    }


def _admin_required(endpoint):
    @wraps(endpoint)
    def wrapped(*args, **kwargs):
        if slip_is_admin() is False:
            flash("Admin access requires the configured MetaMask wallet.")
            return redirect(url_for("admin.login"))
        return endpoint(*args, **kwargs)
    return wrapped



def _overlay_ctx():
    """Overlay-image card context: the configured image plus how many are blocked."""
    try:
        from services.media_overlay import overlay_summary

        summary = dict(overlay_summary())
        summary["blocked_count"] = (
            db.session.query(db.func.count(Media.id))
            .filter(Media.overlay_blocked.is_(True))
            .scalar()
            or 0
        )
        return summary
    except Exception:
        db.session.rollback()
        app.logger.exception("overlay: could not build the admin summary")
        return {"media_id": None, "image_url": None, "thumb_url": None, "blocked_count": 0}


def _nsfw_ctx():
    """Current NSFW filter settings, as template kwargs for the dashboard card."""
    from services import nsfw as nsfw_service
    return {
        "nsfw_enabled": nsfw_service.is_enabled(),
        "nsfw_threshold": nsfw_service.threshold(),
        "nsfw_fail_closed": nsfw_service.fail_closed(),
        "nsfw_scan_video": nsfw_service.scan_video_enabled(),
        "overlay_summary": _overlay_ctx(),
        "nsfw_timeout": nsfw_service.timeout_seconds(),
        "nsfw_configured": bool(nsfw_service.classifier_url()),
    }


def _default_front_page_html():
    if os.path.exists(DEFAULT_GREETING_PATH):
        with open(DEFAULT_GREETING_PATH, encoding="utf-8") as greeting_file:
            return greeting_file.read()
    return ""


def current_front_page_html():
    return get_setting(FRONT_PAGE_SETTING_KEY, _default_front_page_html())


def invalidate_front_page_cache():
    cache_connection = cache.Cache()
    # The index route caches under firehose-v4-<theme>-<rank_mode>-render, plus
    # a -etag and a -ts companion (blueprints/main.py index()). The v4 keys were
    # missing here: this function cleared v3 only, so every caller -- a board
    # edit, a delete, a publication -- was clearing keys nothing writes any more
    # and the front page went on serving the old render until its own 20-second
    # TTL turned over. Clearing the -ts key is what actually forces the rebuild;
    # dropping the body alone would leave a "fresh" stamp pointing at nothing.
    #
    # Cover every theme rather than the config default trio, both ranking
    # buckets, and the older v3/v2 keys for any legacy render path still warm in
    # a long-lived key store.
    theme_list = set(app.config.get("THEME_LIST") or ())
    theme_list |= {"stock", "harajuku", "wildride", "midnight", "cyberpunk", "711chan"}
    for theme in theme_list:
        for rank_mode in ("rec", "chrono"):
            key = "firehose-v4-%s-%s-render" % (theme, rank_mode)
            cache_connection.invalidate(key)
            cache_connection.invalidate("%s-etag" % key)
            cache_connection.invalidate("%s-ts" % key)
        cache_connection.invalidate("firehose-v3-%s-render" % theme)
        cache_connection.invalidate("firehose-v3-%s-render-etag" % theme)
        cache_connection.invalidate("firehose-v2-%s-render" % theme)
    cache_connection.invalidate("firehose-threads")
    cache_connection.invalidate("firehose-threads-v2-candidates")


def invalidate_activity_cache():
    cache_connection = cache.Cache()
    cache_connection.invalidate("board-activity-threads")
    theme_list = app.config.get("THEME_LIST") or ("stock", "harajuku", "wildride")
    for theme in theme_list:
        cache_connection.invalidate("board-activity-%s-render" % theme)


def invalidate_all_board_caches():
    invalidate_front_page_cache()
    invalidate_activity_cache()
    cache_connection = cache.Cache()
    theme_list = app.config.get("THEME_LIST") or ("stock", "harajuku", "wildride")
    for board in db.session.query(Board).all():
        invalidate_board_cache(board.id)
    for (thread_id,) in db.session.query(Thread.id).all():
        for theme in theme_list:
            cache_connection.invalidate("thread-v8-%d-%s-render" % (thread_id, theme))
            cache_connection.invalidate("thread-v8-%d-%s-render-etag" % (thread_id, theme))
            cache_connection.invalidate("thread-v7-%d-%s-render" % (thread_id, theme))
            cache_connection.invalidate("thread-v7-%d-%s-render-etag" % (thread_id, theme))
            cache_connection.invalidate("thread-v6-%d-%s-render" % (thread_id, theme))
            cache_connection.invalidate("thread-v6-%d-%s-render-etag" % (thread_id, theme))
            cache_connection.invalidate("thread-v5-%d-%s-render" % (thread_id, theme))


def _format_admin_timestamp(raw_value):
    if not raw_value:
        return "never"
    text = str(raw_value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = _datetime.datetime.fromisoformat(text)
    except ValueError:
        return raw_value
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(_datetime.timezone.utc).replace(tzinfo=None)
    return parsed.strftime("%Y-%m-%d %H:%M UTC")



def _board_metrics_payload(window_days=BOARD_METRICS_WINDOW_DAYS):
    since = _datetime.datetime.utcnow() - _datetime.timedelta(days=window_days - 1)
    boards = db.session.query(Board).order_by(Board.name.asc()).all()
    try:
        visits = (
            db.session.query(BoardVisit)
            .filter(BoardVisit.started_at >= since)
            .order_by(BoardVisit.started_at.asc(), BoardVisit.id.asc())
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed loading board metrics; returning an empty metrics dataset")
        visits = []

    board_rows = {}
    for board in boards:
        board_rows[board.id] = {
            "id": board.id,
            "name": board.name,
            "title": board.title,
            "visits": 0,
            "unique_visitors": set(),
            "total_seconds": 0,
            "average_seconds": 0,
            "last_seen_at": None,
        }

    overall_visitors = set()
    daily_totals = {}
    for visit in visits:
        board_row = board_rows.get(visit.board_id)
        if board_row is None:
            continue
        duration_seconds = max(0, int(visit.duration_seconds or 0))
        day_key = (visit.started_at or since).date().isoformat()
        board_row["visits"] += 1
        board_row["total_seconds"] += duration_seconds
        board_row["unique_visitors"].add(visit.visitor_token)
        if visit.last_seen_at and (board_row["last_seen_at"] is None or visit.last_seen_at > board_row["last_seen_at"]):
            board_row["last_seen_at"] = visit.last_seen_at
        overall_visitors.add(visit.visitor_token)
        if daily_totals.get(day_key) is None:
            daily_totals[day_key] = {}
        daily_totals[day_key][visit.board_id] = daily_totals[day_key].get(visit.board_id, 0) + 1

    board_list = []
    for board_row in board_rows.values():
        unique_visitors = len(board_row.pop("unique_visitors"))
        visits_count = board_row["visits"]
        board_row["unique_visitors"] = unique_visitors
        board_row["average_seconds"] = int(round(board_row["total_seconds"] / visits_count)) if visits_count else 0
        board_row["last_seen_at"] = (
            board_row["last_seen_at"].isoformat() + "Z"
            if board_row["last_seen_at"] is not None
            else None
        )
        board_list.append(board_row)

    board_list.sort(key=lambda row: (-row["visits"], -row["total_seconds"], row["title"].lower()))
    top_boards = [row for row in board_list if row["visits"] > 0][:8]
    top_board_ids = [row["id"] for row in top_boards]

    daily_labels = [
        (since + _datetime.timedelta(days=offset)).date().isoformat()
        for offset in range(window_days)
    ]
    daily_series = []
    for board_row in top_boards:
        daily_series.append({
            "board_id": board_row["id"],
            "label": board_row["title"],
            "data": [daily_totals.get(label, {}).get(board_row["id"], 0) for label in daily_labels],
        })

    total_visits = sum(row["visits"] for row in board_list)
    total_seconds = sum(row["total_seconds"] for row in board_list)
    most_popular_board = top_boards[0] if top_boards else None
    return {
        "window_days": window_days,
        "summary": {
            "total_visits": total_visits,
            "unique_visitors": len(overall_visitors),
            "total_seconds": total_seconds,
            "average_seconds": int(round(total_seconds / total_visits)) if total_visits else 0,
            "most_popular_board": {
                "name": most_popular_board["name"],
                "title": most_popular_board["title"],
                "visits": most_popular_board["visits"],
            } if most_popular_board else None,
        },
        "boards": board_list,
        "charts": {
            "top_board_ids": top_board_ids,
            "daily_labels": daily_labels,
            "daily_series": daily_series,
        },
    }


def _wallet_challenge_message():
    nonce = secrets.token_urlsafe(32)
    issued_at = int(time.time())
    session[ADMIN_CHALLENGE_SESSION_KEY] = nonce
    session[ADMIN_CHALLENGE_ISSUED_AT_KEY] = issued_at
    wallet_address = configured_admin_wallet_address()
    return "\n".join((
        "%s admin authentication" % app.config.get("INSTANCE_NAME", "Syndichan"),
        "Wallet: %s" % wallet_address,
        "Nonce: %s" % nonce,
        "Issued At: %s" % _datetime.datetime.utcfromtimestamp(issued_at).isoformat() + "Z",
        "Only sign this message if you intend to unlock the admin dashboard.",
    ))


def _verify_signature_with_renderer(address, message, signature):
    verify_url = app.config["RENDERER_HOST"] + "/verify/wallet"
    response = requests.post(
        verify_url,
        json={"address": address, "message": message, "signature": signature},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def _recent_posts(limit=40):
    recent_posts = (
        db.session.query(Post)
        .filter(Post.source_type == "local")
        .order_by(Post.datetime.desc(), Post.id.desc())
        .limit(limit)
        .all()
    )
    posts = []
    poster_ids = [post.poster for post in recent_posts if post.poster is not None]
    posters = {
        poster.id: poster
        for poster in db.session.query(Poster).filter(Poster.id.in_(poster_ids)).all()
    } if poster_ids else {}
    post_threads = {post.id: post.thread for post in recent_posts}
    thread_rows = {}
    if post_threads:
        from model.Thread import Thread

        thread_rows = {
            thread.id: thread
            for thread in db.session.query(Thread).filter(Thread.id.in_(post_threads.values())).all()
        }
    board_rows = {}
    media_rows = {}
    if thread_rows:
        board_rows = {
            board.id: board
            for board in db.session.query(Board).filter(Board.id.in_([thread.board for thread in thread_rows.values()])).all()
        }
    media_ids = sorted({post.media for post in recent_posts if getattr(post, "media", None) is not None})
    if media_ids:
        media_rows = {
            media.id: media
            for media in db.session.query(Media).filter(Media.id.in_(media_ids)).all()
        }
    for post in recent_posts:
        poster = posters.get(post.poster)
        thread = thread_rows.get(post.thread)
        board = board_rows.get(thread.board) if thread else None
        media = media_rows.get(post.media)
        posts.append({
            "id": post.id,
            "thread_id": post.thread,
            "board_name": board.name if board else "?",
            "poster_ip": poster.ip_address if poster else None,
            "author_name": post.author_name,
            "body_preview": (post.body[:160] + "...") if len(post.body) > 160 else post.body,
            "delete_url": url_for("admin.delete_post", post_id=post.id),
            "ban_url": url_for("admin.ban_post", post_id=post.id),
            "shadowban_url": url_for("admin.shadowban_post", post_id=post.id),
            "can_ban": poster is not None,
            "media_sha256": media.sha256 if media is not None else None,
            "media_thumb_url": storage.get_thumb_url(media.id) if media is not None else None,
            # None, not a URL: blueprints/upload.py was removed with the
            # stripped features, so url_for("upload.file") raised
            # BuildError while BUILDING THIS PAYLOAD -- a 500 on the whole
            # listing for any post carrying media. The field keeps its
            # shape (it was already None when there is no media) and the
            # caller's "is there a URL" check keeps working; inventing a
            # route that does not exist would only move the error.
            "media_url": None,
            "block_media_url": url_for("admin.block_media_for_post", post_id=post.id) if media is not None else None,
        })
    return posts


def _editable_slips():
    slips = (
        db.session.query(Slip)
        .filter(Slip.name != WALLET_ADMIN_SLIP_NAME)
        .order_by(Slip.name.asc(), Slip.id.asc())
        .all()
    )
    if not slips:
        return []
    slip_ids = [slip.id for slip in slips]
    assignments_by_slip_id = {}
    for assignment in (
        db.session.query(SlipBoardModerator)
        .filter(SlipBoardModerator.slip_id.in_(slip_ids))
        .order_by(SlipBoardModerator.slip_id.asc(), SlipBoardModerator.board_id.asc())
        .all()
    ):
        assignments_by_slip_id.setdefault(assignment.slip_id, set()).add(assignment.board_id)
    return [
        {
            "id": slip.id,
            "name": slip.name,
            "is_mod": bool(slip.is_mod),
            "moderated_board_ids": assignments_by_slip_id.get(slip.id, set()),
        }
        for slip in slips
    ]


def _blocked_media_hash_rows():
    return (
        db.session.query(BlockedMediaHash)
        .order_by(BlockedMediaHash.created_at.desc(), BlockedMediaHash.sha256.asc())
        .all()
    )


def _cleanup_orphaned_scraper_sources(board):
    """Delete scraper DB rows for submitted threads no remaining board references and return them."""
    import os
    import sqlite3
    from services.aggregator_sync.config import WATERMARK_CACHE_KEY_TEMPLATE
    from services.aggregator_sync.scraper_db import (
        aggregator_db_path,
        _reddit_uses_universal_schema,
        _scraper_posts_source_column,
        _sqlite_table_exists,
    )
    boards = list(board) if isinstance(board, (list, tuple, set)) else _board_tree(board)
    deleting_board_ids = [current_board.id for current_board in boards if getattr(current_board, "id", None)]
    if not deleting_board_ids:
        return set()

    orphaned_sources = set()
    source_triples = {
        (source.source_type, source.source_name, source.source_thread_id)
        for current_board in boards
        for source in getattr(current_board, "sources", []) or []
    }

    for source_type, source_name, source_thread_id in sorted(source_triples):
        shared_count = (
            db.session.query(BoardSource)
            .filter(
                BoardSource.source_type == source_type,
                BoardSource.source_name == source_name,
                BoardSource.source_thread_id == source_thread_id,
                BoardSource.board_id.notin_(deleting_board_ids),
            )
            .count()
        )
        if shared_count > 0:
            continue

        orphaned_sources.add((source_type, source_name, source_thread_id))

        try:
            db_path = aggregator_db_path(source_type)
        except ValueError:
            continue

        cache.Cache().invalidate(WATERMARK_CACHE_KEY_TEMPLATE % (source_type, source_name))

        if not os.path.exists(db_path):
            continue

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                if source_type == "reddit" and _reddit_uses_universal_schema(conn):
                    if _sqlite_table_exists(conn, "comments"):
                        conn.execute(
                            "DELETE FROM comments WHERE CAST(post_id AS TEXT) = ?",
                            (str(source_thread_id),),
                        )
                    conn.execute(
                        "DELETE FROM posts WHERE subreddit = ? AND CAST(id AS TEXT) = ?",
                        (source_name, str(source_thread_id)),
                    )
                else:
                    col = _scraper_posts_source_column(conn, source_type)
                    conn.execute(
                        "DELETE FROM posts WHERE %s = ? AND thread_id = ?" % col,
                        (source_name, str(source_thread_id)),
                    )
                if _sqlite_table_exists(conn, "thread_monitors"):
                    conn.execute(
                        "DELETE FROM thread_monitors WHERE board = ? AND thread_id = ?",
                        (source_name, str(source_thread_id)),
                    )
                # Drop the source registry row once no thread rows remain for it.
                col = "subreddit" if (source_type == "reddit" and _reddit_uses_universal_schema(conn)) else _scraper_posts_source_column(conn, source_type)
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM posts WHERE %s = ?" % col,
                    (source_name,),
                ).fetchone()[0]
                if remaining == 0:
                    if _sqlite_table_exists(conn, "sources"):
                        conn.execute("DELETE FROM sources WHERE name = ?", (source_name,))
                    if source_type == "reddit" and _sqlite_table_exists(conn, "subreddits"):
                        conn.execute("DELETE FROM subreddits WHERE name = ?", (source_name,))
                conn.commit()
                app.logger.info(
                    "Deleted scraper data for %s/%s thread %s (no other boards reference it)",
                    source_type, source_name, source_thread_id,
                )
            finally:
                conn.close()
        except Exception:
            app.logger.exception(
                "Failed to delete scraper data for %s/%s thread %s",
                source_type, source_name, source_thread_id,
            )
    return orphaned_sources


def _board_tree(board):
    boards = []

    def _walk(current_board):
        boards.append(current_board)
        for child in list(getattr(current_board, "geo_children", []) or []):
            _walk(child)

    _walk(board)
    return boards


def _source_watermark_cards():
    return [source_watermark_summary(source_type) for source_type in SUPPORTED_SOURCE_TYPES]


def _delete_media_record(media_id):
    if media_id is None:
        return
    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if media is None:
        return
    try:
        media.delete_attachment()
    except Exception:
        app.logger.exception("Failed deleting watermark media attachment %s", media_id)
    db.session.delete(media)


def _watermark_upload_mimetype(uploaded_file) -> str:
    detected = (uploaded_file.content_type or "").strip().lower()
    if detected:
        return detected
    guessed, _encoding = mimetypes.guess_type(uploaded_file.filename or "")
    return (guessed or "").lower()


def _delete_board(board):
    boards = list(board) if isinstance(board, (list, tuple, set)) else _board_tree(board)
    board_ids = [current_board.id for current_board in boards if getattr(current_board, "id", None)]
    if not board_ids:
        return

    banner_rows = (
        db.session.query(BoardBanner.id, BoardBanner.media_id)
        .filter(BoardBanner.board_id.in_(board_ids))
        .all()
    )
    banner_media_ids = [media_id for _banner_id, media_id in banner_rows if media_id is not None]

    thread_ids = [
        thread_id
        for (thread_id,) in db.session.query(Thread.id).filter(Thread.board.in_(board_ids)).all()
    ]

    post_rows = []
    imported_media_ids = []
    if thread_ids:
        post_rows = (
            db.session.query(Post.id, Post.media)
            .filter(Post.thread.in_(thread_ids))
            .all()
        )
        imported_media_ids = [
            media_id
            for (media_id,) in (
                db.session.query(ImportedMedia.media_id)
                .filter(ImportedMedia.thread_id.in_(thread_ids))
                .all()
            )
            if media_id is not None
        ]

    post_ids = [post_id for post_id, _media_id in post_rows]
    media_ids = sorted(
        {
            media_id
            for _post_id, media_id in post_rows
            if media_id is not None
        }
        | set(imported_media_ids)
        | set(banner_media_ids)
    )

    if media_ids:
        for media in db.session.query(Media).filter(Media.id.in_(media_ids)).all():
            try:
                media.delete_attachment()
            except Exception:
                app.logger.exception("Failed deleting media attachment %s during board delete", media.id)

    db.session.query(BoardBan).filter(BoardBan.board_id.in_(board_ids)).delete(synchronize_session=False)
    db.session.query(BoardVisit).filter(BoardVisit.board_id.in_(board_ids)).delete(synchronize_session=False)
    db.session.query(SlipBoardModerator).filter(
        SlipBoardModerator.board_id.in_(board_ids)
    ).delete(synchronize_session=False)
    if post_ids:
        db.session.query(Reply).filter(
            or_(Reply.reply_from.in_(post_ids), Reply.reply_to.in_(post_ids))
        ).delete(synchronize_session=False)

    if thread_ids:
        db.session.execute(
            thread_tags.delete().where(thread_tags.c.thread_id.in_(thread_ids))
        )
        db.session.query(Post).filter(Post.thread.in_(thread_ids)).delete(synchronize_session=False)
        db.session.query(Poster).filter(Poster.thread.in_(thread_ids)).delete(synchronize_session=False)
        db.session.query(ImportedMedia).filter(
            ImportedMedia.thread_id.in_(thread_ids)
        ).delete(synchronize_session=False)
        db.session.query(Thread).filter(Thread.id.in_(thread_ids)).delete(synchronize_session=False)

    if banner_rows:
        db.session.query(BoardBanner).filter(BoardBanner.board_id.in_(board_ids)).delete(synchronize_session=False)

    if media_ids:
        db.session.query(ImageMagnet).filter(ImageMagnet.media_id.in_(media_ids)).delete(synchronize_session=False)
        db.session.query(Media).filter(Media.id.in_(media_ids)).delete(synchronize_session=False)

    for current_board in reversed(boards):
        db.session.delete(current_board)


@admin_blueprint.route("/login")
def login():
    if slip_is_admin():
        return redirect(url_for("admin.dashboard"))
    return render_template("admin-login.html")


@admin_blueprint.route("/logout")
def logout():
    from blueprints.slip import unset

    return unset()


@admin_blueprint.route("/wallet/challenge", methods=["POST"])
def wallet_challenge():
    return jsonify({
        "message": _wallet_challenge_message(),
    })


@admin_blueprint.route("/wallet/verify", methods=["POST"])
def wallet_verify():
    payload = request.get_json(force=True) or {}
    address = (payload.get("address") or "").strip().lower()
    signature = payload.get("signature")
    nonce = session.get(ADMIN_CHALLENGE_SESSION_KEY)
    issued_at = session.get(ADMIN_CHALLENGE_ISSUED_AT_KEY)
    if not nonce or not issued_at:
        return jsonify({"error": "No active login challenge"}), 400
    if (time.time() - issued_at) > ADMIN_CHALLENGE_TTL:
        session.pop(ADMIN_CHALLENGE_SESSION_KEY, None)
        session.pop(ADMIN_CHALLENGE_ISSUED_AT_KEY, None)
        return jsonify({"error": "Login challenge expired"}), 400

    expected_message = "\n".join((
        "%s admin authentication" % app.config.get("INSTANCE_NAME", "Syndichan"),
        "Wallet: %s" % configured_admin_wallet_address(),
        "Nonce: %s" % nonce,
        "Issued At: %s" % _datetime.datetime.utcfromtimestamp(issued_at).isoformat() + "Z",
        "Only sign this message if you intend to unlock the admin dashboard.",
    ))

    if address != configured_admin_wallet_address():
        return jsonify({"error": "Unauthorized wallet address"}), 403

    try:
        verification = _verify_signature_with_renderer(address, expected_message, signature)
    except Exception:
        app.logger.exception("Admin wallet verification failed")
        return jsonify({"error": "Wallet verification failed"}), 502

    if verification.get("valid") is not True:
        return jsonify({"error": "Invalid wallet signature"}), 403

    try:
        begin_wallet_admin_session(address)
        db.session.commit()
    except Exception as error:
        db.session.rollback()
        app.logger.exception("Admin wallet session creation failed")
        # The exception TEXT is returned, not just "check server logs".
        #
        # That is a deliberate exception to the usual rule about not leaking
        # internals, and it is safe HERE specifically: control only reaches this
        # line after the signature verified AND the recovered address matched
        # the configured admin wallet, so the caller has already proved by
        # signature that they are the operator. There is nobody else to leak to.
        #
        # It is here because "check server logs" is useless advice to an
        # operator whose only way in is this page: the logs are behind the
        # dashboard they cannot reach, and on a hosted deployment they may need
        # cluster access to read at all. The failure this most often hides is a
        # missing table or column -- bootstrap.py stamps alembic at head after
        # create_all(), so a model not imported at that moment gets a table no
        # migration ever creates -- and the exception names it in one line.
        return jsonify({
            "error": "Session creation failed: %s: %s" % (type(error).__name__, error),
        }), 500
    session.pop(ADMIN_CHALLENGE_SESSION_KEY, None)
    session.pop(ADMIN_CHALLENGE_ISSUED_AT_KEY, None)
    return jsonify({"ok": True, "redirect": url_for("admin.dashboard")})


@admin_blueprint.route("/")
@_admin_required
def dashboard():
    board_defaults = {
        "name": "",
        "display_name": "",
        "rules": "",
        "max_threads": 100,
        "mimetypes": "image/jpeg|image/png|image/gif|image/webp|video/webm",
        "is_private": False,
        "board_type": "standard",
        "geo_strategy": "city",
        "geo_radius_miles": 50,
    }
    boards = db.session.query(Board).order_by(Board.name.asc()).all()
    bans = db.session.query(Ban).order_by(Ban.created_at.desc(), Ban.id.desc()).all()
    from model.ShadowBan import list_shadowbans
    shadowbans = list_shadowbans()
    from model.BanPageAsset import (
        BAN_PAGE_FEATURES as _BAN_PAGE_FEATURES,
        enabled_ban_page_features as _enabled_ban_page_features,
        ban_page_customization as _ban_page_customization,
    )
    from services.shadowban_cleanup import shadowban_delete_days as _shadowban_delete_days
    from services.thread_flush import unviewed_delete_days as _thread_unviewed_days
    from services.scraped_thread_retire import (
        retire_days as _scraped_retire_days,
        retire_failure_threshold as _scraped_retire_failures,
    )
    word_filters = db.session.query(WordFilter).order_by(WordFilter.id.asc()).all()
    board_names = {board.id: board.name for board in boards}
    captcha_challenges = (
        db.session.query(CaptchaChallenge)
        .order_by(CaptchaChallenge.created_at.asc(), CaptchaChallenge.id.asc())
        .all()
    )
    from model.Federation import pending_chan_requests

    # The delivery wallet pays gas for every automatic token delivery. When it
    # runs dry nothing errors loudly: the delivery fails, the purchase quietly
    # stays queued, and the first sign is a customer asking where their tokens
    # are. Surfaced here so it is noticed as a warning rather than as a
    # complaint. Best-effort — a chain that cannot be read must not take the
    # whole dashboard down with it.
    try:
        from services import token_delivery
        delivery_gas = token_delivery.gas_status()
    except Exception:
        delivery_gas = {"configured": True, "unknown": True,
                        "reason": "could not be checked"}

    return render_template(
        "admin-dashboard.html",
        delivery_gas=delivery_gas,
        chan_requests=pending_chan_requests(limit=100),
        captcha_challenges=captcha_challenges,
        captcha_questions_per_challenge=QUESTIONS_PER_CHALLENGE,
        board_inactivity_days=inactivity_delete_days(),
        video_inactivity_days=_video_inactivity_delete_days(),
        aggregator_retention_days=int(get_setting("aggregator_retention_days", "7") or "7"),
        # The two age clocks for scraped content. Read through the service so
        # the admin form shows the value actually in force (clamped, defaulted)
        # rather than the raw setting string.
        scraped_max_age_hours=_scraped_max_age_hours(),
        scraped_metadata_days=_scraped_metadata_days(),
        **_nsfw_ctx(),
        video_allowed_mimetypes=get_setting("video_allowed_mimetypes", ""),
        board_default_mimetypes=get_setting("board_default_mimetypes", DEFAULT_BOARD_MIMETYPES),
        admin_wallet_address=configured_admin_wallet_address(),
        front_page_html=current_front_page_html(),
        front_page_updates=recent_front_page_updates(limit=25),
        ban_page_assets=ban_page_assets(),
        ban_asset_kinds=BAN_ASSET_KINDS,
        ban_page_features=_BAN_PAGE_FEATURES,
        ban_page_enabled_features=_enabled_ban_page_features(),
        ban_page_custom=_ban_page_customization(),
        ban_page_theme_choices=sorted(app.config.get("THEME_LIST") or ["stock", "harajuku", "wildride", "midnight", "cyberpunk", "711chan"]),
        warrant_canary=warrant_canary_config(),
        warrant_canary_statuses=WC_STATUSES,
        warrant_canary_themes=WC_THEMES,
        boards=boards,
        slips=_editable_slips(),
        bans=bans,
        shadowbans=shadowbans,
        shadowban_delete_days=_shadowban_delete_days(),
        thread_unviewed_days=_thread_unviewed_days(),
        scraped_retire_days=_scraped_retire_days(),
        scraped_retire_failures=_scraped_retire_failures(),
        recent_posts=_recent_posts(),
        blocked_media_hashes=_blocked_media_hash_rows(),
        board_defaults=board_defaults,
        empty_source_config="",
        format_source_config=format_source_config,
        source_watermarks=_source_watermark_cards(),
        word_filters=word_filters,
        word_filter_board_names=board_names,
        nntp_peers=_nntp_list_peers(),
        nntp_group_maps=_nntp_list_group_maps(),
        nntp_address_blocks=_nntp_list_address_blocks(),
        nntp_sync_interval_minutes=_nntp_sync_interval_minutes(),
        nntp_fingerprints=_nntp_list_fingerprints(),
        nntp_fp_settings=_nntp_fingerprint_settings(),
        nntp_publish_content=_nntp_publish_content_enabled(),
        nntp_source_label=get_setting("nntpchan_source_label", ""),
        nntp_source_watermark_url=get_setting("nntpchan_source_watermark_url", ""),
        nntp_require_watermark=str(get_setting("nntpchan_require_watermark", "0")).strip().lower() not in ("", "0", "false", "no", "off"),
        nntp_tombstone_days=get_setting("nntpchan_tombstone_days", "30"),
        nntp_hub_admin_token_set=bool((get_setting("nntpchan_hub_admin_token", "") or "").strip()),
        nntp_preflight=_nntp_preflight(),
        falco=_falco_dashboard_state(),
    )


# ===== Falco runtime security (falcosecurity/falco) =====
# Falco (the privileged container) OWNS detection; these routes are maniwani's
# control surface over the ingested alerts: view/filter/ack/delete, tune what is
# stored (enable, min severity, retention), and mute noisy rules at ingest.
def _falco_dashboard_state():
    """Settings + status for the #falco card. Defensive: a missing table or a
    transient DB error must never break the whole dashboard."""
    default_priorities = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"]
    token_set = bool((os.environ.get("FALCO_INGEST_TOKEN") or "").strip())
    try:
        from model.FalcoAlert import (
            ingest_enabled, min_priority, retention_days, muted_rules,
            PRIORITY_ORDER, unacknowledged_count,
        )
        return {
            "enabled": ingest_enabled(),
            "min_priority": min_priority(),
            "retention_days": retention_days(),
            "muted_rules": muted_rules(),
            "priorities": PRIORITY_ORDER,
            "token_set": token_set,
            "last_alert_at": get_setting("falco_last_alert_at", ""),
            "last_ingest_at": get_setting("falco_last_ingest_at", ""),
            "unacknowledged": unacknowledged_count(),
        }
    except Exception:
        db.session.rollback()
        return {
            "enabled": True, "min_priority": "notice", "retention_days": 14,
            "muted_rules": [], "priorities": default_priorities, "token_set": token_set,
            "last_alert_at": "", "last_ingest_at": "", "unacknowledged": 0,
        }


@admin_blueprint.route("/falco/alerts.json")
@_admin_required
def falco_alerts_json():
    from model.FalcoAlert import (
        recent_alerts, counts_by_priority, unacknowledged_count, top_containers, purge_expired,
    )
    try:
        purge_expired()
        db.session.commit()
    except Exception:
        db.session.rollback()
    priority = (request.args.get("priority") or "").strip() or None
    container = (request.args.get("container") or "").strip() or None
    unacked = (request.args.get("unacked") or "").strip().lower() in ("1", "true", "yes", "on")
    try:
        limit = int(request.args.get("limit") or 100)
    except (TypeError, ValueError):
        limit = 100
    alerts = recent_alerts(limit=limit, priority=priority, container=container, unacked_only=unacked)
    return jsonify({
        "alerts": [a.as_dict() for a in alerts],
        "counts": counts_by_priority(days=7),
        "unacknowledged": unacknowledged_count(),
        "top_containers": top_containers(),
        "last_ingest_at": get_setting("falco_last_ingest_at", ""),
        "last_alert_at": get_setting("falco_last_alert_at", ""),
    })


@admin_blueprint.route("/scrapers/pause", methods=["POST"])
@_admin_required
def scrapers_set_paused():
    """Stop or resume ALL scraping.

    Exists so the database can be maintained or cleared without new content
    arriving mid-operation -- a purge racing an active crawl re-imports what it
    just deleted. Takes effect on the next sync tick (<= 60s) with no restart,
    since a pause that needs a rollout is useless for the case it exists for.
    """
    from services.aggregator_sync.state import SCRAPING_PAUSED_SETTING

    paused = bool(request.form.get("paused"))
    set_setting(SCRAPING_PAUSED_SETTING, "1" if paused else "0")
    db.session.commit()
    app.logger.warning(
        "admin: scraping %s by operator", "PAUSED" if paused else "RESUMED"
    )
    flash(
        "All scraping paused. Nothing new will be imported until you resume."
        if paused else
        "Scraping resumed."
    )
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/scrapers/purge-all", methods=["POST"])
@_admin_required
@csrf_protect
def scrapers_purge_all_content():
    """Delete ALL imported content, keeping the import configuration.

    What survives is deliberately narrow: BoardSource rows (which site/board
    feeds which local board) and the boards themselves, so crawling resumes into
    the same places afterwards. Everything those sources produced is removed.

    Requires scraping to be PAUSED first. Purging while crawlers run re-imports
    what was just deleted and the operation never converges -- so this refuses
    rather than appearing to work.
    """
    from services.aggregator_sync.state import scraping_paused
    from services.source_purge import purge_source

    if not scraping_paused():
        flash("Pause scraping first - a purge while crawlers run re-imports what it deletes.")
        return redirect(url_for("admin.dashboard"))
    if (request.form.get("confirm") or "").strip().upper() != "DELETE":
        flash("Type DELETE to confirm the purge.")
        return redirect(url_for("admin.dashboard"))

    rows = db.session.execute(db.text(
        "SELECT DISTINCT source_type FROM thread "
        "WHERE source_type IS NOT NULL AND source_type <> 'local'"
    )).fetchall()
    threads = media = 0
    failures = []
    for (source_type,) in rows:
        try:
            # remove_sources=False is the whole point: the mapping of remote
            # board -> local board is the configuration being preserved.
            result = purge_source(source_type, remove_sources=False)
            # Keys are threads/media/sources/skipped -- NOT deleted_*; reading
            # the wrong names reported 0 purged even on a successful run.
            threads += result.get("threads", 0) or 0
            media += result.get("media", 0) or 0
        except Exception:
            db.session.rollback()
            app.logger.exception("purge-all: failed for %s", source_type)
            failures.append(source_type)
    app.logger.warning(
        "admin: purge-all removed %d thread(s), %d media mapping(s)", threads, media
    )
    flash("Purged %d imported thread(s) and %d media mapping(s). Import configuration kept.%s"
          % (threads, media, (" Failed: " + ", ".join(failures)) if failures else ""))
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/falco/settings", methods=["POST"])
@_admin_required
def falco_save_settings():
    from model.FalcoAlert import (
        INGEST_ENABLED_SETTING, MIN_PRIORITY_SETTING, RETENTION_DAYS_SETTING, PRIORITY_RANK,
    )
    set_setting(INGEST_ENABLED_SETTING, "1" if request.form.get("ingest_enabled") else "0")
    prio = (request.form.get("min_priority") or "").strip().lower()
    if prio in PRIORITY_RANK:
        set_setting(MIN_PRIORITY_SETTING, prio)
    days = (request.form.get("retention_days") or "").strip()
    if days.isdigit():
        set_setting(RETENTION_DAYS_SETTING, str(int(days)))
    db.session.commit()
    flash("Falco settings saved.")
    return redirect(url_for("admin.dashboard") + "#falco")


@admin_blueprint.route("/falco/mute", methods=["POST"])
@_admin_required
def falco_mute():
    from model.FalcoAlert import mute_rule, unmute_rule
    rule = (request.form.get("rule") or "").strip()
    if (request.form.get("action") or "").strip().lower() == "unmute":
        unmute_rule(rule)
    elif rule:
        mute_rule(rule)
    db.session.commit()
    flash("Updated Falco rule mutes.")
    return redirect(url_for("admin.dashboard") + "#falco")


@admin_blueprint.route("/falco/alerts/<int:alert_id>/ack", methods=["POST"])
@_admin_required
def falco_ack(alert_id):
    from model.FalcoAlert import acknowledge
    acknowledge(alert_id, True)
    return ("", 204)


@admin_blueprint.route("/falco/alerts/<int:alert_id>/delete", methods=["POST"])
@_admin_required
def falco_delete_alert(alert_id):
    from model.FalcoAlert import delete_alert
    delete_alert(alert_id)
    return ("", 204)


@admin_blueprint.route("/falco/ack-all", methods=["POST"])
@_admin_required
def falco_ack_all():
    from model.FalcoAlert import acknowledge_all
    acknowledge_all()
    flash("Acknowledged all Falco alerts.")
    return redirect(url_for("admin.dashboard") + "#falco")


@admin_blueprint.route("/chan-requests/<int:request_id>/apply", methods=["POST"])
@_admin_required
def chan_request_apply(request_id):
    """Apply an operator's add/remove request to the aggregated-chans list."""
    from model.Federation import apply_chan_request
    apply_chan_request(request_id)
    flash("Applied the chan request to the aggregation list.")
    return redirect(url_for("admin.dashboard") + "#chan-requests")


@admin_blueprint.route("/chan-requests/<int:request_id>/dismiss", methods=["POST"])
@_admin_required
def chan_request_dismiss(request_id):
    from model.Federation import dismiss_chan_request
    dismiss_chan_request(request_id)
    flash("Dismissed the chan request.")
    return redirect(url_for("admin.dashboard") + "#chan-requests")


def _push_aggregator_retention(days: int) -> dict:
    """Push the retention window to every aggregator so each prunes to the new
    value on its next cycle. Best-effort.

    reddit-aggregator is a separate codebase but now implements the same
    POST /settings/retention contract, so it is included.
    """
    import os

    # ONE crawler. The per-site containers were collapsed into it, so the
    # retention setting has one destination instead of four.
    #
    # The legacy variables are still consulted so a deployment that has not
    # applied the new manifests keeps working, and so the same URL appearing
    # under several names is written ONCE — otherwise this posts the same
    # setting to the same container four times and reports four results, which
    # reads as four scrapers still existing.
    targets = {}
    generic = os.environ.get("GENERIC_AGGREGATOR_URL")
    for name, variable in (("4chan", "FOURCHAN_AGGREGATOR_URL"),
                           ("8chan", "EIGHTCHAN_AGGREGATOR_URL"),
                           ("7chan", "SEVENCHAN_AGGREGATOR_URL"),
                           ("reddit", "REDDIT_AGGREGATOR_URL")):
        targets[name] = os.environ.get(variable) or generic
    targets["generic"] = generic
    seen = set()
    for name in list(targets):
        url = (targets[name] or "").rstrip("/")
        if not url or url in seen:
            targets.pop(name)
            continue
        seen.add(url)
    results = {}
    for name, url in targets.items():
        if not url:
            continue
        try:
            resp = requests.post(url.rstrip("/") + "/settings/retention", json={"days": days}, timeout=5)
            results[name] = bool(resp.ok)
        except Exception:
            results[name] = False
    return results


@admin_blueprint.route("/storage-offload/status.json")
@_admin_required
def storage_offload_status():
    """Offload progress plus the used-vs-available figures for the chart."""
    from services.storage_offload import progress
    from services.storage_usage import summary

    payload = progress()
    # force=1 bypasses the hourly memo; the chart polls with it off.
    payload["storage"] = summary(force=bool(request.args.get("force")))
    return jsonify(payload)


@admin_blueprint.route("/storage-offload/run", methods=["POST"])
@_admin_required
def storage_offload_run():
    """Offload one batch now. Deliberately batched rather than 'migrate
    everything': each object is a full read from the primary store plus an encrypted,
    erasure-coded write, and an unbounded loop inside a request would hold a
    worker (and its DB transaction) for hours."""
    from services.storage_offload import offload_batch

    try:
        size = max(1, min(500, int(request.form.get("batch") or 25)))
    except ValueError:
        size = 25
    result = offload_batch(limit=size)
    if not result.get("enabled"):
        flash("Storage offload is not configured (DHT_S3_ENDPOINT is unset).")
    else:
        message = "Offloaded %d of %d examined." % (result["offloaded"], result["examined"])
        if result.get("failed"):
            message += " %d failed: %s." % (
                result["failed"],
                ", ".join("%s x%d" % (k, v) for k, v in sorted(result["reasons"].items())),
            )
        flash(message)
    return redirect(url_for("admin.dashboard") + "#storage-offload")


@admin_blueprint.route("/scraped-retention", methods=["POST"])
@_admin_required
def save_scraped_retention():
    """The two retention clocks: how far back we keep scraped CONTENT, and how
    long the identity METADATA outlives it. See services/scraped_retention.py."""
    from services.scraped_retention import (
        MAX_AGE_SETTING, METADATA_SETTING,
        DEFAULT_MAX_AGE_HOURS, DEFAULT_METADATA_DAYS,
    )

    def _parse(field, default, lo, hi, label):
        raw = (request.form.get(field) or "").strip()
        if not raw:
            return default, None
        try:
            value = int(float(raw))
        except ValueError:
            return None, "Enter a whole number for %s." % label
        if value <= 0:
            return 0, None                      # explicit "disabled"
        return max(lo, min(hi, value)), None

    hours, err = _parse("max-age-hours", DEFAULT_MAX_AGE_HOURS, 1, 24 * 365, "the scrape window")
    if err:
        flash(err)
        return redirect(url_for("admin.dashboard") + "#scraped-retention")
    days, err = _parse("metadata-days", DEFAULT_METADATA_DAYS, 1, 3650, "metadata retention")
    if err:
        flash(err)
        return redirect(url_for("admin.dashboard") + "#scraped-retention")

    set_setting(MAX_AGE_SETTING, str(hours))
    set_setting(METADATA_SETTING, str(days))
    db.session.commit()

    window = ("%d hour(s)" % hours) if hours else "unlimited (age purging disabled)"
    keep = ("%d day(s)" % days) if days else "forever"
    flash("Scrape window set to %s; purged-thread metadata kept for %s." % (window, keep))
    return redirect(url_for("admin.dashboard") + "#scraped-retention")


@admin_blueprint.route("/scraped-retention/preview.json")
@_admin_required
def scraped_retention_preview():
    """What a sweep would purge right now. Read-only -- the card shows this
    before the operator commits to anything."""
    from services.scraped_retention_sweep import preview
    return jsonify(preview())


@admin_blueprint.route("/scraped-retention/run", methods=["POST"])
@_admin_required
def scraped_retention_run():
    """Run the retention sweep now instead of waiting for the timer."""
    from services.scraped_retention_sweep import sweep
    result = sweep()
    flash(
        "Retention sweep: purged %d thread(s) and %d media, kept %d with local replies, "
        "expired %d metadata stub(s)."
        % (result.get("purged", 0), result.get("media_deleted", 0),
           result.get("kept_local_replies", 0), result.get("stubs_expired", 0))
    )
    return redirect(url_for("admin.dashboard") + "#scraped-retention")


@admin_blueprint.route("/aggregator-retention", methods=["POST"])
@_admin_required
def save_aggregator_retention():
    """Set how many days of scraped remote content the aggregators keep, and push
    it to each crawler live."""
    raw = (request.form.get("aggregator-retention-days") or "").strip()
    try:
        days = int(raw)
    except ValueError:
        flash("Enter a whole number of days.")
        return redirect(url_for("admin.dashboard") + "#aggregator-retention")
    days = max(0, min(days, 3650))
    set_setting("aggregator_retention_days", str(days))
    # Commit before pushing: set_setting() does not commit, and a transaction must
    # not stay open across the crawler HTTP calls below.
    db.session.commit()
    results = _push_aggregator_retention(days)
    applied = sorted(n for n, ok in results.items() if ok)
    unreached = sorted(n for n, ok in results.items() if not ok)
    window = ("%d days" % days) if days else "unlimited (pruning disabled)"
    message = "Aggregator retention set to %s." % window
    if applied:
        message += " Applied live to: %s." % ", ".join(applied)
    if unreached:
        message += " Could not reach %s — save again once it's back up." % ", ".join(unreached)
    flash(message)
    return redirect(url_for("admin.dashboard") + "#aggregator-retention")


@admin_blueprint.route("/nsfw-filter", methods=["POST"])
@_admin_required
def save_nsfw_filter():
    """Threshold and policy for the open_nsfw image filter."""
    from services import nsfw as nsfw_service

    raw = (request.form.get("nsfw-threshold") or "").strip()
    try:
        threshold = float(raw)
    except ValueError:
        flash("Enter the NSFW threshold as a number between 0 and 1.")
        return redirect(url_for("admin.dashboard") + "#nsfw-filter")
    if not 0.0 <= threshold <= 1.0:
        flash("The NSFW threshold must be between 0 and 1.")
        return redirect(url_for("admin.dashboard") + "#nsfw-filter")

    applied = nsfw_service.set_threshold(threshold)
    nsfw_service.set_enabled(bool(request.form.get("nsfw-enabled")))
    nsfw_service.set_fail_closed(bool(request.form.get("nsfw-fail-closed")))
    nsfw_service.set_scan_video(bool(request.form.get("nsfw-scan-video")))
    raw_timeout = (request.form.get("nsfw-timeout") or "").strip()
    if raw_timeout:
        try:
            nsfw_service.set_timeout_seconds(float(raw_timeout))
        except ValueError:
            flash("Ignored the timeout: enter it as a number of seconds.")
    db.session.commit()
    flash(
        "NSFW filter %s, rejecting images scoring %.2f or higher. Classifier %s."
        % (
            "enabled" if nsfw_service.is_enabled() else "disabled",
            applied,
            "unavailable — uploads are blocked" if nsfw_service.fail_closed()
            else "unavailable — uploads are allowed through",
        )
    )
    return redirect(url_for("admin.dashboard") + "#nsfw-filter")


@admin_blueprint.route("/nsfw-filter/selftest")
@_admin_required
def nsfw_selftest():
    """Score generated images so an operator can confirm the model is working."""
    from services import nsfw as nsfw_service
    ok, detail = nsfw_service.health()
    return jsonify({
        "ok": ok,
        "detail": detail,
        "threshold": nsfw_service.threshold(),
        "enabled": nsfw_service.is_enabled(),
        "fail_closed": nsfw_service.fail_closed(),
        "url": nsfw_service.classifier_url(),
        "scores": nsfw_service.selftest(),
    })


@admin_blueprint.route("/spam-blocklist")
@_admin_required
def spam_blocklist():
    """Manage the spam URL blocklist enforced on every post submission."""
    from model.UrlBlocklist import (
        UrlBlocklistEntry, autoban_duration, autoban_enabled, entry_count, entry_form,
    )
    from model.Ban import BAN_DURATION_CHOICES
    query = (request.args.get("q") or "").strip()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 100
    base = db.session.query(UrlBlocklistEntry)
    if query:
        base = base.filter(UrlBlocklistEntry.pattern.ilike("%%%s%%" % query))
    total = base.with_entities(db.func.count(UrlBlocklistEntry.id)).scalar() or 0
    entries = (
        base.order_by(UrlBlocklistEntry.hit_count.desc(), UrlBlocklistEntry.pattern.asc())
        .limit(per_page)
        .offset((page - 1) * per_page)
        .all()
    )
    return render_template(
        "admin-spam-blocklist.html",
        entries=entries,
        entry_form=entry_form,
        query=query,
        page=page,
        per_page=per_page,
        total=total,
        pages=max(1, (total + per_page - 1) // per_page),
        enabled_count=entry_count(enabled_only=True),
        all_count=entry_count(enabled_only=False),
        autoban=autoban_enabled(),
        autoban_duration=autoban_duration(),
        duration_choices=BAN_DURATION_CHOICES,
    )


@admin_blueprint.route("/spam-blocklist/add", methods=["POST"])
@_admin_required
def spam_blocklist_add():
    from model.UrlBlocklist import add_entries_bulk, add_entry
    raw = request.form.get("pattern") or ""
    bulk = request.form.get("bulk") or ""
    upload = request.files.get("bulk-file")
    if upload is not None and upload.filename:
        try:
            bulk = "\n".join(
                (bulk, upload.read().decode("utf-8", errors="replace"))
            )
        except Exception:
            flash("Could not read that file.")
            return redirect(url_for("admin.spam_blocklist"))

    if bulk.strip():
        try:
            summary = add_entries_bulk(bulk, note="imported by admin")
        except Exception:
            db.session.rollback()
            app.logger.exception("bulk blocklist import failed")
            flash("Import failed — nothing was changed.")
            return redirect(url_for("admin.spam_blocklist"))
        message = "Imported %d blocklist entr%s." % (
            summary["added"], "y" if summary["added"] == 1 else "ies")
        if summary["duplicates"]:
            message += " Skipped %d already present." % summary["duplicates"]
        if summary["exempt"]:
            message += (
                " Skipped %d that would have blocked a site we aggregate (%s%s)."
                % (len(summary["exempt"]), ", ".join(summary["exempt"][:5]),
                   ", ..." if len(summary["exempt"]) > 5 else "")
            )
        if summary["errors"]:
            message += " %d line(s) could not be parsed." % len(summary["errors"])
        flash(message)
        return redirect(url_for("admin.spam_blocklist"))

    if not raw.strip():
        flash("Enter a URL, domain, token or /regex/ to block.")
        return redirect(url_for("admin.spam_blocklist"))
    try:
        entry = add_entry(raw, note=request.form.get("note") or "added by admin")
    except ValueError as error:
        flash(str(error))
        return redirect(url_for("admin.spam_blocklist"))
    except Exception:
        db.session.rollback()
        app.logger.exception("blocklist add failed")
        flash("Could not add that entry.")
        return redirect(url_for("admin.spam_blocklist"))
    flash("Blocking %s." % entry.pattern)
    return redirect(url_for("admin.spam_blocklist"))


@admin_blueprint.route("/spam-blocklist/<int:entry_id>/remove", methods=["POST"])
@_admin_required
def spam_blocklist_remove(entry_id):
    from model.UrlBlocklist import remove_entry
    flash("Removed from the blocklist." if remove_entry(entry_id) else "That entry no longer exists.")
    return redirect(url_for("admin.spam_blocklist", q=request.form.get("q") or None))


@admin_blueprint.route("/spam-blocklist/<int:entry_id>/toggle", methods=["POST"])
@_admin_required
def spam_blocklist_toggle(entry_id):
    from model.UrlBlocklist import set_entry_enabled
    enabled = (request.form.get("enabled") or "") == "1"
    set_entry_enabled(entry_id, enabled)
    flash("Entry %s." % ("enabled" if enabled else "disabled"))
    return redirect(url_for("admin.spam_blocklist", q=request.form.get("q") or None))


@admin_blueprint.route("/spam-blocklist/settings", methods=["POST"])
@_admin_required
def spam_blocklist_settings():
    from model.UrlBlocklist import set_autoban_duration, set_autoban_enabled
    enabled = bool(request.form.get("autoban"))
    set_autoban_enabled(enabled)
    set_autoban_duration(request.form.get("autoban-duration") or "")
    db.session.commit()
    flash(
        "Blocklist hits now also ban the poster's IP."
        if enabled else
        "Blocklist hits reject the post only (no IP ban)."
    )
    return redirect(url_for("admin.spam_blocklist"))




@admin_blueprint.route("/scraped/<int:thread_id>/flag", methods=["POST"])
@_admin_required
def flag_scraped_thread(thread_id):
    from model.SourceModeration import host_of, record_strike, STRIKES_PER_BAN
    thread = db.session.query(Thread).filter(Thread.id == thread_id).one_or_none()
    if thread is None or thread.source_type == "local":
        flash("No such scraped thread.")
        return redirect(url_for("admin.dashboard"))
    host = host_of(thread.source_url)
    if not host:
        flash("This thread has no source host, so it can't be attributed to a site.")
        return redirect(url_for("admin.dashboard"))
    status = record_strike(
        host, source_url=thread.source_url,
        reason=(request.form.get("reason") or "flagged as illegal content via admin"),
    )
    # Remove the offending imported thread from display when it carries no local
    # user replies (deleting an imported thread only ever drops local Post rows).
    removed = False
    remove_failed = False
    local_posts = db.session.query(Post.id).filter(Post.thread == thread.id, Post.source_type == "local").count()
    if local_posts == 0:
        try:
            # services.aggregator_sync.media, NOT aggregator_sync.media:
            # backend/aggregator_sync.py is a flat compatibility MODULE, not a
            # package, so `from aggregator_sync.media import ...` raises
            # ModuleNotFoundError. The bare except below swallowed it, so
            # flagging illegal content recorded the strike, reported success and
            # left the thread on the site — with an empty tail, since local_posts
            # is 0 in this branch. Never let this failure be invisible again.
            from services.aggregator_sync.media import delete_thread
            delete_thread(thread)
            removed = True
        except Exception:
            remove_failed = True
            app.logger.exception("flag_scraped_thread: could not delete thread %s", thread_id)
    if status.get("permanent"):
        verdict = "%s is now PERMANENTLY banned from aggregation." % host
    elif status.get("active") and status.get("banned_until"):
        verdict = "%s is banned from aggregation until %s UTC." % (host, status["banned_until"].strftime("%Y-%m-%d"))
    else:
        verdict = "%s now has %d of %d strikes toward a ban." % (host, status.get("strikes", 0), STRIKES_PER_BAN)
    if removed:
        tail = " Thread removed."
    elif remove_failed:
        tail = " WARNING: the thread could NOT be removed — it is still visible. Check the logs."
    elif local_posts:
        tail = " (thread kept — it has local replies)"
    else:
        tail = ""
    flash("Strike recorded. %s%s" % (verdict, tail))
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/scraped/lift", methods=["POST"])
@_admin_required
def lift_source_ban():
    from model.SourceModeration import lift_ban
    host = (request.form.get("host") or "").strip()
    flash("Cleared all strikes and bans for %s." % host if lift_ban(host) else "No moderation record for %s." % host)
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/falco/clear", methods=["POST"])
@_admin_required
def falco_clear():
    from model.FalcoAlert import clear_alerts
    clear_alerts()
    flash("Cleared all Falco alerts.")
    return redirect(url_for("admin.dashboard") + "#falco")


@admin_blueprint.route("/front-page-updates", methods=["POST"])
@_admin_required
def create_front_page_update_route():
    slip = get_slip()
    update = create_front_page_update(
        request.form.get("title"),
        request.form.get("body"),
        created_by_slip_id=(slip.id if slip else None),
    )
    if update is None:
        flash("An update needs some body text.")
    else:
        db.session.commit()
        invalidate_front_page_cache()
        flash("Front page update posted.")
    return redirect(url_for("admin.dashboard") + "#front-page-updates")


@admin_blueprint.route("/front-page-updates/<int:update_id>/delete", methods=["POST"])
@_admin_required
def delete_front_page_update_route(update_id):
    if delete_front_page_update(update_id):
        db.session.commit()
        invalidate_front_page_cache()
        flash("Front page update removed.")
    return redirect(url_for("admin.dashboard") + "#front-page-updates")


@admin_blueprint.route("/ban-page/assets", methods=["POST"])
@_admin_required
def add_ban_page_asset_route():
    if add_ban_page_asset(request.form.get("kind"), request.form.get("value")) is None:
        flash("Choose a type and enter a URL (or message text).")
    else:
        db.session.commit()
        flash("Ban-page item added.")
    return redirect(url_for("admin.dashboard") + "#ban-page")


@admin_blueprint.route("/ban-page/assets/<int:asset_id>/delete", methods=["POST"])
@_admin_required
def delete_ban_page_asset_route(asset_id):
    if delete_ban_page_asset(asset_id):
        db.session.commit()
        flash("Ban-page item removed.")
    return redirect(url_for("admin.dashboard") + "#ban-page")


@admin_blueprint.route("/ban-page/settings", methods=["POST"])
@_admin_required
def save_ban_page_settings():
    from model.BanPageAsset import (
        BAN_PAGE_FEATURE_KEYS,
        set_ban_page_features,
        save_ban_page_customization,
    )
    selected = [k for k in request.form.getlist("features") if k in BAN_PAGE_FEATURE_KEYS]
    set_ban_page_features(selected)
    save_ban_page_customization(
        theme=request.form.get("theme", ""),
        custom_css=request.form.get("custom_css", ""),
        custom_html=request.form.get("custom_html", ""),
        custom_js=request.form.get("custom_js", ""),
    )
    db.session.commit()
    flash("Ban page settings saved.")
    return redirect(url_for("admin.dashboard") + "#ban-page")


@admin_blueprint.route("/warrant-canary", methods=["POST"])
@_admin_required
def save_warrant_canary():
    f = request.form
    status = (f.get("wc_status") or "active").strip().lower()
    theme = (f.get("wc_theme") or "auto").strip().lower()
    set_setting(_wc.K_ENABLED, "1" if f.get("wc_enabled") == "on" else "0")
    set_setting(_wc.K_STATUS, status if status in WC_STATUSES else "active")
    set_setting(_wc.K_THEME, theme if theme in WC_THEMES else "auto")
    set_setting(_wc.K_TITLE, (f.get("wc_title") or "").strip()[:120] or "Warrant Canary")
    set_setting(_wc.K_STATEMENT, (f.get("wc_statement") or "").strip())
    set_setting(_wc.K_LAST_UPDATED, (f.get("wc_last_updated") or "").strip()[:32])
    set_setting(_wc.K_NEXT_UPDATE, (f.get("wc_next_update") or "").strip()[:32])
    set_setting(_wc.K_SHOW_NEXT, "1" if f.get("wc_show_next_update") == "on" else "0")
    set_setting(_wc.K_SHOW_HISTORY, "1" if f.get("wc_show_history") == "on" else "0")
    set_setting(_wc.K_ACTIVE_LABEL, (f.get("wc_active_label") or "Active").strip()[:32] or "Active")
    db.session.commit()
    invalidate_front_page_cache()
    flash("Warrant Canary updated.")
    return redirect(url_for("admin.dashboard") + "#warrant-canary")


@admin_blueprint.route("/warrant-canary/history", methods=["POST"])
@_admin_required
def add_warrant_canary_history():
    if add_warrant_canary_entry(request.form.get("date"), request.form.get("status")) is None:
        flash("A history entry needs a date and a status.")
    else:
        db.session.commit()
        invalidate_front_page_cache()
        flash("Verification entry added.")
    return redirect(url_for("admin.dashboard") + "#warrant-canary")


@admin_blueprint.route("/warrant-canary/history/<int:entry_id>/delete", methods=["POST"])
@_admin_required
def delete_warrant_canary_history(entry_id):
    if delete_warrant_canary_entry(entry_id):
        db.session.commit()
        invalidate_front_page_cache()
        flash("Verification entry removed.")
    return redirect(url_for("admin.dashboard") + "#warrant-canary")


@admin_blueprint.route("/wordfilters", methods=["POST"])
@_admin_required
def create_site_word_filter():
    scope = (request.form.get("scope") or "boards").strip().lower()
    is_global = scope == "all"
    raw_board_ids = [value for value in request.form.getlist("board-ids") if value]
    try:
        requested_board_ids = {int(value) for value in raw_board_ids}
    except ValueError:
        flash("Select valid boards for the wordfilter.")
        return redirect(url_for("admin.dashboard") + "#wordfilters")
    board_ids = {
        board_id
        for (board_id,) in db.session.query(Board.id).filter(Board.id.in_(requested_board_ids)).all()
    } if requested_board_ids else set()
    if not is_global and board_ids != requested_board_ids:
        flash("One or more selected boards no longer exist.")
        return redirect(url_for("admin.dashboard") + "#wordfilters")
    slip = get_slip()
    try:
        create_word_filter(
            pattern=request.form.get("pattern"),
            replacement=request.form.get("replacement"),
            board_ids=board_ids,
            is_global=is_global,
            case_sensitive=bool(request.form.get("case-sensitive")),
            whole_word=bool(request.form.get("whole-word")),
            creator_slip_id=slip.id if slip else None,
            created_by_sysop=True,
        )
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
        return redirect(url_for("admin.dashboard") + "#wordfilters")
    flash("Created the sysop wordfilter.")
    return redirect(url_for("admin.dashboard") + "#wordfilters")


@admin_blueprint.route("/wordfilters/<int:word_filter_id>/delete", methods=["POST"])
@_admin_required
def delete_site_word_filter(word_filter_id):
    word_filter = db.session.query(WordFilter).filter(WordFilter.id == word_filter_id).one_or_none()
    if word_filter is None:
        flash("Wordfilter not found.")
    else:
        db.session.delete(word_filter)
        db.session.commit()
        flash("Deleted the wordfilter.")
    return redirect(url_for("admin.dashboard") + "#wordfilters")


@admin_blueprint.route("/captcha/challenges", methods=["POST"])
@_admin_required
def create_captcha_challenge():
    correct_urls = (request.form.get("correct-images") or "").splitlines()
    decoy_urls = (request.form.get("decoy-images") or "").splitlines()
    try:
        create_challenge(
            category=request.form.get("category"),
            title=request.form.get("title"),
            correct_urls=correct_urls,
            decoy_urls=decoy_urls,
        )
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
        return redirect(url_for("admin.dashboard") + "#captcha")
    flash("Created the CAPTCHA challenge.")
    return redirect(url_for("admin.dashboard") + "#captcha")


@admin_blueprint.route("/captcha/challenges/<int:challenge_id>/delete", methods=["POST"])
@_admin_required
def delete_captcha_challenge(challenge_id):
    challenge = db.session.query(CaptchaChallenge).filter(CaptchaChallenge.id == challenge_id).one_or_none()
    if challenge is None:
        flash("CAPTCHA challenge not found.")
    else:
        db.session.delete(challenge)
        db.session.commit()
        flash("Deleted the CAPTCHA challenge.")
    return redirect(url_for("admin.dashboard") + "#captcha")


@admin_blueprint.route("/captcha/challenges/<int:challenge_id>/questions", methods=["POST"])
@_admin_required
def add_captcha_questions(challenge_id):
    challenge = db.session.query(CaptchaChallenge).filter(CaptchaChallenge.id == challenge_id).one_or_none()
    if challenge is None:
        flash("CAPTCHA challenge not found.")
        return redirect(url_for("admin.dashboard") + "#captcha")
    correct_urls = (request.form.get("correct-images") or "").splitlines()
    decoy_urls = (request.form.get("decoy-images") or "").splitlines()
    try:
        added = add_questions_to_challenge(challenge, correct_urls, decoy_urls)
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
        return redirect(url_for("admin.dashboard") + "#captcha")
    flash("Added %d image%s to /%s/." % (added, "" if added == 1 else "s", challenge.category))
    return redirect(url_for("admin.dashboard") + "#captcha")


@admin_blueprint.route("/captcha/questions/<int:question_id>/delete", methods=["POST"])
@_admin_required
def delete_captcha_question(question_id):
    challenge_id = remove_question(question_id)
    if challenge_id is None:
        flash("CAPTCHA image not found.")
    else:
        db.session.commit()
        flash("Removed the image from the challenge.")
    return redirect(url_for("admin.dashboard") + "#captcha")


@admin_blueprint.route("/captcha/challenges/<int:challenge_id>/toggle", methods=["POST"])
@_admin_required
def toggle_captcha_challenge(challenge_id):
    challenge = db.session.query(CaptchaChallenge).filter(CaptchaChallenge.id == challenge_id).one_or_none()
    if challenge is None:
        flash("CAPTCHA challenge not found.")
    else:
        challenge.is_active = not challenge.is_active
        db.session.commit()
        flash("%s the CAPTCHA challenge." % ("Enabled" if challenge.is_active else "Disabled"))
    return redirect(url_for("admin.dashboard") + "#captcha")


# NOTE: the URL must not contain "analytics" — privacy/ad-block extensions
# (uBlock, Brave shields) block any request matching /analytics. client-side,
# so the fetch never leaves the browser and the panel renders empty. The
# endpoint (function) name is unchanged, so url_for() callers are unaffected.
@admin_blueprint.route("/boards/metrics.json")
@_admin_required
def board_metrics():
    return jsonify(_board_metrics_payload())


@admin_blueprint.route("/live-typing.json")
@_admin_required
def live_typing_feed():
    """Active in-progress post/reply drafts for the live-monitor panel — the
    text visitors are typing right now, keyed to their IP."""
    from services.live_typing import active_drafts
    return jsonify({"typists": active_drafts()})


@admin_blueprint.route("/live-visitors.json")
@_admin_required
def live_visitors_feed():
    """Current visitors (by IP), geolocated to country coordinates, for the live
    world map on the composition monitor. Real-time — the panel polls this a few
    times a second and reconciles the dots without a page refresh."""
    from services.presence import active_visitors, visitor_count
    # Storage nodes ride along on the same poll as visitors so the map needs
    # one request, not two. Storage is blue, independently verified gateways
    # are green, visitors are red, and co-located roles alternate colours.
    try:
        from model.StorageNode import active_storage_nodes, network_summary

        nodes = active_storage_nodes()
        summary = network_summary()
        # The levelling view rides along on the same poll: an operator asking
        # "is the storage evenly spread" should not have to open a second page,
        # and a rebalance nobody can see is indistinguishable from one that is
        # not running (roadmap/dht-storage-roadmap.md phase 4.3).
        # Two read-only views of the same rows, fetched once. Both are None
        # rather than empty when they cannot be produced: an empty plan means
        # "nothing to move" and an empty dispersal summary means "no active
        # nodes", and neither of those is "the query failed".
        summary["levelling"] = None
        summary["dispersal"] = None
        try:
            from model.StorageNode import StorageNode
            from services.pool_levelling import from_storage_nodes

            rows = db.session.query(StorageNode).all()
            summary["levelling"] = from_storage_nodes(rows)
        except Exception:
            app.logger.exception("live map: levelling plan unavailable")
            rows = None
        # Whether dispersal is WORKING, which is a different question from how
        # evenly it is spread. Read entirely out of the rows already fetched --
        # the figures arrive on each node's signed heartbeat, so this request
        # path does NO network I/O. Asking nine nodes over I2P from a handler
        # the panel polls every three seconds is how this site 504'd before
        # (roadmap phase 4.3, and the inline news sync in GET /).
        if rows is not None:
            try:
                from services.dispersal_health import from_storage_nodes as dispersal

                summary["dispersal"] = dispersal(rows)
            except Exception:
                app.logger.exception("live map: dispersal health unavailable")
    except Exception:
        app.logger.exception("live map: storage nodes unavailable")
        nodes, summary = [], {"nodes": 0, "capacity_bytes": 0, "capacity_human": "0.0 B"}
    try:
        from services.gateway_registry import active_gateways

        gateways, gateway_error = active_gateways()
        # Merge a co-located storage+gateway process by its externally observed
        # address. A dedicated gateway has no storage heartbeat and is appended
        # as a green-only node.
        nodes_by_ip = {node.get("ip"): node for node in nodes if node.get("ip")}
        for gateway in gateways:
            existing = nodes_by_ip.get(gateway.get("ip"))
            if existing is None:
                nodes.append(gateway)
                nodes_by_ip[gateway.get("ip")] = gateway
            else:
                existing.update({
                    "gateway": True,
                    "healthy": gateway.get("healthy"),
                    "verified": gateway.get("verified"),
                    "tls_valid": gateway.get("tls_valid"),
                    "hostname": gateway.get("hostname"),
                    "latency_ms": gateway.get("latency_ms"),
                    "last_seen": gateway.get("last_seen"),
                    "expires_at": gateway.get("expires_at"),
                    "status_url": gateway.get("status_url"),
                })
    except Exception:
        app.logger.exception("live map: gateway registry unavailable")
        gateways, gateway_error = [], "gateway registry unavailable"
    # Running (and queued) DCS containers ride along too, so the live monitor can
    # list what the container network is actually running right now.
    try:
        from model.LabInstance import LabInstance, STATUS_RUNNING, STATUS_QUEUED
        rows = (
            db.session.query(LabInstance)
            .filter(LabInstance.status.in_((STATUS_RUNNING, STATUS_QUEUED)))
            .order_by(LabInstance.created_at.desc())
            .limit(60)
            .all()
        )
        containers = [{
            "machine": r.image_key,
            "status": r.status,
            "worker": (r.worker_node_id or "")[:12],
            "address": r.i2p_address or "",
            "seconds_remaining": r.seconds_remaining,
            "queue_position": r.queue_position,
        } for r in rows]
    except Exception:
        app.logger.exception("live map: container list unavailable")
        containers = []
    return jsonify({
        "visitors": active_visitors(),
        "total": visitor_count(),
        "storage_nodes": nodes,
        "storage_summary": summary,
        "gateways": gateways,
        "gateway_registry_error": gateway_error,
        "containers": containers,
    })


@admin_blueprint.route("/slips/<int:slip_id>/permissions", methods=["POST"])
@_admin_required
def update_slip_permissions(slip_id):
    slip = db.session.query(Slip).filter(Slip.id == slip_id).one_or_none()
    if slip is None or slip.name == WALLET_ADMIN_SLIP_NAME:
        flash("Slip not found.")
        return redirect(url_for("admin.dashboard") + "#slips")

    raw_board_ids = [value.strip() for value in request.form.getlist("moderated-board-ids") if value and value.strip()]
    try:
        board_ids = {int(value) for value in raw_board_ids}
    except ValueError:
        flash("Select valid boards for moderator assignments.")
        return redirect(url_for("admin.dashboard") + "#slips")

    valid_board_ids = {
        board_id
        for (board_id,) in db.session.query(Board.id).filter(Board.id.in_(board_ids)).all()
    } if board_ids else set()
    if valid_board_ids != board_ids:
        flash("One or more selected boards no longer exist.")
        return redirect(url_for("admin.dashboard") + "#slips")

    slip.is_mod = bool(request.form.get("is-mod"))
    db.session.query(SlipBoardModerator).filter(SlipBoardModerator.slip_id == slip.id).delete(
        synchronize_session=False
    )
    for board_id in sorted(valid_board_ids):
        db.session.add(SlipBoardModerator(slip_id=slip.id, board_id=board_id))
    db.session.add(slip)
    db.session.commit()
    flash("Updated moderator permissions for slip '%s'." % slip.name)
    return redirect(url_for("admin.dashboard") + "#slips")


@admin_blueprint.route("/slips/<int:slip_id>/sitewide-moderation", methods=["POST"])
@_admin_required
def update_slip_sitewide_permission(slip_id):
    slip = db.session.query(Slip).filter(Slip.id == slip_id).one_or_none()
    if slip is None or slip.name == WALLET_ADMIN_SLIP_NAME:
        flash("Slip not found.")
        return redirect(url_for("admin.dashboard") + "#slips")

    slip.is_mod = bool(request.form.get("is-mod"))

    # A SEPARATE grant, on the same form because that is where an operator looks
    # for "what may this account do" -- not the same grant with a second name.
    # Moderating a board is removing spam and abuse. Approving an article that
    # names a private individual is a publishing decision with legal
    # consequences, and the editor desk is open to people holding no admin
    # rights at all. One person may hold both; they are still two decisions.
    #
    # Guarded by a hidden marker rather than by the checkbox alone: an unchecked
    # box sends nothing, so a form that did not carry the field at all would be
    # indistinguishable from one that carried it unchecked, and rendering the
    # moderator form somewhere without this control would silently strip
    # everybody's editor rights.
    if request.form.get("editor-field-present"):
        slip.is_editor = bool(request.form.get("is-editor"))

    db.session.add(slip)
    db.session.commit()
    flash("Updated sitewide permissions for slip '%s'." % slip.name)
    return redirect(url_for("admin.dashboard") + "#slips")


def _slip_references():
    """Every column in the schema that points at slip.id, newest tables included.

    IMPORTS EVERY MODEL FIRST, and that is load-bearing rather than tidy. This
    function derives the list from `db.metadata`, and metadata holds only what
    has been IMPORTED. bootstrap.py imports every model, but the Dockerfile runs
    bootstrap at IMAGE BUILD time, so a running container has only what the live
    import path happened to pull in. Measured against production: 16 tables
    referenced slip.id, and `post_vote` -- which exists in that database with a
    foreign key to slip -- was not among them.

    That is the very failure the rest of this docstring describes, arriving by a
    different route: replacing the hand-written list with a derivation fixed the
    stale-list problem and introduced a completeness one.

    Derived from the metadata rather than listed by hand. The hand-written list
    this replaces covered twelve tables and the schema has grown to thirty-seven:
    votes, arcade progress, DAO ballots, lab instances, bot tokens and store
    orders all arrived later, and every one of them with a NOT NULL slip_id made
    account deletion fail with a foreign-key violation. The failure was total —
    any account that had ever voted on a post could not be deleted at all — and
    silent, because the handler caught it and flashed "Could not delete slip".

    A list that has to be updated by hand every time a table is added will be
    out of date again by the next feature. This cannot be.
    """
    from services.model_registry import import_all_models

    import_all_models()
    from shared import db as _db

    out = []
    for table in _db.metadata.sorted_tables:
        for column in table.columns:
            for fk in column.foreign_keys:
                if fk.column.table.name == "slip" and fk.column.name == "id":
                    out.append((table, column))
    return out


def _release_published_work(slip_id):
    """Let this author's PUBLISHED work outlive the account.

    The generic rule below -- a NOT NULL slip_id means the row cannot exist
    without the account, so it goes -- is right for a vote and wrong for a
    story. `NewsStory.slip_id` is NOT NULL by design so an editor can always
    tell who filed something, and applying the generic rule to it meant deleting
    an author deleted their published, corrected and RETRACTED stories: URLs
    already sitting in other people's citations began 404ing, and the retraction
    notice an editor wrote was destroyed along with the story it was about.

    So the split is by whether the work is PUBLIC, not by whether the column is
    nullable:

      * public statuses keep their row and lose their author. The story, its
        byline mode, its correction and retraction notices and its revisions all
        survive; nothing on the page changes except that there is no longer an
        account behind it.
      * everything unpublished -- drafts, submissions, things in review -- has no
        public URL and nobody citing it, so it goes with the account.

    Pen names are RETIRED rather than deleted for the same reason plus one more:
    retirement is what stops a released slug being reissued, and a pen name row
    that vanished would free its name for somebody who would inherit its
    readers.
    """
    from model.NewsStory import NewsStory, PUBLIC_STATUSES
    from model.PenName import PenName

    stories = db.session.query(NewsStory).filter(NewsStory.slip_id == slip_id)

    # Unpublished work goes. Deleted first so the release below cannot
    # accidentally orphan a draft as an authorless row nobody can reach.
    stories.filter(~NewsStory.status.in_(PUBLIC_STATUSES)).delete(
        synchronize_session=False)

    # Published work is released, not removed.
    db.session.query(NewsStory).filter(
        NewsStory.slip_id == slip_id,
        NewsStory.status.in_(PUBLIC_STATUSES),
    ).update({NewsStory.slip_id: None}, synchronize_session=False)

    now = _datetime.datetime.utcnow()
    db.session.query(PenName).filter(PenName.owner_slip_id == slip_id).update(
        {PenName.owner_slip_id: None, PenName.retired: True,
         PenName.retired_at: now},
        synchronize_session=False)


def _delete_slip(slip):
    """Delete a slip and release everything that references it.

    Nullable references are cleared, so records that outlive the account (bans
    someone issued, comments they left) survive as anonymous rather than
    vanishing — deleting an account should not rewrite the moderation history of
    a board. Rows whose slip_id is NOT NULL cannot exist without the account, so
    they go with it.

    Tables are visited in reverse dependency order so a row is never orphaned by
    the deletion of something it points at.
    """
    slip_id = slip.id

    _release_published_work(slip_id)

    for table, column in reversed(_slip_references()):
        if table.name == "slip":
            continue
        if column.nullable:
            db.session.execute(
                table.update().where(column == slip_id).values({column.name: None}))
        else:
            db.session.execute(table.delete().where(column == slip_id))
    db.session.query(Slip).filter(Slip.id == slip_id).delete(synchronize_session=False)


@admin_blueprint.route("/slips/<int:slip_id>/delete", methods=["POST"])
@_admin_required
@csrf_protect
def delete_slip(slip_id):
    slip = db.session.query(Slip).filter(Slip.id == slip_id).one_or_none()
    if slip is None or slip.name == WALLET_ADMIN_SLIP_NAME:
        flash("Slip not found.")
        return redirect(url_for("admin.dashboard") + "#slips")
    name = slip.name
    try:
        _delete_slip(slip)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to delete slip %s", slip_id)
        flash("Could not delete slip '%s'." % name)
        return redirect(url_for("admin.dashboard") + "#slips")
    flash("Deleted slip '%s'." % name)
    return redirect(url_for("admin.dashboard") + "#slips")


@admin_blueprint.route("/boards/<int:board_id>/moderators", methods=["POST"])
@_admin_required
def update_board_moderators(board_id):
    board = db.session.query(Board).filter(Board.id == board_id).one_or_none()
    if board is None:
        flash("Board not found.")
        return redirect(url_for("admin.dashboard") + "#slips")

    raw_slip_ids = [
        value.strip()
        for value in request.form.getlist("moderator-slip-ids")
        if value and value.strip()
    ]
    try:
        requested_slip_ids = {int(value) for value in raw_slip_ids}
    except ValueError:
        flash("Select valid slips for moderator assignments.")
        return redirect(url_for("admin.dashboard") + "#slips")

    valid_slips = (
        db.session.query(Slip.id, Slip.is_mod)
        .filter(Slip.id.in_(requested_slip_ids), Slip.name != WALLET_ADMIN_SLIP_NAME)
        .all()
    ) if requested_slip_ids else []
    valid_slip_ids = {slip_id for slip_id, _is_mod in valid_slips}
    if valid_slip_ids != requested_slip_ids:
        flash("One or more selected slips no longer exist.")
        return redirect(url_for("admin.dashboard") + "#slips")

    # Owners already have moderation rights through board ownership, so an
    # explicit moderator row would be redundant and misleading in the panel.
    explicit_moderator_ids = {
        slip_id for slip_id, is_mod in valid_slips
        if not is_mod and slip_id != board.owner_slip_id
    }
    db.session.query(SlipBoardModerator).filter(SlipBoardModerator.board_id == board.id).delete(
        synchronize_session=False
    )
    for slip_id in sorted(explicit_moderator_ids):
        db.session.add(SlipBoardModerator(slip_id=slip_id, board_id=board.id))
    db.session.commit()
    flash("Updated moderators for /%s/." % board.name)
    return redirect(url_for("admin.dashboard") + "#slips")


@admin_blueprint.route("/upload-filetypes", methods=["POST"])
@_admin_required
def save_upload_filetypes():
    from board_sources import DEFAULT_MIMETYPES
    video_types = (request.form.get("video-allowed-mimetypes") or "").strip()
    board_types = (request.form.get("board-default-mimetypes") or "").strip()
    set_setting("video_allowed_mimetypes", video_types)
    set_setting("board_default_mimetypes", board_types or DEFAULT_MIMETYPES)
    db.session.commit()  # set_setting() stages only; without this nothing persists
    flash("Saved upload file-type settings.")
    return redirect(url_for("admin.dashboard") + "#upload-filetypes")


@admin_blueprint.route("/board-inactivity", methods=["POST"])
@_admin_required
def save_board_inactivity():
    from services.board_cleanup import SETTING_KEY as INACTIVITY_KEY
    raw = (request.form.get("board-inactivity-days") or "").strip()
    try:
        days = int(raw)
    except ValueError:
        flash("Enter a whole number of days.")
        return redirect(url_for("admin.dashboard") + "#board-inactivity")
    if days < 0:
        days = 0
    set_setting(INACTIVITY_KEY, str(days))
    db.session.commit()  # set_setting() stages only; without this nothing persists
    if days == 0:
        flash("Inactive-board deletion disabled.")
    else:
        flash("User-created boards will be deleted after %d day%s without a new post." % (days, "" if days == 1 else "s"))
    return redirect(url_for("admin.dashboard") + "#board-inactivity")


@admin_blueprint.route("/video-retention", methods=["POST"])
@_admin_required
def save_video_retention():
    from services.video_cleanup import SETTING_KEY as VIDEO_INACTIVITY_KEY
    raw = (request.form.get("video-inactivity-days") or "").strip()
    try:
        days = int(raw)
    except ValueError:
        flash("Enter a whole number of days.")
        return redirect(url_for("admin.dashboard") + "#video-retention")
    if days < 0:
        days = 0
    set_setting(VIDEO_INACTIVITY_KEY, str(days))
    db.session.commit()  # set_setting() stages only; without this nothing persists
    if days == 0:
        flash("Automatic video pruning disabled.")
    else:
        flash("Videos not watched for %d day%s will be automatically pruned." % (days, "" if days == 1 else "s"))
    return redirect(url_for("admin.dashboard") + "#video-retention")


@admin_blueprint.route("/content-retention", methods=["POST"])
@_admin_required
def save_content_retention():
    from services.shadowban_cleanup import SETTING_KEY as SHADOW_KEY
    from services.thread_flush import SETTING_KEY as THREAD_KEY
    from services.scraped_thread_retire import (
        FAILURE_SETTING_KEY as RETIRE_FAIL_KEY,
        SETTING_KEY as RETIRE_KEY,
    )

    def _parse(name):
        raw = (request.form.get(name) or "").strip()
        try:
            return max(0, int(raw))
        except ValueError:
            return None

    shadow_days = _parse("shadowban-delete-days")
    thread_days = _parse("thread-unviewed-days")
    retire_days = _parse("scraped-retire-days")
    retire_failures = _parse("scraped-retire-failures")
    if shadow_days is None or thread_days is None or retire_days is None or retire_failures is None:
        flash("Enter whole numbers of days.")
        return redirect(url_for("admin.dashboard") + "#content-retention")
    set_setting(SHADOW_KEY, str(shadow_days))
    set_setting(THREAD_KEY, str(thread_days))
    set_setting(RETIRE_KEY, str(retire_days))
    set_setting(RETIRE_FAIL_KEY, str(retire_failures))
    db.session.commit()
    flash("Content-retention settings saved (0 = disabled).")
    return redirect(url_for("admin.dashboard") + "#content-retention")


@admin_blueprint.route("/front-page", methods=["POST"])
@_admin_required
def save_front_page():
    set_setting(FRONT_PAGE_SETTING_KEY, request.form.get("front-page-html") or "")
    db.session.commit()
    invalidate_front_page_cache()
    flash("Front page updated.")
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/front-page/reset", methods=["POST"])
@_admin_required
def reset_front_page():
    """Replace the stored front page with the one shipped in this build.

    The stored copy wins over the file, which is right — an operator's edits
    must survive a deploy. The consequence is that improvements to the shipped
    default are invisible on any instance that has ever saved the front page,
    including one that only ever saved the default back unchanged.

    So this is an explicit button rather than something a deploy does quietly.
    It says what it will overwrite, and it refuses when there is nothing to
    apply — a "reset" that reports success while changing nothing teaches an
    operator to distrust the next one.
    """
    shipped = _default_front_page_html()
    if not shipped:
        flash("No shipped front page was found in this build.")
        return redirect(url_for("admin.dashboard"))

    current = get_setting(FRONT_PAGE_SETTING_KEY, "") or ""
    if current == shipped:
        flash("The front page already matches this build's default — nothing changed.")
        return redirect(url_for("admin.dashboard"))

    set_setting(FRONT_PAGE_SETTING_KEY, shipped)
    db.session.commit()
    invalidate_front_page_cache()
    flash("Front page reset to this build's default (%d characters replaced)."
          % len(current))
    return redirect(url_for("admin.dashboard"))


def _store_source_watermark(source_type, uploaded_file):
    """Save an uploaded watermark for one source. Returns (ok, message).

    Shared by the Source Watermarks card and the board-monitoring form so both
    apply the same mime allowlist, replace-and-delete-old behaviour and cache
    invalidation. Keyed by SOURCE TYPE — for an aggregated chan that is its host —
    so this is a PER-SITE image covering everything scraped from that site, not
    one remote board.
    """
    if uploaded_file is None or not (uploaded_file.filename or "").strip():
        return False, "Choose an image to upload."
    detected_mimetype = _watermark_upload_mimetype(uploaded_file)
    if detected_mimetype not in ALLOWED_WATERMARK_IMAGE_MIMETYPES:
        return False, "Watermarks must be PNG, JPEG, GIF, or WebP images."
    uploaded_file.headers["Content-Type"] = detected_mimetype
    try:
        # Via save_attachment, so the watermark is hash/AV/NSFW-checked like any upload.
        new_media = storage.save_attachment(uploaded_file)
        old_media_id = replace_source_watermark(source_type, new_media.id)
        db.session.commit()
        invalidate_all_board_caches()
        if old_media_id is not None and old_media_id != new_media.id:
            _delete_media_record(old_media_id)
            db.session.commit()
    except BlockedMediaError as exc:
        db.session.rollback()
        return False, str(exc)
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed saving source watermark for %s", source_type)
        return False, "Could not save that watermark."
    return True, "Watermark saved for %s." % source_type


@admin_blueprint.route("/overlay-image", methods=["POST"])
@_admin_required
def save_overlay_image():
    """Upload the single image shown in place of overlay-blocked media.

    One site-wide image, mirroring the source-watermark storage convention: the
    Media id lives in a SiteSetting (services/media_overlay.OVERLAY_SETTING).
    """
    from services.media_overlay import overlay_media_id, set_overlay_media_id

    uploaded_file = request.files.get("overlay-image")
    if uploaded_file is None or not (uploaded_file.filename or "").strip():
        flash("Choose an image to upload.")
        return redirect(url_for("admin.dashboard") + "#overlay-image")
    detected_mimetype = _watermark_upload_mimetype(uploaded_file)
    if detected_mimetype not in ALLOWED_WATERMARK_IMAGE_MIMETYPES:
        flash("The overlay must be a PNG, JPEG, GIF or WebP image.")
        return redirect(url_for("admin.dashboard") + "#overlay-image")
    uploaded_file.headers["Content-Type"] = detected_mimetype
    try:
        # nsfw_enforce=False: this is an operator-supplied moderation asset, and
        # blocking it on its own score would leave the gate with no image to show.
        new_media = storage.save_attachment(uploaded_file, nsfw_enforce=False)
        old_media_id = overlay_media_id()
        set_overlay_media_id(new_media.id)
        db.session.commit()
        if old_media_id is not None and old_media_id != new_media.id:
            _delete_media_record(old_media_id)
            db.session.commit()
    except BlockedMediaError as exc:
        db.session.rollback()
        flash(str(exc))
        return redirect(url_for("admin.dashboard") + "#overlay-image")
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed saving the overlay image")
        flash("Could not save that overlay image.")
        return redirect(url_for("admin.dashboard") + "#overlay-image")
    flash("Overlay image saved. Blocked media now shows it to anyone not signed in.")
    return redirect(url_for("admin.dashboard") + "#overlay-image")


@admin_blueprint.route("/overlay-image/clear", methods=["POST"])
@_admin_required
def clear_overlay_image():
    from services.media_overlay import overlay_media_id, set_overlay_media_id

    old_media_id = overlay_media_id()
    set_overlay_media_id(None)
    db.session.commit()
    if old_media_id is not None:
        _delete_media_record(old_media_id)
        db.session.commit()
    # Note: blocked media stays blocked — it falls back to a generated
    # "BLOCKED" placeholder rather than reverting to the real image.
    flash("Overlay image cleared. Blocked media now shows a generated placeholder.")
    return redirect(url_for("admin.dashboard") + "#overlay-image")


@admin_blueprint.route("/media/<int:media_id>/overlay-block", methods=["POST"])
@_admin_required
def toggle_media_overlay_block(media_id):
    """Flag/unflag one media as overlay-blocked.

    Unlike the ban action this keeps the file: signed-in viewers still see it, and
    it can be reversed. Nothing is added to the hash blocklist.
    """
    from services.media_overlay import set_media_overlay_blocked

    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if media is None:
        flash("No such media.")
        return redirect(request.referrer or url_for("admin.dashboard"))
    unblock = (request.form.get("action") or "").strip().lower() == "unblock"
    set_media_overlay_blocked(media, blocked=not unblock)
    db.session.commit()
    invalidate_all_board_caches()
    if unblock:
        flash("Media %d is visible again." % media_id)
    else:
        flash(
            "Media %d is now hidden behind the overlay for anyone not signed into a slip."
            % media_id
        )
    return redirect(request.referrer or url_for("admin.dashboard"))


@admin_blueprint.route("/source-watermarks/<source_type>", methods=["POST"])
@_admin_required
def save_source_watermark(source_type):
    from services.aggregator_sync.scraper_db import is_generic_source_type
    if source_type not in SUPPORTED_SOURCE_TYPES and not is_generic_source_type(source_type):
        flash("Unsupported source type.")
        return redirect(url_for("admin.dashboard") + "#source-watermarks")

    uploaded_file = request.files.get("watermark-image")
    if uploaded_file is None or not (uploaded_file.filename or "").strip():
        flash("Choose an image to upload.")
        return redirect(url_for("admin.dashboard") + "#source-watermarks")

    detected_mimetype = _watermark_upload_mimetype(uploaded_file)
    if detected_mimetype not in ALLOWED_WATERMARK_IMAGE_MIMETYPES:
        flash("Watermarks must be PNG, JPEG, GIF, or WebP images.")
        return redirect(url_for("admin.dashboard") + "#source-watermarks")
    uploaded_file.headers["Content-Type"] = detected_mimetype

    try:
        new_media = storage.save_attachment(uploaded_file)
        old_media_id = replace_source_watermark(source_type, new_media.id)
        db.session.commit()
        invalidate_all_board_caches()

        if old_media_id is not None and old_media_id != new_media.id:
            _delete_media_record(old_media_id)
            db.session.commit()
    except BlockedMediaError as exc:
        db.session.rollback()
        flash(str(exc))
        return redirect(url_for("admin.dashboard") + "#source-watermarks")
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("Failed saving source watermark for %s", source_type)
        flash("Failed to save %s watermark: %s" % (source_display_name(source_type), exc))
        return redirect(url_for("admin.dashboard") + "#source-watermarks")

    flash("%s watermark updated." % source_display_name(source_type))
    return redirect(url_for("admin.dashboard") + "#source-watermarks")


@admin_blueprint.route("/source-watermarks/<source_type>/delete", methods=["POST"])
@_admin_required
def delete_source_watermark(source_type):
    from services.aggregator_sync.scraper_db import is_generic_source_type
    if source_type not in SUPPORTED_SOURCE_TYPES and not is_generic_source_type(source_type):
        flash("Unsupported source type.")
        return redirect(url_for("admin.dashboard") + "#source-watermarks")

    old_media_id = clear_source_watermark(source_type)
    db.session.commit()
    invalidate_all_board_caches()

    if old_media_id is None:
        flash("%s is already using the default watermark." % source_display_name(source_type))
        return redirect(url_for("admin.dashboard") + "#source-watermarks")

    try:
        _delete_media_record(old_media_id)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("Failed deleting source watermark for %s", source_type)
        flash("Removed the %s watermark setting, but cleanup failed: %s" % (source_display_name(source_type), exc))
        return redirect(url_for("admin.dashboard") + "#source-watermarks")

    flash("%s watermark removed. Default source watermark restored." % source_display_name(source_type))
    return redirect(url_for("admin.dashboard") + "#source-watermarks")








@admin_blueprint.route("/posts/<int:post_id>/delete", methods=["POST"])
@_admin_required
def delete_post(post_id):
    post, thread, board = get_post_thread_board_or_404(post_id)
    # The fallback, not the referrer, was the dead half: blueprints/boards.py
    # went with the stripping, so this raised BuildError precisely when
    # there was no referrer -- the case a fallback exists for.
    redirect_target = request.referrer or url_for("admin.dashboard")
    if len(thread.posts) > 0 and thread.posts[0].id == post.id:
        ThreadPosts().delete(thread.id)
    else:
        PostRemoval().delete(post_id)
    invalidate_board_cache(board.id)
    invalidate_front_page_cache()
    invalidate_activity_cache()
    flash("Post deleted.")
    return redirect(redirect_target)


@admin_blueprint.route("/posts/<int:post_id>/ban", methods=["POST"])
def ban_post(post_id):
    post, thread, board = get_post_thread_board_or_404(post_id)
    redirect_target = request.referrer or url_for("threads.view", thread_id=thread.id)
    if slip_can_moderate(board=board) is False:
        flash("Only moderators and admins can ban posters on this board.")
        return redirect(redirect_target)
    if post.poster is None:
        flash("Imported posts cannot be banned by local poster identity.")
        return redirect(redirect_target)
    poster = db.session.query(Poster).filter(Poster.id == post.poster).one_or_none()
    if poster is None:
        flash("Poster information is unavailable for this post.")
        return redirect(redirect_target)

    acting_slip = get_slip()
    reason = (request.form.get("reason") or "").strip() or None
    from model.Ban import expiry_from_duration
    expires_at = expiry_from_duration(request.form.get("duration"))
    when = "permanently" if expires_at is None else ("until %s UTC" % expires_at.strftime("%Y-%m-%d %H:%M"))
    if slip_is_admin():
        ban_ip(
            poster.ip_address,
            reason=reason or "Banned by site admin",
            created_by_slip_id=acting_slip.id if acting_slip else None,
            expires_at=expires_at,
        )
        flash("Poster banned sitewide %s." % when)
    else:
        ban_ip_for_board(
            board.id,
            poster.ip_address,
            reason=reason or ("Banned from /%s/ by board moderator" % board.name),
            created_by_slip_id=acting_slip.id if acting_slip else None,
            expires_at=expires_at,
        )
        flash("Poster banned from /%s/ %s." % (board.name, when))
    db.session.commit()
    return redirect(redirect_target)


@admin_blueprint.route("/posts/<int:post_id>/shadowban", methods=["POST"])
def shadowban_post(post_id):
    post, thread, board = get_post_thread_board_or_404(post_id)
    redirect_target = request.referrer or url_for("threads.view", thread_id=thread.id)
    if slip_can_moderate(board=board) is False:
        flash("Only moderators and admins can shadowban posters.")
        return redirect(redirect_target)
    if post.poster is None:
        flash("Imported posts cannot be shadowbanned by local poster identity.")
        return redirect(redirect_target)
    poster = db.session.query(Poster).filter(Poster.id == post.poster).one_or_none()
    if poster is None:
        flash("Poster information is unavailable for this post.")
        return redirect(redirect_target)
    acting_slip = get_slip()
    reason = (request.form.get("reason") or "").strip() or None
    from model.Ban import expiry_from_duration
    from model.ShadowBan import shadowban
    expires_at = expiry_from_duration(request.form.get("duration"))
    # Target BOTH the poster's IP and their account (if any), so they're caught
    # whether they post logged-in or anonymously.
    shadowban(
        ip_address=poster.ip_address,
        slip_id=poster.slip,
        reason=reason or "Shadowbanned by moderator",
        created_by_slip_id=acting_slip.id if acting_slip else None,
        expires_at=expires_at,
    )
    db.session.commit()
    # Their already-posted content must stop showing to others immediately.
    invalidate_all_board_caches()
    when = "permanently" if expires_at is None else ("until %s UTC" % expires_at.strftime("%Y-%m-%d %H:%M"))
    flash("Poster shadowbanned %s. Their content is now hidden from everyone else; they still see it themselves." % when)
    return redirect(redirect_target)


@admin_blueprint.route("/shadowbans/<int:shadowban_id>/delete", methods=["POST"])
@_admin_required
def delete_shadowban(shadowban_id):
    from model.ShadowBan import remove_shadowban
    entry = remove_shadowban(shadowban_id)
    db.session.commit()
    if entry is None:
        flash("No matching shadowban found.")
    else:
        invalidate_all_board_caches()
        flash("Shadowban lifted.")
    return redirect(url_for("admin.dashboard") + "#shadowbans")


@admin_blueprint.route("/bans/<path:ip_address>/delete", methods=["POST"])
@_admin_required
def delete_ban(ip_address):
    ban = unban_ip(ip_address)
    db.session.commit()
    if ban is None:
        flash("No matching ban found.")
    else:
        flash("Ban removed.")
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/media-blocklist", methods=["POST"])
@_admin_required
def add_blocked_media_hash():
    raw_hash = request.form.get("sha256", "")
    reason = request.form.get("reason", "")
    source_url = request.form.get("source_url", "")
    acting_slip = get_slip()
    try:
        blocked = block_media_hash(
            raw_hash,
            reason=reason,
            source_url=source_url,
            created_by_slip_id=acting_slip.id if acting_slip else None,
        )
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
        return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")
    flash("Blocked media hash %s." % blocked.sha256[:12])
    return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")


@admin_blueprint.route("/media-blocklist/from-post/<int:post_id>", methods=["POST"])
@_admin_required
def block_media_for_post(post_id):
    post, _thread, _board = get_post_thread_board_or_404(post_id)
    if post.media is None:
        flash("That post does not have attached media.")
        return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")
    media = db.session.query(Media).filter(Media.id == post.media).one_or_none()
    if media is None or not media.sha256:
        flash("Media hash is not available for that post.")
        return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")

    acting_slip = get_slip()
    reason = request.form.get("reason") or "Blocked from post #%d" % post.id
    block_media_hash(
        media.sha256,
        reason=reason,
        created_by_slip_id=acting_slip.id if acting_slip else None,
    )
    db.session.commit()
    flash("Blocked media from post #%d." % post.id)
    return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")


@admin_blueprint.route("/imported-posts/<int:thread_id>/<path:source_post_id>/block-media", methods=["POST"])
@_admin_required
def block_imported_post_media(thread_id, source_post_id):
    thread, board = get_thread_and_board_or_404(thread_id)
    if thread.source_type == "local":
        abort(404)
    redirect_target = request.referrer or url_for("threads.view", thread_id=thread.id)
    acting_slip = get_slip()
    reason = request.form.get("reason") or "Blocked imported image from thread %d post %s" % (thread.id, source_post_id)
    try:
        from aggregator_sync import purge_imported_source_post

        result = purge_imported_source_post(
            thread,
            source_post_id,
            block_media=True,
            reason=reason,
            acting_slip_id=acting_slip.id if acting_slip else None,
        )
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
        return redirect(redirect_target)
    invalidate_board_cache(board.id)
    invalidate_front_page_cache()
    invalidate_activity_cache()
    if result.get("blocked_sha256"):
        # Say what actually happened. The old wording ("the scraper database is
        # read-only, so the post will be hidden instead of purged") described the
        # CRAWLER's SQLite row, but read as "the image is still in your database" —
        # and back then it was, because only the display was suppressed. The local
        # copy is now deleted outright, and both hashes are recorded, so a
        # read-only scraper DB no longer weakens the ban.
        parts = ["Banned image %s" % result["blocked_sha256"][:12]]
        if result.get("blocked_fingerprint"):
            parts.append(
                "plus a perceptual fingerprint, so re-encoded reposts are blocked too"
            )
        if result.get("purged_local_media"):
            parts.append("and deleted the stored copy")
        message = ", ".join(parts) + "."
        if not result.get("purged_source_posts", True):
            message += (
                " The remote scraper's own database is read-only so its row remains"
                " there, but the hash blocklist stops it being re-imported."
            )
        flash(message)
    else:
        flash("Purged the imported post.")
    if result.get("deleted_thread"):
        return redirect(url_for("admin.dashboard"))
    return redirect(redirect_target)


@admin_blueprint.route("/media-blocklist/<path:sha256>/delete", methods=["POST"])
@_admin_required
def delete_blocked_media_hash(sha256):
    try:
        normalized = normalize_media_hash(sha256)
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")
    blocked = (
        db.session.query(BlockedMediaHash)
        .filter(BlockedMediaHash.sha256 == normalized)
        .one_or_none()
    )
    if blocked is None:
        flash("No matching blocked media hash found.")
        return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")
    db.session.delete(blocked)
    db.session.commit()
    flash("Blocked media hash removed.")
    return redirect(url_for("admin.dashboard") + "#blocked-media-hashes")



def _site_host(site_url):
    """Host of a chan URL — the source_type used for generic sites.

    Must stay byte-identical to the scraper's runtime.site_host_slug(), which
    names that site's SQLite file; a mismatch means the importer reads a DB that
    does not exist.
    """
    raw = (site_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    from urllib.parse import urlparse
    host = (urlparse(raw).netloc or "").lower().split("@")[-1].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return "".join(ch for ch in host if ch.isalnum() or ch in ".-")


def _monitored_board_rows():
    """Per-source monitored boards, joined to the local board each imports into.

    The local link is a BoardSource with source_thread_id == WHOLE_BOARD_THREAD_ID;
    a board monitored on the scraper with no such row is reported so the admin can
    see that it is being crawled but not imported anywhere.
    """
    import scraper_client
    from services.aggregator_sync.config import (
        SUPPORTED_SCRAPER_TYPES,
        WHOLE_BOARD_THREAD_ID,
    )

    whole_board_sources = {}
    site_urls = {}
    for source in (
        db.session.query(BoardSource)
        .filter(BoardSource.source_thread_id == WHOLE_BOARD_THREAD_ID)
        .all()
    ):
        whole_board_sources.setdefault(
            (source.source_type, (source.source_name or "").lower()), []
        ).append(source)
        if getattr(source, "source_site", None):
            site_urls[source.source_type] = source.source_site

    board_names = {
        board.id: board.name for board in db.session.query(Board).all()
    }
    rows = []
    for source_type in _known_scraper_types():
        monitored = scraper_client.list_monitored_boards(source_type)
        entry = {
            "source_type": source_type,
            "reachable": monitored is not None,
            "site_url": site_urls.get(source_type),
            "is_generic": source_type not in SUPPORTED_SCRAPER_TYPES,
            "watermark_url": source_watermark_image_url(source_type),
            "boards": [],
        }
        for board_name in sorted(monitored or []):
            links = whole_board_sources.get((source_type, board_name.lower()), [])
            entry["boards"].append({
                "name": board_name,
                "not_monitored_on_scraper": False,
                "targets": [
                    {"source_id": s.id, "board_id": s.board_id,
                     "board_name": board_names.get(s.board_id, "?")}
                    for s in links
                ],
            })
        # A whole-board BoardSource whose scraper is no longer monitoring it still
        # imports on each sync, so surface it rather than hiding the mismatch.
        listed = {b["name"].lower() for b in entry["boards"]}
        for (link_type, link_name), links in whole_board_sources.items():
            if link_type != source_type or link_name in listed:
                continue
            entry["boards"].append({
                "name": link_name,
                "not_monitored_on_scraper": True,
                "targets": [
                    {"source_id": s.id, "board_id": s.board_id,
                     "board_name": board_names.get(s.board_id, "?")}
                    for s in links
                ],
            })
        rows.append(entry)
    return rows


@admin_blueprint.route("/chans/boards.json")
@_admin_required
def chan_boards_json():
    """Cached board lists per chan, for the monitoring picker.

    Reads only the local cache — never scans. A scan is many HTTP requests to a
    remote site and must not happen inside a request.
    """
    from model.ChanBoard import boards_by_host, ChanBoardScan

    grouped = boards_by_host()
    states = {s.host: s for s in db.session.query(ChanBoardScan).all()}
    payload = {}
    for host, rows in grouped.items():
        state = states.get(host)
        payload[host] = {
            "boards": [
                {"board": r.board, "path": r.path, "name": r.name or "", "label": r.label}
                for r in rows
            ],
            "last_scanned": state.last_scanned_at.isoformat() if state and state.last_scanned_at else None,
        }
    # Chans scanned but with nothing found, so the UI can say so rather than
    # looking like the scan never ran.
    for host, state in states.items():
        payload.setdefault(host, {
            "boards": [],
            "last_scanned": state.last_scanned_at.isoformat() if state.last_scanned_at else None,
            "error": state.last_error,
        })
    return jsonify({"ok": True, "chans": payload})


@admin_blueprint.route("/chans/rescan", methods=["POST"])
@_admin_required
def chan_boards_rescan():
    """Queue a board rescan. Runs in a thread so the request returns at once."""
    import threading
    from services.chan_board_discovery import _host_of, scan_chan, scan_due_chans

    site_url = (request.form.get("site-url") or "").strip().rstrip("/")

    def _run(target_site):
        with app.app_context():
            try:
                if target_site:
                    scan_chan(_host_of(target_site), target_site)
                else:
                    scan_due_chans(limit=10)
            except Exception:
                app.logger.exception("manual chan board rescan failed")
            finally:
                try:
                    db.session.remove()
                except Exception:
                    pass

    threading.Thread(target=_run, args=(site_url,), daemon=True,
                     name="chan-board-rescan").start()
    flash(
        ("Rescanning %s for boards — reload in a moment." % site_url) if site_url
        else "Rescanning the chans that are due — reload in a moment."
    )
    return redirect(url_for("admin.dashboard") + "#board-monitoring")


@admin_blueprint.route("/monitored-boards/add", methods=["POST"])
@_admin_required
def add_monitored_board():
    """Continuously scrape a remote board and import all of its threads.

    Two independent halves, both reported: tell the scraper to keep discovering
    threads on that board, and create the whole-board BoardSource so the synced
    threads land on a local board.
    """
    import scraper_client
    from board_sources import normalize_source_name, normalize_source_type, scrape_block_reason
    from services.aggregator_sync.config import WHOLE_BOARD_THREAD_ID

    raw_type = (request.form.get("source-type") or "").strip()
    raw_name = (request.form.get("source-name") or "").strip()
    board_id = request.form.get("board-id", type=int)
    allow_nntp = bool(request.form.get("allow-nntp"))
    # A chan picked from the aggregated list. Its HOST becomes the source_type,
    # which is what keeps (source_type, source_thread_id) unique across sites whose
    # thread-id sequences overlap; the full URL is kept so the generic scraper
    # knows what to crawl.
    site_url = (request.form.get("site-url") or "").strip().rstrip("/")
    source_site = None
    if raw_type == "__site__" or site_url:
        if not site_url:
            flash("Choose a chan from the aggregated list, or pick a built-in scraper.")
            return redirect(url_for("admin.dashboard") + "#board-monitoring")
        try:
            from model.Federation import normalize_chan_url
            site_url = normalize_chan_url(site_url)
        except ValueError as error:
            flash(str(error))
            return redirect(url_for("admin.dashboard") + "#board-monitoring")
        source_type = _site_host(site_url)
        if not source_type:
            flash("Could not read a hostname out of %s." % site_url)
            return redirect(url_for("admin.dashboard") + "#board-monitoring")
        source_site = site_url
        source_name = (raw_name or "").strip().strip("/").lower()
    else:
        try:
            source_type = normalize_source_type(raw_type)
        except ValueError as error:
            flash(str(error))
            return redirect(url_for("admin.dashboard") + "#board-monitoring")
        source_name = normalize_source_name(source_type, raw_name)
    if not source_name:
        flash("Enter the remote board or subreddit to monitor.")
        return redirect(url_for("admin.dashboard") + "#board-monitoring")

    messages = []
    if scraper_client.add_monitored_board(source_type, source_name, site=source_site):
        messages.append("%s is now monitoring /%s/." % (source_type, source_name))
    else:
        messages.append(
            "Could not reach the %s scraper — it will not discover threads until "
            "that container is up. Re-submit once it is." % source_type
        )

    if board_id:
        board = db.session.query(Board).filter(Board.id == board_id).one_or_none()
        if board is None:
            messages.append("That local board no longer exists, so nothing is importing yet.")
        else:
            blocked = scrape_block_reason(board, source_type, source_name, WHOLE_BOARD_THREAD_ID)
            # The NNTP exemption exists to stop us scraping a site whose content
            # already arrives over NNTP. A board can carry an unrelated newsgroup
            # and still want a scraped source, so an admin may override it — the
            # rationale is "avoid duplicates", not "never mix". A BAN is never
            # overridable.
            if blocked is not None and blocked["code"] == "nntp" and allow_nntp:
                messages.append(
                    "/%s/ also syncs newsgroup(s) %s over NNTP — importing anyway as requested."
                    % (board.name, ", ".join(blocked.get("newsgroups") or []))
                )
                blocked = None
            if blocked is not None:
                messages.append(
                    "Not importing into /%s/: %s.%s"
                    % (board.name,
                       "it syncs over NNTP (%s)" % ", ".join(blocked.get("newsgroups") or [])
                       if blocked["code"] == "nntp"
                       else "%s is banned from aggregation" % blocked.get("host", source_name),
                       " Tick \"import anyway\" to override." if blocked["code"] == "nntp" else "")
                )
            else:
                existing = (
                    db.session.query(BoardSource)
                    .filter(
                        BoardSource.board_id == board.id,
                        BoardSource.source_type == source_type,
                        BoardSource.source_name == source_name,
                        BoardSource.source_thread_id == WHOLE_BOARD_THREAD_ID,
                    )
                    .one_or_none()
                )
                if existing is not None:
                    messages.append("/%s/ already imports all of it." % board.name)
                else:
                    db.session.add(BoardSource(
                        board_id=board.id,
                        source_type=source_type,
                        source_name=source_name,
                        source_thread_id=WHOLE_BOARD_THREAD_ID,
                        source_site=source_site,
                    ))
                    try:
                        db.session.commit()
                        messages.append("Every thread will be imported into /%s/." % board.name)
                    except Exception:
                        db.session.rollback()
                        app.logger.exception("could not create whole-board source")
                        messages.append("Could not link it to /%s/." % board.name)
    else:
        messages.append(
            "No local board chosen, so it is only being crawled — pick a board to import into."
        )

    # Optional watermark for this source's scraped content.
    watermark_file = request.files.get("watermark-image")
    if watermark_file is not None and (watermark_file.filename or "").strip():
        ok, message = _store_source_watermark(source_type, watermark_file)
        messages.append(message if ok else "Watermark not saved: %s" % message)

    flash(" ".join(messages))
    return redirect(url_for("admin.dashboard") + "#board-monitoring")


@admin_blueprint.route("/sources/purge", methods=["POST"])
@_admin_required
@csrf_protect
def purge_scraped_source():
    """Delete everything imported from one scraped source, site-wide.

    DESTRUCTIVE and irreversible short of re-scraping. Requires the operator to
    type the source name as confirmation, because the preview shown in the UI can
    be stale by the time the button is pressed.
    """
    from services.source_purge import purge_preview, purge_source

    source_type = (request.form.get("source-type") or "").strip()
    source_name = (request.form.get("source-name") or "").strip() or None
    confirm = (request.form.get("confirm") or "").strip()
    keep_replies = bool(request.form.get("keep-replies"))
    back = redirect(url_for("admin.dashboard") + "#board-monitoring")

    if not source_type or source_type == "local":
        flash("Choose a scraped source to purge.")
        return back
    # Case- and whitespace-insensitive. The guard exists to stop an ACCIDENTAL
    # click, and nobody types a source name by accident — matching case exactly
    # adds no safety and rejects operators who typed the right thing.
    if confirm.casefold() != source_type.casefold():
        # Say what was expected AND what arrived. The previous message told the
        # operator to "type it exactly" without showing what they had typed, so
        # an invisible difference — a trailing space, a homoglyph, a name that
        # is not the one the row displays — was unfixable by trying again.
        flash(
            "Purge cancelled — nothing was deleted. Expected %r but received %r."
            % (source_type, confirm)
        )
        return back

    preview = purge_preview(source_type, source_name)
    if not preview or not preview["threads"]:
        flash("Nothing imported from %s to purge." % source_type)
        return back
    try:
        result = purge_source(
            source_type, source_name,
            remove_sources=True, keep_threads_with_replies=keep_replies,
        )
    except Exception:
        app.logger.exception("purge failed for %s", source_type)
        flash("Purge failed — see the logs. Nothing further was deleted.")
        return back

    message = (
        "Purged %s%s: removed %d imported thread(s), %d media mapping(s) and "
        "%d source configuration(s)."
        % (source_type, ("/%s/" % source_name) if source_name else "",
           result["threads"], result["media"], result["sources"])
    )
    if result["skipped"]:
        message += " Kept %d thread(s) that carry local replies." % result["skipped"]
    if preview["local_posts"] and not keep_replies:
        message += " %d local repl%s were deleted with them." % (
            preview["local_posts"], "y" if preview["local_posts"] == 1 else "ies")
    flash(message)
    return back


@admin_blueprint.route("/sources/purge/preview.json")
@_admin_required
def purge_scraped_source_preview():
    """Exact counts for a purge, so the confirmation is not a blind click."""
    from services.source_purge import purge_preview
    preview = purge_preview(
        (request.args.get("source_type") or "").strip(),
        (request.args.get("source_name") or "").strip() or None,
    )
    if preview is None:
        return jsonify({"ok": False, "error": "unknown source"}), 400
    boards = {
        b.id: b.name for b in db.session.query(Board).filter(Board.id.in_(preview["boards"] or [0])).all()
    } if preview["boards"] else {}
    preview["board_names"] = [boards.get(b, str(b)) for b in preview["boards"]]
    return jsonify({"ok": True, "preview": preview})


@admin_blueprint.route("/monitored-boards/watermark", methods=["POST"])
@_admin_required
def set_monitored_board_watermark():
    """Upload/replace the watermark applied to one scraped source's content."""
    source_type = (request.form.get("source-type") or "").strip()
    back = redirect(url_for("admin.dashboard") + "#board-monitoring")
    if not source_type:
        flash("Could not tell which source to watermark.")
        return back
    ok, message = _store_source_watermark(source_type, request.files.get("watermark-image"))
    flash(message if ok else "Watermark not saved: %s" % message)
    return back


@admin_blueprint.route("/monitored-boards/watermark/clear", methods=["POST"])
@_admin_required
def clear_monitored_board_watermark():
    source_type = (request.form.get("source-type") or "").strip()
    back = redirect(url_for("admin.dashboard") + "#board-monitoring")
    if source_type:
        old_media_id = clear_source_watermark(source_type)
        db.session.commit()
        invalidate_all_board_caches()
        if old_media_id is not None:
            _delete_media_record(old_media_id)
            db.session.commit()
        flash("Watermark cleared for %s." % source_type)
    return back


@admin_blueprint.route("/imported-media/repair", methods=["POST"])
@_admin_required
def repair_imported_media():
    """Re-mirror imported posts that are missing their image.

    Runs in a thread: a sweep re-downloads media from remote sites and must not
    block the request. Every repaired image goes through the normal upload gates,
    NSFW classifier included.
    """
    import threading
    from services.imported_media_repair import (
        run_imported_content_validate, run_imported_media_repair,
    )

    try:
        limit = max(1, min(int(request.form.get("limit") or 100), 1000))
    except ValueError:
        limit = 100

    def _run():
        with app.app_context():
            try:
                # Validate the SOURCE rows first (forcing past the "already asked"
                # marks, since this is a deliberate manual run), then mirror.
                checked, requested = run_imported_content_validate(limit=limit, force=True)
                threads, images = run_imported_media_repair(limit=limit)
                app.logger.info(
                    "manual repair: validated %d thread(s), requested %d re-fetch(es), "
                    "re-mirrored %d image(s) across %d thread(s)",
                    checked, requested, images, threads,
                )
            except Exception:
                app.logger.exception("manual media repair failed")
            finally:
                try:
                    db.session.remove()
                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True, name="media-repair-manual").start()
    flash(
        "Re-checking the %d most recent imported threads — asking the crawler to "
        "re-fetch any whose stored post is incomplete, then re-mirroring missing "
        "images. Reload in a moment; every image is NSFW-scanned." % limit
    )
    return redirect(url_for("admin.dashboard") + "#board-monitoring")


@admin_blueprint.route("/monitored-boards/target", methods=["POST"])
@_admin_required
def set_monitored_board_target():
    """Add a local board that a monitored remote board imports into.

    Additive: a remote board may feed several local boards, so this creates one
    whole-board BoardSource and leaves any existing ones alone. Use
    admin.remove_monitored_board_target to drop a single destination.
    """
    from board_sources import scrape_block_reason
    from services.aggregator_sync.config import WHOLE_BOARD_THREAD_ID

    source_type = (request.form.get("source-type") or "").strip()
    source_name = (request.form.get("source-name") or "").strip().strip("/")
    source_site = (request.form.get("site-url") or "").strip().rstrip("/") or None
    board_id = request.form.get("board-id", type=int)
    back = redirect(url_for("admin.dashboard") + "#board-monitoring")

    if not source_type or not source_name:
        flash("Could not tell which monitored board to change.")
        return back
    if not board_id:
        flash("Choose a local board to import into.")
        return back

    board = db.session.query(Board).filter(Board.id == board_id).one_or_none()
    if board is None:
        flash("That local board no longer exists.")
        return back

    blocked = scrape_block_reason(board, source_type, source_name, WHOLE_BOARD_THREAD_ID)
    if blocked is not None and blocked["code"] == "nntp" and request.form.get("allow-nntp"):
        blocked = None  # deliberate admin override; see add_monitored_board
    if blocked is not None:
        flash(
            "Cannot import into /%s/: %s.%s"
            % (board.name,
               "it syncs over NNTP (%s)" % ", ".join(blocked.get("newsgroups") or [])
               if blocked["code"] == "nntp"
               else "%s is banned from aggregation" % blocked.get("host", source_type),
               " Use the monitoring form's \"import anyway\" option to override."
               if blocked["code"] == "nntp" else "")
        )
        return back

    existing = (
        db.session.query(BoardSource)
        .filter(
            BoardSource.board_id == board.id,
            BoardSource.source_type == source_type,
            BoardSource.source_name == source_name,
            BoardSource.source_thread_id == WHOLE_BOARD_THREAD_ID,
        )
        .one_or_none()
    )
    if existing is not None:
        flash("/%s/ already imports %s /%s/." % (board.name, source_type, source_name))
        return back

    db.session.add(BoardSource(
        board_id=board.id,
        source_type=source_type,
        source_name=source_name,
        source_thread_id=WHOLE_BOARD_THREAD_ID,
        source_site=source_site,
    ))
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("could not add whole-board import target")
        flash("Could not save that destination.")
        return back
    flash(
        "%s /%s/ now imports into /%s/. Threads appear on the next sync."
        % (source_type, source_name, board.name)
    )
    return back


@admin_blueprint.route("/monitored-boards/target/<int:source_id>/remove", methods=["POST"])
@_admin_required
def remove_monitored_board_target(source_id):
    """Stop importing one monitored remote board into one local board.

    Only drops the mapping — the scraper keeps crawling the remote board (use
    "Stop" for that). Already-imported threads are NOT deleted here, but note
    that the next sync of that board prunes imported threads whose source is no
    longer configured, unless they carry local replies.
    """
    back = redirect(url_for("admin.dashboard") + "#board-monitoring")
    source = db.session.query(BoardSource).filter(BoardSource.id == source_id).one_or_none()
    if source is None:
        flash("That import mapping no longer exists.")
        return back
    board = db.session.query(Board).filter(Board.id == source.board_id).one_or_none()
    label = "%s /%s/" % (source.source_type, source.source_name)
    board_label = ("/%s/" % board.name) if board is not None else "that board"
    db.session.delete(source)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("could not remove whole-board import target")
        flash("Could not remove that destination.")
        return back
    flash(
        "%s no longer imports into %s. It is still being crawled; existing threads "
        "there may be pruned on the next sync unless they have local replies."
        % (label, board_label)
    )
    return back


@admin_blueprint.route("/monitored-boards/remove", methods=["POST"])
@_admin_required
def remove_monitored_board():
    """Stop monitoring a remote board. Already-imported threads are kept."""
    import scraper_client
    from services.aggregator_sync.config import WHOLE_BOARD_THREAD_ID

    source_type = (request.form.get("source-type") or "").strip()
    source_name = (request.form.get("source-name") or "").strip()
    source_site = (request.form.get("site-url") or "").strip().rstrip("/") or None
    if not source_type or not source_name:
        flash("Nothing to stop monitoring.")
        return redirect(url_for("admin.dashboard") + "#board-monitoring")

    messages = []
    if scraper_client.remove_monitored_board(source_type, source_name, site=source_site):
        messages.append("%s stopped discovering new threads on %s." % (source_type, source_name))
    else:
        messages.append("Could not reach the %s scraper to stop discovery." % source_type)

    removed = (
        db.session.query(BoardSource)
        .filter(
            BoardSource.source_type == source_type,
            BoardSource.source_name == source_name,
            BoardSource.source_thread_id == WHOLE_BOARD_THREAD_ID,
        )
        .delete(synchronize_session=False)
    )
    db.session.commit()
    if removed:
        messages.append(
            "Removed %d whole-board import link. Threads already imported stay put."
            % removed
        )
    flash(" ".join(messages))
    return redirect(url_for("admin.dashboard") + "#board-monitoring")


@admin_blueprint.route("/chans/add", methods=["POST"])
@_admin_required
def chan_add():
    from model.Federation import add_aggregated_chan
    try:
        chan = add_aggregated_chan(request.form.get("url"), request.form.get("name"))
    except ValueError as error:
        flash(str(error))
        return redirect(url_for("admin.dashboard") + "#chan-list")
    except Exception:
        db.session.rollback()
        app.logger.exception("could not add aggregated chan")
        flash("Could not add that chan.")
        return redirect(url_for("admin.dashboard") + "#chan-list")
    flash("Added %s to the aggregated chan list." % chan.url)
    return redirect(url_for("admin.dashboard") + "#chan-list")


@admin_blueprint.route("/chans/ping", methods=["POST"])
@_admin_required
def ping_chans():
    """Ping chans now, in a thread. Optional host= pings just that one."""
    import threading
    from services.chan_ping import run_chan_ping

    host = (request.form.get("host") or "").strip().lower() or None
    try:
        limit = max(1, min(int(request.form.get("limit") or 60), 400))
    except ValueError:
        limit = 60

    def _run():
        with app.app_context():
            try:
                # max_age_minutes=0 so a manual run re-checks everything rather
                # than skipping entries pinged recently.
                # force=True: an operator-initiated ping must run in whichever
                # worker served the request, not only in the maintenance leader.
                run_chan_ping(limit=limit, max_age_minutes=0, only_host=host, force=True)
            except Exception:
                app.logger.exception("manual chan ping failed")
            finally:
                try:
                    db.session.remove()
                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True, name="chan-ping-manual").start()
    flash(
        ("Pinging %s — reload in a moment." % host) if host
        else "Pinging up to %d chans — reload in a moment." % limit
    )
    return redirect(url_for("admin.dashboard") + "#chan-list")


@admin_blueprint.route("/chans/remove-selected", methods=["POST"])
@_admin_required
def chan_remove_selected():
    """Remove several chans from the aggregation list in one go."""
    from model.Federation import remove_aggregated_chans

    ids = request.form.getlist("chan-id")
    if not ids:
        flash("Tick the chans you want to remove first.")
        return redirect(url_for("admin.dashboard") + "#chan-list")
    try:
        removed = remove_aggregated_chans(ids)
    except Exception:
        db.session.rollback()
        app.logger.exception("bulk chan removal failed")
        flash("Could not remove those chans — nothing was changed.")
        return redirect(url_for("admin.dashboard") + "#chan-list")
    if not removed:
        flash("Those chans are no longer on the list.")
    else:
        preview = ", ".join(removed[:4]) + (", …" if len(removed) > 4 else "")
        flash("Removed %d chan%s from the aggregation list: %s"
              % (len(removed), "" if len(removed) == 1 else "s", preview))
    return redirect(url_for("admin.dashboard") + "#chan-list")


@admin_blueprint.route("/chans/<int:chan_id>/remove", methods=["POST"])
@_admin_required
def chan_remove(chan_id):
    from model.Federation import remove_aggregated_chan
    removed = remove_aggregated_chan(chan_id)
    flash(
        ("Removed %s from the aggregated chan list." % removed) if removed
        else "That chan is no longer on the list."
    )
    return redirect(url_for("admin.dashboard") + "#chan-list")


@admin_blueprint.route("/scrapers/export")
@_admin_required
def export_scraped_sources():
    """Download every configured scrape source as one reviewable text file.

    Reviewing sources one at a time in the UI takes hours; this is the same data
    sorted worst-first. `?save=1` also writes it to the repo root as
    aggregated_chans.txt (the repo is bind-mounted in this deployment, so that
    lands on the host); `?format=tsv` gives machine-readable columns.

    Safe on the request path: pure DB reads, and reachability comes from the
    CACHED ping columns. It must never ping — inline network work in a handler is
    what exhausted the connection pool once already.
    """
    from services.scraped_source_export import build_export, write_export

    want_tsv = (request.args.get("format") or "").strip().lower() == "tsv"
    save = (request.args.get("save") or "").strip() in ("1", "true", "yes", "on")
    try:
        if save:
            target, _rows, summary = write_export(tsv=want_tsv)
            text, _rows, summary = build_export(tsv=want_tsv)
            app.logger.info("scraped-source export written to %s", target)
        else:
            text, _rows, summary = build_export(tsv=want_tsv)
    except Exception:
        app.logger.exception("scraped-source export failed")
        flash("Could not build the scraped-source export — check the logs.")
        return redirect(url_for("admin.dashboard"))

    response = make_response(text)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = (
        'attachment; filename="aggregated_chans.%s"' % ("tsv" if want_tsv else "txt")
    )
    return response


def _scraped_max_age_hours():
    from services.scraped_retention import max_age_hours
    return max_age_hours()


def _scraped_metadata_days():
    from services.scraped_retention import metadata_retention_days
    return metadata_retention_days()


# NB: these two helpers must stay ABOVE this decorator. Inserting them between
# the route decorator and scrapers() made the decorator apply to the helper, so
# the endpoint became admin._scraped_max_age_hours, admin.scrapers stopped
# existing, and every url_for('admin.scrapers') on the dashboard raised
# BuildError -- a 500 on the whole admin page.
#
# AND IT HAPPENED AGAIN, IN PYTHON, 2026-08-20. That fix repaired the TEMPLATE
# references; the admin panel was later stripped and its templates deleted, so
# the template half went quiet -- while 53 url_for() calls to six endpoints
# that no longer exist stayed right here in this file, invisible to a scan that
# reads templates. Every one of them would do its work and THEN raise
# BuildError: a 500 AFTER the change, which is the worst available outcome and
# is precisely how POST /federation/request came to accept submissions and then
# error.
#
# All 53 now redirect to admin.dashboard, which exists. That is the CONSERVATIVE
# repair and not a judgement about whether these routes should survive: the
# ruling taken when main.federation was fixed applies unchanged -- "keeping the
# endpoint alive is the conservative choice; retiring it is a product decision,
# not a fix". Which of these admin controls should be deleted outright is
# OUTSTANDING.md 4.13e.
#
# tests/test_url_endpoints.py now scans the BLUEPRINTS as well as the templates,
# so the next one fails a test instead of a request.
def _scraping_is_paused():
    try:
        from services.aggregator_sync.state import scraping_paused

        return scraping_paused()
    except Exception:
        return False






def _known_scraper_types():
    """Every source type the admin panel should report on.

    The configured scrapers plus any source type that actually appears in
    imported content. Derived rather than hardcoded so standing up another
    aggregator container shows up in the analytics panel on its own -- the
    scraper image is already site-generic (SITE_KEY/BASE_URL), so the backend's
    fixed list was the only thing pinning the panel to four sites.
    """
    from services.aggregator_sync.config import SUPPORTED_SCRAPER_TYPES

    types = list(SUPPORTED_SCRAPER_TYPES)
    try:
        for query in (
            db.session.query(Thread.source_type)
            .filter(Thread.source_type.isnot(None), Thread.source_type != "local")
            .distinct(),
            # Configured-but-not-yet-imported sources too, so a generic site shows
            # up the moment it is wired up rather than after its first import.
            db.session.query(BoardSource.source_type)
            .filter(BoardSource.source_type.isnot(None), BoardSource.source_type != "local")
            .distinct(),
        ):
            for (source_type,) in query.all():
                if source_type and source_type not in types:
                    types.append(source_type)
    except Exception:
        app.logger.exception("could not derive scraped source types")
    return tuple(types)


def _scraper_runtime_statuses():
    import scraper_client

    statuses = {}
    for source_type in _known_scraper_types():
        base_url = scraper_client._url_for(source_type)
        if not base_url:
            statuses[source_type] = {"configured": False}
            continue
        try:
            response = requests.get("%s/status" % base_url.rstrip("/"), timeout=8)
            response.raise_for_status()
            payload = response.json()
            payload["configured"] = True
            payload["base_url"] = base_url
            statuses[source_type] = payload
        except Exception as exc:
            statuses[source_type] = {
                "configured": True,
                "base_url": base_url,
                "status": "unreachable",
                "error": str(exc),
            }
    return statuses


def _scrape_status_sources(db_stats, scraper_services, challenges):
    """One entry per selectable data source for the scrape-status page.

    Three kinds, because they are genuinely different things:
      * dedicated       -- 4chan/8chan/7chan/reddit: its own container AND its own DB.
      * generic-container -- the ONE shared generic scraper. Its runtime status
        (cycles, monitors, log) belongs here and is reported once. Previously this
        status was repeated under every generic host, because they all resolve to
        the same GENERIC_AGGREGATOR_URL — which read as duplicated data.
      * generic-site    -- one aggregated chan crawled by that shared container. It
        has its own SQLite file and its own monitored boards, but NO container of
        its own, so it points at the shared container for runtime state.
    """
    import scraper_client
    from services.aggregator_sync.config import SUPPORTED_SCRAPER_TYPES
    from services.aggregator_sync.scraper_db import (
        aggregator_db_path, is_generic_source_type,
    )

    sources = []
    for source_type in SUPPORTED_SCRAPER_TYPES:
        service = (scraper_services or {}).get(source_type) or {}
        sources.append({
            "key": source_type,
            "label": source_type,
            "kind": "dedicated",
            "configured": bool(service.get("configured", True)),
            "base_url": service.get("base_url") or scraper_client._url_for(source_type),
            "runtime": service,
            "runtime_from": source_type,
            "db": (db_stats or {}).get(source_type) or {},
            "monitored_boards": scraper_client.list_monitored_boards(source_type),
            "challenge": (challenges or {}).get(source_type),
        })

    generic_base = scraper_client._url_for("generic")
    generic_runtime = _generic_container_status(generic_base)
    sources.append({
        "key": "generic",
        "label": "generic scraper (shared container)",
        "kind": "generic-container",
        "configured": bool(generic_base),
        "base_url": generic_base,
        "runtime": generic_runtime,
        "runtime_from": "generic",
        "db": {},
        "monitored_boards": None,
        "challenge": None,
        "note": "Crawls every aggregated chan below. Each site has its own database.",
    })

    # Every generic host that is configured to be scraped, whether or not it has
    # produced content yet — a site with an empty DB is exactly what an operator
    # needs to see.
    hosts = set()
    for (source_type,) in (
        db.session.query(BoardSource.source_type)
        .filter(BoardSource.source_type.isnot(None))
        .distinct()
        .all()
    ):
        if source_type and is_generic_source_type(source_type):
            hosts.add(source_type)
    for (source_type,) in (
        db.session.query(Thread.source_type)
        .filter(Thread.source_type.isnot(None))
        .distinct()
        .all()
    ):
        if source_type and is_generic_source_type(source_type):
            hosts.add(source_type)

    for host in sorted(hosts):
        site_url = (
            db.session.query(BoardSource.source_site)
            .filter(BoardSource.source_type == host, BoardSource.source_site.isnot(None))
            .limit(1)
            .scalar()
        )
        sources.append({
            "key": host,
            "label": host,
            "kind": "generic-site",
            "configured": bool(generic_base),
            "base_url": generic_base,
            # Runtime state lives on the shared container, not per site.
            "runtime": generic_runtime,
            "runtime_from": "generic",
            "db": _generic_site_db_stats(host),
            "monitored_boards": scraper_client.list_monitored_boards(host),
            "challenge": None,
            "site_url": site_url,
            "db_path": _safe_db_path(host),
        })
    return sources


def _safe_db_path(source_type):
    from services.aggregator_sync.scraper_db import aggregator_db_path
    try:
        return aggregator_db_path(source_type)
    except Exception:
        return None


def _generic_container_status(base_url):
    """Runtime status of the shared generic scraper container."""
    if not base_url:
        return {"configured": False}
    payload, error = _proxy_get(base_url, "status")
    if payload is None:
        return {"configured": True, "status": "unreachable", "base_url": base_url, "error": error}
    payload["configured"] = True
    payload["base_url"] = base_url
    return payload


def _generic_site_db_stats(host):
    """Post/thread counts for one generic site's own SQLite file."""
    from services.aggregator_sync.scraper_db import _read_scraper_db
    path = _safe_db_path(host)
    if not path:
        return {"error": "no database path"}
    if not os.path.exists(path):
        # Configured but never crawled yet — distinct from "crawled, zero posts".
        return {"exists": False, "path": path, "posts": 0, "threads": 0}

    def _reader(connection):
        row = connection.execute(
            "SELECT COUNT(*), COUNT(DISTINCT thread_id), MAX(scraped_at) FROM posts"
        ).fetchone()
        boards = connection.execute(
            "SELECT board, COUNT(*) c, COUNT(DISTINCT thread_id) t FROM posts "
            "GROUP BY board ORDER BY c DESC LIMIT 25"
        ).fetchall()
        return {
            "exists": True, "path": path,
            "posts": row[0] or 0, "threads": row[1] or 0, "newest": row[2],
            "boards": [
                {"board": b[0], "posts": b[1], "threads": b[2]} for b in boards
            ],
        }

    try:
        return _read_scraper_db(path, _reader)
    except Exception as exc:
        return {"exists": True, "path": path, "error": str(exc)[:200]}


@admin_blueprint.route("/scrape-status/data.json")
@_admin_required
def scrape_status_data():
    try:
        from aggregator_sync import get_sync_status, get_aggregator_db_stats
        import scraper_client
        status_data = get_sync_status()
        db_stats = get_aggregator_db_stats()
        scraper_services = _scraper_runtime_statuses()
        challenges = {}
        for st in ("4chan", "8chan", "7chan"):
            challenge = scraper_client.get_challenge_status(st)
            if challenge:
                challenges[st] = challenge
    except Exception as exc:
        app.logger.exception("Failed to gather scrape status")
        return jsonify({"error": str(exc)}), 500

    reddit_metrics = {"configured": False}
    reddit_base = _reddit_aggregator_url()
    if reddit_base:
        reddit_metrics, reddit_error = _proxy_get(reddit_base, "metrics")
        if reddit_metrics is None:
            reddit_metrics = {
                "configured": True,
                "status": "unreachable",
                "base_url": reddit_base,
                "error": reddit_error,
            }
        else:
            reddit_metrics["configured"] = True
            reddit_metrics["base_url"] = reddit_base

    try:
        sources = _scrape_status_sources(db_stats, scraper_services, challenges)
    except Exception:
        app.logger.exception("could not build scrape-status source list")
        sources = []

    # Capped scrape queues. THIS WORKER ONLY: the counters live in process memory
    # and uwsgi runs `processes = 4`, so whichever worker serves this request is
    # the one being reported. Do not read a zero here as "nothing is queued
    # anywhere" — that mistake has been made before with sync's bg_cycles/is_leader.
    try:
        from services.scrape_queue import stats as _scrape_queue_stats

        queue_stats = _scrape_queue_stats()
        queue_stats["pid"] = os.getpid()
        queue_stats["scope"] = "this uWSGI worker only (of %s)" % (
            os.getenv("UWSGI_PROCESSES") or "4"
        )
    except Exception as exc:
        queue_stats = {"error": str(exc)}

    return jsonify({
        "sync": status_data,
        "db_stats": db_stats,
        "challenges": challenges,
        "reddit_container": reddit_metrics,
        "scraper_services": scraper_services,
        # Selectable per-source view (dedicated scrapers, the shared generic
        # container, and each aggregated chan it crawls).
        "sources": sources,
        "scrape_queues": queue_stats,
    })


def _scraper_proxy_timeout(path: str):
    first_segment = (path or "").split("/", 1)[0]
    if first_segment in {"challenge", "screenshot", "click", "type", "back", "scroll", "resolve"}:
        return (5, 45)
    return (5, 10)


@admin_blueprint.route("/scraper-proxy/<source_type>/<path:path>", methods=["GET", "POST"])
@_admin_required
def scraper_proxy(source_type, path):
    import scraper_client
    base = scraper_client._url_for(source_type)
    if not base:
        return "Scraper not configured", 404
    
    url = f"{base}/{path}"
    headers = {k: v for k, v in request.headers if k.lower() != 'host'}
    timeout = _scraper_proxy_timeout(path)
    
    try:
        if request.method == "POST":
            resp = requests.post(url, json=request.get_json(silent=True), headers=headers, timeout=timeout)
        else:
            resp = requests.get(url, params=request.args, headers=headers, timeout=timeout)
        
        return (resp.content, resp.status_code, resp.headers.items())
    except Exception as exc:
        app.logger.exception("Scraper proxy failed")
        return str(exc), 502


@admin_blueprint.route("/scrape-status/force", methods=["POST"])
@_admin_required
def scrape_status_force():
    from services.aggregator_sync.state import _sync_status
    from board_access import visible_boards
    from model.Board import Board as _Board

    if _sync_status.get("is_syncing"):
        flash("A sync is already in progress.")
        return redirect(url_for("admin.dashboard"))

    flask_app = app
    target_board_ids = [
        board.id
        for board in visible_boards(
            db.session.query(_Board).all(),
            include_geo_generated=True,
        )
    ]

    def _run_forced_sync():
        try:
            from aggregator_sync import sync_boards_if_due
            with flask_app.app_context():
                boards = (
                    db.session.query(_Board)
                    .filter(_Board.id.in_(target_board_ids))
                    .all()
                ) if target_board_ids else []
                sync_boards_if_due(boards, force=True)
        except Exception:
            flask_app.logger.exception("Forced scrape sync failed")
        finally:
            # This spawn had NO session cleanup: a forced sync leaked its
            # connection every time an admin pressed the button.
            try:
                db.session.remove()
            except Exception:
                pass

    # Capped queue with a fixed key, so repeated clicks cannot stack full syncs.
    from services.scrape_queue import submit as _submit_scrape

    if _submit_scrape("sync-forced", "forced-sync", _run_forced_sync,
                      label="admin forced sync (%d boards)" % len(target_board_ids)):
        flash("Sync started in the background.")
    else:
        flash("A sync is already queued — leaving it to finish.")
    return redirect(url_for("admin.dashboard"))


# ---------------------------------------------------------------------------
# Unified scraper analytics API  (all source types in one place)
# ---------------------------------------------------------------------------

def _reddit_aggregator_url():
    import scraper_client
    return scraper_client._url_for("reddit")


def _proxy_get(base_url, path, params=None):
    """GET a scraper endpoint, return (data, error_string)."""
    try:
        resp = requests.get("%s/%s" % (base_url.rstrip("/"), path.lstrip("/")),
                            params=params, timeout=8)
        resp.raise_for_status()
        return resp.json(), None
    except Exception as exc:
        return None, str(exc)


# URL avoids "analytics" so ad-block/privacy extensions don't block the fetch
# (see board_metrics above). Function name is unchanged for url_for() callers.
@admin_blueprint.route("/scrapers/activity.json")
@_admin_required
def scrapers_analytics():
    """
    Unified analytics across all source types.
    Returns per-source-type thread/post counts for the activity chart.
    Query params:
      sources  — comma-separated list of source types to include (default: all)
    """
    from services.aggregator_sync.scraper_db import aggregator_db_path, _read_scraper_db
    import sqlite3

    # Accept both "sources" and the "source" the dashboard JS actually sends.
    raw_requested = request.args.get("sources") or request.args.get("source") or ""
    requested = set(raw_requested.split(",")) - {""}
    all_types = _known_scraper_types()
    include = [t for t in all_types if not requested or t in requested]

    result = {}
    for source_type in include:
        try:
            db_path = aggregator_db_path(source_type)
        except ValueError:
            continue
        # `os` is imported at module scope; the local re-import here only made
        # pyflakes report a shadow, which hides real ones.
        if not os.path.exists(db_path):
            result[source_type] = {"unavailable": True}
            continue
        try:
            def _reader(conn, st=source_type):
                rows = conn.execute(
                    """SELECT board AS source_name,
                              COUNT(DISTINCT thread_id) AS thread_count,
                              COUNT(*) AS post_count,
                              MAX(scraped_at) AS last_scraped,
                              MIN(scraped_at) AS first_scraped
                       FROM posts WHERE board IS NOT NULL
                       GROUP BY board ORDER BY thread_count DESC"""
                ).fetchall()
                # daily activity — last 30 days
                activity = conn.execute(
                    """SELECT date(scraped_at) AS day, COUNT(*) AS posts
                       FROM posts
                       WHERE scraped_at >= date('now', '-30 days')
                       GROUP BY day ORDER BY day"""
                ).fetchall()
                total = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
                return rows, activity, total

            rows, activity, total = _read_scraper_db(db_path, _reader)
            result[source_type] = {
                "total_posts": total,
                "sources": [dict(r) for r in rows],
                "daily": {r["day"]: r["posts"] for r in activity},
            }
        except Exception as exc:
            result[source_type] = {"error": str(exc)}

    return jsonify({"by_source": result})


@admin_blueprint.route("/scrapers/posts.json")
@_admin_required
def scrapers_posts():
    """
    Search posts across selected source types.
    Query params: sources, q, source_name, limit (default 50)
    """
    from services.aggregator_sync.scraper_db import aggregator_db_path, _read_scraper_db
    import os

    # Accept both "sources" and the "source" the dashboard JS actually sends.
    raw_requested = request.args.get("sources") or request.args.get("source") or ""
    requested = set(raw_requested.split(",")) - {""}
    all_types = _known_scraper_types()
    include = [t for t in all_types if not requested or t in requested]
    q = request.args.get("q", "").strip()
    # The dashboard's search box posts this as "board"; keep "source_name" working
    # for any direct API caller. Reading only "source_name" silently ignored the
    # board filter for every search made from the UI.
    source_name_filter = (
        request.args.get("source_name") or request.args.get("board") or ""
    ).strip().lower()
    limit = min(int(request.args.get("limit", 50)), 200)

    combined = []
    per_source_limit = max(limit, 50)

    for source_type in include:
        try:
            db_path = aggregator_db_path(source_type)
        except ValueError:
            continue
        if not os.path.exists(db_path):
            continue
        try:
            def _reader(conn, st=source_type):
                sql = "SELECT *, ? AS source_type FROM posts WHERE post_id = thread_id"
                params = [st]
                if q:
                    sql += " AND (subject LIKE ? OR body_text LIKE ?)"
                    params += [f"%{q}%", f"%{q}%"]
                if source_name_filter:
                    sql += " AND board = ?"
                    params.append(source_name_filter)
                sql += " ORDER BY scraped_at DESC LIMIT ?"
                params.append(per_source_limit)
                return [dict(r) for r in conn.execute(sql, params).fetchall()]

            rows = _read_scraper_db(db_path, _reader)
            combined.extend(rows)
        except Exception:
            pass

    combined.sort(key=lambda r: r.get("scraped_at") or "", reverse=True)
    posts = combined[:limit]
    for p in posts:
        p["source"] = p.pop("source_type", "")
        p["board"] = p.get("board", "")
        p["subject"] = p.get("subject", "")
        p["author"] = p.get("author", "")
    return jsonify({"posts": posts})


# ---------------------------------------------------------------------------
# Reddit-specific admin routes
# ---------------------------------------------------------------------------

@admin_blueprint.route("/reddit/state.json")
@_admin_required
def reddit_state():
    base = _reddit_aggregator_url()
    if not base:
        return jsonify({"reachable": False, "configured": False})
    subreddits, err1 = _proxy_get(base, "subreddits")
    if err1:
        return jsonify({"reachable": False, "error": err1})
    jobs, err2 = _proxy_get(base, "jobs", {"limit": 20})
    job_stats, _ = _proxy_get(base, "jobs/stats")
    return jsonify({
        "reachable": True,
        "configured": True,
        "subreddits": subreddits or [],
        "recent_jobs": jobs or [],
        "job_stats": job_stats or {},
        "error": err2,
    })


@admin_blueprint.route("/reddit/subreddits/add", methods=["POST"])
@_admin_required
def reddit_add_subreddit():
    base = _reddit_aggregator_url()
    if not base:
        return jsonify({"error": "reddit aggregator not configured"}), 503
    payload = request.get_json(force=True, silent=True) or {}
    name = (payload.get("name") or "").strip().lstrip("r/")
    board_id = payload.get("board_id")
    if not name:
        return jsonify({"error": "name required"}), 400
    try:
        resp = requests.post(
            "%s/sources" % base.rstrip("/"),
            json={"name": name, "board_id": board_id},
            timeout=10,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@admin_blueprint.route("/reddit/subreddits/<name>/remove", methods=["POST"])
@_admin_required
def reddit_remove_subreddit(name):
    base = _reddit_aggregator_url()
    if not base:
        return jsonify({"error": "reddit aggregator not configured"}), 503
    try:
        resp = requests.delete("%s/sources/%s" % (base.rstrip("/"), name), timeout=10)
        resp.raise_for_status()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@admin_blueprint.route("/reddit/posts.json")
@_admin_required
def reddit_posts():
    base = _reddit_aggregator_url()
    if not base:
        return jsonify([])
    params = {k: v for k, v in request.args.items() if k in ("q", "subreddit", "author", "min_score", "post_type", "limit")}
    data, _ = _proxy_get(base, "posts", params)
    posts = data if isinstance(data, list) else (data or {}).get("posts", [])
    return jsonify({"posts": posts})


@admin_blueprint.route("/reddit/subreddits/<name>/stats.json")
@_admin_required
def reddit_subreddit_stats(name):
    base = _reddit_aggregator_url()
    if not base:
        return jsonify({}), 503
    data, err = _proxy_get(base, "subreddits/%s/stats" % name)
    if err:
        return jsonify({"error": err}), 502
    return jsonify(data or {})














@admin_blueprint.route("/algorithm-audits", methods=["POST"])
@_admin_required
def create_algorithm_audit():
    audit = generate_audit_package((request.form.get("scope") or "phase5")[:128])
    return redirect(url_for("admin.algorithm_audit", audit_id=audit.id))


@admin_blueprint.route("/algorithm-audits/<audit_id>", methods=["GET"])
@_admin_required
def algorithm_audit(audit_id):
    audit = db.session.get(AlgorithmAudit, audit_id)
    if audit is None:
        abort(404)
    return jsonify({
        "id": audit.id, "scope": audit.scope, "manifest": audit.manifest,
        "checksum": audit.checksum, "status": audit.status, "reviewer": audit.reviewer,
        "findings": audit.findings, "created_at": audit.created_at.isoformat() + "Z",
        "completed_at": audit.completed_at.isoformat() + "Z" if audit.completed_at else None,
    })


@admin_blueprint.route("/algorithm-audits/<audit_id>/review", methods=["POST"])
@_admin_required
def review_algorithm_audit(audit_id):
    audit = db.session.get(AlgorithmAudit, audit_id)
    if audit is None:
        abort(404)
    reviewer = (request.form.get("reviewer") or "").strip()
    if not reviewer:
        return jsonify({"error": "external reviewer is required"}), 400
    audit.reviewer = reviewer[:160]
    audit.findings = [value.strip()[:500] for value in request.form.getlist("findings") if value.strip()][:100]
    audit.status = "externally_reviewed"
    audit.completed_at = _datetime.datetime.utcnow()
    db.session.commit()
    return redirect(url_for("admin.algorithm_audit", audit_id=audit.id))


# =====================================================================
# NNTPChan (route-B federation) admin surface
# =====================================================================
def _nntp_preflight():
    """Whether NNTPChan can work here at all. Never raises: a diagnostic that
    can take the dashboard down with it is worse than no diagnostic."""
    try:
        from services.nntpchan.sync import preflight
        return preflight()
    except Exception:
        app.logger.exception("NNTPChan preflight failed")
        return {"checks": [], "ready": False}


def _nntp_list_peers():
    from model.NntpPeer import list_peers
    return list_peers()


def _nntp_list_group_maps():
    from model.NntpGroupMap import list_group_maps
    return list_group_maps()


def _nntp_list_address_blocks():
    from model.NntpAddressBlock import list_address_blocks
    return list_address_blocks()


def _nntp_sync_interval_minutes():
    from services.nntpchan.sync import INTERVAL_SETTING, DEFAULT_INTERVAL_MINUTES
    raw = get_setting(INTERVAL_SETTING, str(DEFAULT_INTERVAL_MINUTES))
    try:
        return max(0, int(str(raw).strip()))
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_MINUTES


def _nntp_publish_content_enabled():
    from services.nntpchan.publisher import publishing_enabled
    return publishing_enabled()


_NNTP_ANCHOR = "#nntpchan"


def _nntp_redirect():
    return redirect(url_for("admin.dashboard") + _NNTP_ANCHOR)


@admin_blueprint.route("/nntpchan/peers", methods=["POST"])
@_admin_required
def nntp_add_peer():
    from model.NntpPeer import add_peer
    try:
        add_peer(
            request.form.get("host", ""),
            port=request.form.get("port", "119"),
            use_tls=bool(request.form.get("use_tls")),
            description=request.form.get("description", ""),
        )
        db.session.commit()
        flash("NNTPChan peer added.")
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/peers/<int:peer_id>/delete", methods=["POST"])
@_admin_required
def nntp_delete_peer(peer_id):
    from model.NntpPeer import remove_peer
    if remove_peer(peer_id):
        db.session.commit()
        flash("NNTPChan peer removed.")
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/groups", methods=["POST"])
@_admin_required
def nntp_add_group_map():
    from model.NntpGroupMap import add_group_map
    try:
        add_group_map(request.form.get("newsgroup", ""), request.form.get("board_id"))
        db.session.commit()
        flash("Newsgroup mapped to board.")
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/groups/<int:map_id>/delete", methods=["POST"])
@_admin_required
def nntp_delete_group_map(map_id):
    from model.NntpGroupMap import remove_group_map
    if remove_group_map(map_id):
        db.session.commit()
        flash("Newsgroup mapping removed.")
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/address-block", methods=["POST"])
@_admin_required
def nntp_add_address_block():
    from model.NntpAddressBlock import block_address
    acting_slip = get_slip()
    try:
        block_address(
            request.form.get("address", ""),
            reason=request.form.get("reason", ""),
            created_by_slip_id=acting_slip.id if acting_slip else None,
        )
        db.session.commit()
        flash("Address blocked from federated import.")
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/address-block/<int:block_id>/delete", methods=["POST"])
@_admin_required
def nntp_delete_address_block(block_id):
    from model.NntpAddressBlock import unblock_address
    if unblock_address(block_id):
        db.session.commit()
        flash("Address unblocked.")
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/settings", methods=["POST"])
@_admin_required
def nntp_save_settings():
    from services.nntpchan.sync import INTERVAL_SETTING
    raw = (request.form.get("interval_minutes") or "").strip()
    try:
        minutes = max(0, int(raw))
    except (TypeError, ValueError):
        flash("Sync interval must be a whole number of minutes (0 disables).")
        return _nntp_redirect()
    set_setting(INTERVAL_SETTING, str(minutes))
    from services.nntpchan.publisher import (
        PUBLISH_SETTING, SOURCE_LABEL_SETTING, SOURCE_WATERMARK_SETTING,
    )
    set_setting(PUBLISH_SETTING, "1" if request.form.get("publish_content") else "0")
    set_setting(SOURCE_LABEL_SETTING, (request.form.get("source_label") or "").strip())
    set_setting(SOURCE_WATERMARK_SETTING, (request.form.get("source_watermark_url") or "").strip())
    set_setting("nntpchan_require_watermark", "1" if request.form.get("require_watermark") else "0")
    tombstone_days = (request.form.get("tombstone_days") or "").strip()
    try:
        tombstone_days = str(max(0, int(tombstone_days)))
    except (TypeError, ValueError):
        tombstone_days = "30"
    set_setting("nntpchan_tombstone_days", tombstone_days)
    # Optional hub admin token (for XDELGROUP). Blank keeps the current value;
    # a literal "-" clears it.
    hub_token = (request.form.get("hub_admin_token") or "").strip()
    if hub_token == "-":
        set_setting("nntpchan_hub_admin_token", "")
    elif hub_token:
        set_setting("nntpchan_hub_admin_token", hub_token)
    db.session.commit()
    flash("NNTPChan sync settings saved (interval %d min, 0 = disabled)." % minutes)
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/sync-now", methods=["POST"])
@_admin_required
def nntp_sync_now():
    # Run one pass off the request thread so a slow peer never blocks the admin
    # response (mirrors the background loop's own app-context handling).
    import shared
    from services.nntpchan.sync import preflight, sync_now

    # Say so BEFORE starting a pass that cannot import anything. "Sync started"
    # on a deployment with no I2P proxy and no mapped groups is a lie that costs
    # the operator an afternoon of wondering where their articles went.
    state = preflight()
    if not state.get("ready"):
        blocked = [c["name"] for c in state.get("checks", []) if not c["ok"]]
        flash("NNTPChan is not ready to sync: %s. See the checks on this card."
              % ", ".join(blocked))
        return _nntp_redirect()

    shared.spawn_native_thread(target=sync_now, name="nntpchan-sync-now", daemon=True)
    flash("NNTPChan sync started; imported content will appear shortly.")
    return _nntp_redirect()


# =====================================================================
# NNTPChan distance-based image banlist (federated fingerprints)
# =====================================================================
def _nntp_list_fingerprints():
    from model.BannedImageFingerprint import list_fingerprints
    return list_fingerprints()


def _nntp_fingerprint_settings():
    from model.BannedImageFingerprint import distance_threshold
    from services.nntpchan.banlist import (
        banlist_group, ingest_enabled, NODE_ID_SETTING, SECRET_SETTING, DEFAULT_NODE_ID,
    )
    return {
        "threshold": distance_threshold(),
        "banlist_group": banlist_group(),
        "ingest": ingest_enabled(),
        "node_id": get_setting(NODE_ID_SETTING, DEFAULT_NODE_ID),
        "secret_set": bool((get_setting(SECRET_SETTING, "") or "").strip()),
    }


@admin_blueprint.route("/nntpchan/fingerprint/from-post/<int:post_id>", methods=["POST"])
@_admin_required
def nntp_ban_fingerprint_from_post(post_id):
    from model.BannedImageFingerprint import add_local_fingerprint
    from model.Media import Media, storage
    from services.perceptual import compute_fingerprint
    post, _thread, _board = get_post_thread_board_or_404(post_id)
    if post.media is None:
        flash("That post has no image to fingerprint.")
        return _nntp_redirect()
    media = db.session.query(Media).get(post.media)
    if media is None or not (media.mimetype or "").startswith("image/"):
        flash("That post's media is not a fingerprintable image.")
        return _nntp_redirect()
    fingerprint_hex = media.fingerprint
    if not fingerprint_hex:
        # Older media predating the fingerprint column: derive it from the
        # stored bytes and backfill.
        try:
            data = storage.read_attachment_bytes(media.id, media.ext)
            computed = compute_fingerprint(data)
            if computed is not None:
                fingerprint_hex = computed[2]
                media.fingerprint = fingerprint_hex
                db.session.add(media)
        except Exception:
            db.session.rollback()
            app.logger.exception("fingerprint backfill failed for media %s", media.id)
    if not fingerprint_hex:
        flash("Could not compute an image fingerprint for that media.")
        return _nntp_redirect()
    acting_slip = get_slip()
    try:
        row = add_local_fingerprint(
            fingerprint_hex,
            reason=request.form.get("reason", ""),
            created_by_slip_id=acting_slip.id if acting_slip else None,
            sha256=media.sha256,
        )
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc))
        return _nntp_redirect()
    if row is None:
        flash("That image fingerprint is already banned.")
    else:
        flash("Image banned by fingerprint; broadcasts to peers on the next sync.")
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/fingerprint/<int:fp_id>/delete", methods=["POST"])
@_admin_required
def nntp_delete_fingerprint(fp_id):
    # Remove a fingerprint banned by mistake / not actually banworthy. If peers
    # were told about it, this queues an "unban" broadcast so they can re-test
    # their banlist and drop the matching entry too.
    from model.BannedImageFingerprint import revoke_fingerprint
    if revoke_fingerprint(fp_id):
        db.session.commit()
        flash("Image fingerprint removed; an unban will broadcast to peers on the next sync.")
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/fingerprint-settings", methods=["POST"])
@_admin_required
def nntp_save_fingerprint_settings():
    from model.BannedImageFingerprint import THRESHOLD_SETTING, invalidate_cache
    from services.nntpchan.banlist import (
        BANLIST_GROUP_SETTING, INGEST_SETTING, SECRET_SETTING, NODE_ID_SETTING,
        DEFAULT_BANLIST_GROUP, DEFAULT_NODE_ID,
    )
    threshold = (request.form.get("threshold") or "").strip()
    try:
        float(threshold)
    except ValueError:
        flash("Distance threshold must be a number (average per-cell difference, 0-255).")
        return _nntp_redirect()
    set_setting(THRESHOLD_SETTING, threshold)
    set_setting(BANLIST_GROUP_SETTING, (request.form.get("banlist_group") or "").strip() or DEFAULT_BANLIST_GROUP)
    set_setting(INGEST_SETTING, "1" if request.form.get("ingest") else "0")
    set_setting(NODE_ID_SETTING, (request.form.get("node_id") or "").strip() or DEFAULT_NODE_ID)
    # Only overwrite the shared secret when a value is supplied, so saving other
    # settings doesn't wipe it; a literal "-" clears it.
    secret = (request.form.get("secret") or "").strip()
    if secret == "-":
        set_setting(SECRET_SETTING, "")
    elif secret:
        set_setting(SECRET_SETTING, secret)
    db.session.commit()
    invalidate_cache()
    flash("Image distance-ban settings saved.")
    return _nntp_redirect()


@admin_blueprint.route("/nntpchan/newsgroups.json")
@_admin_required
def nntp_newsgroups_json():
    """Enumerate every newsgroup the peer(s) carry — not just locally-mapped
    ones — with metadata (peer article count, whether mapped + to which board,
    how many we've imported, whether it's the banlist group)."""
    from model.NntpPeer import list_peers
    from model.NntpGroupMap import list_group_maps
    from model.NntpArticle import NntpArticle
    from services.nntpchan.client import NNTPClient
    from services.nntpchan.banlist import banlist_group as _banlist_group
    from sqlalchemy import func as _func

    maps = {gm.newsgroup: (gm.id, gm.board_id, gm.enabled) for gm in list_group_maps()}
    board_names = {b.id: b.name for b in db.session.query(Board).all()}
    imported = {
        ng: cnt
        for ng, cnt in db.session.query(
            NntpArticle.newsgroup, _func.count(NntpArticle.id)
        ).group_by(NntpArticle.newsgroup).all()
    }
    banlist = _banlist_group()

    groups = {}
    errors = []
    for peer in list_peers(enabled_only=True):
        try:
            with NNTPClient(peer.host, peer.port, peer.use_tls, timeout=12) as client:
                for name, high, low in client.list_active_groups("*"):
                    g = groups.setdefault(name, {"high": 0, "low": 0, "peers": []})
                    g["high"] = max(g["high"], high)
                    if low:
                        g["low"] = low if not g["low"] else min(g["low"], low)
                    if peer.host not in g["peers"]:
                        g["peers"].append(peer.host)
        except Exception as exc:
            errors.append("%s:%s — %s" % (peer.host, peer.port, exc))

    # Include locally-mapped groups even if the peer returned nothing for them.
    for name in maps:
        groups.setdefault(name, {"high": 0, "low": 0, "peers": []})

    rows = []
    for name in sorted(groups.keys()):
        g = groups[name]
        mapping = maps.get(name)
        articles = (g["high"] - g["low"] + 1) if (g["high"] and g["low"]) else g["high"]
        rows.append({
            "newsgroup": name,
            "articles": max(0, articles),
            "peers": g["peers"],
            "mapped": mapping is not None,
            "map_id": mapping[0] if mapping else None,
            "board_id": mapping[1] if mapping else None,
            "board_name": board_names.get(mapping[1]) if mapping else None,
            "enabled": bool(mapping[2]) if mapping else None,
            "imported": imported.get(name, 0),
            "is_banlist": name == banlist,
        })
    return jsonify({"groups": rows, "errors": errors})


@admin_blueprint.route("/nntpchan/hub/delete-group", methods=["POST"])
@_admin_required
def nntp_hub_delete_group():
    """Delete a newsgroup (and its articles) from the NNTP hub, and drop any
    local mapping for it. Affects every server that shares the hub."""
    from model.NntpPeer import list_peers
    from model.NntpGroupMap import NntpGroupMap
    from services.nntpchan.client import NNTPClient
    group = (request.form.get("newsgroup") or "").strip()
    if not group:
        flash("Newsgroup is required.")
        return _nntp_redirect()
    token = (get_setting("nntpchan_hub_admin_token", "") or "").strip() or None
    results = []
    for peer in list_peers(enabled_only=True):
        try:
            with NNTPClient(peer.host, peer.port, peer.use_tls, timeout=12) as client:
                client.delete_group(group, token=token)
                results.append("%s: ok" % peer.host)
        except Exception as exc:
            results.append("%s: %s" % (peer.host, exc))
    # Drop any local newsgroup->board mapping (the group no longer exists).
    db.session.query(NntpGroupMap).filter(NntpGroupMap.newsgroup == group).delete(synchronize_session=False)
    db.session.commit()
    flash("Deleted '%s' from hub — %s" % (group, "; ".join(results) if results else "no peers configured"))
    return _nntp_redirect()


# ── Arcade ────────────────────────────────────────────────────────────────────
# Operational view of the ported CodePlay features: content inventory, judge
# health, who is playing, and a way to reset a slip that has been cheating.



@admin_blueprint.route("/lab-challenges/create", methods=["POST"])
@_admin_required
def create_lab_challenge():
    from services import lab_registry
    slip = get_slip()
    # Supporting files (optional): each uploaded file becomes a path in the
    # build context, named by its filename.
    files = {}
    for storage in request.files.getlist("files"):
        if storage and storage.filename:
            name = werkzeug_secure_relpath(storage.filename)
            if name:
                files[name] = storage.read()
    try:
        challenge = lab_registry.create_challenge(
            name=request.form.get("name", ""),
            description=request.form.get("description", ""),
            dockerfile=request.form.get("dockerfile", ""),
            files=files,
            primary_port=request.form.get("primary_port", 80),
            is_lab=request.form.get("is_lab") in ("1", "true", "on", "yes"),
            created_by_slip_id=(slip.id if slip is not None else None),
            difficulty=request.form.get("difficulty", "Medium"),
            os=request.form.get("os", "Linux"),
        )
    except lab_registry.RegistryError as exc:
        flash(exc.message)
        return redirect(url_for("admin.dashboard"))
    # Announce the build context to the DHT now if a node is bridged, so users
    # can deploy it immediately. When no node is connected it stays pending and
    # a later publish (or the next spin-up) announces it.
    from services import attack_range as lab
    published = 0
    try:
        published = lab.publish_pending_contexts()
    except Exception:
        app.logger.exception("lab: publish on challenge create failed")
    flash("Challenge '%s' added to the registry (%s).%s" % (
        challenge.name, challenge.build_digest[:19],
        " Published to the DHT." if published else
        (" Not yet on the DHT — no container node is connected." if not lab.dcs_connected() else ""),
    ))
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/lab-challenges/<int:challenge_id>/update", methods=["POST"])
@_admin_required
def update_lab_challenge(challenge_id):
    """Edit a challenge's presentation metadata (difficulty, OS) from the
    registry table. Returns JSON for the inline-edit fetch."""
    from model.LabChallenge import LabChallenge
    from services.lab_registry import _clean_difficulty, _clean_os
    challenge = db.session.query(LabChallenge).filter(LabChallenge.id == challenge_id).one_or_none()
    if challenge is None:
        return jsonify({"error": "no such challenge"}), 404
    if "difficulty" in request.form:
        challenge.difficulty = _clean_difficulty(request.form.get("difficulty"))
    if "os" in request.form:
        challenge.os = _clean_os(request.form.get("os"))
    if "skills" in request.form:
        # Which skill-radar axes this box exercises. Unknown names are dropped
        # rather than stored: a typo would otherwise create a silent axis that
        # feeds nothing and looks like it works.
        from services.codeplay import SKILL_AXIS_KEYS
        from services.lab_skills import parse_skills
        wanted = [axis for axis in parse_skills(request.form.get("skills"))
                  if axis in SKILL_AXIS_KEYS]
        challenge.skills = ",".join(dict.fromkeys(wanted))[:200]
    db.session.commit()
    return jsonify({"ok": True, "difficulty": challenge.difficulty,
                    "os": challenge.os, "skills": challenge.skills})


@admin_blueprint.route("/lab-challenges/<int:challenge_id>/delete", methods=["POST"])
@_admin_required
def delete_lab_challenge(challenge_id):
    from services import lab_registry
    try:
        lab_registry.delete_challenge(challenge_id)
        flash("Challenge retired. New deploys can no longer use it.")
    except lab_registry.RegistryError as exc:
        flash(exc.message)
    return redirect(url_for("admin.dashboard"))


def _lab_challenges_anchor(challenge_id):
    dest = url_for("admin.dashboard")
    return dest + ("#challenge-%d" % challenge_id if challenge_id else "")


@admin_blueprint.route("/lab-challenges/<int:challenge_id>/questions/add", methods=["POST"])
@_admin_required
def add_lab_question(challenge_id):
    """Add a scored question (with a suggested-answer example) to a challenge."""
    from services import lab_registry
    try:
        lab_registry.add_question(
            challenge_id,
            prompt=request.form.get("prompt", ""),
            example_answer=request.form.get("example_answer", ""),
            expected_answer=request.form.get("expected_answer", ""),
            answer_kind=request.form.get("answer_kind", "static"),
            tier=request.form.get("tier", ""),
            points=request.form.get("points", 10),
        )
        flash("Question added.")
    except lab_registry.RegistryError as exc:
        flash(exc.message)
    return redirect(_lab_challenges_anchor(challenge_id))


@admin_blueprint.route("/lab-questions/<int:question_id>/update", methods=["POST"])
@_admin_required
def update_lab_question(question_id):
    from services import lab_registry
    fields = {
        key: request.form.get(key)
        for key in ("prompt", "example_answer", "expected_answer", "answer_kind",
                    "tier", "points", "position")
        if key in request.form
    }
    fields["active"] = request.form.get("active") in ("1", "true", "on", "yes")
    try:
        challenge_id = lab_registry.update_question(question_id, **fields)
        flash("Question updated.")
    except lab_registry.RegistryError as exc:
        flash(exc.message)
        from model.LabQuestion import question_by_id
        found = question_by_id(question_id)
        challenge_id = found.challenge_id if found else None
    return redirect(_lab_challenges_anchor(challenge_id))


@admin_blueprint.route("/lab-questions/<int:question_id>/delete", methods=["POST"])
@_admin_required
def delete_lab_question(question_id):
    from services import lab_registry
    challenge_id = lab_registry.delete_question(question_id)
    flash("Question deleted." if challenge_id else "No such question.")
    return redirect(_lab_challenges_anchor(challenge_id))


# --- Codeplay content (editable questions/answers for every aspect) ----------

def _codeplay_anchor(collection):
    return url_for("admin.dashboard") + ("#col-%s" % collection if collection else "")




# Generation runs in a background thread and reports through this, the same
# shape the vulhub import uses. A request that waited on the model would sit
# for minutes and time out at the proxy long before it finished.
_codeplay_generate_state = {"on": False, "last": None}


@admin_blueprint.route("/codeplay/generate", methods=["POST"])
@_admin_required
def codeplay_generate_content():
    """Generate new items for one collection with the configured model."""
    import threading

    from services import codeplay_generate, openai_api

    if not openai_api.configured():
        flash("No OpenAI key is configured, so nothing can be generated.")
        return redirect(url_for("admin.dashboard"))
    if _codeplay_generate_state["on"]:
        flash("A generation run is already going; let it finish.")
        return redirect(url_for("admin.dashboard"))

    collection = (request.form.get("collection") or "").strip()
    if collection not in codeplay_generate.COLLECTIONS:
        flash("Choose a collection to generate for.")
        return redirect(url_for("admin.dashboard"))
    try:
        count = int(request.form.get("count") or 10)
    except (TypeError, ValueError):
        count = 10
    category = (request.form.get("category") or "").strip() or None
    difficulty = (request.form.get("difficulty") or "").strip() or None

    flask_app = app._get_current_object()

    def run():
        _codeplay_generate_state["on"] = True
        try:
            with flask_app.app_context():
                report = codeplay_generate.generate(
                    collection, count, category=category, difficulty=difficulty)
                _codeplay_generate_state["last"] = report
                flask_app.logger.info("codeplay generation: %s", report)
        except Exception as exc:  # noqa: BLE001 - surfaced on the page, never raised here
            _codeplay_generate_state["last"] = {
                "collection": collection, "asked": count, "accepted": 0,
                "rejected_invalid": 0, "rejected_duplicate": 0,
                "errors": [str(exc)],
            }
            flask_app.logger.exception("codeplay generation failed")
        finally:
            _codeplay_generate_state["on"] = False

    threading.Thread(target=run, daemon=True).start()
    flash("Generating %d %s items — the page updates as they land." % (count, collection))
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/codeplay/add", methods=["POST"])
@_admin_required
def codeplay_add():
    import json as _json
    from services import codeplay_content as cc
    collection = request.form.get("collection", "")
    try:
        payload = _json.loads(request.form.get("payload", "") or "{}")
        cc.add_item(collection, payload, difficulty=request.form.get("difficulty") or None)
        flash("Added item to %s." % collection)
    except Exception as exc:
        flash("Could not add item: %s" % exc)
    return redirect(_codeplay_anchor(collection))


@admin_blueprint.route("/codeplay/<int:row_id>/update", methods=["POST"])
@_admin_required
def codeplay_update(row_id):
    import json as _json
    from services import codeplay_content as cc
    from model.CodeplayContent import item_by_id
    row = item_by_id(row_id)
    collection = row.collection if row else ""
    try:
        payload = _json.loads(request.form.get("payload", "")) if request.form.get("payload") else None
        active = request.form.get("active") in ("1", "true", "on", "yes")
        cc.update_item(row_id, payload=payload, active=active)
        flash("Updated item.")
    except Exception as exc:
        flash("Could not update: %s" % exc)
    return redirect(_codeplay_anchor(collection))


@admin_blueprint.route("/codeplay/<int:row_id>/delete", methods=["POST"])
@_admin_required
def codeplay_delete(row_id):
    from services import codeplay_content as cc
    collection = cc.delete_item(row_id) or ""
    flash("Deleted item." if collection else "No such item.")
    return redirect(_codeplay_anchor(collection))


@admin_blueprint.route("/codeplay/publish", methods=["POST"])
@_admin_required
def codeplay_publish():
    from services import codeplay_content as cc
    try:
        pub = cc.publish_to_dht()
        flash("Published to the DHT: %s" % (", ".join(pub.keys()) if pub else "nothing (no endpoint / failed — see logs)"))
    except Exception as exc:
        flash("Publish failed: %s" % exc)
    return redirect(url_for("admin.dashboard"))


@admin_blueprint.route("/codeplay/reseed", methods=["POST"])
@_admin_required
def codeplay_reseed():
    from services import codeplay_content as cc
    added = cc.seed_from_bundled(force=True)
    flash("Re-seeded missing items: %s" % (added or "none (all present)"))
    return redirect(url_for("admin.dashboard"))


# --- Content search + purge (moderation) -------------------------------------

@admin_blueprint.route("/purge")
@_admin_required
def purge_search():
    """Search media by hash / id / NSFW score / kind / post keyword, so an admin
    can find and purge specific explicit content."""
    from services import media_purge
    args = request.args
    did_search = any(args.get(k) for k in ("q", "sha256", "media_id", "min_nsfw", "kind"))
    results = []
    if did_search:
        results = media_purge.search(
            text=args.get("q") or None, sha256=args.get("sha256") or None,
            media_id=args.get("media_id") or None, min_nsfw=args.get("min_nsfw") or None,
            kind=args.get("kind") or None, limit=200,
        )
    return render_template(
        "admin-purge.html", results=results, did_search=did_search,
        q=args.get("q", ""), sha256=args.get("sha256", ""), media_id=args.get("media_id", ""),
        min_nsfw=args.get("min_nsfw", ""), kind=args.get("kind", ""),
    )


POF_CONTRACTS_SETTING = "pof_contracts"


@admin_blueprint.route("/contracts")
@_admin_required
def contracts_console():
    """Wallet-connected console to DEPLOY the Proof-of-Facilitation contracts
    (owner = the connected wallet) and INTERACT with them (ABI-driven)."""
    from services.pof_genesis import get_genesis

    from model.Store import credits_per_dollar

    # The sale rate is passed in so the console can price a mint in dollars
    # before asking to confirm it. One rate, read from where the store keeps it,
    # rather than a second copy that could drift.
    return render_template("admin-contracts.html", genesis=get_genesis(create=False),
                           sale_rate=credits_per_dollar())


# Manual credit grants.
#
# Every other way credits move is keyed to something automatic — a Stripe
# session, a subscription invoice, an epoch receipt. This is the path for when
# one of those goes wrong, which it did: a delivery that credited the wrong
# amount leaves somebody short, and without this the only remedies were to mint
# a second time (losing track of why) or to tell them no.
@admin_blueprint.route("/contracts/grants.json")
@_admin_required
def contracts_grants():
    from model.CreditGrant import open_grants, recent_grants, total_granted

    def row(grant):
        return {
            "id": grant.id,
            "wallet": grant.wallet,
            "credits": int(grant.credits or 0),
            "reason": grant.reason,
            "purchase_id": grant.purchase_id,
            "tx_hash": grant.tx_hash,
            "sent": grant.sent,
            "created_at": grant.created_at.isoformat() + "Z" if grant.created_at else None,
        }

    response = jsonify({
        "pending": [row(g) for g in open_grants()],
        "recent": [row(g) for g in recent_grants()],
        "total_granted": total_granted(),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_blueprint.route("/contracts/grants", methods=["POST"])
@_admin_required
def contracts_grant_create():
    """Record an intent to send credits. The transfer itself is signed in the
    browser; this is the row that says who authorised it and why.

    Recorded BEFORE the transaction rather than after, so a transfer that lands
    while the browser is closed still has a record pointing at it. An unexplained
    movement out of the treasury is the one thing this ledger exists to prevent.
    """
    from model.CreditGrant import CreditGrant

    payload = request.get_json(silent=True) or {}
    wallet = str(payload.get("wallet") or "").strip().lower()
    reason = str(payload.get("reason") or "").strip()
    try:
        credits = int(payload.get("credits") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "AXONCoins must be a whole number."}), 400

    if len(wallet) != 42 or not wallet.startswith("0x"):
        return jsonify({"error": "Recipient must be a 0x address."}), 400
    if credits <= 0:
        return jsonify({"error": "Enter how many AXONCoins to send."}), 400
    if not reason:
        # Required, and not as ceremony: a year from now the only way to answer
        # "why does this address have 40 credits" is that somebody wrote it down
        # at the time.
        return jsonify({"error": "Say what this grant is for."}), 400

    purchase_id = payload.get("purchase_id")
    try:
        purchase_id = int(purchase_id) if purchase_id else None
    except (TypeError, ValueError):
        purchase_id = None

    slip = get_slip()
    grant = CreditGrant(
        wallet=wallet, credits=credits, reason=reason[:255],
        purchase_id=purchase_id,
        granted_by_slip_id=slip.id if slip else None,
    )
    db.session.add(grant)
    db.session.commit()
    app.logger.info("credit grant %d recorded: %d credits to %s (%s)",
                    grant.id, credits, wallet, reason[:80])
    return jsonify({"ok": True, "id": grant.id})


@admin_blueprint.route("/contracts/grants/<int:grant_id>/sent", methods=["POST"])
@_admin_required
def contracts_grant_sent(grant_id):
    """Record that a grant's transfer landed on-chain."""
    from model.CreditGrant import CreditGrant

    payload = request.get_json(silent=True) or {}
    grant = (
        db.session.query(CreditGrant)
        .filter(CreditGrant.id == grant_id)
        .one_or_none()
    )
    if grant is None:
        return jsonify({"error": "No such grant."}), 404
    if grant.tx_hash:
        # Already recorded. Reported rather than overwritten: two transactions
        # for one grant means somebody sent twice, and quietly replacing the
        # first hash would erase the evidence of it.
        return jsonify({"ok": True, "already": True, "tx_hash": grant.tx_hash})

    if payload.get("ok"):
        grant.tx_hash = str(payload.get("tx_hash") or "")[:80]
        grant.sent_at = _datetime.datetime.utcnow()
        db.session.commit()
        app.logger.info("credit grant %d sent: %s", grant.id, grant.tx_hash)
        return jsonify({"ok": True})

    # Failed. The row stays, unsent, so it is still on the work list.
    return jsonify({"ok": True, "recorded": False})


@admin_blueprint.route("/contracts/deliveries.json")
@_admin_required
def contracts_deliveries():
    """Paid credit purchases still owed delivery.

    Payment and delivery are tracked apart on purpose: this list is exactly the
    money taken that has not yet been honoured, which is the number an operator
    needs to be able to see at a glance.
    """
    from model.CreditPurchase import undelivered

    rows = [{
        "id": p.id,
        "wallet": p.wallet,
        "credits": int(p.credits or 0),
        "dollars": "%.2f" % ((p.amount_cents or 0) / 100.0),
        "paid_at": p.paid_at.isoformat() + "Z" if p.paid_at else None,
    } for p in undelivered()]
    response = jsonify({"pending": rows, "owed_credits": sum(r["credits"] for r in rows)})
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_blueprint.route("/contracts/deliveries/send", methods=["POST"])
@_admin_required
def contracts_delivery_send():
    """Deliver a queued purchase from the SERVER, using the Treasury owner key.

    The existing flow signs in the admin's browser, which stopped working the
    moment Treasury ownership moved to a dedicated wallet: MetaMask is connected
    as a personal account that is no longer the owner, so releaseOrder reverts
    with OwnableUnauthorizedAccount. Correctly — that separation is the point,
    and it is why the key lives on the server instead.

    This is the other half of that move. The server already holds the owner key
    and services/token_delivery already knows how to spend it; it was only ever
    wired to the Stripe webhook, so purchases queued BEFORE automatic delivery
    existed had nothing to trigger them.

    Every guard the webhook path has applies here unchanged — the ceiling, the
    orderFilled check, the contract's own refusal to fill an order twice — so a
    double click costs a read rather than a double delivery.
    """
    from model.CreditPurchase import CreditPurchase, STATUS_PAID, mark_delivered
    from services import token_delivery

    payload = request.get_json(silent=True) or {}
    try:
        purchase_id = int(payload.get("id"))
    except (TypeError, ValueError):
        return jsonify({"error": "id is required"}), 400

    purchase = db.session.query(CreditPurchase).filter(
        CreditPurchase.id == purchase_id).one_or_none()
    if purchase is None:
        return jsonify({"error": "no such purchase"}), 404
    if purchase.status != STATUS_PAID:
        # Only a PAID purchase is owed anything. Delivering against a pending or
        # already-delivered row would send tokens for a payment that has not
        # confirmed, or send them twice.
        return jsonify({"error": "purchase is %s, not paid" % purchase.status}), 400

    if not token_delivery.enabled():
        return jsonify({"error":
            "Automatic delivery is not configured on this server, so there is "
            "no key here that can spend the Treasury."}), 503

    try:
        tx_hash = token_delivery.deliver(purchase)
    except token_delivery.DeliveryError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("admin: delivery failed for purchase %d", purchase.id)
        return jsonify({"error": "The delivery transaction could not be sent."}), 502

    mark_delivered(purchase, tx_hash)
    db.session.commit()
    return jsonify({"ok": True, "tx_hash": tx_hash, "status": purchase.status})


@admin_blueprint.route("/contracts/deliveries/result", methods=["POST"])
@_admin_required
def contracts_delivery_result():
    """Record that a purchase's credits reached the buyer's wallet."""
    from model.CreditPurchase import CreditPurchase, mark_delivered

    payload = request.get_json(silent=True) or {}
    try:
        purchase_id = int(payload.get("id"))
    except (TypeError, ValueError):
        return jsonify({"error": "id is required"}), 400
    purchase = db.session.query(CreditPurchase).filter(
        CreditPurchase.id == purchase_id).one_or_none()
    if purchase is None:
        return jsonify({"error": "no such purchase"}), 404
    if payload.get("ok"):
        mark_delivered(purchase, payload.get("tx_hash") or "")
        db.session.commit()
        return jsonify({"ok": True, "status": purchase.status})
    # Left as paid, not failed: the buyer is still owed these credits and the
    # queue must keep showing that until they are actually sent.
    return jsonify({"ok": True, "status": purchase.status, "note": "left queued"})


@admin_blueprint.route("/snapshot/revoke", methods=["POST"])
@_admin_required
def snapshot_revoke():
    """Stop every gateway serving a snapshot.

    For a snapshot that leaked something, carried injected script, or is simply
    wrong. Cumulative and signed: gateways drop it rather than merely flagging
    it, and fall back to the previous one.
    """
    from services.snapshot_control import revoke

    sequences = request.form.getlist("sequence") or []
    try:
        sequences = [int(value) for value in sequences if str(value).strip()]
    except (TypeError, ValueError):
        return jsonify({"error": "sequence must be a number"}), 400
    if not sequences:
        return jsonify({"error": "nothing to revoke"}), 400
    record = revoke(sequences=sequences,
                    reason=request.form.get("reason") or "security")
    return jsonify({"ok": True, "revoked": record["revoked_sequences"],
                    "record": record["sequence"],
                    "signed": bool(record["signature"])})


@admin_blueprint.route("/snapshot/defensive-mode", methods=["POST"])
@_admin_required
def snapshot_defensive():
    """Shed read traffic to the gateways for a bounded time.

    Deliberately bounded — the maximum is enforced in the service, not taken
    from this form. A mode with no ceiling is one an extra zero typed under
    pressure leaves on for a week.
    """
    from services.snapshot_control import clear_defensive_mode, declare_defensive_mode

    if (request.form.get("action") or "").lower() == "clear":
        clear_defensive_mode()
        return jsonify({"ok": True, "mode": "NORMAL"})
    try:
        seconds = int(request.form.get("seconds") or 3600)
    except (TypeError, ValueError):
        return jsonify({"error": "seconds must be a number"}), 400
    record = declare_defensive_mode(
        seconds, reason=request.form.get("reason") or "origin_overload")
    return jsonify({"ok": True, "expires_at": record["expires_at"],
                    "signed": bool(record["signature"])})


@admin_blueprint.route("/snapshot/collect", methods=["POST"])
@_admin_required
def snapshot_collect():
    """Drop snapshots and objects nothing retained still references."""
    from services.snapshot_store import collect

    return jsonify(collect())


@admin_blueprint.route("/threats.json")
@_admin_required
def threats_overview():
    """What the scorer WOULD have done, so thresholds come from evidence.

    This is the entire deliverable of phase 1. Nothing is enforced, so the only
    thing worth looking at is the shape of the distribution and which signals
    are firing — a reason that fires on everything is miscalibrated, and one
    that never fires is dead weight pretending to be defence.
    """
    import datetime

    from model.ThreatEvent import ThreatEvent, distribution, top_reasons

    try:
        hours = max(1, min(int(request.args.get("hours") or 24), 24 * 14))
    except (TypeError, ValueError):
        hours = 24
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)

    worst = (db.session.query(ThreatEvent)
             .filter(ThreatEvent.at >= since)
             .order_by(ThreatEvent.score.desc(), ThreatEvent.id.desc())
             .limit(25).all())

    import json as _json

    return jsonify({
        "window_hours": hours,
        "enforcing": False,
        "note": "Observe-only. Nothing here was blocked or challenged; "
                "would_have is what the current thresholds WOULD have done.",
        "distribution": distribution(since),
        "top_reasons": top_reasons(since),
        "worst": [{
            # Masked even in the admin view. The full address is in the table
            # for the one job it has -- telling clients apart -- and an
            # interface that prints it invites copying it somewhere public.
            "network": _mask(event.address),
            "country": event.country,
            "score": event.score,
            "band": event.band,
            "would_have": event.would_have,
            "path": event.path,
            "at": event.at.isoformat() + "Z",
            "reasons": _json.loads(event.reasons or "[]"),
        } for event in worst],
    })


def _mask(address):
    """A /24 or /32 -- enough to recognise a network, not enough to name a person.

    Applied at every point anything is displayed rather than at storage, because
    the log genuinely needs whole addresses to tell one client from another
    while no interface ever needs to show one.
    """
    if not address:
        return ""
    if ":" in address:
        return ":".join(address.split(":")[:2]) + "::/32"
    parts = address.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else address


@admin_blueprint.route("/snapshot/build", methods=["POST"])
@_admin_required
def snapshot_build():
    """Build and activate one emergency snapshot, in THIS process.

    Deliberately an endpoint rather than a command. Running the builder as a
    separate process means importing the app a second time, which re-runs the
    startup DDL against the database the live process is already using — those
    statements take AccessExclusiveLock, and doing it once already deadlocked
    against the running server and took the pod down.

    So the build happens where the app already is, and anything outside asks.
    """
    from services.snapshot import build_and_publish

    result = build_and_publish()
    return jsonify(result), (200 if result.get("ok") else 409)


@admin_blueprint.route("/cutover", methods=["GET"])
@_admin_required
def cutover_status():
    """The write freeze, and the order a cutover has to happen in."""
    from services.cutover import DEFAULT_FREEZE_SECONDS, MAX_FREEZE_SECONDS, current, plan
    from services.succession import restore_checklist

    return jsonify({
        "freeze": current(),
        "default_seconds": DEFAULT_FREEZE_SECONDS,
        "maximum_seconds": MAX_FREEZE_SECONDS,
        "cutover_plan": plan(request.args.get("server") or "",
                             request.args.get("domain") or ""),
        "cold_restore_checklist": restore_checklist(
            request.args.get("domain") or ""),
    })


@admin_blueprint.route("/cutover/freeze", methods=["POST"])
@_admin_required
def cutover_freeze():
    """Stop accepting writes so a backup can be a complete record.

    The first step of a cutover, and the one whose absence produces no error:
    a backup taken while posts are still landing is missing whatever arrived
    after it started, and that only shows up later as posts that are gone.
    """
    from services.cutover import freeze

    payload = request.get_json(silent=True) or {}
    record = freeze(payload.get("seconds"),
                    reason=payload.get("reason") or "cutover",
                    note=payload.get("note") or "")
    return jsonify({"ok": True, "freeze": record})


@admin_blueprint.route("/cutover/thaw", methods=["POST"])
@_admin_required
def cutover_thaw():
    """Accept writes again.

    Deliberately reachable while frozen — see services/cutover.ALWAYS_OPEN. A
    freeze that locks the operator out of the endpoint that lifts it turns a
    planned cutover into a real outage.
    """
    from services.cutover import thaw

    thaw()
    return jsonify({"ok": True, "freeze": None})


@admin_blueprint.route("/backup", methods=["POST"])
@_admin_required
def backup_download():
    """Produce an encrypted backup and hand it back.

    The passphrase is supplied here and never stored. That is the whole point:
    the artifact is meant to be held by gateways, so nothing on this server may
    be able to open it — otherwise seizing this server yields both the copies
    and the means to read them.

    Streamed as one response rather than written to disk. A plaintext-adjacent
    file left in a container is a copy nobody remembers to delete.
    """
    from services.backup import BackupError, dump_stream, encrypt

    payload = request.get_json(silent=True) or {}
    passphrase = payload.get("passphrase") or ""
    try:
        blob = encrypt(dump_stream(), passphrase,
                       extra={"instance": app.config.get("INSTANCE_NAME") or ""})
    except BackupError as error:
        # No logging of the passphrase, obviously — but also not of its length,
        # which is a real hint when combined with a stolen artifact.
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("backup: could not build one")
        return jsonify({"error": "The backup could not be built. The log says "
                                 "why; nothing was written."}), 500

    from services.backup import split

    envelope, _, _ = split(blob)
    response = make_response(blob)
    response.headers["Content-Type"] = "application/octet-stream"
    response.headers["Content-Disposition"] = (
        'attachment; filename="syndichan-backup-%s.bin"'
        % _datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S"))
    # Published so a holder can be challenged on it later without ever being
    # able to decrypt it.
    response.headers["X-Syndichan-Ciphertext-SHA256"] = envelope["ciphertext_sha256"]
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_blueprint.route("/backup/verify", methods=["POST"])
@_admin_required
def backup_verify():
    """Check an artifact is intact, without needing the passphrase.

    The question a storage challenge asks a gateway, answerable here too so an
    operator can confirm a copy is still good without decrypting it — and
    therefore without the plaintext ever existing on this machine.
    """
    from services.backup import BackupError, split, verify

    upload = request.files.get("backup")
    if upload is None:
        return jsonify({"error": "No file was uploaded."}), 400
    blob = upload.read()
    try:
        envelope, _, body = split(blob)
    except BackupError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({
        "intact": verify(blob),
        "created_at": envelope.get("created_at"),
        "ciphertext_bytes": envelope.get("ciphertext_bytes"),
        "ciphertext_sha256": envelope.get("ciphertext_sha256"),
        "note": "Intact means these are the bytes that were made. It does NOT "
                "mean the contents are genuine — whoever rewrote the ciphertext "
                "could rewrite this digest beside it. Only the passphrase "
                "holder can answer that, from the AEAD tags, at restore time.",
    })


@admin_blueprint.route("/network-directive", methods=["GET"])
@_admin_required
def network_directive_admin():
    """Issue the signed statement of where this network lives."""
    from services import network_directive as nd

    return render_template(
        "admin-network-directive.html",
        current=nd.current(),
        history=list(reversed(nd.history()))[:20],
        next_sequence=nd.next_sequence(),
        frozen=nd.frozen(),
        wallet=nd.admin_wallet(),
        delay_seconds=nd.DEFAULT_DELAY_SECONDS,
    )


@admin_blueprint.route("/network-directive/preview", methods=["POST"])
@_admin_required
def network_directive_preview():
    """The exact text to sign, built HERE rather than in the browser.

    The bytes that get signed have to be the bytes the server will verify. A
    page that assembles its own message is a page that can drift from the
    verifier by one space and produce signatures that fail for reasons nobody
    can see. So the browser asks for the text, shows it, and signs it verbatim.
    """
    import time

    from services import network_directive as nd

    payload = request.get_json(silent=True) or {}
    try:
        directive = nd.build(
            payload.get("kind") or nd.KIND_MOVE,
            payload.get("sequence") or nd.next_sequence(),
            int(time.time()),
            origin_domain=payload.get("origin_domain") or "",
            origin_address=payload.get("origin_address") or "",
            origin_key=payload.get("origin_key") or "",
            emergency=bool(payload.get("emergency")),
            note=payload.get("note") or "",
        )
        nd.check_acceptable(directive)
    except nd.DirectiveError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({"directive": directive, "canonical": nd.canonical(directive),
                    "rehearsal": nd.rehearse(directive)})


@admin_blueprint.route("/network-directive", methods=["POST"])
@_admin_required
def network_directive_issue():
    """Verify a wallet signature over a directive and put it into force.

    Being logged in as admin is NOT sufficient. The signature is the authority
    here, because this document travels to machines that have no session with
    us and can only check the wallet — so a directive accepted on the strength
    of a cookie would be one nothing downstream could verify.
    """
    from services import network_directive as nd

    payload = request.get_json(silent=True) or {}
    directive = payload.get("directive") or {}
    signature = (payload.get("signature") or "").strip()
    if not signature:
        return jsonify({"error": "A wallet signature is required."}), 400

    # Rebuilt from the signed fields alone. Anything else the browser sent is
    # not covered by the signature and must not survive into what is stored.
    directive = {field: directive.get(field) for field in nd.SIGNED_FIELDS}
    try:
        nd.check_acceptable(directive)
    except nd.DirectiveError as error:
        return jsonify({"error": str(error)}), 409

    expected = nd.admin_wallet()
    if not expected:
        return jsonify({
            "error": "No ADMIN_WALLET_ADDRESS is configured, so there is no "
                     "wallet to check this against. Set it before issuing a "
                     "directive — nodes verify against a pinned address and "
                     "would refuse anything issued now.",
        }), 409

    try:
        signer = nd.verify_signature(directive, signature)
    except RuntimeError:
        return jsonify({"error": "Signature verification is unavailable right "
                                 "now. Nothing was changed."}), 502
    if signer is None:
        return jsonify({"error": "That signature did not verify."}), 400
    if signer.strip().lower() != expected:
        # Logged loudly: a valid signature from the wrong wallet is either a
        # wallet switch nobody meant to make, or an attempt.
        app.logger.error("network directive REFUSED: signed by %s, expected %s",
                         signer, expected)
        return jsonify({"error": "That signature is from %s, but this network "
                                 "is pinned to %s." % (signer, expected)}), 403

    record = nd.accept(directive, signature, signer)

    # Published to the object store as well as the well-known URL. That is the
    # one path a node can read without the origin being up, its domain
    # resolving, or its certificate being valid — all three of which a
    # directive may be announcing the loss of.
    #
    # Reported rather than fatal: the directive is already in force, and
    # failing the whole issuance because a secondary publication did not land
    # would leave the operator unsure which parts happened.
    published = nd.publish_to_dht()
    return jsonify({
        "ok": True, "directive": record, "published_to_dht": published,
        "note": None if published else
        "The directive is in force and served at "
        "/.well-known/syndichan/network.json, but could NOT be written to the "
        "object store. Nodes that cannot reach this domain will not learn "
        "about the move — check the log and retry before relying on it.",
    })


@admin_blueprint.route("/node-releases", methods=["GET"])
@_admin_required
def node_releases_admin():
    """What is currently downloadable from /network, and what is missing."""
    from services.node_release import PLATFORMS, binary_name, index

    published = index()
    rows = [{
        "key": "%s-%s" % (platform["os"], platform["arch"]),
        "os": platform["os"], "arch": platform["arch"],
        "label": platform["label"],
        "binary": binary_name(platform),
        "published": published.get("%s-%s" % (platform["os"], platform["arch"])),
    } for platform in PLATFORMS]
    if request.args.get("format") == "json":
        return jsonify({"platforms": rows})
    return render_template("admin-node-releases.html", rows=rows)


@admin_blueprint.route("/node-releases", methods=["POST"])
@_admin_required
def node_releases_publish():
    """Upload one node binary and publish its hash.

    An upload rather than a file in the image. Six platforms is ~180 MB that
    would ride in every deploy, on a host that has already had its images
    garbage-collected out from under it by disk pressure, for files that change
    only when the node is rebuilt. `dist/` is gitignored, so they were never in
    the image anyway.

    The platform is taken from the form AND from the file's own header, and they
    have to agree — see services.node_release.executable_platform.
    """
    from services.node_release import PLATFORMS, publish

    upload = request.files.get("binary")
    if upload is None:
        return jsonify({"error": "No file was uploaded."}), 400

    wanted_os = (request.form.get("os") or "").strip().lower()
    wanted_arch = (request.form.get("arch") or "").strip().lower()
    if not any(p["os"] == wanted_os and p["arch"] == wanted_arch for p in PLATFORMS):
        return jsonify({"error": "Unknown platform %s/%s." % (wanted_os, wanted_arch)}), 400

    body = upload.read()
    if not body:
        return jsonify({"error": "The uploaded file was empty."}), 400

    entry = publish("%s-%s" % (wanted_os, wanted_arch), body,
                    version=(request.form.get("version") or "").strip()[:64],
                    toolchain=(request.form.get("toolchain") or "").strip()[:64])
    if entry is None:
        return jsonify({
            "error": "Not published. Either the file is not a %s/%s executable, "
                     "or the object store did not accept and return it — the log "
                     "says which." % (wanted_os, wanted_arch),
        }), 409
    return jsonify({"ok": True, "platform": "%s-%s" % (wanted_os, wanted_arch),
                    **entry})


@admin_blueprint.route("/contracts/settlement", methods=["POST"])
@_admin_required
def contracts_settlement_store():
    """Store a settlement produced by pof-settle, before it is submitted.

    Computing and posting are separate decisions: an operator should be able to
    read what a run produced — including who it refused to pay and why — before
    spending gas committing to it.
    """
    import json as _json

    from model.PofSettlement import PofSettlement, settlement_for_epoch

    payload = request.get_json(silent=True) or {}
    try:
        epoch = int(payload.get("epoch"))
    except (TypeError, ValueError):
        return jsonify({"error": "epoch is required"}), 400

    def root(name):
        value = str(payload.get(name) or "").strip().lower()
        return value if value.startswith("0x") and len(value) == 66 else ""

    receipt_root, reward_root = root("receipt_root"), root("reward_root")
    if not receipt_root or not reward_root:
        return jsonify({"error": "receipt_root and reward_root must be 32-byte hex"}), 400

    existing = settlement_for_epoch(epoch)
    if existing is not None and existing.submitted_tx:
        # Already on-chain. Overwriting would leave the site disagreeing with
        # the chain about what was committed, which is worse than refusing.
        return jsonify({
            "error": "Epoch %d is already submitted (tx %s)." % (epoch, existing.submitted_tx),
        }), 409

    claims = payload.get("claims") or []
    rejections = payload.get("rejections") or []
    record = existing or PofSettlement(epoch=epoch)
    record.receipt_root = receipt_root
    record.reward_root = reward_root
    record.node_state_root = root("node_state_root") or ("0x" + "0" * 64)
    record.randomness = root("randomness") or ("0x" + "0" * 64)
    record.total_rewards = str(payload.get("total_rewards") or "0")[:80]
    record.accepted = int(payload.get("accepted") or 0)
    record.rejected = int(payload.get("rejected") or 0)
    record.rejections = _json.dumps(rejections)[:20000]
    record.claims = _json.dumps(claims)[:2000000]
    if existing is None:
        db.session.add(record)
    db.session.commit()
    return jsonify({"ok": True, "epoch": epoch, "claims": len(claims)})


@admin_blueprint.route("/contracts/settlement/<int:epoch>.json")
@_admin_required
def contracts_settlement_get(epoch):
    """The stored settlement for an epoch, for the console to submit."""
    from model.PofSettlement import settlement_for_epoch

    record = settlement_for_epoch(epoch)
    if record is None:
        return jsonify({"error": "No settlement stored for epoch %d." % epoch}), 404
    import json as _json

    response = jsonify({
        "epoch": record.epoch,
        "receipt_root": record.receipt_root,
        "reward_root": record.reward_root,
        "node_state_root": record.node_state_root,
        "randomness": record.randomness,
        "total_rewards": record.total_rewards,
        "accepted": record.accepted,
        "rejected": record.rejected,
        "rejections": _json.loads(record.rejections or "[]"),
        "claim_count": len(record.claim_rows()),
        "submitted_tx": record.submitted_tx,
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_blueprint.route("/contracts/settlement/submitted", methods=["POST"])
@_admin_required
def contracts_settlement_submitted():
    """Record that an epoch's roots reached the chain."""
    import datetime as _dt

    from model.PofSettlement import settlement_for_epoch

    payload = request.get_json(silent=True) or {}
    try:
        epoch = int(payload.get("epoch"))
    except (TypeError, ValueError):
        return jsonify({"error": "epoch is required"}), 400
    record = settlement_for_epoch(epoch)
    if record is None:
        return jsonify({"error": "no settlement stored for that epoch"}), 404
    record.submitted_tx = str(payload.get("tx_hash") or "")[:80]
    record.submitted_at = _dt.datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True})


@admin_blueprint.route("/contracts/registrations.json")
@_admin_required
def contracts_registrations():
    """Nodes queued for on-chain registration.

    Their ed25519 proofs were verified when they queued, so this list is not an
    approval queue — it is a work list of registrations waiting on gas.
    """
    from model.PofRegistration import pending_registrations

    rows = []
    for record in pending_registrations():
        rows.append({
            "id": record.id,
            "p2p_public_key": record.p2p_public_key,
            "wallet": record.wallet,
            "capabilities": int(record.capabilities or 0),
            "endpoint_commitment": record.endpoint_commitment or ("0x" + "0" * 64),
            "nonce": int(record.nonce or 0),
            "v": int(record.sig_v or 0),
            "r": record.sig_r,
            "s": record.sig_s,
            # A node files its own registration with the ed25519 proof only — it
            # holds no wallet key and cannot produce the secp256k1 half. Which
            # half is present decides which contract call can register it, so it
            # is reported rather than left for the console to guess.
            "has_wallet_signature": bool(
                int(record.sig_v or 0) and record.sig_r and record.sig_s),
            "queued_at": record.created_at.isoformat() + "Z" if record.created_at else None,
            "error": record.error,
        })
    response = jsonify({"pending": rows})
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_blueprint.route("/contracts/registrations/result", methods=["POST"])
@_admin_required
def contracts_registration_result():
    """Record how one registration's on-chain submission went."""
    from model.PofRegistration import mark_failed, mark_submitted

    payload = request.get_json(silent=True) or {}
    try:
        record_id = int(payload.get("id"))
    except (TypeError, ValueError):
        return jsonify({"error": "id is required"}), 400
    if payload.get("ok"):
        record = mark_submitted(record_id, payload.get("tx_hash") or "")
    else:
        record = mark_failed(record_id, payload.get("error") or "submission failed")
    if record is None:
        return jsonify({"error": "no such registration"}), 404
    db.session.commit()
    return jsonify({"ok": True, "status": record.status})


@admin_blueprint.route("/contracts/genesis/arm", methods=["POST"])
@_admin_required
def contracts_genesis_arm():
    """Mint the genesis seed (once) so it can be posted on-chain.

    Separate from submitting: the seed must exist and be published before any
    node can compute its first witness set, and minting it is not the same
    decision as spending gas to commit it.
    """
    from services.pof_genesis import get_genesis

    record = get_genesis(create=True)
    return jsonify({
        "ok": True,
        "seed": record["seed"],
        "epoch": record.get("epoch", 0),
        "created_at": record.get("created_at"),
        "submitted_tx": record.get("submitted_tx"),
        "already_armed": record.get("submitted_tx") is not None,
    })


@admin_blueprint.route("/contracts/genesis/submitted", methods=["POST"])
@_admin_required
def contracts_genesis_submitted():
    """Record the genesis transaction hash after the wallet posted it."""
    from services.pof_genesis import mark_submitted

    tx_hash = (request.get_json(silent=True) or {}).get("tx_hash") or ""
    tx_hash = tx_hash.strip()[:80]
    if not tx_hash:
        return jsonify({"error": "tx_hash is required"}), 400
    record = mark_submitted(tx_hash)
    if record is None:
        return jsonify({"error": "Genesis has not been armed"}), 400
    return jsonify({"ok": True, "submitted_tx": record["submitted_tx"]})


@admin_blueprint.route("/contracts/addresses.json")
@_admin_required
def contracts_addresses():
    import json as _json
    from model.SiteSetting import get_setting
    raw = get_setting(POF_CONTRACTS_SETTING, "") or "{}"
    try:
        data = _json.loads(raw)
    except ValueError:
        data = {}
    response = jsonify(data)
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_blueprint.route("/contracts/addresses", methods=["POST"])
@_admin_required
def contracts_save_addresses():
    """Persist deployed contract addresses (per network) so the console, the
    aggregator, and the gateway all read the same set."""
    import json as _json
    from model.SiteSetting import set_setting
    data = request.get_json(silent=True) or {}
    set_setting(POF_CONTRACTS_SETTING, _json.dumps(data)[:20000])
    db.session.commit()
    return jsonify({"ok": True})


@admin_blueprint.route("/purge/execute", methods=["POST"])
@_admin_required
@csrf_protect
def purge_execute():
    """Purge the selected media: blocklist the hash, delete from the DHT, and
    delete referencing posts/videos + the Media row."""
    from services import media_purge
    acting = get_slip()
    ids = request.form.getlist("media_ids")
    if not ids and request.form.get("media_id"):
        ids = [request.form.get("media_id")]
    reason = request.form.get("reason") or "admin content purge"
    results = media_purge.purge_media_ids(
        ids, reason=reason, acting_slip_id=(acting.id if acting else None)
    )
    purged = sum(1 for r in results if r.get("ok"))
    posts = sum(r.get("posts_deleted", 0) for r in results)
    failed = [r for r in results if not r.get("ok")]
    try:
        invalidate_front_page_cache()
        invalidate_activity_cache()
    except Exception:
        app.logger.exception("purge: cache invalidation failed")
    msg = ("Purged %d media object(s) from the site store and the DHT gateway, "
           "deleted %d post(s); hashes blocklisted so they can't be re-uploaded. "
           "Shards already held by other peers are NOT recalled."
           % (purged, posts))
    if failed:
        msg += " %d failed (see logs)." % len(failed)
    flash(msg)
    return redirect(url_for("admin.purge_search"))


# --- DHT object purge --------------------------------------------------------
#
# Separate from the media search-and-purge above, and deliberately so. That page
# answers "find explicit content and get rid of it"; this one answers "delete
# THIS object out of the distributed store and tell me exactly which layers that
# reached". The second question has a different and less comfortable answer --
# remote shards are not recallable -- and it needs a preview and a typed
# confirmation rather than a checkbox.


def _dht_purge_actor():
    """(slip_id, wallet, ip) for the audit row."""
    from model.Slip import ADMIN_WALLET_SESSION_KEY
    from services.client_ip import get_client_ip

    acting = get_slip()
    try:
        ip = get_client_ip()
    except Exception:
        ip = None
    return (acting.id if acting else None,
            session.get(ADMIN_WALLET_SESSION_KEY) or configured_admin_wallet_address(),
            ip)


def _render_dht_purge(preview=None, result=None, target="", reason="", error=None,
                      listing=None, ledger=None, detail=None,
                      list_bucket="", list_prefix="", list_marker=""):
    from model.DhtPurgeAudit import recent
    from services import dht_object_purge

    try:
        history = recent(limit=25)
    except Exception:
        db.session.rollback()
        app.logger.exception("dht purge: could not read the audit log")
        history = []
    return render_template(
        "admin-dht-purge.html",
        preview=preview, result=result, target=target, reason=reason,
        error=error, history=history,
        listing=listing, ledger=ledger, detail=detail,
        list_bucket=list_bucket, list_prefix=list_prefix, list_marker=list_marker,
        buckets=sorted(dht_object_purge.KNOWN_BUCKETS.items()),
        remote_note=dht_object_purge.REMOTE_SHARDS_RECALLABLE,
        holders_note=dht_object_purge.REMOTE_HOLDERS_UNKNOWN,
    )


@admin_blueprint.route("/dht-purge")
@_admin_required
def dht_purge():
    """The purge page, which now also LISTS what the DHT holds.

    One page, not two. The list exists so an operator can find the thing to
    delete; splitting it off would mean copying a canonical target between two
    screens, which is how the wrong key gets purged.
    """
    from services import dht_object_purge

    bucket = (request.args.get("bucket") or "").strip().lower()
    prefix = (request.args.get("prefix") or "").strip()
    marker = (request.args.get("marker") or "").strip()
    listing = ledger = None
    error = None
    try:
        ledger = dht_object_purge.ledger_summary()
    except Exception:
        app.logger.exception("dht purge: ledger summary failed")
        ledger = {"available": False, "error": "the summary call raised"}
    if bucket:
        try:
            listing = dht_object_purge.list_placements(bucket, prefix, marker)
        except dht_object_purge.TargetError as exc:
            error = str(exc)
        except Exception as exc:
            app.logger.exception("dht purge: listing failed for %r", bucket)
            error = "Could not list %s: %s" % (bucket, exc)
    return _render_dht_purge(ledger=ledger, listing=listing, error=error,
                             list_bucket=bucket, list_prefix=prefix,
                             list_marker=marker)


@admin_blueprint.route("/dht-purge/object")
@_admin_required
def dht_purge_object():
    """The per-shard view of one object: every shard, its size, and the peers
    that confirmed holding it -- which is the axis a per-shard delete needs and
    the one the ledger's own index cannot provide."""
    from services import dht_object_purge

    target = (request.args.get("target") or "").strip()
    try:
        parsed = dht_object_purge.parse_target(target)
    except dht_object_purge.TargetError as exc:
        return _render_dht_purge(target=target, error=str(exc))
    if parsed["kind"] != "object":
        return _render_dht_purge(
            target=target,
            error="Shard detail is per object; %s names a media row with "
                  "several. Open one of its keys." % parsed["canonical"])
    try:
        detail = dht_object_purge.object_placement(parsed["bucket"], parsed["key"])
    except Exception as exc:
        app.logger.exception("dht purge: placement lookup failed for %r", target)
        return _render_dht_purge(target=target,
                                 error="Could not read the ledger: %s" % exc)
    detail["canonical"] = parsed["canonical"]
    detail["bucket"] = parsed["bucket"]
    detail["key"] = parsed["key"]
    return _render_dht_purge(detail=detail, target=parsed["canonical"],
                             list_bucket=parsed["bucket"])


@admin_blueprint.route("/dht-purge/recall", methods=["POST"])
@_admin_required
@csrf_protect
def dht_purge_recall():
    """Recall shards from their holders WITHOUT deleting the object.

    Same retype-to-confirm gate as a purge: it destroys data on other operators'
    machines, and the fact that the object survives here does not make that less
    true.
    """
    from services import dht_object_purge

    target = (request.form.get("target") or "").strip()
    reason = (request.form.get("reason") or "").strip() or None
    confirmation = (request.form.get("confirm") or "").strip()
    shard_ids = [s.strip() for s in request.form.getlist("shard") if s.strip()]
    slip_id, wallet, ip = _dht_purge_actor()
    try:
        result = dht_object_purge.recall(
            target, confirmation, shard_ids=shard_ids, reason=reason,
            acting_slip_id=slip_id, acting_wallet=wallet, acting_ip=ip)
    except dht_object_purge.TargetError as exc:
        return _render_dht_purge(target=target, reason=reason or "", error=str(exc))
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("dht purge: recall failed for %r", target)
        return _render_dht_purge(target=target, reason=reason or "",
                                 error="The recall failed: %s" % exc)
    if result["outcome"] == "refused":
        return _render_dht_purge(
            target=target, reason=reason or "",
            error="The confirmation did not match. Type %r exactly. Nothing was "
                  "recalled." % result["target"])
    return _render_dht_purge(result=result, target=target, reason=reason or "")


@admin_blueprint.route("/dht-purge/preview", methods=["POST"])
@_admin_required
@csrf_protect
def dht_purge_preview():
    """Show what a purge would touch. Deletes nothing -- POST only because a
    target can be long enough to be awkward in a query string, not because it
    changes anything."""
    from services import dht_object_purge

    target = (request.form.get("target") or "").strip()
    reason = (request.form.get("reason") or "").strip()
    try:
        preview = dht_object_purge.preview(target)
    except dht_object_purge.TargetError as exc:
        return _render_dht_purge(target=target, reason=reason, error=str(exc))
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("dht purge: preview failed for %r", target)
        return _render_dht_purge(target=target, reason=reason,
                                 error="Could not inspect that target: %s" % exc)
    return _render_dht_purge(preview=preview, target=target, reason=reason)


@admin_blueprint.route("/dht-purge/execute", methods=["POST"])
@_admin_required
@csrf_protect
def dht_purge_execute():
    """Purge, after the operator has retyped the exact target.

    The confirmation check lives in the service, not here, so that it cannot be
    bypassed by any future caller that forgets it.
    """
    from services import dht_object_purge

    target = (request.form.get("target") or "").strip()
    reason = (request.form.get("reason") or "").strip() or None
    confirmation = (request.form.get("confirm") or "").strip()
    slip_id, wallet, ip = _dht_purge_actor()
    try:
        result = dht_object_purge.purge(
            target, confirmation, reason=reason, acting_slip_id=slip_id,
            acting_wallet=wallet, acting_ip=ip,
            delete_rows=(request.form.get("delete_rows") == "on"),
            blocklist_hash=(request.form.get("blocklist_hash") == "on"),
        )
    except dht_object_purge.TargetError as exc:
        return _render_dht_purge(target=target, reason=reason or "", error=str(exc))
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("dht purge: execute failed for %r", target)
        return _render_dht_purge(target=target, reason=reason or "",
                                 error="The purge failed: %s" % exc)

    if result["outcome"] == "refused":
        return _render_dht_purge(
            target=target, reason=reason or "",
            error="The confirmation did not match. Type %r exactly. Nothing was "
                  "deleted." % result["target"])
    try:
        invalidate_front_page_cache()
        invalidate_activity_cache()
    except Exception:
        app.logger.exception("dht purge: cache invalidation failed")
    return _render_dht_purge(result=result, reason=reason or "")


# One import at a time; a re-trigger while a run is live is a no-op.
_vulhub_import_running = {"on": False, "last": None}


def _vulhub_dir():
    """Where a vulhub checkout lives on this host. Set VULHUB_DIR to point at a
    `git clone https://github.com/vulhub/vulhub` on the box; falls back to a
    bundled data dir if one was shipped."""
    import os
    cand = os.environ.get("VULHUB_DIR", "").strip()
    if cand:
        return cand
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/
    return os.path.join(here, "data", "vulhub")


@admin_blueprint.route("/lab-challenges/import-vulhub", methods=["POST"])
@_admin_required
def import_vulhub_challenges():
    """Bulk-import the vulhub collection as compose challenges. Runs in a
    background thread so the request returns immediately; progress goes to the
    app log and the challenge count on the page reflects it as it lands."""
    import os
    import threading
    from services import vulhub_import

    root = _vulhub_dir()
    if not os.path.isdir(root):
        flash("No vulhub checkout found at %s. Set VULHUB_DIR to a "
              "'git clone https://github.com/vulhub/vulhub' on the server." % root)
        return redirect(url_for("admin.dashboard"))
    if _vulhub_import_running["on"]:
        flash("A vulhub import is already running — check back shortly.")
        return redirect(url_for("admin.dashboard"))

    def run():
        _vulhub_import_running["on"] = True
        try:
            with app.app_context():
                stats = vulhub_import.import_vulhub(
                    root, logger=lambda m: app.logger.info("vulhub: %s", m))
                _vulhub_import_running["last"] = stats
                # Announce the new contexts to the DHT if a node is bridged.
                try:
                    from services import attack_range as lab
                    lab.publish_pending_contexts(limit=10000)
                except Exception:
                    app.logger.exception("vulhub: publish after import failed")
        except Exception:
            app.logger.exception("vulhub: import failed")
        finally:
            _vulhub_import_running["on"] = False

    threading.Thread(target=run, name="vulhub-import", daemon=True).start()
    flash("Importing vulhub from %s in the background — refresh in a moment to "
          "see the catalog fill in." % root)
    return redirect(url_for("admin.dashboard"))


def werkzeug_secure_relpath(filename):
    """A conservative relative path for an uploaded build-context file: forward
    slashes, no traversal, no leading slash."""
    import posixpath
    name = filename.replace("\\", "/").lstrip("/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    return posixpath.join(*parts) if parts else ""




@admin_blueprint.route("/arcade/reset/<int:slip_id>", methods=["POST"])
@_admin_required
def arcade_reset(slip_id):
    """Wipe one slip's arcade progress.

    For a score obtained by abuse rather than play. Deletes the attempt history
    too -- leaving it would keep the skill radar populated from solves that are
    being revoked.
    """
    from model.Codeplay import CodeplayAttempt, CodeplayProgress
    db.session.query(CodeplayAttempt).filter(CodeplayAttempt.slip_id == slip_id).delete()
    db.session.query(CodeplayProgress).filter(CodeplayProgress.slip_id == slip_id).delete()
    db.session.commit()
    flash("Arcade progress reset for slip %d." % slip_id)
    return redirect(url_for("admin.dashboard"))


# ── Software update ───────────────────────────────────────────────────────────
# The button the operator actually uses. The backend never talks to the
# Kubernetes API (see services/software_update.py for why) — it drops a request
# file the in-cluster updater watches, and reads back the status the updater
# publishes. Build/apply/verify/rollback all happen in the updater.

@admin_blueprint.route("/software/update", methods=["POST"])
@_admin_required
def software_update():
    from services.software_update import request_update
    slip = get_slip()
    ok, message = request_update(
        requested_by=(slip.name if slip is not None else "admin"),
        force=request.form.get("force") in ("1", "true", "on", "yes"),
    )
    if request.headers.get("Accept", "").startswith("application/json") \
            or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": ok, "message": message}), (200 if ok else 409)
    flash(message)
    return redirect(url_for("admin.dashboard") + "#software-update")


@admin_blueprint.route("/software/cancel", methods=["POST"])
@_admin_required
def software_update_cancel():
    """Drop a request the updater is never going to consume.

    Without this a stuck request disables the update button forever, because
    the card refuses to queue a second one while any request is pending.
    """
    from services.software_update import cancel_requests
    removed, message = cancel_requests()
    if request.headers.get("Accept", "").startswith("application/json") \
            or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "removed": removed, "message": message})
    flash(message)
    return redirect(url_for("admin.dashboard") + "#software-update")


@admin_blueprint.route("/software/status.json")
@_admin_required
def software_update_status():
    """Polled by the admin card. Carries the failure log too, so a failed
    deploy can be diagnosed from the browser rather than over SSH."""
    from services.software_update import admin_payload
    response = jsonify(admin_payload())
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Status page: incidents and the reports visitors send in.
#
# Incidents are written by hand, never opened automatically. A failing probe
# says something changed; it does not say what, who it affects, or whether the
# operator already knows. Auto-filed incidents teach readers to ignore the page,
# and a status page nobody believes is worth less than none at all.
# ---------------------------------------------------------------------------

@admin_blueprint.route("/status")
@_admin_required
def status_admin():
    from services.status_board import board, ensure_default_components

    # Seeded on first view rather than by a migration: a migration that inserts
    # rows cannot be re-run, and this way the operator gets the starting list
    # the moment they look for it.
    try:
        ensure_default_components()
    except Exception:
        db.session.rollback()
        app.logger.exception("could not seed default status components")

    from model.Status import IMPACTS, INCIDENT_STATUSES, StatusComponent, StatusReport

    reports = (
        db.session.query(StatusReport)
        .order_by(StatusReport.acknowledged.asc(), StatusReport.at.desc())
        .limit(100)
        .all()
    )
    components = (
        db.session.query(StatusComponent)
        .order_by(StatusComponent.position.asc())
        .all()
    )
    return render_template(
        "admin-status.html",
        status_board=board(include_detail=True),
        reports=reports,
        components=components,
        impacts=IMPACTS,
        incident_statuses=INCIDENT_STATUSES,
    )


@admin_blueprint.route("/status/incident", methods=["POST"])
@_admin_required
def status_open_incident():
    """Open an incident and post its first update in one action.

    One action because an incident with no update is a headline with no
    information, and that is the state somebody would leave it in while busy
    dealing with the actual outage.
    """
    from model.Status import (
        IMPACTS, INCIDENT_STATUSES, StatusIncident, StatusIncidentUpdate,
    )

    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()
    impact = (request.form.get("impact") or "minor").strip()
    component = (request.form.get("component") or "").strip() or None
    if not title or not body:
        flash("An incident needs a title and a first update.")
        return redirect(url_for("admin.status_admin"))
    if impact not in IMPACTS:
        impact = "minor"

    incident = StatusIncident(
        title=title[:160], component_key=(component or None),
        impact=impact, status=INCIDENT_STATUSES[0])
    db.session.add(incident)
    db.session.flush()
    db.session.add(StatusIncidentUpdate(
        incident_id=incident.id, status=INCIDENT_STATUSES[0], body=body))
    db.session.commit()
    flash("Incident opened.")
    return redirect(url_for("admin.status_admin"))


@admin_blueprint.route("/status/incident/<int:incident_id>/update", methods=["POST"])
@_admin_required
def status_update_incident(incident_id):
    import datetime as _dt

    from model.Status import (
        INCIDENT_RESOLVED, INCIDENT_STATUSES, StatusIncident, StatusIncidentUpdate,
    )

    incident = (
        db.session.query(StatusIncident)
        .filter(StatusIncident.id == incident_id).one_or_none()
    )
    if incident is None:
        flash("No such incident.")
        return redirect(url_for("admin.status_admin"))

    status = (request.form.get("status") or "").strip()
    body = (request.form.get("body") or "").strip()
    if status not in INCIDENT_STATUSES:
        flash("Choose a status for the update.")
        return redirect(url_for("admin.status_admin"))
    if not body:
        flash("Say what changed — an update with no text tells a reader nothing.")
        return redirect(url_for("admin.status_admin"))

    incident.status = status
    # Set once. Re-resolving an incident that was reopened would otherwise
    # rewrite history to say it ended the second time.
    if status == INCIDENT_RESOLVED and incident.resolved_at is None:
        incident.resolved_at = _dt.datetime.utcnow()
    if status != INCIDENT_RESOLVED:
        incident.resolved_at = None
    db.session.add(StatusIncidentUpdate(
        incident_id=incident.id, status=status, body=body))
    db.session.commit()
    flash("Update posted.")
    return redirect(url_for("admin.status_admin"))


@admin_blueprint.route("/status/report/<int:report_id>/ack", methods=["POST"])
@_admin_required
def status_ack_report(report_id):
    from model.Status import StatusReport

    report = (
        db.session.query(StatusReport)
        .filter(StatusReport.id == report_id).one_or_none()
    )
    if report is not None:
        # Acknowledged, not deleted: a cluster of reports from one region is
        # evidence about an outage, and deleting them as they are read destroys
        # the pattern that would have identified it.
        report.acknowledged = True
        db.session.commit()
    return redirect(url_for("admin.status_admin"))


@admin_blueprint.route("/status/component", methods=["POST"])
@_admin_required
def status_save_component():
    from model.Status import StatusComponent

    key = (request.form.get("key") or "").strip().lower()[:48]
    if not key or not key.replace("-", "").replace("_", "").isalnum():
        flash("A component key must be short and alphanumeric.")
        return redirect(url_for("admin.status_admin"))

    row = (
        db.session.query(StatusComponent)
        .filter(StatusComponent.key == key).one_or_none()
    )
    if row is None:
        row = StatusComponent(key=key)
        db.session.add(row)
    row.name = (request.form.get("name") or key)[:80]
    row.description = (request.form.get("description") or "")[:300]
    row.probe_url = (request.form.get("probe_url") or "")[:300]
    try:
        row.timeout_ms = max(500, min(int(request.form.get("timeout_ms") or 8000), 60000))
    except (TypeError, ValueError):
        row.timeout_ms = 8000
    try:
        row.position = int(request.form.get("position") or 0)
    except (TypeError, ValueError):
        row.position = 0
    row.enabled = bool(request.form.get("enabled"))
    db.session.commit()
    flash("Saved %s." % key)
    return redirect(url_for("admin.status_admin"))
