"""Data for the board sidebar (templates/includes/board-sidebar.html).

The right-hand rail on a board's catalog and thread pages: who moderates it, how
to reach them, how busy it is, its rules, its moderator-curated bookmarks and
when it was created.

Two things shape this module:

* It runs on EVERY catalog and thread render. Anonymous renders are served from
  the response cache, but any logged-in viewer bypasses that cache
  (viewer_can_use_public_cache), so the aggregate counts would otherwise run
  several GROUP BYs per page view. They are memoized in the shared keystore with
  an embedded expiry -- Cache has no TTL of its own.
* "Contributors" is a COUNT of distinct poster IPs and nothing else. Poster
  identity here is per-thread (model/Poster.py keys on thread), so counting
  Poster rows would count one person once per thread they posted in. IPs are the
  only board-wide handle available, and they are aggregated to a number that
  never reaches the template -- the named list below uses author_name/tripcode,
  which posters chose and which already appear publicly on their posts.
"""
import datetime as _datetime
import json

from flask import url_for

import cache
from model.Board import Board
from model.BoardBookmark import bookmarks_for_board
from model.BoardVisit import BoardVisit
from model.Post import Post
from model.Poster import Poster
from model.Profile import Profile
from model.Slip import Slip, SlipBoardModerator
from model.Thread import Thread
from shared import app, db


# How long a visitor counts as "here now" after their last board-metrics ping.
ONLINE_WINDOW_MINUTES = 5
CONTRIBUTOR_WINDOW_DAYS = 7
TOP_CONTRIBUTOR_LIMIT = 5
# Two memos with different clocks. The 7-day aggregates are the expensive ones
# and barely move, so they get a long TTL; "here now" is the only figure that
# looks broken when stale, so it gets a short one. Both matter because
# sidebar-stats.json is polled once a minute by every open page on the board —
# without these, that is a fan-out of GROUP BYs proportional to traffic.
_STATS_TTL_SECONDS = 300
_ONLINE_TTL_SECONDS = 30
# Cheap, but still one query per moderator plus one for the links — not worth
# paying on every page view of a busy board.
_META_TTL_SECONDS = 120
_STATS_CACHE_PREFIX = "board-sidebar-stats-v1-"
_ONLINE_CACHE_PREFIX = "board-sidebar-online-v1-"
_META_CACHE_PREFIX = "board-sidebar-meta-v1-"


def _utcnow():
    return _datetime.datetime.utcnow()


def _memoize(key, ttl_seconds, producer):
    """Cache a value for ttl_seconds, with stampede protection.

    cache.Cache has no expiry, so the payload carries its own. The part that
    matters is what happens on a MISS: the existing entry's expiry is pushed
    forward BEFORE computing, so concurrent requests arriving in the same window
    see a live entry and reuse the stale value instead of every one of them
    running the same aggregate. Without that, expiry is a synchronised
    thundering herd across every worker.
    """
    connection = cache.Cache()
    stale = None
    try:
        raw = connection.get(key)
        if raw:
            payload = json.loads(raw)
            if payload.get("expires_at", 0) > _utcnow().timestamp():
                return payload["data"]
            stale = payload.get("data")
    except Exception:
        app.logger.exception("Board sidebar cache read failed for %s", key)

    if stale is not None:
        # Reserve the recompute: hold the stale value for a short grace period
        # so everyone arriving right now serves it rather than piling on.
        try:
            connection.set(key, json.dumps({
                "expires_at": _utcnow().timestamp() + 15,
                "data": stale,
            }))
        except Exception:
            app.logger.exception("Board sidebar cache reservation failed for %s", key)

    data = producer()
    try:
        connection.set(key, json.dumps({
            "expires_at": _utcnow().timestamp() + ttl_seconds,
            "data": data,
        }))
    except Exception:
        app.logger.exception("Board sidebar cache write failed for %s", key)
    return data


def invalidate_board_sidebar_stats(board_id):
    """Drop both memos for a board. The meta one matters most in practice: it
    holds the moderator list and the bookmarks, so without this a moderator
    editing a bookmark would not see it for _META_TTL_SECONDS."""
    try:
        connection = cache.Cache()
        connection.invalidate(_STATS_CACHE_PREFIX + str(board_id))
        connection.invalidate(_META_CACHE_PREFIX + str(board_id))
    except Exception:
        app.logger.exception("Board sidebar cache invalidation failed for board %s", board_id)


def _visitors_online_cached(board_id):
    return _memoize(
        _ONLINE_CACHE_PREFIX + str(board_id),
        _ONLINE_TTL_SECONDS,
        lambda: int(_visitors_online(board_id)),
    )


def board_moderators(board):
    """The board's own staff: its owner first, then explicitly appointed mods.

    Sitewide admins can moderate every board but are deliberately not listed --
    this card is about who is responsible for THIS board, and listing every
    sysop on every board would be both noisy and a standing roster of the site's
    admins on public pages.
    """
    rows = []
    seen = set()

    def append(slip, is_owner):
        if slip is None or slip.id in seen:
            return
        seen.add(slip.id)
        profile = (
            db.session.query(Profile)
            .filter(Profile.slip_id == slip.id, Profile.is_public.is_(True))
            .one_or_none()
        )
        profile_url = None
        if profile is not None:
            try:
                profile_url = url_for("profiles.view", slug=profile.slug)
            except Exception:
                profile_url = "/profile/u/%s" % profile.slug
        rows.append({
            "slip_id": slip.id,
            "name": slip.name,
            "is_owner": is_owner,
            "profile_url": profile_url,
        })

    if board.owner_slip_id is not None:
        append(db.session.query(Slip).filter(Slip.id == board.owner_slip_id).one_or_none(), True)

    appointed = (
        db.session.query(Slip)
        .join(SlipBoardModerator, SlipBoardModerator.slip_id == Slip.id)
        .filter(SlipBoardModerator.board_id == board.id)
        .order_by(Slip.name.asc())
        .all()
    )
    for slip in appointed:
        append(slip, False)
    return rows


def _visitors_online(board_id):
    cutoff = _utcnow() - _datetime.timedelta(minutes=ONLINE_WINDOW_MINUTES)
    return (
        db.session.query(db.func.count(db.distinct(BoardVisit.visitor_token)))
        .filter(BoardVisit.board_id == board_id, BoardVisit.last_seen_at >= cutoff)
        .scalar()
    ) or 0


def _board_post_query(board_id):
    return (
        db.session.query(Post)
        .join(Thread, Thread.id == Post.thread)
        .filter(Thread.board == board_id, Post.source_type == "local")
    )


def _weekly_contributors(board_id, cutoff):
    """Distinct people who posted on this board in the window, by IP.

    Aggregate only -- the individual IPs never leave this function. See the
    module docstring for why Poster rows cannot be used instead.
    """
    return (
        db.session.query(db.func.count(db.distinct(Poster.ip_address)))
        .select_from(Post)
        .join(Thread, Thread.id == Post.thread)
        .join(Poster, Poster.id == Post.poster)
        .filter(
            Thread.board == board_id,
            Post.source_type == "local",
            Post.datetime >= cutoff,
        )
        .scalar()
    ) or 0


def _top_named_contributors(board_id, cutoff):
    """Most active posters in the window who chose a name or tripcode.

    Only self-chosen public identities appear here -- an anonymous poster is
    never de-anonymised into this list, they simply are not in it.
    """
    rows = (
        db.session.query(Post.author_name, db.func.count(Post.id).label("posts"))
        .join(Thread, Thread.id == Post.thread)
        .filter(
            Thread.board == board_id,
            Post.source_type == "local",
            Post.datetime >= cutoff,
            Post.author_name.isnot(None),
            Post.author_name != "",
            Post.author_name != "Anonymous",
        )
        .group_by(Post.author_name)
        .order_by(db.desc("posts"))
        .limit(TOP_CONTRIBUTOR_LIMIT)
        .all()
    )
    return [{"name": name, "posts": int(count)} for (name, count) in rows]


def board_stats(board_id):
    """Counters for the sidebar. Memoized; see _memoize and the TTL constants."""

    def produce():
        cutoff = _utcnow() - _datetime.timedelta(days=CONTRIBUTOR_WINDOW_DAYS)
        thread_count = (
            db.session.query(db.func.count(Thread.id)).filter(Thread.board == board_id).scalar()
        ) or 0
        post_count = _board_post_query(board_id).with_entities(db.func.count(Post.id)).scalar() or 0
        posts_week = (
            _board_post_query(board_id)
            .with_entities(db.func.count(Post.id))
            .filter(Post.datetime >= cutoff)
            .scalar()
        ) or 0
        return {
            "threads": int(thread_count),
            "posts": int(post_count),
            "posts_week": int(posts_week),
            "contributors_week": int(_weekly_contributors(board_id, cutoff)),
            "top_contributors": _top_named_contributors(board_id, cutoff),
        }

    stats = dict(_memoize(_STATS_CACHE_PREFIX + str(board_id), _STATS_TTL_SECONDS, produce))
    # Separate, much shorter memo — see the TTL constants.
    stats["online"] = int(_visitors_online_cached(board_id))
    return stats


EMPTY_STATS = {
    "threads": None, "posts": None, "posts_week": None,
    "contributors_week": None, "top_contributors": [], "online": None,
}


def _cached_board_meta(board):
    """Moderator list + bookmarks, memoized. Both are small indexed lookups, but
    board_moderators still costs a profile query per moderator, and this runs on
    every catalog and thread render."""

    def produce():
        return {
            "moderators": board_moderators(board),
            "bookmarks": [
                {"label": bookmark.label, "url": bookmark.url}
                for bookmark in bookmarks_for_board(board.id)
            ],
        }

    return _memoize(_META_CACHE_PREFIX + str(board.id), _META_TTL_SECONDS, produce)


def board_sidebar_context(board, can_manage=False, can_moderate=False):
    """Everything templates/includes/board-sidebar.html renders.

    NO AGGREGATE QUERIES. This runs on every catalog and thread render, and the
    counters need a COUNT over the board's posts, a COUNT(DISTINCT) over its
    posters and a GROUP BY. Doing that inline made thread views slow enough to
    saturate the gevent workers — and because a markup change also bumps the
    render-cache key, every page is a cold miss at exactly the moment the new
    code ships, so they all pay it at once and nginx starts serving its 503.

    The counters ship as None and are filled in by /boards/<name>/sidebar-stats.json
    (see boards.sidebar_stats), which is memoized and off the render path.

    Returns None when there is no board to describe (e.g. an orphaned thread),
    so the template can skip the rail entirely.
    """
    if board is None:
        return None
    stats = dict(EMPTY_STATS)
    try:
        meta = _cached_board_meta(board)
        moderators = meta.get("moderators") or []
        bookmarks = meta.get("bookmarks") or []
    except Exception:
        # A board page must render even if this table is missing (migration not
        # yet applied) or the query fails.
        db.session.rollback()
        app.logger.exception("Board sidebar metadata failed for board %s", board.id)
        moderators = []
        bookmarks = []
    return {
        "board_name": board.name,
        "board_title": board.title,
        "created_at": board.created_at,
        "description": (board.api_description or "").strip() or None,
        "rules": (board.rules or "").strip() or None,
        "moderators": moderators,
        "bookmarks": bookmarks,
        "stats": stats,
        "can_manage": bool(can_manage),
        "can_moderate": bool(can_moderate),
        "online_window_minutes": ONLINE_WINDOW_MINUTES,
        "contributor_window_days": CONTRIBUTOR_WINDOW_DAYS,
    }


def board_for_thread(thread_id):
    board_id = db.session.query(Thread.board).filter(Thread.id == thread_id).scalar()
    if board_id is None:
        return None
    return db.session.query(Board).filter(Board.id == board_id).one_or_none()
