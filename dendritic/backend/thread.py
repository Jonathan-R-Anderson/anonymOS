import json
from typing import List

from flask import g, request

import time as _time

import cache
from board_access import get_board_or_404
import keystore
from model.NewPost import NewPost
from model.SubmissionError import SubmissionError
from model.Tag import Tag
from model.Thread import Thread
from services.thread_retention import make_room_for_new_thread
from shared import app, db


def get_tags(args: dict) -> List[Tag]:
    "Returns a list of Tag objects from the given tag list."
    if not args["tags"]:
        return []

    tags = list(map(lambda s: s.strip(), args["tags"].split(",")))
    ret = []

    # add all the tags that already exist in the database
    for row in db.session.query(Tag, Tag.name).filter(Tag.name.in_(tags)):
        tags.remove(row.name)
        ret.append(row.Tag)

    # create the remaining tabs and add them to the transaction
    # (the above loop removes all tags that already exist in the database
    # from the list, # therefore simply looping over the tags list should
    # suffice)
    for tag in tags:
        ret.append(Tag(name=tag))

    return ret



def publish_new_thread(thread: Thread):
    "Publishes the new thread to the pub-sub system."

    client = keystore.Pubsub()
    client.publish("new-thread", json.dumps({
        "thread": thread.id,
        "board": thread.board,
    }))


def create_thread(args: dict) -> Thread:
    "Creates a new thread out of the given arguments."

    board = get_board_or_404(args["board"])
    if getattr(board, "api_only", False) and not getattr(g, "bot_api_authorized", False):
        raise SubmissionError(
            "This board only accepts posts through its bot API (see the FAQ).",
            args["board"],
        )
    if board.is_geo_root:
        raise SubmissionError(
            "This nearby board only routes you into a local area board. Open the board page first.",
            args["board"],
        )
    if "media" not in request.files or not request.files["media"].filename:
        raise SubmissionError(
            "A file is required to post a thread!", args["board"])

    tags = get_tags(args)
    for tag in tags:
        db.session.add(tag)
    db.session.flush()

    make_room_for_new_thread(board)

    thread = Thread(board=args["board"], views=0, tags=tags)
    db.session.add(thread)
    db.session.flush()
    NewPost().post(thread)

    publish_new_thread(thread)

    return thread


def create_thread_via_api(board_id: int, post_args: dict, tags_value: str = None) -> Thread:
    """Create a thread programmatically for the authenticated bot API.

    Unlike create_thread(), this does NOT require an uploaded file (bots usually
    post text) and it feeds post_args straight into create_post() instead of
    re-reading the request form. The caller MUST have set g.bot_api_authorized
    (the bot endpoint does), so the api_only gate inside create_post() permits it.
    """
    from post import create_post
    board = get_board_or_404(board_id)
    if board.is_geo_root:
        raise SubmissionError(
            "This nearby board only routes into a local area board.", board_id)
    tags = get_tags({"tags": tags_value or ""})
    for tag in tags:
        db.session.add(tag)
    db.session.flush()
    make_room_for_new_thread(board)
    thread = Thread(board=board_id, views=0, tags=tags)
    db.session.add(thread)
    db.session.flush()
    create_post(thread, post_args)
    publish_new_thread(thread)
    return thread


def invalidate_board_cache(board_id: int):
    """Invalidates the cache for the given board in addition to the firehose."""
    # Same rule as a thread: the signed version has to advance exactly when the
    # bytes do, or a gateway can serve an older signed catalogue indefinitely.
    # The front page is bumped alongside, because this function also drops the
    # firehose render — one invalidation, two objects whose content changed.
    bump_content_version("/boards/%d" % board_id)
    bump_content_version("/")
    cache_connection = cache.Cache()
    # Cover every theme, not just the old default trio — otherwise a deleted
    # thread lingers in the cached catalog for midnight/cyberpunk/711chan viewers.
    theme_list = set(app.config.get("THEME_LIST") or ())
    theme_list |= {"stock", "harajuku", "wildride", "midnight", "cyberpunk", "711chan"}
    # invalidate full-page renders. The catalog is served as board-<id>-v10-... —
    # the old v7 key here never matched it, so deleted threads kept showing (then
    # 404'd on click). Clear the current key (+ etag) and the legacy ones too.
    # Whenever the catalog's markup changes the version is bumped so stale cached
    # pages are not served; keep the previous keys listed here so they get swept.
    for theme in theme_list:
        cache_connection.invalidate("board-%d-v10-%s-render" % (board_id, theme))
        cache_connection.invalidate("board-%d-v10-%s-render-etag" % (board_id, theme))
        cache_connection.invalidate("board-%d-v9-%s-render" % (board_id, theme))
        cache_connection.invalidate("board-%d-v9-%s-render-etag" % (board_id, theme))
        cache_connection.invalidate("board-%d-v8-%s-render" % (board_id, theme))
        cache_connection.invalidate("board-%d-v7-%s-render" % (board_id, theme))
        cache_connection.invalidate("firehose-v3-%s-render" % theme)
        cache_connection.invalidate("firehose-v3-%s-render-etag" % theme)
        cache_connection.invalidate("firehose-v2-%s-render" % theme)
    # invalidate retrieved thread listings
    catalog_thread_key = "board-%d-threads-v7" % board_id
    cache_connection.invalidate(catalog_thread_key)
    # invalidate firehose listing
    cache_connection.invalidate("firehose-threads")
    cache_connection.invalidate("firehose-threads-v2-candidates")
    # invalidate board activity feed
    cache_connection.invalidate("board-activity-threads")
    for theme in theme_list:
        board_activity_render_key = "board-activity-%s-render" % theme
        cache_connection.invalidate(board_activity_render_key)


def bump_content_version(key: str) -> int:
    """Advance the signed version for one object.

    The origin signature covers key, version and body hash, and the version is
    what stops a gateway serving an old but genuinely-signed copy forever. It
    therefore has to advance exactly when the content does — which is here, at
    the same moment the render cache is invalidated, because that IS the moment
    the bytes stop being the bytes we signed.

    Never raises. A version that failed to advance costs a reader the ability to
    detect staleness on one object; an exception here would cost them the post
    they were trying to make.
    """
    try:
        connection = cache.Cache()
        slot = "sig-gen:%s" % key
        current = connection.get(slot)
        nxt = (int(current) + 1) if current is not None else int(_time.time())
        connection.set(slot, nxt)
        return nxt
    except Exception:
        app.logger.exception("could not bump the content version for %s", key)
        return 0


def invalidate_thread_render_cache(thread_id: int):
    # The signed version advances with the invalidation, not after it: a reader
    # who fetches between the two would otherwise get new bytes under the old
    # version, which is indistinguishable from a gateway replaying them.
    bump_content_version("/threads/%d" % thread_id)
    cache_connection = cache.Cache()
    theme_list = app.config.get("THEME_LIST") or ("stock", "harajuku", "wildride")
    for theme in theme_list:
        # Current key plus the previous one, so a version bump does not strand
        # stale bodies that nothing invalidates any more.
        cache_connection.invalidate("thread-v8-%d-%s-render" % (thread_id, theme))
        cache_connection.invalidate("thread-v8-%d-%s-render-etag" % (thread_id, theme))
        cache_connection.invalidate("thread-v7-%d-%s-render" % (thread_id, theme))
        cache_connection.invalidate("thread-v7-%d-%s-render-etag" % (thread_id, theme))
        cache_connection.invalidate("thread-v6-%d-%s-render" % (thread_id, theme))
        cache_connection.invalidate("thread-v6-%d-%s-render-etag" % (thread_id, theme))
        cache_connection.invalidate("thread-v5-%d-%s-render" % (thread_id, theme))
