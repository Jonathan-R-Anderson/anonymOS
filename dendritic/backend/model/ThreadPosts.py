import datetime
import json
import os
import re

from flask import abort
from flask import url_for
from flask.json import jsonify

import cache
from board_access import get_thread_and_board_or_404
from model.ImageMagnet import ImageMagnet
from model.Media import Media
from model.Post import Post, render_for_threads
from model.PostPresentation import media_payload, post_display_name, post_tripcode, poster_display_id, source_metadata
from model.Poster import Poster
from model.Reply import Reply, REPLY_REGEXP
from model.Slip import get_slip, slip_can_moderate, slip_from_id, slip_is_admin
from model.Thread import Thread
from shared import app, db


def thread_posts_cache_key(thread_id):
    # v5: OP pinned first via creation-order (id) sort — see retrieve().
    # v6: payloads carry is_local_post, which _attach_votes uses to decide
    #     whether a post can be voted on. A v5 entry has no such key, so every
    #     post in it reads as non-votable and the vote controls silently
    #     disappear — bump the version whenever a field the render depends on is
    #     ADDED here, not just when one changes meaning.
    return "thread-posts-v6-%d" % thread_id


def _datetime_handler(obj):
    if isinstance(obj, datetime.datetime):
        return obj.timestamp()


def _sort_datetime_key(value):
    """Comparable ascending key for a post's datetime. Handles naive/aware
    datetimes and missing values so scraped and local posts sort together."""
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value
    return datetime.datetime.min


def _slip_payload(slip, board=None):
    if slip is None:
        return None
    is_admin = bool(getattr(slip, "is_admin", False))
    payload = {
        "id": slip.id,
        "is_admin": is_admin,
        "is_mod": (not is_admin) and bool(slip_can_moderate(slip, board=board)),
    }
    # Surface a profile link + hover-preview target when the poster opted into
    # linking their name from posts (and their profile is public).
    profile = getattr(slip, "profile", None)
    if profile is not None and profile.is_public and getattr(profile, "link_on_comments", False):
        payload["profile_slug"] = profile.slug
        payload["profile_url"] = url_for("profiles.view", slug=profile.slug)
        payload["profile_preview_url"] = url_for("profiles.preview", slug=profile.slug)
    if profile is not None and getattr(profile, "show_avatar", False) and getattr(profile, "avatar_media_id", None):
        payload["avatar_url"] = url_for("upload.thumb", media_id=profile.avatar_media_id)

    # Pooled tipping (P15). Computed HERE, in the one place every post render
    # gets its author data, so the availability rule exists once rather than
    # five times in five templates. availability() fails closed: a disabled,
    # unconfigured or unpayable recipient yields None and no button renders.
    try:
        from services.pooled_tips import availability
        tip = availability(slip, get_slip())
    except Exception:
        # Tipping must never be able to break a thread render.
        tip = None
    if tip:
        payload["tip"] = tip
    return payload


class ThreadPosts:
    def get(self, thread_id):
        # Render the post bodies (greentext, spoilers, anti-AI %%, reply links,
        # markdown) exactly like the server-rendered thread page does, so the
        # client's live-update setPosts() replaces the SSR posts with equally
        # formatted ones instead of reverting them to raw markdown. Mirrors the
        # render_for_threads() call in blueprints/threads.py.
        posts = self.retrieve(thread_id)
        render_for_threads(posts)
        return jsonify(posts)

    def delete(self, thread_id):
        thread = db.session.query(Thread).filter(Thread.id == thread_id).one()
        self._tombstone_federated_thread(thread_id)
        from model.PostRemoval import PostRemoval
        for post in thread.posts:
            PostRemoval().delete_impl(post.id)
        db.session.delete(thread)
        db.session.commit()

    def _tombstone_federated_thread(self, thread_id):
        """If this thread was NNTP-federated (imported or published by us),
        record its root Message-ID as a tombstone so it won't re-populate from
        the peer, and drop its provenance-ledger rows."""
        try:
            from model.NntpArticle import NntpArticle
            from model.NntpDeletedThread import tombstone_thread
            rows = (
                db.session.query(NntpArticle)
                .filter(NntpArticle.local_thread_id == thread_id)
                .all()
            )
            if not rows:
                return
            for root in {r.thread_root for r in rows if r.thread_root}:
                newsgroup = next((r.newsgroup for r in rows if r.thread_root == root), None)
                tombstone_thread(root, newsgroup)
            for row in rows:
                db.session.delete(row)
        except Exception:
            from shared import app
            app.logger.exception("NNTPChan: tombstone-on-delete failed for thread %s", thread_id)

    def retrieve(self, thread_id):
        session = db.session
        thread, board = get_thread_and_board_or_404(thread_id)
        self._sync_board_if_available(board)
        thread = session.query(Thread).filter(Thread.id == thread_id).one_or_none()
        if thread is None:
            abort(404)
        if thread.source_type != "local":
            posts = self._json_friendly_imported(thread)
            local_posts = (
                session.query(Post)
                .filter(Post.thread == thread_id)
                .order_by(Post.datetime.asc(), Post.id.asc())
                .all()
            )
            if local_posts:
                posts.extend(self._json_friendly(local_posts, thread, start_index=len(posts)))
            # Interleave scraped and local posts by their real post time so a
            # local reply made 2h ago sits above a post scraped 1m ago. The OP
            # is pinned first; both sides use naive-UTC datetimes so they sort
            # together. Stable sort keeps equal-timestamped scraped posts in
            # their original scraped order.
            posts.sort(key=lambda post: (not post.get("is_op"), _sort_datetime_key(post.get("datetime"))))
            self._attach_body_reply_links(posts)
            return self._attach_viewer_permissions(posts, board, thread_id)
        cache_connection = cache.Cache()
        cache_key = thread_posts_cache_key(thread_id)
        cached_posts = cache_connection.get(cache_key)
        if cached_posts:
            deserialized_posts = json.loads(cached_posts)
            for post in deserialized_posts:
                post["datetime"] = datetime.datetime.utcfromtimestamp(post["datetime"])
            return self._attach_viewer_permissions(deserialized_posts, board, thread_id)
        # Order by post id (creation order) rather than the relationship's
        # datetime ordering: an imported/scraped OP can have its datetime bumped
        # to a recent activity time, which would sort it AFTER local replies.
        # Post ids are monotonic with creation, so the OP (smallest id) is always
        # first and replies stay in true chronological order.
        ordered_posts = sorted(thread.posts, key=lambda post: post.id)
        posts = self._json_friendly(ordered_posts, thread)
        cache_connection.set(cache_key, json.dumps(posts, default=_datetime_handler))
        return self._attach_viewer_permissions(posts, board, thread_id)

    def _json_friendly_imported(self, thread):
        """Read all posts for an imported thread directly from its SQLite scraper DB."""
        from model.BlockedMediaHash import get_blocked_media_hash
        from model.BlockedSourcePost import blocked_source_post_ids
        from services.aggregator_sync.api import _source_row_media_hash
        from services.aggregator_sync.scraper_db import (
            aggregator_db_path,
            _read_scraper_db,
            _scraper_posts_source_column,
            _reddit_uses_universal_schema,
            _sqlite_table_exists,
            _thread_source_name_candidates,
        )
        from services.aggregator_sync.media import imported_thread_media_payload, imported_thread_media_rows
        from services.aggregator_sync.text import (
            _clip_imported_text,
            _translated_imported_body,
            imported_row_datetime,
            row_value,
        )
        from services.aggregator_sync.config import MAX_IMPORTED_SOURCE_ID_LENGTH

        if not thread.source_thread_id:
            return []

        try:
            db_path = aggregator_db_path(thread.source_type)
        except ValueError:
            return []
        if not os.path.exists(db_path):
            return []

        source_thread_id = thread.source_thread_id

        def _reader(conn):
            rows = []
            if thread.source_type == "reddit" and _reddit_uses_universal_schema(conn):
                op = conn.execute(
                    """
                    SELECT id AS post_id, id AS thread_id, NULL AS parent_post_id,
                           title AS subject, selftext AS body_text, author,
                           CASE
                               WHEN permalink LIKE '/%' THEN 'https://redlib.catsarch.com' || permalink
                               ELSE COALESCE(permalink, url)
                           END AS url,
                           image_url,
                           image_path,
                           COALESCE(created_utc, scraped_at) AS scraped_at
                    FROM posts WHERE id = ?
                    """,
                    (source_thread_id,),
                ).fetchone()
                if op:
                    rows.append(dict(op))
                if _sqlite_table_exists(conn, "comments"):
                    comments = conn.execute(
                        """
                        SELECT comment_id AS post_id, post_id AS thread_id,
                               REPLACE(REPLACE(parent_id, 't1_', ''), 't3_', '') AS parent_post_id,
                               NULL AS subject, body AS body_text, author,
                               NULL AS url, NULL AS image_url, NULL AS image_path,
                               COALESCE(created_utc, scraped_at) AS scraped_at
                        FROM comments WHERE post_id = ?
                        ORDER BY COALESCE(created_utc, scraped_at) ASC, comment_id ASC
                        """,
                        (source_thread_id,),
                    ).fetchall()
                    rows.extend([dict(r) for r in comments])
                if op is None and rows:
                    placeholder = {
                        "post_id": source_thread_id,
                        "thread_id": source_thread_id,
                        "parent_post_id": None,
                        "subject": "[removed]",
                        "body_text": "[removed by moderation]",
                        "author": "[removed]",
                        "url": None,
                        "image_url": None,
                        "image_path": None,
                        "scraped_at": row_value(rows[0], "scraped_at"),
                    }
                    rows.insert(0, placeholder)
                return rows

            source_col = _scraper_posts_source_column(conn, thread.source_type)
            op = conn.execute(
                "SELECT * FROM posts WHERE thread_id = ? AND post_id = thread_id LIMIT 1",
                (source_thread_id,),
            ).fetchone()
            source_name = (thread.source_name or "").strip()
            if op is not None:
                source_name = str(op[source_col] or "").strip()
            if op is None:
                source_name_candidates = _thread_source_name_candidates(
                    conn,
                    thread.source_type,
                    source_thread_id,
                    source_name,
                ) or ([source_name] if source_name else [])
                for candidate_source_name in source_name_candidates:
                    op = conn.execute(
                        "SELECT * FROM posts WHERE thread_id = ? AND %s = ? ORDER BY scraped_at ASC, post_id ASC LIMIT 1" % source_col,
                        (source_thread_id, candidate_source_name),
                    ).fetchone()
                    if op is not None:
                        source_name = candidate_source_name
                        break
            if op is None:
                return []
            if thread.source_type in ("4chan", "8chan", "7chan"):
                all_rows = conn.execute(
                    (
                        "SELECT * FROM posts WHERE thread_id = ? AND %s = ?"
                        " ORDER BY CASE WHEN post_id = thread_id THEN 0 ELSE 1 END,"
                        " CAST(post_id AS INTEGER) ASC, post_id ASC"
                    )
                    % source_col,
                    (source_thread_id, source_name),
                ).fetchall()
            else:
                all_rows = conn.execute(
                    "SELECT * FROM posts WHERE thread_id = ? AND %s = ?"
                    " ORDER BY scraped_at ASC, post_id ASC" % source_col,
                    (source_thread_id, source_name),
                ).fetchall()
            return [dict(r) for r in all_rows]

        try:
            sqlite_rows = _read_scraper_db(db_path, _reader)
        except Exception:
            app.logger.exception("Failed to read SQLite posts for imported thread %s", thread.id)
            return []

        if not sqlite_rows:
            return []

        # Posts a moderator has deleted are recorded in a durable Postgres
        # blocklist (works even when the scraper SQLite DB is read-only). Drop
        # them here so they never render, whether or not they carry media.
        blocked_post_ids = blocked_source_post_ids(thread.source_type, thread.source_thread_id)

        seen_blocked_hashes = {}
        filtered_rows = []
        for row in sqlite_rows:
            if blocked_post_ids:
                row_post_id = _clip_imported_text(row.get("post_id"), MAX_IMPORTED_SOURCE_ID_LENGTH)
                if row_post_id in blocked_post_ids:
                    continue
            try:
                media_hash, _source_url, _absolute_path = _source_row_media_hash(thread.source_type, row)
            except Exception:
                app.logger.exception(
                    "Failed to inspect imported media hash for thread %s source row %s",
                    thread.id,
                    row.get("post_id") if isinstance(row, dict) else row,
                )
                media_hash = None
            if not media_hash:
                filtered_rows.append(row)
                continue
            is_blocked = seen_blocked_hashes.get(media_hash)
            if is_blocked is None:
                try:
                    is_blocked = get_blocked_media_hash(media_hash) is not None
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass
                    app.logger.exception(
                        "Failed to check blocked-media hash while rendering imported thread %s",
                        thread.id,
                    )
                    is_blocked = False
                seen_blocked_hashes[media_hash] = is_blocked
            if is_blocked:
                continue
            filtered_rows.append(row)
        sqlite_rows = filtered_rows
        self._reconcile_outbound_replies(thread, sqlite_rows)

        denormalized_posts = []
        source_post_id_map = {}
        source_post_ids = []
        # Use thread.id * 1_000_000 + position as a stable synthetic integer ID
        # so markdown render caching works without real PostgreSQL Post IDs.
        for index, row in enumerate(sqlite_rows):
            synthetic_id = thread.id * 1_000_000 + index
            source_post_id = _clip_imported_text(
                row.get("post_id"),
                MAX_IMPORTED_SOURCE_ID_LENGTH,
            ) or str(index)
            source_post_id_map[source_post_id] = synthetic_id
            source_post_ids.append(source_post_id)

        keyed_imported_media = imported_thread_media_rows(thread.id, source_post_ids)

        for index, row in enumerate(sqlite_rows):
            source_post_id = _clip_imported_text(
                row.get("post_id"),
                MAX_IMPORTED_SOURCE_ID_LENGTH,
            ) or str(index)
            synthetic_id = source_post_id_map[source_post_id]

            post_dt = imported_row_datetime(row)

            p_dict = {
                "body": _translated_imported_body(
                    row,
                    source_post_id_map,
                    source_type=thread.source_type,
                ),
                "datetime": post_dt,
                "id": synthetic_id,
                "source_post_id": source_post_id,
                "thread_id": thread.id,
                "is_op": index == 0,
                "poster": row.get("author") or "anonymous",
                "poster_identity": "imported:%s:%s" % (thread.source_type, source_post_id),
                "poster_id": None,
                "tripcode": None,
                "subject": row.get("subject") if index == 0 else None,
                "media": None,
                "spoiler": False,
                "slip": None,
                "replies": [],
                "delete_url": None,
                "move_url": None,
                "ban_url": None,
                "block_media_url": None,
                "fingerprint_ban_url": None,
            }
            if index == 0:
                p_dict["tags"] = [tag.name for tag in thread.tags]
            p_dict.update(imported_thread_media_payload(thread, row, keyed_media_rows=keyed_imported_media))
            p_dict.update(source_metadata(thread.source_type, thread.source_name, thread.source_url))
            p_dict["delete_url"] = url_for(
                "threads.delete_imported_post",
                thread_id=thread.id,
                source_post_id=source_post_id,
            )
            if row_value(row, "image_path"):
                p_dict["block_media_url"] = url_for(
                    "admin.block_imported_post_media",
                    thread_id=thread.id,
                    source_post_id=source_post_id,
                )
            self._apply_comment_origin_metadata(p_dict, thread, is_scraped_comment=True)
            denormalized_posts.append(p_dict)

        return denormalized_posts

    def _reconcile_outbound_replies(self, thread, sqlite_rows):
        """Confirm manually submitted drafts once the read-side scraper sees them.

        Matching is deliberately conservative. A source post id from a future
        extension will be authoritative; the manual handoff can only match a
        unique normalized body inside a narrow time window.
        """
        from model.OutboundReply import (
            OutboundReply,
            STATUS_AMBIGUOUS,
            STATUS_CONFIRMED,
            STATUS_SUBMITTED,
        )
        from services.aggregator_sync.text import imported_row_datetime, row_value

        pending = (
            db.session.query(OutboundReply)
            .filter(
                OutboundReply.thread_id == thread.id,
                OutboundReply.status == STATUS_SUBMITTED,
            )
            .all()
        )
        if not pending:
            return

        def _normalized(value):
            return re.sub(r"\s+", " ", str(value or "")).strip()

        changed = False
        for outbound in pending:
            lower_bound = outbound.created_at - datetime.timedelta(minutes=5)
            upper_bound = outbound.created_at + datetime.timedelta(hours=24)
            wanted_body = _normalized(outbound.body)
            candidates = []
            for row in sqlite_rows:
                source_post_id = str(row_value(row, "post_id") or "").strip()
                if not source_post_id or source_post_id == str(thread.source_thread_id):
                    continue
                if _normalized(row_value(row, "body_text")) != wanted_body:
                    continue
                row_datetime = imported_row_datetime(row)
                if row_datetime is not None and not (lower_bound <= row_datetime <= upper_bound):
                    continue
                candidates.append(row)

            if len(candidates) == 1:
                source_post_id = str(row_value(candidates[0], "post_id")).strip()
                outbound.source_post_id = source_post_id[:128]
                source_post_url = row_value(candidates[0], "url")
                outbound.source_post_url = str(source_post_url).strip() if source_post_url else None
                outbound.transition_to(STATUS_CONFIRMED)
                db.session.add(outbound)
                changed = True
            elif len(candidates) > 1:
                outbound.last_error_code = "multiple_source_matches"
                outbound.last_error_detail = "More than one source reply matched this draft."
                outbound.transition_to(STATUS_AMBIGUOUS)
                db.session.add(outbound)
                changed = True

        if changed:
            db.session.commit()

    def _json_friendly(self, posts, thread, start_index=0):
        poster_subquery = db.session.query(Post.poster).filter(Post.thread == thread.id).subquery()
        unkeyed_posters = db.session.query(Poster).filter(Poster.id.in_(poster_subquery)).all()
        keyed_posters = {p.id: p for p in unkeyed_posters}
        media_subquery = db.session.query(Post.media).filter(Post.thread == thread.id).subquery()
        unkeyed_media = (
            db.session.query(
                Media.id,
                Media.ext,
                Media.mimetype,
                Media.is_animated,
                Media.torrent_info_hash,
                Media.torrent_piece_length,
                ImageMagnet.magnet_url.label("image_magnet_url"),
            )
            .outerjoin(ImageMagnet, ImageMagnet.media_id == Media.id)
            .filter(Media.id.in_(media_subquery))
            .all()
        )
        keyed_media = {m.id: m for m in unkeyed_media}
        reply_subquery = db.session.query(Post.id).filter(Post.thread == thread.id).subquery()
        unkeyed_replies = db.session.query(Reply).filter(Reply.reply_to.in_(reply_subquery)).all()
        keyed_replies = {}
        for reply in unkeyed_replies:
            if keyed_replies.get(reply.reply_to) is None:
                keyed_replies[reply.reply_to] = []
            keyed_replies[reply.reply_to].append(reply.reply_from)
        from model.Board import Board
        from services.geoip import flag_emoji
        show_country_flags = bool(
            db.session.query(Board.show_country_flags)
            .filter(Board.id == thread.board)
            .scalar()
        )
        denormalized_posts = []
        for index, post in enumerate(posts):
            p_dict = dict()
            p_dict["body"] = post.body
            p_dict["datetime"] = post.datetime
            p_dict["id"] = post.id
            p_dict["thread_id"] = thread.id
            absolute_index = start_index + index
            p_dict["is_op"] = absolute_index == 0
            if absolute_index == 0:
                p_dict["tags"] = [tag.name for tag in thread.tags]
            poster = keyed_posters.get(post.poster)
            slip = slip_from_id(poster.slip) if poster and poster.slip else None
            p_dict["poster"] = post_display_name(post, poster, slip=slip)
            p_dict["poster_identity"] = "local:%s" % (poster.id if poster is not None else post.id)
            p_dict["poster_id"] = poster_display_id(poster)
            # Raw Poster row id (not the display hash) so the shadowban filter in
            # _attach_viewer_permissions can match against shadowbanned identities.
            p_dict["poster_row_id"] = post.poster
            if show_country_flags and poster is not None and getattr(poster, "country_code", None):
                p_dict["country_code"] = poster.country_code
                p_dict["country_flag"] = flag_emoji(poster.country_code)
            p_dict["tripcode"] = post_tripcode(post, poster, slip=slip)
            p_dict["subject"] = post.subject
            p_dict.update(media_payload(post, keyed_media))
            p_dict["spoiler"] = post.spoiler
            # Marks a payload backed by a real Post row, which is what makes it
            # votable (PostVote.post_id is a FK). Imported posts are given a
            # SYNTHETIC integer id (thread.id * 1_000_000 + index) that can
            # collide with a genuine post id, so "the id is an int" is not a safe
            # test — this flag is set only on this path, which only ever handles
            # real rows. Not viewer-specific, so it is fine to cache.
            p_dict["is_local_post"] = True
            p_dict["slip"] = _slip_payload(slip, board=thread.board)
            p_dict.update(source_metadata(
                post.source_type, post.source_name, post.source_url,
                watermark_url=getattr(post, "source_watermark_url", None),
                watermark_label=getattr(post, "source_watermark_label", None),
            ))
            self._apply_comment_origin_metadata(p_dict, thread, is_scraped_comment=post.source_type != "local")
            replies = keyed_replies.get(post.id)
            p_dict["replies"] = replies or list()
            p_dict["delete_url"] = (
                url_for("threads.delete", thread_id=thread.id)
                if p_dict["is_op"]
                else url_for("threads.delete_post", post_id=post.id)
            )
            p_dict["move_url"] = url_for("threads.move", thread_id=thread.id) if p_dict["is_op"] else None
            p_dict["ban_url"] = url_for("admin.ban_post", post_id=post.id) if post.poster is not None else None
            p_dict["shadowban_url"] = url_for("admin.shadowban_post", post_id=post.id) if post.poster is not None else None
            p_dict["block_media_url"] = None
            # Distance-based image ban (local content). Offered only for image
            # media; gated to admins in _attach_viewer_permissions. Bans the
            # image by perceptual fingerprint and broadcasts it to NNTP peers.
            _media_row = keyed_media.get(post.media) if post.media is not None else None
            p_dict["fingerprint_ban_url"] = (
                url_for("admin.nntp_ban_fingerprint_from_post", post_id=post.id)
                if (_media_row is not None and (getattr(_media_row, "mimetype", "") or "").startswith("image/"))
                else None
            )
            denormalized_posts.append(p_dict)
        return denormalized_posts

    def _apply_comment_origin_metadata(self, post_payload, thread, is_scraped_comment):
        if getattr(thread, "source_type", "local") == "local":
            post_payload["comment_origin"] = "local"
            post_payload["comment_origin_label"] = None
            return
        if is_scraped_comment:
            post_payload["comment_origin"] = "scraped"
            post_payload["comment_origin_label"] = "Scraped"
            return
        post_payload["comment_origin"] = "local"
        post_payload["comment_origin_label"] = "Local"
        post_payload["poster_id"] = None

    def _attach_body_reply_links(self, posts):
        keyed_posts = {post["id"]: post for post in posts}
        for post in posts:
            for match in re.finditer(REPLY_REGEXP, post.get("body") or ""):
                reply_to = int(match.group(2))
                if reply_to == post["id"]:
                    continue
                target = keyed_posts.get(reply_to)
                if target is None:
                    continue
                if post["id"] not in target["replies"]:
                    target["replies"].append(post["id"])

    def _attach_viewer_permissions(self, posts, board, thread_id=None):
        viewer_can_moderate = slip_can_moderate(board=board)
        viewer_is_admin = slip_is_admin()
        # Votes are thread-scoped. Fall back to the payload's own thread_id so
        # single-post callers (threads.render_post) do not have to thread it in.
        if thread_id is None and posts:
            thread_id = posts[0].get("thread_id")
        if thread_id is not None:
            self._attach_votes(posts, thread_id)
            self._attach_awards(posts, thread_id)
        for post in posts:
            post["viewer_can_moderate"] = viewer_can_moderate
            post["viewer_is_admin"] = viewer_is_admin
            if viewer_can_moderate is False:
                post["delete_url"] = None
                post["move_url"] = None
                post["ban_url"] = None
                post["shadowban_url"] = None
                post["block_media_url"] = None
                post["fingerprint_ban_url"] = None
                continue
            if viewer_is_admin is False:
                post["move_url"] = None
                post["block_media_url"] = None
                post["fingerprint_ban_url"] = None
        # Shadowban: drop replies authored by a shadowbanned poster, unless the
        # viewer is that author (they bypass the shared cache, so their own posts
        # stay visible to them only). The OP is always kept so the thread still
        # renders; an OP-shadowbanned thread is already hidden from every listing.
        from model.ShadowBan import hidden_poster_ids
        hidden = hidden_poster_ids()
        if hidden:
            posts = [
                post for post in posts
                if post.get("is_op") or post.get("poster_row_id") not in hidden
            ]
        return posts

    def _attach_awards(self, posts, thread_id):
        """Attach award counts, and the award endpoint where one is possible.

        Same reasoning as _attach_votes for living out here rather than in
        _json_friendly: `award_url` depends on WHO is looking (you cannot award
        your own post), and the posts cache is shared by every viewer.

        Counts are read fresh on each cache hit too, so an award appears without
        the thread's render cache having to be thrown away.
        """
        from model.PostAward import counts_for_posts
        from services.post_awards import awardable_for_thread

        # is_local_post, NOT "the id is an int": an imported post is given a
        # SYNTHETIC id (thread.id * 1_000_000 + index) that can collide with a
        # real post id, and keying awards off that would show one author's awards
        # on somebody else's scraped comment. Same guard the vote path uses.
        local = [post for post in posts if post.get("is_local_post")]
        counts = counts_for_posts([post.get("id") for post in local if post.get("id")])
        awardable = awardable_for_thread(thread_id) if local else {}
        viewer = get_slip()
        for post in posts:
            if not post.get("is_local_post"):
                post["awards"] = {}
                post["award_url"] = None
                continue
            post_id = post.get("id")
            post["awards"] = counts.get(post_id) or {}
            author_slip_id = awardable.get(post_id)
            can_award = (
                viewer is not None
                and author_slip_id is not None
                and author_slip_id != viewer.id
            )
            post["award_url"] = (
                url_for("threads.award_post", thread_id=thread_id, post_id=post_id)
                if can_award else None
            )

    def _attach_votes(self, posts, thread_id):
        """Attach vote score + this viewer's own vote to each post.

        Covers scraped posts as well as local ones: the target is a
        thread-scoped key, not a post.id, precisely because imported posts have
        no Post row (see model/PostVote.py).

        Deliberately here and not in _json_friendly: that method's output is
        cached per THREAD with no viewer scoping, so a per-slip field written
        there would be handed to whoever warmed the cache next — one user's votes
        showing as everyone's. This runs after every cache read instead.

        Keeping the score here too (rather than caching it) means a vote shows up
        immediately, and the posts cache never needs invalidating on vote.
        """
        from model.PostVote import (
            scores_for_thread,
            target_key_for_payload,
            viewer_votes_for_thread,
            vote_tallies_for_thread,
        )

        scores = scores_for_thread(thread_id)
        # Up/down split as well as the net score: the tree shapes a node by how
        # CONTESTED it is, and a net score cannot tell +10/-10 from 0/0.
        tallies = vote_tallies_for_thread(thread_id)
        viewer_slip = get_slip()
        viewer_votes = viewer_votes_for_thread(
            thread_id, viewer_slip.id if viewer_slip is not None else None
        )
        can_vote = viewer_slip is not None
        vote_url = url_for("threads.vote_post", thread_id=thread_id)
        for post in posts:
            target_key = target_key_for_payload(post)
            if target_key is None:
                post["score"] = 0
                post["upvotes"] = 0
                post["downvotes"] = 0
                post["viewer_vote"] = 0
                post["vote_target"] = None
                post["vote_url"] = None
                post["can_vote"] = False
                continue
            tally = tallies.get(target_key) or {}
            post["upvotes"] = int(tally.get("up", 0))
            post["downvotes"] = int(tally.get("down", 0))
            post["score"] = int(scores.get(target_key, 0))
            post["viewer_vote"] = int(viewer_votes.get(target_key, 0))
            post["vote_target"] = target_key
            post["vote_url"] = vote_url
            post["can_vote"] = can_vote

    def _sync_board_if_available(self, board):
        if board is None:
            return False
        if app.config.get("AGGREGATOR_REQUEST_SYNC", False) is False:
            return False
        try:
            import gevent
            from aggregator_sync import sync_board_if_due
            flask_app = app
            board_id = board.id

            def _run():
                with flask_app.app_context():
                    try:
                        from model.Board import Board
                        b = db.session.query(Board).filter(Board.id == board_id).one_or_none()
                        if b:
                            sync_board_if_due(b)
                    except Exception:
                        db.session.rollback()
                        flask_app.logger.exception(
                            "Board aggregator sync failed while retrieving thread for board %s", board_id
                        )
                    finally:
                        db.session.remove()

            gevent.spawn(_run)
            return True
        except Exception:
            app.logger.exception("Board aggregator sync failed while retrieving thread for board %s", board.id)
            return False
