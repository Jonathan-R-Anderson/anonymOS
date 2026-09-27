import datetime
import json
import math
import os
import re
from collections import Counter
from html import unescape

from flask import abort
from flask.json import jsonify
from sqlalchemy import func

from board_access import get_board_or_404
import cache
from model.Board import Board
from model.Post import Post
from model.Thread import Thread
from model.PostPresentation import media_payload, source_metadata
from model.ThreadPosts import _datetime_handler
from services.aggregator_sync.media import imported_thread_media_payload
from shared import app, db

KEYWORD_STOP_WORDS = {
    "a", "about", "above", "after", "again", "against", "all", "also", "am", "an",
    "and", "any", "are", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can", "cant", "could", "couldnt",
    "did", "didnt", "do", "does", "doesnt", "doing", "dont", "down", "during",
    "each", "few", "for", "from", "further", "had", "has", "have", "having", "he",
    "her", "here", "hers", "herself", "him", "himself", "his", "how", "i", "if",
    "im", "in", "into", "is", "isnt", "it", "its", "itself", "ive", "just", "me",
    "more", "most", "my", "myself", "no", "nor", "not", "now", "of", "off", "on",
    "once", "only", "or", "other", "our", "ours", "ourselves", "out", "over",
    "own", "same", "she", "should", "shouldnt", "so", "some", "such", "than",
    "that", "thats", "the", "their", "theirs", "them", "themselves", "then",
    "there", "theres", "these", "they", "theyre", "this", "those", "through", "to",
    "too", "under", "until", "up", "very", "was", "wasnt", "we", "were", "werent",
    "what", "when", "where", "which", "while", "who", "whom", "why", "will", "with",
    "wont", "would", "wouldnt", "you", "your", "youre", "yours", "yourself",
    "yourselves",
}
KEYWORD_HTML_RE = re.compile(r"<[^>]*>")
KEYWORD_LINK_RE = re.compile(r"https?://\S+")
KEYWORD_REPLY_RE = re.compile(r"(?:>>|&gt;&gt;)\d+")
KEYWORD_TOKEN_RE = re.compile(r"[a-z0-9']+")
KEYWORD_LIMIT = 6


def _keyword_surface(text):
    return KEYWORD_HTML_RE.sub(" ", unescape(text or ""))


def _stem_keyword(token):
    normalized = token
    if len(normalized) > 5 and normalized.endswith("ies"):
        normalized = normalized[:-3] + "y"
    elif len(normalized) > 5 and normalized.endswith("ing"):
        normalized = normalized[:-3]
    elif len(normalized) > 4 and normalized.endswith("ed"):
        normalized = normalized[:-2]
    elif len(normalized) > 4 and normalized.endswith("ly"):
        normalized = normalized[:-2]
    elif len(normalized) > 4 and normalized.endswith("es"):
        normalized = normalized[:-2]
    elif (
        len(normalized) > 3
        and normalized.endswith("s")
        and not normalized.endswith("ss")
        and not normalized.endswith("us")
        and not normalized.endswith("ous")
        and not normalized.endswith("is")
    ):
        normalized = normalized[:-1]
    return normalized


def _keyword_tokens(text):
    cleaned = (
        _keyword_surface(text)
        .lower()
        .replace("\u2018", "'")
        .replace("\u2019", "'")
    )
    cleaned = KEYWORD_LINK_RE.sub(" ", cleaned)
    cleaned = KEYWORD_REPLY_RE.sub(" ", cleaned)
    cleaned = re.sub(r"[^a-z0-9'\s]+", " ", cleaned)
    tokens = []
    for raw_token in KEYWORD_TOKEN_RE.findall(cleaned):
        if not raw_token or raw_token.isdigit():
            continue
        surface = raw_token.strip("'")
        if not surface:
            continue
        stem = _stem_keyword(surface)
        if len(stem) < 2 or stem in KEYWORD_STOP_WORDS:
            continue
        tokens.append((surface, stem))
    return tokens


class BoardCatalog:
    def get(self, board_id):
        return jsonify(self.retrieve(board_id))

    def retrieve(self, board_id):
        session = db.session
        board = get_board_or_404(board_id)
        board = session.query(Board).filter(Board.id == board_id).one_or_none()
        if board is None:
            abort(404)
        cache_connection = cache.Cache()
        board_cache_key = "board-%d-threads-v7" % board_id
        cached_threads = cache_connection.get(board_cache_key)
        if cached_threads:
            deserialized_threads = json.loads(cached_threads)
            for thread in deserialized_threads:
                thread["last_updated"] = datetime.datetime.utcfromtimestamp(thread["last_updated"])
            return self._sort_threads(deserialized_threads)
        thread_list = board.threads
        json_friendly = self._sort_threads(self._to_json(thread_list))
        cache_friendly = json.dumps(json_friendly, default=_datetime_handler)
        cache_connection.set(board_cache_key, cache_friendly)
        return json_friendly

    def _sort_threads(self, threads):
        return sorted(
            threads,
            key=lambda thread: (
                thread.get("last_updated") or datetime.datetime.min,
                thread.get("id") or 0,
            ),
            reverse=True,
        )

    def _to_json(self, threads):
        imported_threads = [t for t in threads if t.source_type != "local"]
        imported_op_data = self._fetch_imported_op_data(imported_threads) if imported_threads else {}
        local_stats = self._local_thread_stats(threads)

        result = []
        for thread in threads:
            thread_stats = local_stats.get(thread.id, {})
            local_post_count = thread_stats.get("num_posts", 0)
            local_media_count = thread_stats.get("num_media", 0)
            if thread.source_type == "local":
                if local_post_count == 0 or not thread.posts:
                    continue
                op = thread.posts[0]
                t_dict = dict()
                t_dict["subject"] = op.subject
                t_dict["last_updated"] = thread.last_updated
                t_dict["body"] = op.body
                t_dict["id"] = thread.id
                t_dict.update(media_payload(op))
                t_dict["thread_url"] = "/threads/%d" % thread.id
                t_dict["spoiler"] = op.spoiler
                t_dict["tags"] = list(map(lambda t: t.name, thread.tags))
                t_dict["views"] = thread.views
                t_dict["num_replies"] = max(0, local_post_count - 1)
                t_dict["num_media"] = local_media_count
                t_dict["admin_post"] = thread.admin_is_op()
                t_dict["op_poster_id"] = op.poster
                t_dict.update(source_metadata(
                    "local", None, None,
                    watermark_url=getattr(op, "source_watermark_url", None),
                    watermark_label=getattr(op, "source_watermark_label", None),
                ))
                result.append(t_dict)
            else:
                op_data = imported_op_data.get(thread.id)
                if op_data is None:
                    if local_post_count == 0 or not thread.posts:
                        continue
                    op = thread.posts[0]
                    t_dict = dict()
                    t_dict["subject"] = op.subject
                    t_dict["last_updated"] = thread.last_updated
                    t_dict["body"] = op.body
                    t_dict["id"] = thread.id
                    t_dict.update(media_payload(op))
                    t_dict["thread_url"] = "/threads/%d" % thread.id
                    t_dict["spoiler"] = op.spoiler
                    t_dict["tags"] = [tag.name for tag in thread.tags]
                    t_dict["views"] = thread.views
                    t_dict["num_replies"] = max(0, local_post_count - 1)
                    t_dict["num_media"] = local_media_count
                    t_dict["admin_post"] = False
                    t_dict["op_poster_id"] = op.poster
                    t_dict.update(source_metadata(thread.source_type, thread.source_name, thread.source_url))
                    result.append(t_dict)
                    continue
                t_dict = dict()
                t_dict["subject"] = op_data.get("subject")
                t_dict["last_updated"] = thread.last_updated
                t_dict["body"] = op_data.get("body", "")
                t_dict["id"] = thread.id
                t_dict["thread_url"] = "/threads/%d" % thread.id
                t_dict["spoiler"] = False
                t_dict["tags"] = [tag.name for tag in thread.tags]
                t_dict["views"] = thread.views
                t_dict["num_replies"] = op_data.get("num_replies", 0) + local_post_count
                t_dict["num_media"] = op_data.get("num_media", 0) + local_media_count
                t_dict["admin_post"] = False
                t_dict.update(imported_thread_media_payload(thread, op_data))
                t_dict.update(source_metadata(thread.source_type, thread.source_name, thread.source_url))
                result.append(t_dict)
        self._annotate_keywords(result)
        return result

    def _annotate_keywords(self, threads):
        documents = []
        document_frequency = Counter()

        for thread in threads:
            text_parts = [
                thread.get("subject") or "",
                thread.get("body") or "",
                " ".join(thread.get("tags") or []),
            ]
            token_pairs = _keyword_tokens(" ".join(text_parts))
            stem_counts = Counter()
            stem_surfaces = {}
            for surface, stem in token_pairs:
                stem_counts[stem] += 1
                stem_surfaces.setdefault(stem, Counter())[surface] += 1
            for stem in stem_counts.keys():
                document_frequency[stem] += 1
            documents.append(
                {
                    "thread": thread,
                    "token_count": len(token_pairs),
                    "stem_counts": stem_counts,
                    "stem_surfaces": stem_surfaces,
                }
            )

        total_documents = max(1, len(documents))
        for document in documents:
            ranked_keywords = []
            token_count = max(1, document["token_count"])
            for stem, count in document["stem_counts"].items():
                tf = count / token_count
                idf = math.log((1 + total_documents) / (1 + document_frequency.get(stem, 0))) + 1
                representative = sorted(
                    document["stem_surfaces"][stem].items(),
                    key=lambda entry: (-entry[1], len(entry[0]), entry[0]),
                )[0][0]
                ranked_keywords.append((tf * idf, representative))
            ranked_keywords.sort(key=lambda entry: (-entry[0], entry[1]))
            document["thread"]["keywords"] = [
                keyword for _, keyword in ranked_keywords[:KEYWORD_LIMIT]
            ]

    def _local_thread_stats(self, threads):
        thread_ids = [thread.id for thread in threads]
        if not thread_ids:
            return {}

        stats = {
            thread_id: {"num_posts": 0, "num_media": 0}
            for thread_id in thread_ids
        }
        post_counts = (
            db.session.query(Post.thread, func.count(Post.id))
            .filter(Post.thread.in_(thread_ids))
            .group_by(Post.thread)
            .all()
        )
        media_counts = (
            db.session.query(Post.thread, func.count(Post.id))
            .filter(Post.thread.in_(thread_ids), Post.media.isnot(None))
            .group_by(Post.thread)
            .all()
        )

        for thread_id, count in post_counts:
            stats[thread_id]["num_posts"] = int(count or 0)
        for thread_id, count in media_counts:
            stats[thread_id]["num_media"] = int(count or 0)

        return stats

    def _fetch_imported_op_data(self, imported_threads):
        """Read OP subject/body/image and post counts from SQLite for catalog display."""
        from services.aggregator_sync.scraper_db import (
            aggregator_db_path,
            _read_scraper_db,
            _scraper_posts_source_column,
            _reddit_uses_universal_schema,
            _thread_source_name_candidates,
            _sqlite_table_exists,
        )
        from services.aggregator_sync.text import row_value, _clip_imported_text
        from services.aggregator_sync.config import (
            MAX_IMPORTED_BODY_LENGTH,
            MAX_IMPORTED_SOURCE_ID_LENGTH,
            MAX_IMPORTED_SUBJECT_LENGTH,
        )

        by_source_type = {}
        for thread in imported_threads:
            if thread.source_thread_id:
                by_source_type.setdefault(thread.source_type, []).append(thread)

        result = {}
        for source_type, threads in by_source_type.items():
            try:
                db_path = aggregator_db_path(source_type)
            except ValueError:
                continue
            if not os.path.exists(db_path):
                continue

            thread_pairs = []
            pair_to_page_id = {}
            for thread in threads:
                pair_key = ((thread.source_name or "").strip(), str(thread.source_thread_id))
                thread_pairs.append(pair_key)
                pair_to_page_id[pair_key] = thread.id
            source_thread_ids = sorted({pair[1] for pair in thread_pairs})
            if not source_thread_ids:
                continue

            def _reader(conn, pair_map=pair_to_page_id, source_ids=source_thread_ids, stype=source_type):
                rows = {}
                if stype == "reddit" and _reddit_uses_universal_schema(conn):
                    placeholders = ",".join(["?"] * len(source_ids))
                    ops = conn.execute(
                        (
                            "SELECT id AS source_thread_id, title AS subject, selftext AS body_text, image_url, image_path "
                            "FROM posts WHERE id IN (%s)"
                        ) % placeholders,
                        source_ids,
                    ).fetchall()
                    reply_counts = {}
                    if _sqlite_table_exists(conn, "comments"):
                        reply_rows = conn.execute(
                            (
                                "SELECT post_id AS source_thread_id, COUNT(*) AS num_replies "
                                "FROM comments WHERE post_id IN (%s) GROUP BY post_id"
                            ) % placeholders,
                            source_ids,
                        ).fetchall()
                        reply_counts = {
                            str(row["source_thread_id"]): int(row["num_replies"] or 0)
                            for row in reply_rows
                        }
                    for op in ops:
                        source_thread_id = str(op["source_thread_id"])
                        pg_id = pair_map.get(("", source_thread_id))
                        if pg_id is None:
                            continue
                        rows[pg_id] = {
                            "source_post_id": _clip_imported_text(source_thread_id, MAX_IMPORTED_SOURCE_ID_LENGTH),
                            "subject": _clip_imported_text(op["subject"], MAX_IMPORTED_SUBJECT_LENGTH),
                            "body": _clip_imported_text(op["body_text"] or "", MAX_IMPORTED_BODY_LENGTH) or "",
                            "image_url": row_value(op, "image_url"),
                            "image_path": row_value(op, "image_path"),
                            "num_replies": reply_counts.get(source_thread_id, 0),
                            "num_media": 1 if row_value(op, "image_path") or row_value(op, "image_url") else 0,
                        }
                    return rows

                from services.aggregator_sync.scraper_db import _sqlite_table_columns
                post_cols = _sqlite_table_columns(conn, "posts")
                has_image_url = "image_url" in post_cols
                has_image_path = "image_path" in post_cols
                source_col = _scraper_posts_source_column(conn, stype)
                placeholders = ",".join(["?"] * len(source_ids))
                op_rows = conn.execute(
                    (
                        "SELECT * FROM posts WHERE thread_id IN (%s) AND post_id = thread_id"
                    ) % placeholders,
                    source_ids,
                ).fetchall()
                representative_rows = {
                    (str(row_value(op, source_col) or "").strip(), str(row_value(op, "thread_id"))): op
                    for op in op_rows
                }
                count_rows = conn.execute(
                    (
                        "SELECT %s AS source_name, thread_id, COUNT(*) AS num_posts "
                        "FROM posts WHERE thread_id IN (%s) GROUP BY %s, thread_id"
                    ) % (source_col, placeholders, source_col),
                    source_ids,
                ).fetchall()
                count_map = {
                    (str(row["source_name"] or "").strip(), str(row["thread_id"])): int(row["num_posts"] or 0)
                    for row in count_rows
                }
                media_map = {}
                media_conditions = []
                if has_image_path:
                    media_conditions.append("image_path IS NOT NULL AND image_path != ''")
                if has_image_url:
                    media_conditions.append("image_url IS NOT NULL AND image_url != ''")
                if media_conditions:
                    media_rows = conn.execute(
                        (
                            "SELECT %s AS source_name, thread_id, COUNT(*) AS num_media "
                            "FROM posts WHERE thread_id IN (%s) AND (%s) GROUP BY %s, thread_id"
                        ) % (source_col, placeholders, " OR ".join(media_conditions), source_col),
                        source_ids,
                    ).fetchall()
                    media_map = {
                        (str(row["source_name"] or "").strip(), str(row["thread_id"])): int(row["num_media"] or 0)
                        for row in media_rows
                    }
                missing_pairs = [
                    pair_key
                    for pair_key in count_map.keys()
                    if pair_key in pair_map and pair_key not in representative_rows
                ]
                for source_value, thread_id in missing_pairs:
                    fallback_row = conn.execute(
                        (
                            "SELECT * FROM posts WHERE %s = ? AND thread_id = ? "
                            "ORDER BY scraped_at ASC, post_id ASC LIMIT 1"
                        ) % source_col,
                        (source_value, thread_id),
                    ).fetchone()
                    if fallback_row is not None:
                        representative_rows[(source_value, thread_id)] = fallback_row
                for pair_key in thread_pairs:
                    pg_id = pair_map.get(pair_key)
                    if pg_id is None:
                        continue
                    source_name, thread_id = pair_key
                    candidate_pairs = [
                        (candidate_source_name, thread_id)
                        for candidate_source_name in (
                            _thread_source_name_candidates(conn, stype, thread_id, source_name)
                            or ([source_name] if source_name else [])
                        )
                    ]
                    op = None
                    matched_pair = None
                    for candidate_pair in candidate_pairs:
                        op = representative_rows.get(candidate_pair)
                        if op is not None:
                            matched_pair = candidate_pair
                            break
                    if op is None:
                        for candidate_source_name, candidate_thread_id in candidate_pairs:
                            fallback_row = conn.execute(
                                (
                                    "SELECT * FROM posts WHERE %s = ? AND thread_id = ? "
                                    "ORDER BY scraped_at ASC, post_id ASC LIMIT 1"
                                ) % source_col,
                                (candidate_source_name, candidate_thread_id),
                            ).fetchone()
                            if fallback_row is not None:
                                op = fallback_row
                                matched_pair = (candidate_source_name, candidate_thread_id)
                                break
                    if op is None:
                        continue
                    lookup_pairs = [matched_pair] if matched_pair is not None else []
                    lookup_pairs.extend(
                        candidate_pair
                        for candidate_pair in candidate_pairs
                        if candidate_pair not in lookup_pairs
                    )
                    num_posts = next(
                        (count_map[candidate_pair] for candidate_pair in lookup_pairs if candidate_pair in count_map),
                        1,
                    )
                    rows[pg_id] = {
                        "source_post_id": _clip_imported_text(row_value(op, "post_id"), MAX_IMPORTED_SOURCE_ID_LENGTH),
                        "subject": _clip_imported_text(row_value(op, "subject"), MAX_IMPORTED_SUBJECT_LENGTH),
                        "body": _clip_imported_text(row_value(op, "body_text", "") or "", MAX_IMPORTED_BODY_LENGTH) or "",
                        "image_url": row_value(op, "image_url") if has_image_url else None,
                        "image_path": row_value(op, "image_path") if has_image_path else None,
                        "num_replies": max(0, num_posts - 1),
                        "num_media": next(
                            (media_map[candidate_pair] for candidate_pair in lookup_pairs if candidate_pair in media_map),
                            0,
                        ),
                    }
                return rows

            try:
                result.update(_read_scraper_db(db_path, _reader))
            except Exception:
                app.logger.exception("Failed to read SQLite catalog data for source type %s", source_type)

        return result
