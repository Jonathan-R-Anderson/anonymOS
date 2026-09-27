import datetime
import json

from sqlalchemy import desc, func

import cache
from board_access import can_access_board, viewer_can_use_public_cache
from model.Board import Board
from model.BoardListCatalog import BoardCatalog
from model.Post import Post, render_for_catalog
from model.Slip import get_slip
from model.Thread import Thread
from model.ThreadPosts import _datetime_handler
from shared import db


class BoardActivity:
    CACHE_KEY = "board-activity-threads"

    def retrieve(self):
        cache_connection = cache.Cache()
        use_cache = viewer_can_use_public_cache()
        cached_threads = cache_connection.get(self.CACHE_KEY) if use_cache else None
        if cached_threads:
            deserialized_threads = json.loads(cached_threads)
            for thread in deserialized_threads:
                thread["last_updated"] = datetime.datetime.utcfromtimestamp(thread["last_updated"])
            return deserialized_threads

        activity_subquery = (
            db.session.query(
                Post.thread.label("thread_id"),
                func.max(Post.datetime).label("last_local_reply"),
            )
            .filter(Post.source_type == "local")
            .group_by(Post.thread)
            .subquery()
        )

        raw_threads = (
            db.session.query(Thread)
            .join(activity_subquery, activity_subquery.c.thread_id == Thread.id)
            .order_by(desc(activity_subquery.c.last_local_reply), desc(Thread.id))
            .all()
        )

        visible_threads = []
        boards = {}
        thread_board_ids = {}
        slip = get_slip()
        for thread in raw_threads:
            thread_board_ids[thread.id] = thread.board
            board = boards.get(thread.board)
            if board is None:
                board = db.session.query(Board).get(thread.board)
                boards[thread.board] = board
            if board is not None and can_access_board(board, slip):
                visible_threads.append(thread)

        threads = BoardCatalog()._to_json(visible_threads)
        for thread in threads:
            board = boards.get(thread_board_ids.get(thread["id"]))
            thread["board"] = board.name if board else "?"
            thread["board_id"] = board.id if board else None

        render_for_catalog(threads)
        if use_cache:
            cache_connection.set(self.CACHE_KEY, json.dumps(threads, default=_datetime_handler))
        return threads
