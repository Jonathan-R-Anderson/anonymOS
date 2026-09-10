import datetime
import json

from flask.json import jsonify
from sqlalchemy import desc

import cache
from board_access import can_access_board, viewer_can_use_public_cache
from shared import app, db
from model.Board import Board
from model.BoardListCatalog import BoardCatalog
from model.Post import render_for_catalog
from model.Thread import Thread
from model.Slip import get_slip
from model.ThreadPosts import _datetime_handler


class Firehose:
    def get(self):
        from flask import request
        if request.args.get("sort") == "recent":
            # Recency feed for the live front page. The default firehose is
            # recommendation-ranked and truncated to FIREHOSE_LENGTH, so a
            # brand-new thread (no engagement) never survives ranking to the top
            # and the front page can't reflect new posts without a refresh. This
            # mode returns the raw candidate pool, which _get_threads() already
            # orders by Thread.last_updated DESC, unranked — newest first.
            threads = self._get_threads()
            from model.ShadowBan import hidden_poster_ids
            hidden = hidden_poster_ids()
            if hidden:
                threads = [t for t in threads if t.get("op_poster_id") not in hidden]
            limit = max(1, int(app.config.get("FIREHOSE_LENGTH", 10))) * 3
            return jsonify(threads[:limit])
        threads, _result = self._rank_threads("firehose_api")
        return jsonify(threads)

    def get_impl(self):
        threads, _result = self._rank_threads("firehose")
        # Hide threads whose OP is shadowbanned (unless the viewer is that author).
        # Shadowbanned viewers bypass the shared cache (viewer_can_use_public_cache),
        # so this per-request filter keeps their own threads visible to them only.
        from model.ShadowBan import hidden_poster_ids
        hidden = hidden_poster_ids()
        if hidden:
            threads = [t for t in threads if t.get("op_poster_id") not in hidden]
        for thread in threads:
            board_id = thread["board"]
            board = db.session.query(Board).get(board_id)
            thread["board"] = board.name
        render_for_catalog(threads)
        return threads

    def _rank_threads(self, surface):
        from services.recommendations.engine import rank_payloads

        threads = self._get_threads()
        return rank_payloads(
            threads, "thread", surface, limit=app.config["FIREHOSE_LENGTH"], board_scoped=False,
        )

    def _get_threads(self):
        firehose_cache_key = "firehose-threads-v2-candidates"
        cache_connection = cache.Cache()
        use_cache = viewer_can_use_public_cache()
        cached_threads = cache_connection.get(firehose_cache_key) if use_cache else None
        if cached_threads:
            deserialized_threads = json.loads(cached_threads)
            for thread in deserialized_threads:
                thread["last_updated"] = datetime.datetime.utcfromtimestamp(thread["last_updated"])
            return deserialized_threads
        firehose_limit = max(100, app.config["FIREHOSE_LENGTH"] * 10)
        raw_threads = db.session.query(Thread).order_by(desc(Thread.last_updated)).all()
        visible_threads = []
        slip = get_slip()
        for thread in raw_threads:
            board = db.session.query(Board).get(thread.board)
            if can_access_board(board, slip):
                visible_threads.append(thread)
            if len(visible_threads) >= firehose_limit:
                break
        threads = BoardCatalog()._to_json(visible_threads)
        for thread in threads:
            db_thread = db.session.query(Thread).get(thread["id"])
            thread["board"] = db_thread.board
        if use_cache:
            cache_friendly = json.dumps(threads, default=_datetime_handler)
            cache_connection.set(firehose_cache_key, cache_friendly)
        return threads
