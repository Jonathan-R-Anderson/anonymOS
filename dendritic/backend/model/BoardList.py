from model.Board import Board
from model.BoardListCatalog import BoardCatalog
from model.PostPresentation import media_payload
from services.aggregator_sync.media import imported_thread_media_payload
from board_access import visible_boards
from shared import db


class BoardList:
    def get(self):
        board_query = list(visible_boards(db.session.query(Board).all()))
        imported_threads = []
        for board in board_query:
            imported_threads.extend([thread for thread in board.threads if thread.source_type != "local"])
        imported_op_data = BoardCatalog()._fetch_imported_op_data(imported_threads) if imported_threads else {}
        boards = []
        for board in board_query:
            b_dict = {}
            b_dict["id"] = board.id
            b_dict["name"] = board.name
            b_dict["display_name"] = board.title
            b_dict["private"] = board.is_private
            b_dict["owner"] = board.owner_slip_id
            b_dict["source_count"] = len(board.sources)
            b_dict["board_type"] = board.board_type
            b_dict["geo_scope"] = board.geo_scope_label
            b_dict["media"] = None
            b_dict["thumb_url"] = None
            b_dict["media_url"] = None
            b_dict["torrent"] = None
            b_dict["mimetype"] = None
            for thread in board.threads:
                if thread.source_type != "local":
                    op_data = imported_op_data.get(thread.id)
                    if op_data is None:
                        continue
                    media = imported_thread_media_payload(thread, op_data)
                    if media.get("media") is not None and media.get("thumb_url"):
                        b_dict["media"] = media["media"]
                        b_dict["thumb_url"] = media["thumb_url"]
                        b_dict["media_url"] = media.get("media_url")
                        b_dict["torrent"] = media.get("torrent")
                        b_dict["mimetype"] = media.get("mimetype")
                        break
                    continue
                if len(thread.posts) == 0:
                    continue
                op = thread.posts[0]
                media = media_payload(op)
                if media["media"] is not None and op.spoiler is not True:
                    b_dict["media"] = media["media"]
                    b_dict["thumb_url"] = media["thumb_url"]
                    b_dict["media_url"] = media.get("media_url")
                    b_dict["torrent"] = media.get("torrent")
                    b_dict["mimetype"] = media.get("mimetype")
                    break
            boards.append(b_dict)
        return boards
