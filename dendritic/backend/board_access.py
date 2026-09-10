from typing import Iterable, List, Optional, Tuple

from flask import abort, has_request_context

from geo_boards import viewer_can_access_geo_board
from model.Board import Board
from model.Post import Post
from model.Slip import Slip, get_slip, slip_can_moderate, slip_is_admin
from model.Thread import Thread
from shared import db, db_retry


def _resolve_slip(slip: Optional[Slip] = None) -> Optional[Slip]:
    if slip is not None:
        return slip
    if has_request_context() is False:
        return None
    return get_slip()


def _viewer_can_manage(board: Board, slip: Optional[Slip] = None) -> bool:
    slip = _resolve_slip(slip)
    if slip is None:
        return False
    is_admin = slip_is_admin(slip) if has_request_context() else bool(getattr(slip, "is_admin", False))
    return is_admin or board.owner_slip_id == slip.id


def _viewer_can_moderate(board: Board, slip: Optional[Slip] = None) -> bool:
    slip = _resolve_slip(slip)
    if slip is None:
        return False
    return slip_can_moderate(slip, board=board)


def can_access_board(board: Board, slip: Optional[Slip] = None) -> bool:
    if board.is_geo_root:
        return True
    if _viewer_can_manage(board, slip):
        return True
    if _viewer_can_moderate(board, slip):
        return True
    if board.is_geo_generated:
        return viewer_can_access_geo_board(board)
    if board.is_private is False:
        return True
    return False


def can_manage_board(board: Board, slip: Optional[Slip] = None) -> bool:
    return _viewer_can_manage(board, slip)


def ensure_board_access(board: Board, slip: Optional[Slip] = None) -> Board:
    if can_access_board(board, slip):
        return board
    abort(404)


# @db_retry()
def get_board_or_404(board_id: int, slip: Optional[Slip] = None) -> Board:
    board = db.session.query(Board).filter(Board.id == board_id).one_or_none()
    if board is None:
        abort(404)
    return ensure_board_access(board, slip)


# @db_retry()
def get_board_by_name_or_404(board_name: str, slip: Optional[Slip] = None) -> Board:
    board = db.session.query(Board).filter(Board.name == board_name).one_or_none()
    if board is None:
        abort(404)
    return ensure_board_access(board, slip)


# @db_retry()
def get_thread_and_board_or_404(thread_id: int, slip: Optional[Slip] = None) -> Tuple[Thread, Board]:
    thread = db.session.query(Thread).filter(Thread.id == thread_id).one_or_none()
    if thread is None:
        abort(404)
    board = get_board_or_404(thread.board, slip)
    return thread, board


# @db_retry()
def get_post_thread_board_or_404(post_id: int, slip: Optional[Slip] = None) -> Tuple[Post, Thread, Board]:
    post = db.session.query(Post).filter(Post.id == post_id).one_or_none()
    if post is None:
        abort(404)
    thread, board = get_thread_and_board_or_404(post.thread, slip)
    return post, thread, board


def visible_boards(
    boards: Iterable[Board],
    slip: Optional[Slip] = None,
    include_geo_generated: bool = False,
) -> List[Board]:
    slip = _resolve_slip(slip)
    visible = []
    for board in boards:
        if board.is_geo_generated and include_geo_generated is False:
            continue
        if board.is_geo_generated and _viewer_can_manage(board, slip) is False and _viewer_can_moderate(board, slip) is False:
            continue
        if can_access_board(board, slip):
            visible.append(board)
    return visible


def viewer_can_use_public_cache(board: Optional[Board] = None, slip: Optional[Slip] = None) -> bool:
    slip = _resolve_slip(slip)
    if board is not None and (board.is_geo_root or board.is_geo_generated):
        return False
    if slip is not None or (board is not None and board.is_private):
        return False
    # Anonymous, public board: normally cacheable — but a shadowbanned viewer
    # (matched by IP here, since they're not logged in) must bypass the shared
    # cache so the per-request filter can keep showing them THEIR OWN otherwise
    # hidden content while everyone else's cached render excludes it.
    if has_request_context():
        from model.ShadowBan import viewer_is_shadowbanned
        if viewer_is_shadowbanned():
            return False
        # Privileged viewers (incl. the wallet-admin sysop who has no personal
        # slip session) must always get a fresh, mod-context render — never the
        # shared anonymous copy — so the moderation controls always appear.
        if slip_can_moderate(board=board):
            return False
    return True
