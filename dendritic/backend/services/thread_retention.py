from model.Thread import Thread
from shared import db

from services.aggregator_sync.media import delete_thread


def trim_board_threads(board, limit=None, protected_thread_ids=None):
    if limit is None:
        limit = board.max_threads
    limit = max(int(limit), 0)
    protected_thread_ids = set(protected_thread_ids or ())

    board_threads = (
        db.session.query(Thread)
        .filter(Thread.board == board.id)
        .order_by(Thread.last_updated.asc(), Thread.id.asc())
        .all()
    )
    excess_threads = len(board_threads) - limit
    if excess_threads <= 0:
        return []

    removable_threads = [thread for thread in board_threads if thread.id not in protected_thread_ids]
    if len(removable_threads) < excess_threads:
        removable_threads = board_threads

    evicted_threads = removable_threads[:excess_threads]
    for thread in evicted_threads:
        delete_thread(thread)
    return evicted_threads


def make_room_for_new_thread(board):
    return trim_board_threads(board, limit=max(int(board.max_threads) - 1, 0))
