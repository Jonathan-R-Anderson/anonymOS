"""Delete inactive user-created boards.

A sysop-wide setting (`board_inactivity_delete_days`, default 30) sets a hard
limit on how many days a board may go with no new post before it is deleted.
The limit applies ONLY to user-created boards — boards owned by an admin (or
with no owner, or non-standard geo boards) are exempt. A background thread runs
the sweep hourly; it can also be invoked directly.
"""
import datetime as _datetime

from sqlalchemy import func

import shared
from shared import db
from model.Board import Board
from model.Thread import Thread
from model.SiteSetting import get_setting


SETTING_KEY = "board_inactivity_delete_days"
DEFAULT_DAYS = 30
_SWEEP_INTERVAL_SECONDS = 3600


def inactivity_delete_days():
    """The configured limit in days. 0 (or invalid/negative) disables deletion."""
    raw = get_setting(SETTING_KEY, str(DEFAULT_DAYS))
    try:
        days = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_DAYS
    return max(0, days)


def _owner_is_admin(board):
    owner_slip_id = getattr(board, "owner_slip_id", None)
    if owner_slip_id is None:
        # No owner => not a user-created board; exempt.
        return True
    from model.Slip import slip_from_id
    owner = slip_from_id(owner_slip_id)
    if owner is None:
        return False
    return bool(getattr(owner, "is_admin", False))


def _board_last_activity(board):
    """Most recent post activity for a board (max thread bump time), falling
    back to the board's creation time when it has no threads."""
    latest = (
        db.session.query(func.max(Thread.last_updated))
        .filter(Thread.board == board.id)
        .scalar()
    )
    if latest is not None:
        return latest
    return getattr(board, "created_at", None)


def run_board_cleanup():
    """Delete every eligible user-created board past the inactivity limit.
    Returns the number of boards deleted."""
    days = inactivity_delete_days()
    if days <= 0:
        return 0
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=days)
    # Only standard boards can expire (geo/geo-generated boards are exempt).
    candidates = (
        db.session.query(Board)
        .filter(Board.board_type == "standard")
        .all()
    )
    # Import here to avoid a circular import at module load (admin imports models).
    from blueprints.admin import _delete_board
    deleted = 0
    for board in candidates:
        if _owner_is_admin(board):
            continue
        last_activity = _board_last_activity(board)
        if last_activity is None:
            continue  # unknown age; leave it alone
        if last_activity < cutoff:
            _delete_board(board)
            deleted += 1
    if deleted:
        db.session.commit()
    return deleted


def start_board_cleanup(flask_app):
    def _loop():
        import time as _time
        _time.sleep(30)
        while True:
            try:
                with flask_app.app_context():
                    removed = run_board_cleanup()
                    if removed:
                        flask_app.logger.info("Board cleanup deleted %d inactive board(s)", removed)
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("Board inactivity cleanup failed")
            _time.sleep(_SWEEP_INTERVAL_SECONDS)

    shared.spawn_native_thread(target=_loop, name="board-cleanup", daemon=True)
