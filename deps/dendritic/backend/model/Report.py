"""User reports of posts, surfaced to the moderators of the board the post is
on. Not tied to a hard Post FK so it works for both local and imported posts;
the click-through uses thread_id + the post's display id as an anchor.

The same table also carries board-level messages to the mods ("message the
mods" in the board sidebar), distinguished by `kind`. They reuse this table
rather than getting their own so they land in the moderator queue and the report
bell that already exist. A board message has no post and no thread, so
`thread_id` is nullable and anything building a thread link must check `kind`
(or thread_id) first — see mod_reports() in blueprints/boards.py.
"""
import datetime as _datetime

from shared import db


MAX_REASON_LENGTH = 500

KIND_POST_REPORT = "post"
KIND_BOARD_MESSAGE = "board_message"


class Report(db.Model):
    __tablename__ = "report"

    id = db.Column(db.Integer, primary_key=True)
    # The reported post's display id and its thread (for the click-through
    # anchor) plus the board it lives on (for moderator scoping). Both are NULL
    # for KIND_BOARD_MESSAGE, which is addressed to the board, not to a post.
    post_id = db.Column(db.String(128), nullable=True)
    thread_id = db.Column(db.Integer, nullable=True, index=True)
    kind = db.Column(
        db.String(24), nullable=False, default=KIND_POST_REPORT, server_default=KIND_POST_REPORT, index=True
    )
    board_id = db.Column(db.Integer, db.ForeignKey("board.id", ondelete="CASCADE"), nullable=True, index=True)
    reason = db.Column(db.String(MAX_REASON_LENGTH), nullable=True)
    reporter_ip = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True)
    resolved = db.Column(db.Boolean, nullable=False, default=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)


def moderatable_board_ids(slip):
    """Board ids a slip may moderate: the sentinel "ALL" for admins / sitewide
    mods, otherwise the set of explicitly-assigned + owned boards. None means
    the slip has no moderation role at all."""
    if slip is None:
        return None
    from model.Slip import slip_is_admin, slip_moderated_board_ids
    from model.Board import Board
    if slip_is_admin(slip) or bool(getattr(slip, "is_mod", False)):
        return "ALL"
    ids = set(slip_moderated_board_ids(slip))
    owned = {
        board_id
        for (board_id,) in db.session.query(Board.id).filter(Board.owner_slip_id == slip.id).all()
    }
    ids |= owned
    return ids if ids else None


def viewer_moderates_anything():
    """True if the current viewer can moderate at least one board (admin,
    sitewide mod, assigned board mod, or board owner) — i.e. should see the
    report notifier."""
    from model.Slip import get_slip
    return moderatable_board_ids(get_slip()) is not None


def open_reports_for_slip(slip):
    scope = moderatable_board_ids(slip)
    if scope is None:
        return []
    query = db.session.query(Report).filter(Report.resolved.is_(False))
    if scope != "ALL":
        query = query.filter(Report.board_id.in_(scope))
    return query.order_by(Report.created_at.desc()).limit(50).all()


def slip_can_resolve_report(slip, report):
    scope = moderatable_board_ids(slip)
    if scope is None:
        return False
    if scope == "ALL":
        return True
    return report.board_id in scope


def resolve_reports_for_thread(thread_id, slip):
    """When a moderator opens a thread, clear its open reports (they've now seen
    the reported content, regardless of what they do about it). No-op for
    non-moderators / boards they can't moderate. Returns the number resolved."""
    if slip is None:
        return 0
    open_ids = [
        report_id
        for (report_id,) in db.session.query(Report.id)
        .filter(Report.thread_id == thread_id, Report.resolved.is_(False))
        .all()
    ]
    if not open_ids:
        return 0
    from model.Thread import Thread
    from model.Slip import slip_can_moderate
    board_id = db.session.query(Thread.board).filter(Thread.id == thread_id).scalar()
    # A lightweight board object is enough for slip_can_moderate's ownership check.
    from model.Board import Board
    board = db.session.query(Board).filter(Board.id == board_id).one_or_none() if board_id else None
    if not slip_can_moderate(slip=slip, board=board):
        return 0
    resolved_at = _datetime.datetime.utcnow()
    count = (
        db.session.query(Report)
        .filter(Report.id.in_(open_ids))
        .update({Report.resolved: True, Report.resolved_at: resolved_at}, synchronize_session=False)
    )
    return count


def create_report(thread_id, post_id, reason, reporter_ip):
    """Create a report for a post, resolving its board from the thread. Skips
    (returns None) if the same IP already has an open report on that post."""
    from model.Thread import Thread
    thread = db.session.query(Thread).filter(Thread.id == thread_id).one_or_none()
    if thread is None:
        return None
    board_id = thread.board
    post_id = (str(post_id).strip() or None) if post_id is not None else None
    reason = (reason or "").strip()[:MAX_REASON_LENGTH] or None

    existing = (
        db.session.query(Report.id)
        .filter(
            Report.resolved.is_(False),
            Report.thread_id == thread_id,
            Report.post_id == post_id,
            Report.reporter_ip == reporter_ip,
        )
        .first()
    )
    if existing is not None:
        return None

    report = Report(
        post_id=post_id,
        thread_id=thread_id,
        board_id=board_id,
        reason=reason,
        reporter_ip=reporter_ip,
        kind=KIND_POST_REPORT,
    )
    db.session.add(report)
    return report


# A sender gets one open message per board at a time. The sidebar form is
# unauthenticated (anyone reading a board can reach the mods), so without this a
# single visitor could flood the moderation queue.
def create_board_message(board_id, message, sender_ip):
    """Queue a "message the mods" note for a board. Returns the Report, or None
    if this sender already has an unresolved message open on this board."""
    message = (message or "").strip()[:MAX_REASON_LENGTH]
    if not message:
        raise ValueError("Enter a message for the moderators.")

    existing = (
        db.session.query(Report.id)
        .filter(
            Report.resolved.is_(False),
            Report.kind == KIND_BOARD_MESSAGE,
            Report.board_id == board_id,
            Report.reporter_ip == sender_ip,
        )
        .first()
    )
    if existing is not None:
        return None

    report = Report(
        post_id=None,
        thread_id=None,
        board_id=board_id,
        reason=message,
        reporter_ip=sender_ip,
        kind=KIND_BOARD_MESSAGE,
    )
    db.session.add(report)
    return report


def board_messages_for_board(board_id, include_resolved=False, limit=50):
    """Board-level messages addressed to one board's moderators, newest first."""
    query = db.session.query(Report).filter(
        Report.kind == KIND_BOARD_MESSAGE,
        Report.board_id == board_id,
    )
    if include_resolved is False:
        query = query.filter(Report.resolved.is_(False))
    return query.order_by(Report.created_at.desc()).limit(limit).all()
