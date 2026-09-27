"""One player's daily challenge, written once per day.

The uniqueness constraint on (slip_id, day) is the feature, not bookkeeping.
Without it a refresh generates a new challenge, and a player who dislikes
today's question simply reloads until they get an easy one — which turns a daily
challenge into a slot machine and makes any streak built on it meaningless.

It also bounds cost: at most one generation per player per day, enforced by the
database rather than by remembering to check.
"""

import datetime as _datetime
import json as _json

from shared import db


class CodeplayDailyChallenge(db.Model):
    __tablename__ = "codeplay_daily_challenge"
    __table_args__ = (
        db.UniqueConstraint("slip_id", "day", name="uq_codeplay_daily_slip_day"),
    )

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    day = db.Column(db.Date, nullable=False, index=True)
    payload = db.Column(db.Text, nullable=False, default="{}")
    # Which weak categories this was aimed at, kept so the page can say why
    # somebody got this challenge. A personalised system that cannot explain
    # itself feels arbitrary, and arbitrary is indistinguishable from broken.
    aimed_at = db.Column(db.String(200), nullable=False, default="", server_default="")
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow)

    def item(self):
        try:
            data = _json.loads(self.payload) if self.payload else {}
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}


def mark_completed(slip_id, day, now=None):
    """Idempotent: re-submitting a solved challenge must not move its date."""
    row = (
        db.session.query(CodeplayDailyChallenge)
        .filter(CodeplayDailyChallenge.slip_id == slip_id,
                CodeplayDailyChallenge.day == day)
        .one_or_none()
    )
    if row is None or row.completed_at is not None:
        return row
    row.completed_at = now or _datetime.datetime.utcnow()
    return row


def streak(slip_id, now=None):
    """Consecutive days completed, ending today or yesterday.

    Yesterday counts as still-alive so a streak does not die at midnight before
    the player has had any chance to act on it — the alternative punishes
    timezone as much as effort.
    """
    today = (now or _datetime.datetime.utcnow()).date()
    rows = (
        db.session.query(CodeplayDailyChallenge.day)
        .filter(CodeplayDailyChallenge.slip_id == slip_id,
                CodeplayDailyChallenge.completed_at.isnot(None))
        .order_by(CodeplayDailyChallenge.day.desc())
        .limit(400)
        .all()
    )
    days = [row[0] for row in rows]
    if not days:
        return 0
    if (today - days[0]).days > 1:
        return 0
    count, expected = 0, days[0]
    for day in days:
        if day != expected:
            break
        count += 1
        expected = expected - _datetime.timedelta(days=1)
    return count
