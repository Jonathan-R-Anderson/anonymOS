"""Gamified coding practice, keyed to a slip.

Ported from the CodePlay project (React + Express + MongoDB) into this app's
stack. Only the mechanics and content came across; its accounts did not. The
upstream had its own username/email/password User collection and JWT login,
which would have been a second, parallel identity system sitting next to slips.
There is exactly one identity here and it is the slip, so progress hangs off
slip_id and every route is gated by get_slip().
"""
import datetime as _datetime

from shared import db


# XP needed to reach level N is LEVEL_STEP * N. Upstream used `level * 100`
# and recomputed the level ad hoc in the UI; doing it in one place keeps the
# stored level and the progress bar from disagreeing.
LEVEL_STEP = 100

# What each mode is worth. Upstream awarded a flat 10 for everything except
# problems; graded by effort instead so a hard problem outweighs a flashcard.
XP_BY_MODE = {
    "mcq": 5,
    "flashcard": 3,
    "bughunter": 12,
    "daily": 15,
    "problem": 25,
}
# Six bands, adopted from the Edabit import because three cannot usefully order
# eight thousand problems. Easy/Medium/Hard keep their names and multipliers, so
# every pre-existing problem and every XP figure already awarded still means what
# it meant. See services/edabit_import.py.
#
# .get(difficulty, 1.0) at the call site makes an unknown label score as Easy
# rather than raise, which is the right failure: a mislabelled problem should
# still pay something.
DIFFICULTY_MULTIPLIER = {
    "Very Easy": 0.5,
    "Easy": 1.0,
    "Medium": 1.5,
    "Hard": 2.0,
    "Very Hard": 3.0,
    "Expert": 4.0,
}


class CodeplayProgress(db.Model):
    """One row per slip. Created lazily on first activity."""
    __tablename__ = "codeplay_progress"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), unique=True, nullable=False)
    xp = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    level = db.Column(db.Integer, nullable=False, default=1, server_default="1")
    # Consecutive days with at least one solved item.
    streak = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    best_streak = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    last_active_on = db.Column(db.Date, nullable=True)
    # Earned badge slugs, newline-separated. A JSON column would be tidier but
    # this table is read on every profile render and a plain string keeps it
    # portable across the sqlite devmode config and Postgres.
    badges = db.Column(db.Text, nullable=False, default="", server_default="")
    attempts = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    correct = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    slip = db.relationship(
        "Slip",
        backref=db.backref("codeplay", uselist=False, cascade="all, delete-orphan"),
    )

    @property
    def badge_list(self):
        return [b for b in (self.badges or "").split("\n") if b]

    def award_badge(self, slug):
        if slug in self.badge_list:
            return False
        current = self.badge_list + [slug]
        self.badges = "\n".join(current)
        return True

    @property
    def xp_into_level(self):
        """XP earned toward the next level, and what that level costs."""
        needed = LEVEL_STEP * self.level
        earned = self.xp - sum(LEVEL_STEP * n for n in range(1, self.level))
        return max(0, earned), needed

    @property
    def level_percent(self):
        earned, needed = self.xp_into_level
        if needed <= 0:
            return 0
        return min(100, int(round(earned * 100.0 / needed)))

    @property
    def accuracy(self):
        if not self.attempts:
            return 0
        return int(round(self.correct * 100.0 / self.attempts))


class CodeplayAttempt(db.Model):
    """One row per graded answer.

    Kept rather than only counters because the skill radar is derived from
    per-category history, and because a repeat of an already-solved item must
    not pay XP twice.
    """
    __tablename__ = "codeplay_attempt"
    __table_args__ = (
        db.Index("ix_codeplay_attempt_slip_mode", "slip_id", "mode"),
        db.Index("ix_codeplay_attempt_lookup", "slip_id", "mode", "item_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False)
    mode = db.Column(db.String(16), nullable=False)
    item_id = db.Column(db.String(64), nullable=False)
    category = db.Column(db.String(64), nullable=False, default="", server_default="")
    difficulty = db.Column(db.String(16), nullable=False, default="", server_default="")
    was_correct = db.Column(db.Boolean, nullable=False, default=False, server_default="0")
    xp_awarded = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    created_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow
    )

    slip = db.relationship("Slip", backref=db.backref("codeplay_attempts", cascade="all, delete-orphan"))
