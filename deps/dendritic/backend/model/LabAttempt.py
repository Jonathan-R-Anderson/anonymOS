"""Every answer submitted to a lab question, right or wrong.

LabSolve records that somebody got there. This records HOW, and the difference
is the whole point: a box solved on the first try in forty minutes and the same
box solved on the sixtieth try over a week are the same row in LabSolve and
completely different evidence about the person.

Wrong answers are the more useful half. They are what makes it possible to say
anything about skill at all — without them every solve looks equally clean, and
a skill chart built on solves alone measures persistence and calls it ability.

WHAT IS DELIBERATELY NOT STORED
-------------------------------
The submitted text. A wrong answer to an instance-secret question is often a
password, a token, or a hash the person pulled off the box, and keeping a log of
those is a liability with no use — the count and the timing are what feed the
chart, and the string never does.
"""

import datetime as _datetime

from shared import db


class LabAttempt(db.Model):
    __tablename__ = "lab_attempt"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    challenge_id = db.Column(db.Integer, nullable=False, index=True)
    question_id = db.Column(db.Integer, db.ForeignKey("lab_question.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    was_correct = db.Column(db.Boolean, nullable=False, default=False)
    # Minutes from this slip's first attempt at the question to this one.
    # Measured from the first ATTEMPT rather than from when the container
    # booted: people leave a box running overnight, and counting that as
    # thinking time would make everyone look slow in proportion to how tidy they
    # are about shutting down.
    minutes_elapsed = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def first_attempt_at(slip_id, question_id):
    """When this slip first tried this question, or None."""
    return (
        db.session.query(db.func.min(LabAttempt.created_at))
        .filter(LabAttempt.slip_id == slip_id, LabAttempt.question_id == question_id)
        .scalar()
    )


def record(slip_id, challenge_id, question_id, was_correct, now=None):
    """Log an attempt and return it. Caller commits."""
    now = now or _datetime.datetime.utcnow()
    started = first_attempt_at(slip_id, question_id) or now
    minutes = max(0, int((now - started).total_seconds() // 60))
    attempt = LabAttempt(
        slip_id=slip_id, challenge_id=challenge_id, question_id=question_id,
        was_correct=bool(was_correct), minutes_elapsed=minutes, created_at=now,
    )
    db.session.add(attempt)
    return attempt


def effort_for(slip_id, question_id):
    """(failed_attempts, minutes) for this slip's run at this question.

    Read at the moment of the solve. Attempts after a solve are not counted —
    people re-submit a flag to check it stuck, and punishing that would make the
    chart measure UI confusion.
    """
    rows = (
        db.session.query(LabAttempt.was_correct, LabAttempt.minutes_elapsed)
        .filter(LabAttempt.slip_id == slip_id, LabAttempt.question_id == question_id)
        .order_by(LabAttempt.created_at.asc())
        .all()
    )
    failed, minutes = 0, 0
    for was_correct, elapsed in rows:
        minutes = int(elapsed or 0)
        if was_correct:
            break
        failed += 1
    return failed, minutes
