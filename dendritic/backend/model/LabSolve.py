"""The lab scoring ledger -- one row per lab question a researcher has answered
correctly.

The unique constraint on (slip_id, question_id) makes a second correct
submission a no-op rather than a double award. A slip's total lab points is the
sum of ``points_awarded`` over its rows; ``instance_id`` records which boot the
answer was solved on (useful for instance-secret questions).
"""
import datetime as _datetime

from shared import db


class LabSolve(db.Model):
    __tablename__ = "lab_solve"
    __table_args__ = (
        db.UniqueConstraint("slip_id", "question_id", name="uq_lab_solve_slip_question"),
    )

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    question_id = db.Column(db.Integer, db.ForeignKey("lab_question.id"), nullable=False, index=True)
    # Denormalised so a leaderboard / per-challenge progress query needs no join.
    challenge_id = db.Column(db.Integer, nullable=False, index=True)
    instance_id = db.Column(db.Integer, nullable=True)
    points_awarded = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def already_solved(slip_id, question_id):
    return (
        db.session.query(LabSolve.id)
        .filter(LabSolve.slip_id == slip_id, LabSolve.question_id == question_id)
        .first()
        is not None
    )


def solved_question_ids(slip_id, challenge_id=None):
    """The set of question ids this slip has solved (optionally scoped to one
    challenge), for marking answered questions in the UI."""
    query = db.session.query(LabSolve.question_id).filter(LabSolve.slip_id == slip_id)
    if challenge_id is not None:
        query = query.filter(LabSolve.challenge_id == challenge_id)
    return {row[0] for row in query.all()}


def total_points(slip_id):
    total = (
        db.session.query(db.func.coalesce(db.func.sum(LabSolve.points_awarded), 0))
        .filter(LabSolve.slip_id == slip_id)
        .scalar()
    )
    return int(total or 0)
