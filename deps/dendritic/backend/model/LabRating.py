"""What people thought of a box, from the people who actually finished it.

Rating is gated on completion — a solved user or root flag — for the same reason
bounty ratings are gated on having transacted: an open rating box is a place to
punish a machine for being hard, and the only opinion worth publishing about a
challenge comes from somebody who got through it.

Two separate numbers, because they are separate questions:

  quality     was this a good box? (1-5)
  difficulty  what would YOU have rated it? — collected because the author's
              own label is a guess, and the people who finished it are the only
              ones who can correct it.
"""

import datetime as _datetime

from shared import db

DIFFICULTIES = ("Easy", "Medium", "Hard", "Insane")


class LabRating(db.Model):
    __tablename__ = "lab_rating"
    __table_args__ = (
        db.UniqueConstraint("challenge_id", "slip_id", name="uq_lab_rating_once"),
    )

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey("lab_challenge.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    quality = db.Column(db.Integer, nullable=False, default=3)
    # The rater's own difficulty call, or "" if they did not offer one.
    difficulty = db.Column(db.String(12), nullable=False, default="", server_default="")
    comment = db.Column(db.String(500), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def rating_by(challenge_id, slip_id):
    if not slip_id:
        return None
    return (
        db.session.query(LabRating)
        .filter(LabRating.challenge_id == challenge_id, LabRating.slip_id == slip_id)
        .one_or_none()
    )


def summary_for(challenge_id):
    """Mean quality, count, and what finishers actually called the difficulty.

    `mean` is None with no ratings rather than 0: a new box and a bad box are
    opposite facts, and showing an unrated one as zero libels it.
    """
    rows = (
        db.session.query(LabRating.quality, LabRating.difficulty)
        .filter(LabRating.challenge_id == challenge_id)
        .all()
    )
    if not rows:
        return {"count": 0, "mean": None, "difficulty": None}

    scores = [int(q) for q, _d in rows if q is not None]
    votes = {}
    for _q, difficulty in rows:
        if difficulty:
            votes[difficulty] = votes.get(difficulty, 0) + 1
    consensus = max(votes, key=votes.get) if votes else None
    return {
        "count": len(scores),
        "mean": round(sum(scores) / float(len(scores)), 1) if scores else None,
        "difficulty": consensus,
        "votes": votes,
    }
