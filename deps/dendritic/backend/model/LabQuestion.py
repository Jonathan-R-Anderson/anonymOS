"""Per-challenge questions a researcher answers to earn points.

A lab challenge (model.LabChallenge) can carry an ordered list of questions.
Each is worth some points and has one of two answer kinds:

  * "static"          -- the admin sets the expected answer; it is the same for
                         everyone (e.g. "Which CVE does this box exploit?").
  * "instance_secret" -- the correct answer is the per-boot random secret the
                         worker injected into THIS user's container
                         (LabInstance.container_password). Because the secret is
                         regenerated on every boot, the answer cannot be shared:
                         a user has to actually reach it inside their own
                         instance to submit it.

`example_answer` is a NON-secret hint shown as the input's placeholder so the
user knows the shape of what to enter. It is never checked against anything.
"""
import datetime as _datetime

from shared import db

ANSWER_STATIC = "static"
ANSWER_INSTANCE_SECRET = "instance_secret"
ANSWER_KINDS = (ANSWER_STATIC, ANSWER_INSTANCE_SECRET)

# Which foothold a question represents. Most questions are neither — they are
# ordinary "which CVE is this" questions worth points. The two that matter are
# the ones every box is actually about:
#
#   user  the first shell, whoever you landed as
#   root  full control of the box
#
# They are marked rather than inferred because only the box's author knows which
# question is which, and first blood is a public claim that has to be right.
TIER_NONE = ""
TIER_USER = "user"
TIER_ROOT = "root"
TIERS = (TIER_NONE, TIER_USER, TIER_ROOT)


class LabQuestion(db.Model):
    __tablename__ = "lab_question"

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer,
        db.ForeignKey("lab_challenge.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    prompt = db.Column(db.Text, nullable=False, default="")
    # A non-secret example of what to enter, shown to the user as placeholder text.
    example_answer = db.Column(db.String(255), nullable=False, default="")
    # The correct answer for a "static" question. Ignored for "instance_secret",
    # where the answer is the running instance's per-boot secret.
    expected_answer = db.Column(db.String(255), nullable=False, default="")
    answer_kind = db.Column(db.String(32), nullable=False, default=ANSWER_STATIC)
    # "user", "root", or "" — see TIERS above. Solving a tiered question is what
    # completing a box MEANS, so it is also what unlocks rating it and what
    # first blood is claimed against.
    tier = db.Column(db.String(8), nullable=False, default=TIER_NONE, server_default="")
    points = db.Column(db.Integer, nullable=False, default=10)
    position = db.Column(db.Integer, nullable=False, default=0)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    def to_public(self):
        """Fields safe to show a user -- NEVER the expected answer."""
        return {
            "id": self.id,
            "prompt": self.prompt,
            "example_answer": self.example_answer,
            "answer_kind": self.answer_kind,
            # Safe to publish: it says which flag a question IS, never what it is.
            "tier": self.tier,
            "points": self.points,
            "position": self.position,
        }

    def to_admin(self):
        return {
            **self.to_public(),
            "challenge_id": self.challenge_id,
            "expected_answer": self.expected_answer,
            "active": self.active,
        }


def questions_for_challenge(challenge_id, active_only=True):
    query = db.session.query(LabQuestion).filter(LabQuestion.challenge_id == challenge_id)
    if active_only:
        query = query.filter(LabQuestion.active.is_(True))
    return query.order_by(LabQuestion.position.asc(), LabQuestion.id.asc()).all()


def question_by_id(question_id):
    return (
        db.session.query(LabQuestion)
        .filter(LabQuestion.id == question_id)
        .one_or_none()
    )
