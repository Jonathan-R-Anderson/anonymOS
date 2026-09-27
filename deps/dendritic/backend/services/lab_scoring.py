"""Lab question scoring: grade a submitted answer and award points exactly once.

For a "static" question the submission is compared to the admin's expected
answer (the same for everyone). For an "instance_secret" question it is compared
to the per-boot secret the worker injected into the submitter's OWN running
instance (LabInstance.container_password) -- so the correct answer is unique per
boot and can't be shared. Points are awarded at most once per (slip, question)
via LabSolve's unique constraint.
"""
import hmac

from sqlalchemy.exc import IntegrityError

from shared import db
from model.LabQuestion import question_by_id, ANSWER_INSTANCE_SECRET
from model.LabInstance import single_active_for
from model.LabSolve import LabSolve, already_solved, total_points


def _normalize(value):
    return (value or "").strip().casefold()


def _matches(submitted, expected):
    """Case-insensitive, whitespace-trimmed, constant-time comparison."""
    if not expected:
        return False
    return hmac.compare_digest(_normalize(submitted), _normalize(expected))


def _expected_for(question, slip):
    """The correct answer for this question and this user, or None if it can't be
    determined right now (an instance-secret question with no matching running
    box)."""
    if question.answer_kind == ANSWER_INSTANCE_SECRET:
        instance = single_active_for(slip.id)
        if instance is None or instance.image_key != question.challenge.slug:
            return None
        return instance.container_password or None
    return question.expected_answer or None


def _log_attempt(slip, question, was_correct):
    """Record the attempt. Never raises: grading must not fail because the
    telemetry behind the skill chart did."""
    try:
        from model.LabAttempt import record
        record(slip.id, question.challenge_id, question.id, was_correct)
        # Committed here rather than left to the caller: the WRONG-answer path
        # returns without ever committing, so a deferred write would silently
        # drop exactly the attempts the skill chart is built on.
        db.session.commit()
    except Exception:
        from shared import app
        db.session.rollback()
        app.logger.exception("lab: could not record attempt for slip %s", slip.id)


def submit_answer(slip, question_id, submitted):
    """Grade one answer. Returns a dict with keys:
       ok        -- False only on a structural problem (no such question / no slip)
       correct   -- whether the answer matched
       already   -- already solved before this submission
       awarded   -- points granted by THIS submission (0 if wrong/already)
       points    -- the question's point value
       total     -- the slip's total lab points after this submission
       reason    -- a user-facing hint when ok is False or a secret box is needed
    """
    if slip is None:
        return {"ok": False, "reason": "You need a slip to answer questions."}
    question = question_by_id(question_id)
    if question is None or not question.active:
        return {"ok": False, "reason": "That question is no longer available."}

    if already_solved(slip.id, question_id):
        return {"ok": True, "correct": True, "already": True, "awarded": 0,
                "points": question.points, "total": total_points(slip.id)}

    expected = _expected_for(question, slip)
    if expected is None and question.answer_kind == ANSWER_INSTANCE_SECRET:
        return {"ok": True, "correct": False, "already": False, "awarded": 0,
                "points": question.points, "total": total_points(slip.id),
                "reason": "Launch this machine first — the answer is the secret inside your own running instance."}

    if not _matches(submitted, expected):
        # Wrong answers are recorded, and are the more useful half of the
        # record: without them every solve looks equally clean and the skill
        # chart measures persistence rather than ability. The submitted TEXT is
        # never kept -- see model/LabAttempt.py.
        _log_attempt(slip, question, False)
        return {"ok": True, "correct": False, "already": False, "awarded": 0,
                "points": question.points, "total": total_points(slip.id)}

    # Correct. Award once; the unique (slip_id, question_id) constraint is the
    # real guard against a double award under a concurrent double-submit.
    _log_attempt(slip, question, True)
    instance = single_active_for(slip.id)
    db.session.add(LabSolve(
        slip_id=slip.id, question_id=question.id, challenge_id=question.challenge_id,
        instance_id=instance.id if instance else None,
        points_awarded=question.points,
    ))
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return {"ok": True, "correct": True, "already": True, "awarded": 0,
                "points": question.points, "total": total_points(slip.id)}
    return {"ok": True, "correct": True, "already": False, "awarded": question.points,
            "points": question.points, "total": total_points(slip.id)}
