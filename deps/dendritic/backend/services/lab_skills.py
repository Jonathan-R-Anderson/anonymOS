"""What a box says about the person who solved it.

A solve on its own is a poor signal — it says somebody got there, not how. This
turns the record in model/LabAttempt.py into two things:

  * a per-axis contribution to the skill radar, weighted by how cleanly the box
    went, so the chart measures ability rather than persistence;
  * first blood, which is a public claim and therefore has to be exactly right.

THE WEIGHTS ARE JUDGEMENTS, NOT MEASUREMENTS
--------------------------------------------
There is no principled constant for "how much worse is a solve that took thirty
tries". The numbers below were chosen so that:

  * a clean solve counts fully, and nothing counts for MORE than a clean solve —
    the scale has a ceiling, so speed cannot be farmed;
  * a messy solve still counts for something. Someone who ground through a box
    over three days learned it, and a scheme that scored them near zero would be
    measuring confidence rather than skill;
  * the floor is reached slowly. Falling off a cliff at N attempts would make the
    chart a record of one bad evening.

They are written here, in one place, rather than spread through the scoring so
that changing the site's opinion about effort is one edit and not an
archaeology exercise.
"""

# A solve with no failed attempts scores 1.0. Each failure costs, with
# diminishing effect, down to FLOOR.
FAILURE_COST = 0.06
FLOOR = 0.45

# Minutes past which extra time stops counting against anybody. A long box is a
# long box; beyond this the number is measuring life, not difficulty.
SLOW_AFTER_MINUTES = 240
# What a maximally slow solve keeps. Time is a weaker signal than attempts —
# people eat, sleep and leave boxes running — so it is weighted much more gently.
SLOW_FLOOR = 0.8


def effort_weight(failed_attempts, minutes):
    """0.36–1.0: how much a solve should count toward the skill chart.

    Multiplicative in the two signals, because they are independent evidence:
    thirty attempts in ten minutes is a brute-force script, ten minutes with one
    attempt is somebody who knew the box, and both should not score the same.
    """
    failed = max(0, int(failed_attempts or 0))
    attempt_factor = max(FLOOR, 1.0 - (FAILURE_COST * failed))

    minutes = max(0, int(minutes or 0))
    if minutes <= 0:
        speed_factor = 1.0
    else:
        overshoot = min(1.0, minutes / float(SLOW_AFTER_MINUTES))
        speed_factor = 1.0 - ((1.0 - SLOW_FLOOR) * overshoot)

    return round(attempt_factor * speed_factor, 4)


def parse_skills(value):
    """A challenge's skills field -> a list of axis keys.

    Free text with commas rather than a join table: the set of axes is defined
    in code, an admin types two or three of them per box, and a table here would
    add a migration to every axis change for no gain.
    """
    return [part.strip().lower() for part in (value or "").split(",") if part.strip()]


def lab_axis_totals(slip_id):
    """{axis_key: weighted points} this slip has earned from boxes.

    Weighted by effort at the moment of each solve, so the number carries the
    "how" and not just the "whether".
    """
    from model.LabAttempt import effort_for
    from model.LabChallenge import LabChallenge
    from model.LabSolve import LabSolve
    from shared import db

    rows = (
        db.session.query(LabSolve.question_id, LabSolve.points_awarded, LabChallenge.skills)
        .join(LabChallenge, LabChallenge.id == LabSolve.challenge_id)
        .filter(LabSolve.slip_id == slip_id)
        .all()
    )
    totals = {}
    for question_id, points, skills in rows:
        axes = parse_skills(skills)
        if not axes:
            continue  # a box whose author never said what it exercises
        failed, minutes = effort_for(slip_id, question_id)
        weighted = float(points or 0) * effort_weight(failed, minutes)
        # Split across the axes a box claims, so tagging a machine with every
        # axis does not multiply what it is worth.
        share = weighted / float(len(axes))
        for axis in axes:
            totals[axis] = totals.get(axis, 0.0) + share
    return totals


def first_bloods(challenge_id):
    """{"user": row, "root": row} — the first person to each tier, or None.

    Read from the solve log rather than stored on the challenge: a denormalised
    winner is a field that can be wrong, and this is a claim about a person that
    is published under their name.
    """
    from model.LabQuestion import LabQuestion, TIER_ROOT, TIER_USER
    from model.LabSolve import LabSolve
    from model.Slip import Slip
    from shared import db

    out = {TIER_USER: None, TIER_ROOT: None}
    for tier in (TIER_USER, TIER_ROOT):
        row = (
            db.session.query(LabSolve.created_at, Slip.name, Slip.id)
            .join(LabQuestion, LabQuestion.id == LabSolve.question_id)
            .join(Slip, Slip.id == LabSolve.slip_id)
            .filter(LabSolve.challenge_id == challenge_id, LabQuestion.tier == tier)
            .order_by(LabSolve.created_at.asc())
            .first()
        )
        if row is not None:
            out[tier] = {"at": row[0], "name": row[1], "slip_id": row[2]}
    return out


def completed_tiers(slip_id, challenge_id):
    """Which tiers this slip has solved on this box.

    Completion is exactly this: the box is done when its root flag is in, or
    when there is no root flag and the user flag is. Anything softer would let
    somebody rate a machine they poked at for five minutes.
    """
    from model.LabQuestion import LabQuestion, TIER_ROOT, TIER_USER
    from model.LabSolve import LabSolve
    from shared import db

    rows = (
        db.session.query(LabQuestion.tier)
        .join(LabSolve, LabSolve.question_id == LabQuestion.id)
        .filter(LabSolve.slip_id == slip_id, LabSolve.challenge_id == challenge_id)
        .all()
    )
    return {tier for (tier,) in rows if tier in (TIER_USER, TIER_ROOT)}


def has_completed(slip_id, challenge_id):
    """Whether this slip has finished the box, in the sense above."""
    from model.LabQuestion import LabQuestion, TIER_ROOT, TIER_USER
    from shared import db

    done = completed_tiers(slip_id, challenge_id)
    if TIER_ROOT in done:
        return True
    root_exists = (
        db.session.query(LabQuestion.id)
        .filter(LabQuestion.challenge_id == challenge_id,
                LabQuestion.tier == TIER_ROOT, LabQuestion.active.is_(True))
        .first()
    )
    return TIER_USER in done and root_exists is None
