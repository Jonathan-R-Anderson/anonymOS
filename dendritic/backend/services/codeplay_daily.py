"""A daily challenge built from what a player is actually bad at.

The shared daily pool asks everybody the same thing, which means it is too easy
for half the players and too hard for the rest, and neither half learns much. A
player's own attempt history already says where they struggle — CodeplayAttempt
records the category and whether they got it right — so the challenge can aim
there instead of guessing.

DETERMINISTIC PER (PLAYER, DAY), WHICH IS THE WHOLE DESIGN
----------------------------------------------------------
The same player asking twice on the same day gets the same challenge. Without
that, refreshing rerolls it, and a player who does not like today's question
simply reloads until they get an easy one — which turns a daily challenge into a
slot machine and makes the streak meaningless.

So the row is keyed on (slip, day) and written once. Generation happens at most
once per player per day, which also bounds what this can spend.

WHAT "WEAKEST" MEANS, AND WHY IT IS NOT JUST THE LOWEST SCORE
-------------------------------------------------------------
A category attempted twice and failed twice is 0%, and a category attempted
sixty times and failed thirty is 50%. The first is noise; the second is a real
weakness. So categories below a minimum number of attempts are ignored
altogether rather than ranked, and a player with no history gets a broad
starter challenge instead of a confident diagnosis of a person the site has
never seen.
"""

import datetime as _datetime
import json as _json

# Below this many attempts a category's accuracy is noise. Two failures in a
# row is a bad afternoon, not a weakness worth building a challenge around.
MIN_ATTEMPTS_FOR_SIGNAL = 4

# How many weak categories feed the prompt. One is brittle (a single bad day
# decides a week of challenges); too many stops being personal at all.
WEAK_CATEGORIES = 3

# A player this accurate in a category is not weak in it, whatever the ranking
# says — otherwise a strong player gets a "weakness" challenge on their best
# subject simply because something had to come last.
STRONG_ENOUGH = 0.85


def _today(now=None):
    return (now or _datetime.datetime.utcnow()).date()


def profile(slip_id, now=None):
    """What this player is good and bad at, from their own attempts.

    Returns {"weak": [...], "strong": [...], "attempts": n, "accuracy": float
    or None, "level": int}. Empty lists are a legitimate answer for somebody
    new, and the caller must treat that as "no signal" rather than "bad at
    everything".
    """
    from model.Codeplay import CodeplayAttempt, CodeplayProgress
    from shared import db

    rows = (
        db.session.query(
            CodeplayAttempt.category,
            db.func.count(CodeplayAttempt.id),
            db.func.sum(db.case((CodeplayAttempt.was_correct, 1), else_=0)),
        )
        .filter(CodeplayAttempt.slip_id == slip_id)
        .group_by(CodeplayAttempt.category)
        .all()
    )

    ranked, total, correct_total = [], 0, 0
    for category, attempts, correct in rows:
        attempts = int(attempts or 0)
        correct = int(correct or 0)
        total += attempts
        correct_total += correct
        name = (category or "").strip()
        if not name or attempts < MIN_ATTEMPTS_FOR_SIGNAL:
            continue
        ranked.append((correct / float(attempts), name, attempts))

    ranked.sort()
    weak = [name for accuracy, name, _ in ranked if accuracy < STRONG_ENOUGH][:WEAK_CATEGORIES]
    strong = [name for accuracy, name, _ in reversed(ranked) if accuracy >= STRONG_ENOUGH][:WEAK_CATEGORIES]

    progress = (
        db.session.query(CodeplayProgress)
        .filter(CodeplayProgress.slip_id == slip_id)
        .one_or_none()
    )
    return {
        "weak": weak,
        "strong": strong,
        "attempts": total,
        "accuracy": (correct_total / float(total)) if total else None,
        "level": int(getattr(progress, "level", 1) or 1),
    }


def _difficulty_for(profile_data):
    """Aim just above where the player is, not at where they are.

    A challenge you can already do is a chore. One far beyond you is a wall.
    Accuracy is the signal rather than level, because level only ever goes up
    and therefore says how much somebody has played, not how well.
    """
    accuracy = profile_data.get("accuracy")
    if accuracy is None or profile_data.get("attempts", 0) < MIN_ATTEMPTS_FOR_SIGNAL:
        return "Easy"
    if accuracy >= 0.8:
        return "Hard"
    if accuracy >= 0.55:
        return "Medium"
    return "Easy"


SYSTEM = (
    "You write a single daily programming challenge for one learner. "
    "Return ONLY a JSON object of the form "
    '{"title": str, "description": str, "difficulty": "Easy"|"Medium"|"Hard", '
    '"category": str, "timeLimit": int minutes, "xpReward": int, '
    '"examples": [{"input": str, "output": str, "explanation": str}], '
    '"constraints": [str], "hints": [str]}. '
    "It must be solvable in the stated time by somebody at that level, and "
    "must include at least one worked example."
)


def _prompt(profile_data, difficulty):
    lines = ["Write one %s challenge." % difficulty]
    if profile_data["weak"]:
        lines.append(
            "Aim it at what this learner keeps getting wrong: %s."
            % ", ".join(profile_data["weak"]))
    else:
        # Said explicitly rather than left to the model to infer from silence,
        # which produces a confident diagnosis of somebody it has never seen.
        lines.append("This learner has no meaningful history yet, so choose a "
                     "broad, welcoming fundamentals topic.")
    if profile_data["strong"]:
        lines.append("Avoid these, which they already handle well: %s."
                     % ", ".join(profile_data["strong"]))
    return "\n".join(lines)


def challenge_for(slip_id, now=None, generate=True):
    """This player's challenge for today, generating it once if needed.

    Returns the item dict, or None when there is none and none could be made.
    Never raises: a daily challenge failing to generate must not break the page
    it appears on.
    """
    from model.CodeplayDaily import CodeplayDailyChallenge
    from shared import app, db

    day = _today(now)
    existing = (
        db.session.query(CodeplayDailyChallenge)
        .filter(CodeplayDailyChallenge.slip_id == slip_id,
                CodeplayDailyChallenge.day == day)
        .one_or_none()
    )
    if existing is not None:
        return existing.item()
    if not generate:
        return None

    try:
        from services import openai_api
        from services.codeplay_generate import validate_problem

        if not openai_api.configured():
            return _fallback(slip_id, day)

        profile_data = profile(slip_id, now=now)
        difficulty = _difficulty_for(profile_data)
        answer = openai_api.complete_json(
            SYSTEM, _prompt(profile_data, difficulty), max_tokens=1500)

        # Validated with the same rules as any other problem. A personalised
        # item is not exempt from being correct, and the failure mode here is
        # worse: it is the one thing the player is shown today.
        item = validate_problem(answer)
        if item is None:
            return _fallback(slip_id, day)

        item["difficulty"] = difficulty
        item["timeLimit"] = _bounded_int(answer.get("timeLimit"), 5, 60, 15)
        item["xpReward"] = _bounded_int(answer.get("xpReward"), 5, 100, 20)
        item["personalised"] = True
        item["aimedAt"] = profile_data["weak"]

        return _store(slip_id, day, item, profile_data)
    except Exception:
        app.logger.exception("daily challenge generation failed for slip %s", slip_id)
        db.session.rollback()
        return _fallback(slip_id, day)


def _bounded_int(value, low, high, default):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(number, high))


def _store(slip_id, day, item, profile_data=None):
    """Write once. A duplicate insert means another request won the race, and
    the right answer is that player's existing challenge, not a second one."""
    from model.CodeplayDaily import CodeplayDailyChallenge
    from shared import db

    row = CodeplayDailyChallenge(
        slip_id=slip_id, day=day,
        payload=_json.dumps(item),
        aimed_at=",".join((profile_data or {}).get("weak", []))[:200],
    )
    db.session.add(row)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        found = (
            db.session.query(CodeplayDailyChallenge)
            .filter(CodeplayDailyChallenge.slip_id == slip_id,
                    CodeplayDailyChallenge.day == day)
            .one_or_none()
        )
        return found.item() if found else None
    return item


def _fallback(slip_id, day):
    """The shared pool, when a personal one cannot be made.

    Chosen deterministically from (slip, day) so it is still stable across a
    refresh — a fallback that rerolled would reintroduce exactly the shopping
    behaviour the design exists to prevent.
    """
    import hashlib

    from model.CodeplayContent import CodeplayContent
    from shared import db

    rows = (
        db.session.query(CodeplayContent)
        .filter(CodeplayContent.collection == "daily", CodeplayContent.active.is_(True))
        .order_by(CodeplayContent.id.asc())
        .all()
    )
    if not rows:
        return None
    seed = hashlib.sha256(("%s:%s" % (slip_id, day.isoformat())).encode()).digest()
    item = rows[int.from_bytes(seed[:4], "big") % len(rows)].item()
    item = dict(item)
    item["personalised"] = False
    return item
