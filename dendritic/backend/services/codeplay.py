"""Scoring, progression and the skill radar.

Content lives in backend/data/codeplay/*.json, converted from the upstream
TypeScript tables. It is static reference data, not user data, so it is read
once and cached in the process rather than loaded into the database.
"""
import datetime as _datetime
import json
import os
import random

from sqlalchemy import func

from model.Codeplay import (
    DIFFICULTY_MULTIPLIER,
    LEVEL_STEP,
    XP_BY_MODE,
    CodeplayAttempt,
    CodeplayProgress,
)
from shared import app, db


_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "codeplay")
_CACHE = {}

MODES = ("mcq", "flashcard", "bughunter", "daily", "problem")

# The radar's axes. Chosen to describe what someone has actually done here
# rather than mirroring the content's 16 raw categories, which are too many to
# read on a chart and too granular to be meaningful.
#
# The security axes are fed almost entirely by the LAB — the quiz bank has very
# little security content, and a chart whose right-hand half was permanently
# empty would read as "this person cannot do security" rather than "we never
# asked". Each lab challenge declares which axes it exercises (LabChallenge
# .skills); see services/lab_skills.py.
#
# Nine axes is close to the practical ceiling for a readable radar. Adding a
# tenth means taking one away.
SKILL_AXES = (
    ("algorithms", "Algorithms", {"Algorithms", "Graph Theory", "Graph", "Data Structures",
                                  "Array", "Arrays", "String", "Strings", "Lists",
                                  "Dictionaries", "Linked List", "Tree", "Stack", "Queue",
                                  "Dynamic Programming", "Recursion", "Math", "Sorting",
                                  "Logic", "Comparison"}),
    ("languages", "Languages", {"JavaScript", "Python", "Java", "C++", "TypeScript",
                                "Functions", "Closures", "Scope", "Type Conversion",
                                "Null Safety", "Pointers", "Memory Management"}),
    ("web", "Web", {"React", "HTML", "CSS", "Web Development", "Frontend", "Async"}),
    ("systems", "Systems", {"Database", "Git", "Software Engineering", "DevOps",
                            "Operating Systems", "Linux", "Resources", "Exceptions"}),
    ("design", "Design", {"OOP", "Design Patterns", "Architecture", "Classes", "Objects"}),
    ("appsec", "AppSec", {"Security", "Web Security", "Application Security"}),
    ("exploitation", "Exploitation", {"Exploitation", "Binary Exploitation",
                                      "Privilege Escalation", "Reverse Engineering"}),
    ("networking", "Networking", {"Networking", "Protocols", "Network Security"}),
    ("crypto", "Cryptography", {"Cryptography", "Encryption", "Hashing"}),
)

# Axes with no questions behind them in the bundled bank, fed instead by lab
# challenges (and by anything the OpenAI generator is later asked to produce for
# those categories).
#
# Written down rather than left implicit because an axis nothing can score is
# normally a BUG — a permanently flat spoke that reads as "this person cannot do
# security" instead of "we never asked". These four are flat on purpose until
# somebody labels boxes with them, and the distinction has to be visible to
# whoever next wonders why the right-hand side of the chart is empty.
LAB_FED_AXES = frozenset({"appsec", "exploitation", "networking", "crypto"})

# Axis keys, for validating what an admin types into a challenge's skills field.
SKILL_AXIS_KEYS = tuple(key for key, _label, _cats in SKILL_AXES)

# Lab points that count as one quiz solve on the radar. A box is worth much more
# than one quiz question, and this is the exchange rate — set so that a typical
# 20-point flag is worth about two solves rather than filling an axis outright.
LAB_POINTS_PER_SOLVE = 10.0


def load(name):
    """One content collection, cached for the life of the process.

    Reads the editable DB (model.CodeplayContent) first so admin edits and
    DHT-published content take effect at runtime; falls back to the bundled JSON
    when a collection has no rows yet (e.g. before the one-time seed). Cache is
    cleared by services.codeplay_content on any edit."""
    if name not in _CACHE:
        _CACHE[name] = _load_uncached(name)
    return _CACHE[name]


def _load_uncached(name):
    try:
        from model.CodeplayContent import build_collection, collection_rows
        if collection_rows(name, active_only=True):
            return build_collection(name, active_only=True)
    except Exception:
        db.session.rollback()
        app.logger.exception("codeplay: DB content load failed for %s; using bundled JSON", name)
    path = os.path.join(_DATA_DIR, "%s.json" % name)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        app.logger.exception("codeplay: cannot load content %s", path)
        return [] if name != "daily" else {}


def content_available():
    """False when the content files are missing, so the UI can say so instead
    of rendering empty game modes."""
    return bool(load("mcq")) and bool(load("problems"))


def categories(name="mcq"):
    return sorted({item.get("category", "") for item in load(name) if item.get("category")})


def progress_for(slip, create=False):
    """The slip's progress row. Never raises into a request."""
    if slip is None:
        return None
    try:
        row = db.session.query(CodeplayProgress).filter(
            CodeplayProgress.slip_id == slip.id
        ).one_or_none()
    except Exception:
        db.session.rollback()
        app.logger.exception("codeplay: cannot load progress for slip %s", slip.id)
        return None
    if row is None and create:
        row = CodeplayProgress(slip_id=slip.id)
        db.session.add(row)
        db.session.flush()
    return row


def already_solved(slip, mode, item_id):
    """Has this slip already answered this item correctly?

    Guards the XP economy: without it, re-answering one easy question in a loop
    is an infinite score.
    """
    if slip is None:
        return False
    return db.session.query(
        db.session.query(CodeplayAttempt).filter(
            CodeplayAttempt.slip_id == slip.id,
            CodeplayAttempt.mode == mode,
            CodeplayAttempt.item_id == str(item_id),
            CodeplayAttempt.was_correct.is_(True),
        ).exists()
    ).scalar()


def _touch_streak(progress, today):
    """Advance, hold or reset the day streak."""
    last = progress.last_active_on
    if last == today:
        return
    if last is not None and (today - last).days == 1:
        progress.streak += 1
    else:
        progress.streak = 1
    progress.best_streak = max(progress.best_streak, progress.streak)
    progress.last_active_on = today


BADGES = (
    ("welcome", "Welcome", "Answered your first question"),
    ("first-solve", "First Steps", "Got one right"),
    ("streak-7", "Consistency", "Seven days in a row"),
    ("streak-30", "Relentless", "Thirty days in a row"),
    ("solver-10", "Problem Solver", "Ten items solved"),
    ("solver-50", "Algorithm Master", "Fifty items solved"),
    ("level-5", "Journeyman", "Reached level 5"),
    ("level-10", "Veteran", "Reached level 10"),
    ("sharpshooter", "Sharpshooter", "90% accuracy over 20+ answers"),
    ("polymath", "Polymath", "Scored on every skill axis"),
)
BADGE_INDEX = {slug: (name, desc) for slug, name, desc in BADGES}


def _evaluate_badges(slip, progress):
    solved = db.session.query(func.count(CodeplayAttempt.id)).filter(
        CodeplayAttempt.slip_id == slip.id, CodeplayAttempt.was_correct.is_(True)
    ).scalar() or 0
    earned = []
    checks = [
        ("welcome", progress.attempts >= 1),
        ("first-solve", solved >= 1),
        ("streak-7", progress.streak >= 7),
        ("streak-30", progress.streak >= 30),
        ("solver-10", solved >= 10),
        ("solver-50", solved >= 50),
        ("level-5", progress.level >= 5),
        ("level-10", progress.level >= 10),
        ("sharpshooter", progress.attempts >= 20 and progress.accuracy >= 90),
        ("polymath", all(v > 0 for v in skill_vector(slip).values())),
    ]
    for slug, condition in checks:
        if condition and progress.award_badge(slug):
            earned.append(slug)
    return earned


def record_attempt(slip, mode, item_id, correct, category="", difficulty=""):
    """Grade one answer. Returns a dict the view renders.

    Repeats are recorded for history but pay no XP, so the score reflects
    coverage rather than how many times someone pressed the same button.
    """
    result = {"xp": 0, "levelled_up": False, "badges": [], "repeat": False}
    if slip is None:
        return result
    progress = progress_for(slip, create=True)
    if progress is None:
        return result

    repeat = already_solved(slip, mode, item_id)
    result["repeat"] = repeat

    xp = 0
    if correct and not repeat:
        base = XP_BY_MODE.get(mode, 5)
        xp = int(round(base * DIFFICULTY_MULTIPLIER.get(difficulty, 1.0)))

    db.session.add(CodeplayAttempt(
        slip_id=slip.id, mode=mode, item_id=str(item_id),
        category=(category or "")[:64], difficulty=(difficulty or "")[:16],
        was_correct=bool(correct), xp_awarded=xp,
    ))

    progress.attempts += 1
    if correct:
        progress.correct += 1
        _touch_streak(progress, _datetime.date.today())
    if xp:
        progress.xp += xp
        before = progress.level
        # A single answer can cross more than one level boundary.
        while progress.xp >= sum(LEVEL_STEP * n for n in range(1, progress.level + 1)):
            progress.level += 1
        result["levelled_up"] = progress.level > before
    result["xp"] = xp

    result["badges"] = [BADGE_INDEX[s][0] for s in _evaluate_badges(slip, progress)
                        if s in BADGE_INDEX]
    return result


def skill_vector(slip):
    """Per-axis score, 0-100, from what this slip has actually solved here.

    Each axis is scaled against a target count rather than against other users,
    so an early adopter's chart is not full merely for being first.
    """
    scores = {key: 0 for key, _label, _cats in SKILL_AXES}
    if slip is None:
        return scores
    try:
        rows = db.session.query(
            CodeplayAttempt.category, func.count(CodeplayAttempt.id)
        ).filter(
            CodeplayAttempt.slip_id == slip.id,
            CodeplayAttempt.was_correct.is_(True),
        ).group_by(CodeplayAttempt.category).all()
    except Exception:
        db.session.rollback()
        app.logger.exception("codeplay: skill vector failed for slip %s", slip.id)
        return scores

    TARGET = 12.0     # solves for a full axis
    totals = {key: 0.0 for key, _l, _c in SKILL_AXES}
    for category, count in rows:
        for key, _label, cats in SKILL_AXES:
            if category in cats:
                totals[key] += count

    # Boxes count too, weighted by how cleanly they went. A lab question is
    # worth points rather than a count, so it is converted at LAB_POINTS_PER_SOLVE
    # to keep one axis comparable with another — otherwise a 50-point root flag
    # would fill an axis on its own and the chart would say more about which
    # boxes have generous scoring than about the person.
    try:
        from services.lab_skills import lab_axis_totals
        for axis, weighted_points in lab_axis_totals(slip.id).items():
            if axis in totals:
                totals[axis] += weighted_points / LAB_POINTS_PER_SOLVE
    except Exception:
        db.session.rollback()
        app.logger.exception("codeplay: lab skill blend failed for slip %s", slip.id)

    for key, total in totals.items():
        scores[key] = int(min(100, round(total * 100.0 / TARGET)))
    return scores


def radar_points(scores, size=220, padding=34):
    """Geometry for the spider chart, computed server-side.

    Server-side so the chart is plain SVG in the page: no charting library, no
    extra request, and it renders identically with JavaScript disabled. Colours
    come from the --sc-* palette so it follows the site's theme selector.
    """
    import math

    centre = size / 2.0
    radius = centre - padding
    axes = list(SKILL_AXES)
    count = len(axes)
    step = (2 * math.pi) / count

    def point(index, fraction):
        # -90deg so the first axis points straight up.
        angle = (index * step) - (math.pi / 2)
        return (centre + math.cos(angle) * radius * fraction,
                centre + math.sin(angle) * radius * fraction)

    rings = []
    for ring in (0.25, 0.5, 0.75, 1.0):
        rings.append(" ".join("%.1f,%.1f" % point(i, ring) for i in range(count)))

    spokes, labels, value_points = [], [], []
    for index, (key, label, _cats) in enumerate(axes):
        edge = point(index, 1.0)
        spokes.append(edge)
        text = point(index, 1.16)
        anchor = "middle"
        if text[0] < centre - 4:
            anchor = "end"
        elif text[0] > centre + 4:
            anchor = "start"
        labels.append({"x": text[0], "y": text[1] + 4, "anchor": anchor,
                       "label": label, "value": scores.get(key, 0)})
        value_points.append(point(index, max(0.02, scores.get(key, 0) / 100.0)))

    return {
        "size": size,
        "centre": centre,
        "rings": rings,
        "spokes": spokes,
        "labels": labels,
        "polygon": " ".join("%.1f,%.1f" % p for p in value_points),
        "vertices": value_points,
    }


def leaderboard(limit=25):
    """Top slips by XP. Names come from the slip, so there is no second
    display-name concept to keep in sync."""
    from model.Slip import Slip
    try:
        rows = db.session.query(CodeplayProgress, Slip).join(
            Slip, Slip.id == CodeplayProgress.slip_id
        ).filter(CodeplayProgress.xp > 0).order_by(
            CodeplayProgress.xp.desc(), CodeplayProgress.level.desc()
        ).limit(limit).all()
    except Exception:
        db.session.rollback()
        app.logger.exception("codeplay: leaderboard query failed")
        return []
    return [{"rank": i + 1, "name": slip.name, "slip_id": slip.id,
             "xp": p.xp, "level": p.level, "streak": p.streak,
             "accuracy": p.accuracy}
            for i, (p, slip) in enumerate(rows)]


def pick_questions(mode, category=None, difficulty=None, count=10, seed=None):
    """A shuffled quiz set, filtered as asked."""
    pool = load({"mcq": "mcq", "flashcard": "flashcards",
                 "bughunter": "bughunter"}.get(mode, mode))
    if not isinstance(pool, list):
        return []
    items = [q for q in pool
             if (not category or q.get("category") == category)
             and (not difficulty or q.get("difficulty") == difficulty)]
    rng = random.Random(seed)
    rng.shuffle(items)
    return items[:count]


def daily_challenge(difficulty="Easy", today=None):
    """The day's challenge — same for everyone, rotating by date."""
    table = load("daily")
    bucket = table.get(difficulty) if isinstance(table, dict) else None
    if not bucket:
        return None
    day = today or _datetime.date.today()
    return bucket[day.toordinal() % len(bucket)]


def profile_summary(slip):
    """Everything the profile page shows. Safe when the slip has never played."""
    progress = progress_for(slip)
    scores = skill_vector(slip)
    solved = 0
    if slip is not None:
        try:
            solved = db.session.query(func.count(CodeplayAttempt.id)).filter(
                CodeplayAttempt.slip_id == slip.id,
                CodeplayAttempt.was_correct.is_(True),
            ).scalar() or 0
        except Exception:
            db.session.rollback()
    return {
        "progress": progress,
        "xp": progress.xp if progress else 0,
        "level": progress.level if progress else 1,
        "streak": progress.streak if progress else 0,
        "best_streak": progress.best_streak if progress else 0,
        "accuracy": progress.accuracy if progress else 0,
        "level_percent": progress.level_percent if progress else 0,
        "solved": solved,
        "badges": [{"slug": s, "name": BADGE_INDEX[s][0], "description": BADGE_INDEX[s][1]}
                   for s in (progress.badge_list if progress else [])
                   if s in BADGE_INDEX],
        "skills": scores,
        "radar": radar_points(scores),
        "played": bool(progress and progress.attempts),
    }
