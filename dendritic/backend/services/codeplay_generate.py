"""Generating codeplay content, and refusing most of what comes back.

The model produces text that looks right. This module's job is to decide
whether it IS right, because a malformed item is worse than a missing one:

  * an MCQ whose correctAnswer indexes past its options marks a correct answer
    wrong, and the player has no way to tell the fault is ours;
  * a flashcard with two identical options is unanswerable;
  * a bug-hunt whose "buggy" code has no bug wastes the one thing the exercise
    is for.

So every field is checked, and an item that fails any check is DROPPED. A batch
that yields six usable questions out of ten is a good batch. A batch that stores
ten and breaks four is a bad one that looks better.

DUPLICATES ARE THE OTHER HALF. Asking a model for twenty questions about
JavaScript arrays repeatedly produces the same twenty questions. Every candidate
is compared against what is already stored, normalised, and dropped if it is a
restatement — otherwise "generate more" quietly means "generate the same again".
"""

import json as _json
import re as _re

# One request cannot be allowed to spend arbitrary money or run arbitrarily
# long. Callers asking for more get several batches, which also gives the
# de-duplicator a chance to see earlier items.
MAX_PER_BATCH = 10
MAX_PER_RUN = 100

COLLECTIONS = ("mcq", "flashcards", "bughunter", "problems")

DIFFICULTIES = ("Easy", "Medium", "Hard")

_WORD_RE = _re.compile(r"[a-z0-9]+")


def _fingerprint(text):
    """A loose identity for a question, so near-restatements collide.

    Word-set rather than exact string, so reordering and punctuation do not
    hide a repeat.

    It does NOT catch rephrasing — "what is returned by map()" uses different
    words and survives. That is deliberate: a fingerprint loose enough to match
    synonyms would also match genuinely different questions about the same
    topic, and silently dropping good content is worse than storing the
    occasional near-repeat. The prompt carries recent titles as the first line
    of defence; this is the cheap backstop behind it.
    """
    words = _WORD_RE.findall((text or "").lower())
    return " ".join(sorted(set(words)))


def existing_fingerprints(collection):
    from model.CodeplayContent import CodeplayContent
    from shared import db

    out = set()
    rows = (
        db.session.query(CodeplayContent.payload)
        .filter(CodeplayContent.collection == collection)
        .all()
    )
    for (payload,) in rows:
        try:
            item = _json.loads(payload or "{}")
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        out.add(_fingerprint(_identity_text(collection, item)))
    return out


def _identity_text(collection, item):
    """The field that decides whether two items are the same question."""
    if collection == "mcq":
        return item.get("question", "")
    if collection == "flashcards":
        return item.get("code", "")
    if collection in ("bughunter", "problems", "daily"):
        return "%s %s" % (item.get("title", ""), item.get("description", ""))
    return _json.dumps(item, sort_keys=True)


# --- validation -------------------------------------------------------------

def _clean_options(raw):
    """Four distinct non-empty options, or None.

    Distinct matters: two identical options make one of them a wrong answer
    that is textually a right answer, which is unfair in a way the player
    cannot argue with.
    """
    if not isinstance(raw, list) or len(raw) != 4:
        return None
    options = []
    for value in raw:
        if not isinstance(value, str):
            return None
        text = value.strip()
        if not text or len(text) > 300:
            return None
        options.append(text)
    if len({o.lower() for o in options}) != 4:
        return None
    return options


def _index_in_range(value, length):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < length


def validate_mcq(item):
    question = (item.get("question") or "").strip()
    explanation = (item.get("explanation") or "").strip()
    options = _clean_options(item.get("options"))
    if not question or len(question) > 500 or options is None:
        return None
    if not _index_in_range(item.get("correctAnswer"), len(options)):
        return None
    if not explanation:
        # An MCQ with no explanation teaches nothing when it is answered
        # wrongly, which is the moment it exists for.
        return None
    return {
        "question": question,
        "options": options,
        "correctAnswer": item["correctAnswer"],
        "explanation": explanation[:1200],
        "category": (item.get("category") or "").strip()[:64],
        "difficulty": _difficulty(item.get("difficulty")),
    }


def validate_flashcard(item):
    code = (item.get("code") or "").strip()
    options = _clean_options(item.get("options"))
    explanation = (item.get("explanation") or "").strip()
    if not code or len(code) > 2000 or options is None or not explanation:
        return None
    if not _index_in_range(item.get("correct"), len(options)):
        return None
    return {
        "code": code,
        "options": options,
        "correct": item["correct"],
        "explanation": explanation[:1200],
        "category": (item.get("category") or "").strip()[:64],
        "difficulty": _difficulty(item.get("difficulty")),
    }


def validate_bughunter(item):
    title = (item.get("title") or "").strip()
    description = (item.get("description") or "").strip()
    buggy = (item.get("buggyCode") or "").strip()
    fixed = (item.get("fixedCode") or "").strip()
    explanation = (item.get("explanation") or "").strip()
    if not title or not description or not buggy or not fixed or not explanation:
        return None
    if len(buggy) > 4000 or len(fixed) > 4000:
        return None
    # The whole exercise is spotting a difference. If there is none, the model
    # produced a puzzle with no answer and the player will hunt forever.
    if _normalise_code(buggy) == _normalise_code(fixed):
        return None
    return {
        "title": title[:160],
        "description": description[:800],
        "buggyCode": buggy,
        "fixedCode": fixed,
        "explanation": explanation[:1200],
        "category": (item.get("category") or "").strip()[:64],
        "difficulty": _difficulty(item.get("difficulty")),
    }


def validate_problem(item):
    title = (item.get("title") or "").strip()
    description = (item.get("description") or "").strip()
    if not title or not description:
        return None
    examples = []
    for raw in (item.get("examples") or [])[:4]:
        if not isinstance(raw, dict):
            continue
        given = (raw.get("input") or "").strip()
        expect = (raw.get("output") or "").strip()
        if not given or not expect:
            continue
        examples.append({
            "input": given[:400],
            "output": expect[:400],
            "explanation": (raw.get("explanation") or "").strip()[:400],
        })
    # A coding problem with no worked example is a specification, not an
    # exercise: the player cannot tell what shape the answer should take.
    if not examples:
        return None
    return {
        "title": title[:160],
        "description": description[:2000],
        "difficulty": _difficulty(item.get("difficulty")),
        "category": (item.get("category") or "").strip()[:64],
        "examples": examples,
        "constraints": [str(c).strip()[:200] for c in (item.get("constraints") or [])[:6] if str(c).strip()],
        "hints": [str(h).strip()[:300] for h in (item.get("hints") or [])[:4] if str(h).strip()],
    }


VALIDATORS = {
    "mcq": validate_mcq,
    "flashcards": validate_flashcard,
    "bughunter": validate_bughunter,
    "problems": validate_problem,
}


def _normalise_code(text):
    """Collapse cosmetic whitespace so re-spacing is not mistaken for a fix.

    Spaces WITHIN a line are removed entirely, so "i=0" and "i = 0" compare
    equal and a model that "fixes" a bug by reformatting is caught.

    Leading indentation is KEPT, because in Python it is not cosmetic at all:
    moving a line into or out of a loop is a real defect and a real fix, and a
    comparison blind to it would throw away the correct answer.
    """
    lines = []
    for raw in (text or "").splitlines():
        stripped = raw.lstrip()
        indent = len(raw) - len(stripped)
        lines.append("%d:%s" % (indent, "".join(stripped.split())))
    return "\n".join(lines)


def _difficulty(value):
    text = (value or "").strip().title()
    return text if text in DIFFICULTIES else "Medium"


# --- prompting --------------------------------------------------------------

_SHAPES = {
    "mcq": (
        'Each item: {"question": str, "options": [4 distinct strings], '
        '"correctAnswer": 0-3, "explanation": str, "category": str, '
        '"difficulty": "Easy"|"Medium"|"Hard"}'
    ),
    "flashcards": (
        'Each item: {"code": str (a short snippet whose OUTPUT is being asked '
        'about), "options": [4 distinct strings], "correct": 0-3, '
        '"explanation": str, "category": str, "difficulty": ...}'
    ),
    "bughunter": (
        'Each item: {"title": str, "description": str, "buggyCode": str, '
        '"fixedCode": str (MUST differ from buggyCode by a real defect, not '
        'formatting), "explanation": str, "category": str, "difficulty": ...}'
    ),
    "problems": (
        'Each item: {"title": str, "description": str, "difficulty": ..., '
        '"category": str, "examples": [{"input": str, "output": str, '
        '"explanation": str}] (at least one), "constraints": [str], '
        '"hints": [str]}'
    ),
}

SYSTEM = (
    "You write practice material for a programming-education site. "
    "Return ONLY a JSON object of the form {\"items\": [...]}. "
    "Every item must be self-contained, correct, and unambiguous: exactly one "
    "option is right and the others are plausible but definitely wrong. "
    "Prefer JavaScript and Python unless a category demands otherwise."
)


def _prompt(collection, count, category, difficulty, avoid):
    parts = [
        "Write %d %s items." % (count, collection),
        _SHAPES[collection],
    ]
    if category:
        parts.append("Category: %s." % category)
    if difficulty:
        parts.append("Difficulty: %s." % difficulty)
    if avoid:
        # Sending the existing questions themselves would cost a fortune in
        # tokens on a large table, so a sample of titles is the compromise:
        # it steers away from the obvious repeats, and the fingerprint check
        # catches the rest for free.
        parts.append("Do NOT repeat or restate any of these existing items: "
                     + "; ".join(avoid[:40]))
    return "\n".join(parts)


def _sample_titles(collection, limit=40):
    from model.CodeplayContent import CodeplayContent
    from shared import db

    rows = (
        db.session.query(CodeplayContent.payload)
        .filter(CodeplayContent.collection == collection)
        .order_by(CodeplayContent.id.desc())
        .limit(limit)
        .all()
    )
    out = []
    for (payload,) in rows:
        try:
            item = _json.loads(payload or "{}")
        except ValueError:
            continue
        text = _identity_text(collection, item).strip().replace("\n", " ")
        if text:
            out.append(text[:120])
    return out


# --- the run ----------------------------------------------------------------

def generate(collection, count, category=None, difficulty=None, now=None):
    """Generate, validate and store. Returns a report; never raises on content.

    The report separates ASKED, ACCEPTED and each reason for rejection, because
    "generated 3 of 20" with no explanation is indistinguishable from a broken
    integration, and the two need completely different responses.
    """
    from model.CodeplayContent import CodeplayContent
    from services import openai_api
    from shared import db

    if collection not in VALIDATORS:
        raise ValueError("unknown collection %r" % collection)
    wanted = max(1, min(int(count or 0), MAX_PER_RUN))

    report = {"collection": collection, "asked": wanted, "accepted": 0,
              "rejected_invalid": 0, "rejected_duplicate": 0, "errors": []}

    seen = existing_fingerprints(collection)
    avoid = _sample_titles(collection)
    validate = VALIDATORS[collection]
    stored = []

    while len(stored) < wanted and not report["errors"]:
        batch = min(MAX_PER_BATCH, wanted - len(stored))
        try:
            answer = openai_api.complete_json(
                SYSTEM, _prompt(collection, batch, category, difficulty, avoid))
        except Exception as exc:  # noqa: BLE001 - reported, never raised at the caller
            report["errors"].append(str(exc))
            break

        items = answer.get("items")
        if not isinstance(items, list) or not items:
            report["errors"].append("the model returned no items")
            break

        progressed = False
        for raw in items:
            if not isinstance(raw, dict):
                report["rejected_invalid"] += 1
                continue
            clean = validate(raw)
            if clean is None:
                report["rejected_invalid"] += 1
                continue
            mark = _fingerprint(_identity_text(collection, clean))
            if mark in seen:
                report["rejected_duplicate"] += 1
                continue
            seen.add(mark)
            stored.append(clean)
            avoid.append(_identity_text(collection, clean)[:120])
            progressed = True

        # Every item in a whole batch rejected means asking again will almost
        # certainly produce the same, and looping would burn money to discover
        # that repeatedly.
        if not progressed:
            report["errors"].append(
                "a whole batch was rejected as invalid or duplicate; stopping")
            break

    if stored:
        position = _next_position(collection)
        for offset, item in enumerate(stored):
            item_id = "gen-%s-%d" % (collection, position + offset)
            item["id"] = item_id
            db.session.add(CodeplayContent(
                collection=collection,
                item_id=item_id,
                category=item.get("category", "")[:64],
                difficulty=item.get("difficulty", "")[:16],
                payload=_json.dumps(item),
                position=position + offset,
                active=True,
            ))
        db.session.commit()
        report["accepted"] = len(stored)
    return report


def _next_position(collection):
    from model.CodeplayContent import CodeplayContent
    from shared import db

    highest = (
        db.session.query(db.func.max(CodeplayContent.position))
        .filter(CodeplayContent.collection == collection)
        .scalar()
    )
    return int(highest or 0) + 1


def counts():
    """Per-collection totals, for the admin page."""
    from model.CodeplayContent import CodeplayContent
    from shared import db

    rows = (
        db.session.query(CodeplayContent.collection, db.func.count(CodeplayContent.id))
        .group_by(CodeplayContent.collection)
        .all()
    )
    return {collection: int(total) for collection, total in rows}
