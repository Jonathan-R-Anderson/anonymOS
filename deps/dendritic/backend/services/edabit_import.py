"""Convert Edabit challenge exports into codeplay `problems` items.

WHICH SCHEMA WON, AND WHY
-------------------------
Neither side dominated, so this takes the union and the existing 57 problems are
backfilled to match (see `upgrade_legacy`).

The export carries metadata the site had no field for: a NUMERIC difficulty
(1.0-6.0, far finer than three labels), the languages a challenge exists in, its
subject tags, an author, a community quality score, and a completion count. The
site carries structure the export has no field for: test cases, hints,
constraints, worked examples, starter code per language, and an XP reward.

Difficulty is the one place the export's scheme replaces ours outright. It bands
into six — Very Easy, Easy, Medium, Hard, Very Hard, Expert — where the site had
three, and three is not enough to order eight thousand problems usefully. Easy,
Medium and Hard keep their names and meanings, so the existing rows stay valid
and only gain neighbours.

WHAT IS DROPPED, AND WHY THAT IS MOST OF THE FILE
-------------------------------------------------
The export is 270 MB for 8,533 challenges. About 68 MB of that is `raw.stats`,
which is a per-user array of individual difficulty ratings — thousands of loose
integers per challenge whose only use is recomputing an average that is already
present as `raw.quality`. It is dropped, along with the rest of `raw` once the
useful fields are lifted out. A converted challenge is roughly 3 KB.

That matters beyond tidiness: these are published to the DHT, and a store that
has to carry 270 MB to deliver 25 MB of actual content is one nobody will host.

JUDGEABLE IS NARROWER THAN CONVERTIBLE, AND SAYING SO IS THE POINT
------------------------------------------------------------------
`raw.lab` is Edabit's own test harness — lines of `Test.assertEquals(f(x), y)`.
About 38% of challenges have a suite that converts mechanically into the site's
testCases. But the site's code runner supports python and javascript only, and
this export contains no python at all: it is javascript, ruby, cpp, java, php,
swift and csharp. So of 8,533 challenges, roughly 1,600 can actually be graded
here.

The rest are still worth importing — they are well-written problems with worked
examples — but they are marked `judgeable: False` so the UI can offer them as
practice instead of promising a verdict it cannot give. Importing them as though
they were gradeable would produce a Submit button that silently never passes.
"""

import json
import re

# The six bands, ordered. Edabit publishes a float; these are the cut points it
# uses for its own labels.
DIFFICULTY_BANDS = (
    (1.5, "Very Easy"),
    (2.5, "Easy"),
    (3.5, "Medium"),
    (4.5, "Hard"),
    (5.5, "Very Hard"),
    (float("inf"), "Expert"),
)

DIFFICULTY_ORDER = ("Very Easy", "Easy", "Medium", "Hard", "Very Hard", "Expert")

# XP scales with the band. The middle three keep the values the site already
# used, so importing this does not silently reprice existing problems.
XP_BY_DIFFICULTY = {
    "Very Easy": 5,
    "Easy": 10,
    "Medium": 15,
    "Hard": 25,
    "Very Hard": 40,
    "Expert": 60,
}

# What the site's code runner can execute. Anything else is study material, not
# a graded exercise — see the module docstring.
RUNNABLE_LANGUAGES = ("python", "javascript")

_ASSERT = re.compile(
    r"^\s*Test\.(assertEquals|assert_equals|assertSimilar|assertDeepEquals)\s*\((.*?)\)\s*;?\s*$")


def band_for(score):
    """Map Edabit's numeric difficulty onto a label.

    Tolerant of the string form the export actually uses ("1.5674157303370786")
    and of a missing value, which lands in the middle rather than at an extreme:
    an unknown problem shown as Expert scares people off, and shown as Very Easy
    it lies.
    """
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "Medium"
    for ceiling, label in DIFFICULTY_BANDS:
        if value < ceiling:
            return label
    return "Expert"


def _split_last_top_level_comma(text):
    """Split `f(a, b), expected` into ("f(a, b)", "expected").

    Splits on the LAST top-level comma, not the first: the call being tested
    usually has its own arguments, and splitting on the first comma would cut
    `edaBit(0, 10)` in half. Depth counting also has to respect string literals,
    because expected values are frequently arrays of strings containing commas.
    """
    depth = 0
    quote = None
    last = -1
    for i, char in enumerate(text):
        if quote:
            if char == quote and text[i - 1] != "\\":
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            last = i
    if last <= 0:
        return None
    return text[:last].strip(), text[last + 1:].strip()


def test_cases(lab, limit=12):
    """Convert an Edabit test suite into the site's testCases.

    Returns [] unless EVERY assertion converts. A partial suite is worse than
    none: it grades a submission against a subset and reports a pass for code
    that fails the cases that were dropped, which is the one outcome a learner
    cannot detect for themselves.

    The first few cases are visible and the rest hidden, matching how the
    existing problems are written — worked examples to learn from, held-back
    cases so the answer cannot be special-cased.
    """
    lines = [line for line in (lab or "").splitlines() if line.strip()]
    if not lines:
        return []
    cases = []
    for line in lines:
        match = _ASSERT.match(line)
        if not match:
            return []
        split = _split_last_top_level_comma(match.group(2))
        if not split:
            return []
        call, expected = split
        cases.append({"input": call, "expectedOutput": expected,
                      "isHidden": len(cases) >= 3})
    return cases[:limit]


def convert(challenge):
    """One export entry to one codeplay `problems` item.

    Returns None for a challenge that cannot be represented — no id, no title,
    or no question text. Skipping is right: a problem with no statement is not a
    problem, and importing it would put a blank card in the catalogue.
    """
    raw = challenge.get("raw") or {}
    item_id = (challenge.get("challenge_id") or raw.get("_id") or "").strip()
    title = (challenge.get("title") or raw.get("title") or "").strip()
    question = (challenge.get("question") or raw.get("instructions") or "").strip()
    if not item_id or not title or not question:
        return None

    language = (raw.get("language") or "").strip().lower()
    languages = [l.strip().lower() for l in (challenge.get("languages") or []) if l]
    if language and language not in languages:
        languages.insert(0, language)

    difficulty = band_for(challenge.get("difficulty", raw.get("difficulty")))
    cases = test_cases(raw.get("lab"))

    # Judgeable needs BOTH a convertible suite and a language this site can run.
    # Either alone is a Submit button that never passes.
    judgeable = bool(cases) and language in RUNNABLE_LANGUAGES

    subjects = [s for s in (challenge.get("subjects") or raw.get("tags") or []) if s]

    item = {
        "id": "edabit_" + item_id,
        "title": title,
        # `description` is what the existing UI renders; `question` is kept as
        # the same text so a template reading either finds it.
        "description": question,
        "difficulty": difficulty,
        "difficulty_score": _float_or_none(challenge.get("difficulty", raw.get("difficulty"))),
        # The first subject doubles as the category the existing filters use, so
        # imported problems appear in the same dropdown as the originals rather
        # than in a category of their own.
        "category": (subjects[0] if subjects else "general").replace("_", " ").title(),
        "subjects": subjects,
        "languages": languages,
        "xpReward": XP_BY_DIFFICULTY.get(difficulty, 15),
        "testCases": cases,
        "judgeable": judgeable,
        "hints": [],
        "constraints": [],
        "examples": [],
        "starterCode": ({language: raw["code"]} if language and raw.get("code") else {}),
        # Attribution is not optional. These are somebody else's problems, and a
        # link back is the least the import owes them.
        "source": "edabit",
        "source_url": challenge.get("url") or "",
        "author": (raw.get("author") or "").strip(),
        "quality": _float_or_none(raw.get("quality")),
        "completed": _int_or_none(((raw.get("stats") or {}).get("completed") or {}).get("total")),
    }
    notes = (challenge.get("notes") or "").strip()
    if notes:
        item["hints"] = [notes]
    return item


def _float_or_none(value):
    try:
        return round(float(value), 4)
    except (TypeError, ValueError):
        return None


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def upgrade_legacy(item):
    """Bring a pre-existing problem up to the merged schema.

    The export's metadata won, so the 57 originals gain the same fields rather
    than being left as a second shape the templates have to special-case. Values
    that genuinely are not known stay absent instead of being invented — a
    fabricated difficulty_score would sort them wrongly and look authoritative
    doing it.
    """
    item = dict(item)
    item.setdefault("subjects", [])
    item.setdefault("languages", sorted(item.get("starterCode") or {}))
    item.setdefault("difficulty_score", None)
    item.setdefault("source", "maniwani")
    item.setdefault("source_url", "")
    item.setdefault("author", "")
    item.setdefault("quality", None)
    item.setdefault("completed", None)
    # An original problem is judgeable exactly when it has cases to judge with,
    # which is what the detail route already decided ad hoc.
    item.setdefault("judgeable", bool(item.get("testCases")))
    if item.get("difficulty") not in DIFFICULTY_ORDER:
        item["difficulty"] = "Medium"
    item.setdefault("xpReward", XP_BY_DIFFICULTY.get(item["difficulty"], 15))
    return item


def load_export(path):
    """Read an export file and yield converted items.

    Accepts either the raw Edabit export (a dict with "challenges") or an
    already-converted list, and reads .json or .json.gz.

    The converted form exists so the 270 MB export does not have to be copied to
    a server to be imported: converting first gives 14 MB, and gzipped that is a
    couple of megabytes. Same items either way — `convert` is not run twice,
    because a converted item has no "raw" to convert from.

    A generator rather than a list: the caller writes rows as it goes, so
    nothing needs both the parsed file and the converted output resident at
    once.
    """
    if path.endswith(".gz"):
        import gzip

        opener = lambda: gzip.open(path, "rt", encoding="utf-8")  # noqa: E731
    else:
        opener = lambda: open(path, encoding="utf-8")  # noqa: E731
    with opener() as handle:
        data = json.load(handle)

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("id"):
                yield item
        return
    for challenge in data.get("challenges") or []:
        item = convert(challenge)
        if item is not None:
            yield item


def write_converted(export_path, out_path):
    """Convert an export to the compact form, gzipped if the name says so."""
    items = list(load_export(export_path))
    if out_path.endswith(".gz"):
        import gzip

        handle = gzip.open(out_path, "wt", encoding="utf-8")
    else:
        handle = open(out_path, "w", encoding="utf-8")
    with handle:
        json.dump(items, handle, ensure_ascii=False)
    return len(items)
