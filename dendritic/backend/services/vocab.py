"""The vocabulary section: a glossary, and a drill built from the same list.

Everything here reads services/vocab_data.py. There is no database table
deliberately — 205 fixed terms are data, not state, and putting them in Postgres
would mean a migration every time a definition is corrected.

WHY THE DRILL SHOWS THE DEFINITION AND ASKS FOR THE TERM
--------------------------------------------------------
Both directions are useful, but they test different things. Term-to-definition
tests recognition, which feels like knowing and often is not. Definition-to-term
tests recall, which is the harder direction and the one that transfers. The
drill defaults to recall and offers the other, rather than picking the easy one
and letting people mistake fluency for understanding.
"""

import hashlib
import unicodedata

from services.vocab_data import EASY, HARD, MEDIUM, TERMS

# Order matters: this is the order tabs appear and the order of a full listing.
DIFFICULTIES = (EASY, MEDIUM, HARD)

DIFFICULTY_LABELS = {EASY: "Easy", MEDIUM: "Medium", HARD: "Hard"}

DIFFICULTY_BLURBS = {
    EASY: "Meets it in week one, and it means roughly what it sounds like.",
    MEDIUM: "Needs one computing idea already in place to make sense.",
    HARD: "Abstract, formal, or a term whose plain-English reading is wrong.",
}


def _entry(row):
    term, difficulty, category, definition = row
    return {
        "term": term,
        "slug": slug_for(term),
        "difficulty": difficulty,
        "difficulty_label": DIFFICULTY_LABELS.get(difficulty, difficulty),
        "category": category,
        "definition": definition,
    }


def slug_for(term):
    """A stable, URL-safe id for a term.

    Derived from the term rather than stored, so adding a term never renumbers
    anything and a link to a definition keeps working. Accents are folded and
    everything non-alphanumeric becomes a hyphen, which is enough for a list
    that is all ASCII today but need not stay that way.
    """
    folded = unicodedata.normalize("NFKD", term)
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    out = []
    for char in folded.lower():
        out.append(char if char.isalnum() else "-")
    slug = "-".join(part for part in "".join(out).split("-") if part)
    return slug or hashlib.sha256(term.encode("utf-8")).hexdigest()[:12]


def all_terms():
    return [_entry(row) for row in TERMS]


def categories():
    """Categories in the order they first appear, not alphabetically.

    Alphabetical would put Algorithms before Creative Development, which is
    backwards as a reading order and looks arbitrary as a filter.
    """
    seen, out = set(), []
    for _term, _difficulty, category, _definition in TERMS:
        if category not in seen:
            seen.add(category)
            out.append(category)
    return out


def search(query="", difficulty="", category=""):
    """Filter the glossary. Every argument is optional and combines with AND.

    The text match covers the definition as well as the term, because somebody
    who half-remembers a concept searches for what it DOES, not for the word
    they cannot recall — which is precisely the situation a glossary is for.
    """
    needle = (query or "").strip().lower()
    difficulty = (difficulty or "").strip().lower()
    category = (category or "").strip()

    out = []
    for entry in all_terms():
        if difficulty and entry["difficulty"] != difficulty:
            continue
        if category and entry["category"] != category:
            continue
        if needle and needle not in entry["term"].lower() \
                and needle not in entry["definition"].lower():
            continue
        out.append(entry)
    return out


def counts_by_difficulty():
    counts = {level: 0 for level in DIFFICULTIES}
    for _term, difficulty, _category, _definition in TERMS:
        if difficulty in counts:
            counts[difficulty] += 1
    return counts


def grouped():
    """[(difficulty, label, blurb, [entries])] in the listed order.

    Terms within a level are sorted alphabetically; the source order is the
    order they were written, which is nobody's idea of how to find a word.
    """
    out = []
    for level in DIFFICULTIES:
        entries = sorted(
            (entry for entry in all_terms() if entry["difficulty"] == level),
            key=lambda entry: entry["term"].lower(),
        )
        out.append((level, DIFFICULTY_LABELS[level], DIFFICULTY_BLURBS[level], entries))
    return out


def term_by_slug(slug):
    for entry in all_terms():
        if entry["slug"] == slug:
            return entry
    return None
