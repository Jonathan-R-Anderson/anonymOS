"""Persisted per-word sentiment scores learned from real post text.

Post text is coloured client-side from the bundled Loughran-McDonald (LM) lexicon.
This table lets the server *learn* and *refine* a word's sentiment from the
CONTEXTS it actually appears in, and hand those learned scores back to the client
in real time.

Model
-----
The LM lexicon is only the SEED/ANCHOR. LM words are stored with ``source='lm'``
and a fixed, LM-derived score; they never drift and they seed propagation.
Every other non-stopword full-form (non-stem) content word is stored with
``source='learned'`` and starts neutral (score 0). On each sighting its score is
nudged, as a hit_count-weighted running average, toward the mean sentiment of the
known-sentiment words around it (from LM anchors + previously-learned rows). Its
``magnitude`` (confidence) grows with repeated usage. A learned score only
overrides the client's LM score once it is CONFIDENT (hit_count >= threshold).

The primary key is the NON-STEM normalized surface form (lowercased, apostrophes
stripped) to keep parity with the frontend ``normalizeTokenValue``. ``stem`` is an
approximate fallback lookup key (Python has no stemmer, so a small port of the JS
``stemToken`` suffix rules is used; surface match is always tried first).
"""

import datetime as _datetime
import json
import os
import re

from sqlalchemy import text

from shared import db


# Occurrences for a learned word's magnitude/confidence to saturate.
CONFIDENCE_N = 5
# hit_count a learned word needs before its score overrides the client LM score.
CONFIDENCE_THRESHOLD = 3


class WordSentiment(db.Model):
    __tablename__ = "word_sentiment"

    # Normalized full-form (non-stem) surface word.
    word = db.Column(db.String(128), primary_key=True)
    # Approximate stem, for fallback lookups only.
    stem = db.Column(db.String(128), index=True)
    # Sentiment valence in [-1, 1] (green > 0 / red < 0).
    score = db.Column(db.Float, nullable=False, default=0.0)
    # Confidence/intensity of the score, in [0, 1]; grows with hit_count.
    magnitude = db.Column(db.Float, nullable=False, default=0.0)
    # JSON array of LM category labels; NULL for learned (non-lexicon) words.
    categories = db.Column(db.Text)
    # 'lm' (lexicon anchor, fixed score) | 'learned' (score derived from context).
    source = db.Column(db.String(16), nullable=False, default="learned")
    # Times the word has been seen in real post text; drives confidence.
    hit_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=_datetime.datetime.utcnow,
        onupdate=_datetime.datetime.utcnow,
    )

    def to_dict(self):
        return {
            "word": self.word,
            "stem": self.stem,
            "score": self.score,
            "magnitude": self.magnitude,
            "categories": json.loads(self.categories) if self.categories else [],
            "source": self.source,
            "hit_count": self.hit_count,
        }


# ---------------------------------------------------------------------------
# Scoring helpers (Python port of frontend/src/semantic/threadSemantic.js so the
# LM anchor scores agree with the live client scores and coloring does not
# flicker on the DB merge).
# ---------------------------------------------------------------------------

SENTIMENT_CATEGORY_WEIGHTS = {
    "positive": 0.92,
    "negative": -0.96,
    "uncertainty": -0.34,
    "litigious": -0.22,
    "constraining": -0.3,
    "strongModal": 0.08,
    "weakModal": -0.1,
}


def _clamp(value, low, high):
    return max(low, min(high, value))


def normalize_token_value(token):
    """Parity with the frontend normalizeTokenValue: lowercase, apostrophes stripped."""
    return (token or "").lower().replace("'", "")


def stem_token(token):
    """Approximate port of the frontend stemToken suffix rules (fallback key only)."""
    normalized = token or ""
    if len(normalized) > 5 and normalized.endswith("ies"):
        normalized = normalized[:-3] + "y"
    elif len(normalized) > 5 and normalized.endswith("ing"):
        normalized = normalized[:-3]
    elif len(normalized) > 4 and normalized.endswith("ed"):
        normalized = normalized[:-2]
    elif len(normalized) > 4 and normalized.endswith("ly"):
        normalized = normalized[:-2]
    elif len(normalized) > 4 and normalized.endswith("es"):
        normalized = normalized[:-2]
    elif (
        len(normalized) > 3
        and normalized.endswith("s")
        and not normalized.endswith("ss")
        and not normalized.endswith("us")
        and not normalized.endswith("ous")
        and not normalized.endswith("is")
    ):
        normalized = normalized[:-1]
    return normalized


def score_for_categories(categories):
    """Return (score, magnitude) for a set of LM category labels, mirroring the
    isolated-token computation in buildSentimentTokens."""
    if not categories:
        return (0.0, 0.0)
    valence = sum(SENTIMENT_CATEGORY_WEIGHTS.get(category, 0.0) for category in categories)
    valence = _clamp(valence, -1.2, 1.2)
    score = _clamp(valence, -1.0, 1.0)
    magnitude = _clamp(max(abs(valence), len(categories) / 2.9), 0.0, 1.6)
    return (score, magnitude)


# ---------------------------------------------------------------------------
# Optional in-memory Loughran-McDonald lookup, loaded best-effort from the seed
# JSON emitted by frontend/build-helpers/generate-lm-dictionary.js. When present
# it lets learning recognise + anchor LM words without a seeded DB; when absent
# anchors still come from seeded/learned DB rows, and learning degrades to a
# graceful no-op (vocabulary + frequency still accrue).
# ---------------------------------------------------------------------------

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SEED_CANDIDATE_PATHS = (
    os.path.join(_BACKEND_DIR, "data", "loughran_mcdonald_seed.json"),
    os.path.join(os.path.dirname(_BACKEND_DIR), "backend", "data", "loughran_mcdonald_seed.json"),
)


def _load_lm_lookup():
    for candidate in _SEED_CANDIDATE_PATHS:
        try:
            if not os.path.isfile(candidate):
                continue
            with open(candidate, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            continue
        lookup = {}
        if isinstance(data, dict):
            for word, payload in data.items():
                if isinstance(payload, dict):
                    categories = payload.get("categories") or []
                elif isinstance(payload, list):
                    categories = payload
                else:
                    categories = []
                if categories:
                    lookup[normalize_token_value(word)] = list(categories)
        if lookup:
            return lookup
    return {}


_LM_LOOKUP = _load_lm_lookup()


# ---------------------------------------------------------------------------
# Tokenizer: reuse the shared text tokenizer + stopwords (services.text_cluster).
# ---------------------------------------------------------------------------

from services.text_cluster import ENV_STOPWORDS, DOMAIN_STOPWORDS, TOKEN_RE

NEGATOR_WORDS = {
    "no", "nor", "not", "never", "without", "hardly", "barely", "cannot", "cant",
    "dont", "doesnt", "isnt", "arent", "wasnt", "werent", "wont", "couldnt",
    "shouldnt", "wouldnt", "nothing", "nowhere",
}
INTENSIFIER_WORDS = {
    "very", "really", "super", "extremely", "highly", "deeply", "wildly",
    "incredibly", "seriously", "too", "totally", "utterly",
}
# Words never learned as sentiment targets (but negators still act positionally).
_TARGET_STOPWORDS = ENV_STOPWORDS | DOMAIN_STOPWORDS | NEGATOR_WORDS | INTENSIFIER_WORDS

_TAG_RE = re.compile(r"<[^>]*>")
_SENTENCE_SPLIT_RE = re.compile(r"[.!?\n\r;:]+")


def _clean_text(text_value):
    cleaned = _TAG_RE.sub(" ", text_value or "")
    cleaned = cleaned.lower().replace("’", "'").replace("‘", "'")
    cleaned = cleaned.replace("&gt;", " ").replace("&lt;", " ").replace("&amp;", " ")
    return cleaned.replace("'", "")


def _sentences(text_value):
    """Raw token lists, one per sentence-ish chunk, keeping stopwords in place so
    negation and adjacency can be read off the stream."""
    result = []
    for chunk in _SENTENCE_SPLIT_RE.split(_clean_text(text_value)):
        tokens = TOKEN_RE.findall(chunk)
        if tokens:
            result.append(tokens)
    return result


def _is_content_word(token):
    return len(token) >= 3 and not token.isdigit() and token not in _TARGET_STOPWORDS


def _known_sentiment(word, existing):
    """Sentiment of a word for use as CONTEXT: LM anchor first, then a
    previously-learned DB row with real signal. Unknown -> None (no contribution)."""
    categories = _LM_LOOKUP.get(word)
    if categories:
        return score_for_categories(categories)[0]
    row = existing.get(word)
    if row is not None:
        if row.source == "lm":
            return row.score
        if abs(row.score or 0.0) > 0.05:
            return row.score
    return None


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def _upsert(word, stem, score, magnitude, categories, source, hit_count):
    """Absolute upsert: caller has already computed the final field values
    (including hit_count). Works on SQLite (dev) + Postgres (prod)."""
    now = _datetime.datetime.utcnow()
    categories_json = json.dumps(categories) if categories else None
    with db.session.no_autoflush:
        db.session.execute(
            text(
                "INSERT INTO word_sentiment "
                "(word, stem, score, magnitude, categories, source, hit_count, created_at, updated_at) "
                "VALUES (:word, :stem, :score, :magnitude, :categories, :source, :hit_count, :now, :now) "
                "ON CONFLICT (word) DO UPDATE SET "
                "stem = EXCLUDED.stem, score = EXCLUDED.score, magnitude = EXCLUDED.magnitude, "
                "categories = EXCLUDED.categories, source = EXCLUDED.source, "
                "hit_count = EXCLUDED.hit_count, updated_at = EXCLUDED.updated_at"
            ),
            {
                "word": word,
                "stem": stem,
                "score": float(score or 0.0),
                "magnitude": float(magnitude or 0.0),
                "categories": categories_json,
                "source": source,
                "hit_count": int(hit_count),
                "now": now,
            },
        )


def upsert_word_sentiment(word, stem, score, magnitude, categories, source="lm"):
    """Seed/anchor writer (used by scripts/seed_word_sentiment.py): the score /
    categories are authoritative, but hit_count is PRESERVED so seeding does not
    fabricate frequency. New anchors start unseen (hit_count 0)."""
    now = _datetime.datetime.utcnow()
    categories_json = json.dumps(categories) if categories else None
    with db.session.no_autoflush:
        db.session.execute(
            text(
                "INSERT INTO word_sentiment "
                "(word, stem, score, magnitude, categories, source, hit_count, created_at, updated_at) "
                "VALUES (:word, :stem, :score, :magnitude, :categories, :source, 0, :now, :now) "
                "ON CONFLICT (word) DO UPDATE SET "
                "stem = EXCLUDED.stem, score = EXCLUDED.score, magnitude = EXCLUDED.magnitude, "
                "categories = EXCLUDED.categories, source = EXCLUDED.source, "
                "updated_at = EXCLUDED.updated_at"
            ),
            {
                "word": normalize_token_value(word),
                "stem": stem,
                "score": float(score or 0.0),
                "magnitude": float(magnitude or 0.0),
                "categories": categories_json,
                "source": source,
                "now": now,
            },
        )


def score_and_learn_text(text_value):
    """Contextual online learner. For each post, nudge every non-anchor content
    word toward the mean sentiment of the known-sentiment words around it, as a
    hit_count-weighted running average; LM words are fixed anchors that only seed
    propagation. Commits its own writes; on error rolls back and re-raises to the
    (guarded) caller. Returns the number of distinct words touched."""
    sentences = _sentences(text_value)
    if not sentences:
        return 0
    token_set = {
        token
        for tokens in sentences
        for token in tokens
        if len(token) >= 2 and not token.isdigit()
    }
    if not token_set:
        return 0

    try:
        existing = {
            row.word: row
            for row in (
                db.session.query(WordSentiment)
                .filter(WordSentiment.word.in_(list(token_set)))
                .all()
            )
        }

        contexts = {}     # word -> list of per-occurrence context sentiments
        occ_counts = {}   # word -> total content-word occurrences
        for tokens in sentences:
            # Sentiment of every position (for use as context), with simple negation.
            senti = []
            for index, word in enumerate(tokens):
                value = _known_sentiment(word, existing)
                if value is not None and index > 0 and tokens[index - 1] in NEGATOR_WORDS:
                    value = -value
                senti.append(value)
            known_positions = [i for i, value in enumerate(senti) if value is not None]
            known_sum = sum(senti[i] for i in known_positions)
            for index, word in enumerate(tokens):
                if not _is_content_word(word):
                    continue
                occ_counts[word] = occ_counts.get(word, 0) + 1
                # Context = mean sentiment of the OTHER known-sentiment words.
                other_count = len(known_positions) - (1 if senti[index] is not None else 0)
                if other_count > 0:
                    other_sum = known_sum - (senti[index] if senti[index] is not None else 0.0)
                    contexts.setdefault(word, []).append(other_sum / other_count)

        learned = 0
        for word, occ in occ_counts.items():
            row = existing.get(word)
            stem = stem_token(word)
            old_hits = row.hit_count if row is not None else 0
            is_anchor = (word in _LM_LOOKUP) or (row is not None and row.source == "lm")

            if is_anchor:
                categories = _LM_LOOKUP.get(word)
                if categories:
                    score, magnitude = score_for_categories(categories)
                elif row is not None:
                    score, magnitude = row.score, row.magnitude
                    categories = json.loads(row.categories) if row.categories else None
                else:
                    score, magnitude, categories = 0.0, 0.0, None
                _upsert(word, stem, score, magnitude, categories, "lm", old_hits + occ)
            else:
                new_score = row.score if row is not None else 0.0
                hits = old_hits
                signals = contexts.get(word, [])
                for context_sentiment in signals:
                    new_score = (new_score * hits + context_sentiment) / (hits + 1)
                    hits += 1
                hits += occ - len(signals)  # signal-less occurrences still count
                new_magnitude = min(1.0, hits / float(CONFIDENCE_N)) * abs(new_score)
                _upsert(word, stem, new_score, new_magnitude, None, "learned", hits)
            learned += 1

        db.session.commit()
        return learned
    except Exception:
        db.session.rollback()
        raise


# ---------------------------------------------------------------------------
# Reads (real-time retrieval for the selection UI)
# ---------------------------------------------------------------------------

def _is_meaningful(row):
    """Rows worth returning: LM anchors always; learned rows once they carry a
    signal. (The client still gates learned overrides on ``confident``.)"""
    if row.source == "lm":
        return True
    return abs(row.score or 0.0) > 0.0 or (row.magnitude or 0.0) > 0.0


def _entry_for(row):
    payload = row.to_dict()
    confident = (row.source == "lm") or ((row.hit_count or 0) >= CONFIDENCE_THRESHOLD)
    return {
        "score": payload["score"],
        "magnitude": payload["magnitude"],
        "categories": payload["categories"],
        "source": payload["source"],
        "hit_count": payload["hit_count"],
        "confident": confident,
    }


def lookup_scores(words):
    """Batch-fetch persisted scores (indexed ``word IN (...)`` then a stem
    fallback). Returns ``{word: {score, magnitude, categories, source, hit_count,
    confident}}`` keyed by the requested word form."""
    normalized = []
    seen = set()
    for word in words or []:
        value = normalize_token_value(word)
        if value and value not in seen:
            seen.add(value)
            normalized.append(value)
    result = {}
    if not normalized:
        return result

    rows = (
        db.session.query(WordSentiment)
        .filter(WordSentiment.word.in_(normalized))
        .all()
    )
    for row in rows:
        if _is_meaningful(row):
            result[row.word] = _entry_for(row)

    remaining = [word for word in normalized if word not in result]
    if remaining:
        stem_to_words = {}
        for word in remaining:
            stem_to_words.setdefault(stem_token(word), []).append(word)
        stem_rows = (
            db.session.query(WordSentiment)
            .filter(WordSentiment.stem.in_(list(stem_to_words.keys())))
            .all()
        )
        for row in stem_rows:
            if not _is_meaningful(row):
                continue
            entry = _entry_for(row)
            for word in stem_to_words.get(row.stem, []):
                result.setdefault(word, entry)
    return result
