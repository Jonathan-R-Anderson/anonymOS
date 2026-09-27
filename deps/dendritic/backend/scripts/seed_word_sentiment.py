"""Optionally seed the word_sentiment table with Loughran-McDonald anchors.

This is a MANUAL, idempotent, one-off step. The drag-select sentiment feature
works without it (the client always has an in-bundle LM score). Running it loads
the LM lexicon as ``source='lm'`` anchor rows, which lets the contextual learner
in model.WordSentiment.score_and_learn_text propagate sentiment from known words
to new ones.

Usage (from the backend/ directory, inside the project venv):

    python scripts/seed_word_sentiment.py [--seed path/to/loughran_mcdonald_seed.json]

The seed JSON is emitted by frontend/build-helpers/generate-lm-dictionary.js (run
by the frontend gulp build) into backend/data/loughran_mcdonald_seed.json.
"""

import gevent.monkey
gevent.monkey.patch_all()
try:
    import psycogreen.gevent
    psycogreen.gevent.patch_psycopg()
except Exception:
    pass

import argparse
import json
import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from shared import app, db
from model.WordSentiment import upsert_word_sentiment, stem_token, normalize_token_value

DEFAULT_SEED_PATH = os.path.join(_BACKEND_DIR, "data", "loughran_mcdonald_seed.json")


def _load_seed(seed_path):
    with open(seed_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _iter_rows(seed):
    for word, payload in seed.items():
        normalized = normalize_token_value(word)
        if not normalized:
            continue
        if isinstance(payload, dict):
            categories = payload.get("categories") or []
            score = float(payload.get("score") or 0.0)
            magnitude = float(payload.get("magnitude") or 0.0)
            stem = payload.get("stem") or stem_token(normalized)
        elif isinstance(payload, list):
            categories = payload
            score = 0.0
            magnitude = 0.0
            stem = stem_token(normalized)
        else:
            continue
        if not categories:
            continue
        yield normalized, stem, score, magnitude, categories


def seed(seed_path, batch_size=1000):
    seed_data = _load_seed(seed_path)
    count = 0
    with app.app_context():
        for word, stem, score, magnitude, categories in _iter_rows(seed_data):
            upsert_word_sentiment(word, stem, score, magnitude, categories, "lm")
            count += 1
            if count % batch_size == 0:
                db.session.commit()
        db.session.commit()
    return count


def main():
    parser = argparse.ArgumentParser(description="Seed word_sentiment with LM anchors.")
    parser.add_argument("--seed", default=DEFAULT_SEED_PATH, help="Path to the LM seed JSON.")
    args = parser.parse_args()
    if not os.path.isfile(args.seed):
        sys.stderr.write(
            "Seed JSON not found at %s.\n"
            "Run the frontend gulp build (which emits it) or pass --seed PATH.\n"
            % args.seed
        )
        return 1
    count = seed(args.seed)
    sys.stdout.write("Seeded %d Loughran-McDonald anchor words into word_sentiment.\n" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
