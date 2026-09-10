"""Scoring a submission against a private answer key.

The metrics are the small honest ones: accuracy for labels, RMSE and MAE for
numbers, log loss for probabilities. Implemented in plain Python rather than
pulled from a library — they are four lines each, and this file has to be
readable by whoever is arguing about why their score is what it is.

WHAT IS REFUSED, AND WHY IT MATTERS
-----------------------------------
A submission that is missing rows is REFUSED rather than scored on what it has.
Scoring a partial file rewards leaving out the rows you are unsure of, which
turns "predict every row" into "predict the easy ones" and makes two scores
incomparable. Extra rows are ignored: an id the key does not contain says
nothing either way, and refusing over one is pedantry.

The answer key never leaves this module. Not as a download, not in an error
message, not as a count of how many of a specific value it contains — every one
of those leaks the labels given enough submissions.
"""

import math

from shared import db

from model.MlContest import (
    ANSWER_KEY_MAX_BYTES,
    METRIC_KEYS,
    MlSubmission,
    SUBMISSION_MAX_BYTES,
    is_private_row,
    lower_is_better,
    read_csv,
)


class ContestError(RuntimeError):
    """Something the submitter can act on. The message is shown to them."""


def _column_index(headers, wanted, what):
    for index, header in enumerate(headers):
        if header.strip().lower() == (wanted or "").strip().lower():
            return index
    raise ContestError("No %s column called %r. The file has: %s"
                       % (what, wanted, ", ".join(headers) or "nothing"))


def _as_float(value, what):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        raise ContestError("This metric needs numbers, but %s contains %r." % (what, value))


def score_pairs(metric, pairs):
    """(truth, predicted) pairs -> a score. Raises ContestError.

    Returns 0.0 for an empty set rather than dividing by zero: an empty PRIVATE
    split is possible on a tiny key, and a competition should not crash because
    somebody uploaded eleven rows.
    """
    if not pairs:
        return 0.0

    if metric == "accuracy":
        # String comparison, case- and space-insensitive: "Yes", "yes " and
        # "yes" are the same label, and a scoreboard that disagrees is measuring
        # typing.
        hits = sum(1 for truth, predicted in pairs
                   if str(truth).strip().casefold() == str(predicted).strip().casefold())
        return hits / float(len(pairs))

    if metric in ("rmse", "mae"):
        total = 0.0
        for truth, predicted in pairs:
            error = _as_float(truth, "the answer key") - _as_float(predicted, "your file")
            total += (error * error) if metric == "rmse" else abs(error)
        mean = total / float(len(pairs))
        return math.sqrt(mean) if metric == "rmse" else mean

    if metric == "logloss":
        # Clipped, because a confident wrong prediction of exactly 0 or 1 is
        # infinite loss and one row would decide the whole competition.
        epsilon = 1e-15
        total = 0.0
        for truth, predicted in pairs:
            actual = _as_float(truth, "the answer key")
            probability = min(1 - epsilon, max(epsilon, _as_float(predicted, "your file")))
            total -= (actual * math.log(probability)
                      + (1 - actual) * math.log(1 - probability))
        return total / float(len(pairs))

    raise ContestError("Unknown metric %r." % metric)


def prepare_key(data, id_column, target_column):
    """Validate an answer key at upload time. Returns the row count.

    Checked here rather than at the first submission, so a host finds out their
    key is unusable while they are still looking at the form — not when a
    stranger's submission fails for reasons neither of them can see.
    """
    if len(data or b"") > ANSWER_KEY_MAX_BYTES:
        raise ContestError("The answer key must be under %d MB."
                           % (ANSWER_KEY_MAX_BYTES // (1024 * 1024)))
    try:
        headers, rows = read_csv(data)
    except ValueError as exc:
        raise ContestError(str(exc))
    id_index = _column_index(headers, id_column, "id")
    target_index = _column_index(headers, target_column, "target")

    seen = set()
    for row in rows:
        if max(id_index, target_index) >= len(row):
            raise ContestError("The answer key has a row with missing columns.")
        row_id = row[id_index].strip()
        if not row_id:
            raise ContestError("The answer key has a row with a blank id.")
        if row_id in seen:
            raise ContestError("The answer key has a duplicate id: %s" % row_id)
        seen.add(row_id)
    return len(rows)


def _key_pairs(competition):
    """{id: truth} from the stored key. Never returned to a caller outside."""
    headers, rows = read_csv(competition.answer_key)
    id_index = _column_index(headers, competition.id_column, "id")
    target_index = _column_index(headers, competition.target_column, "target")
    out = {}
    for row in rows:
        if max(id_index, target_index) < len(row):
            out[row[id_index].strip()] = row[target_index]
    return out


def score_submission(competition, slip, data, note=""):
    """Score a prediction file and record it. Raises ContestError.

    Both scores are computed now and the private one is simply not shown until
    the competition closes. The alternative — keeping every prediction file to
    score later — means storing thousands of them for a number computed once.
    """
    if not competition.is_open:
        raise ContestError("This competition is closed.")
    if len(data or b"") > SUBMISSION_MAX_BYTES:
        raise ContestError("Submissions must be under %d MB."
                           % (SUBMISSION_MAX_BYTES // (1024 * 1024)))
    try:
        headers, rows = read_csv(data)
    except ValueError as exc:
        raise ContestError(str(exc))

    id_index = _column_index(headers, competition.id_column, "id")
    target_index = _column_index(headers, competition.target_column, "prediction")

    predictions = {}
    for row in rows:
        if max(id_index, target_index) >= len(row):
            continue
        predictions[row[id_index].strip()] = row[target_index]

    truth = _key_pairs(competition)
    missing = [row_id for row_id in truth if row_id not in predictions]
    if missing:
        # A count and a couple of examples. NOT the whole list: a submitter who
        # sends an empty file would otherwise be handed every id in the key.
        raise ContestError(
            "Your file is missing %d of the %d rows to predict (for example: %s)."
            % (len(missing), len(truth), ", ".join(sorted(missing)[:3])))

    salt = competition.slug or str(competition.id)
    public, private = [], []
    for row_id, actual in truth.items():
        pair = (actual, predictions[row_id])
        (private if is_private_row(row_id, salt) else public).append(pair)

    metric = competition.metric if competition.metric in METRIC_KEYS else "accuracy"
    submission = MlSubmission(
        competition_id=competition.id,
        slip_id=slip.id,
        public_score=score_pairs(metric, public),
        private_score=score_pairs(metric, private),
        rows_scored=len(truth),
        note=(note or "").strip()[:200],
    )
    db.session.add(submission)
    db.session.commit()
    return submission


def leaderboard(competition, limit=100):
    """Best entry per person, ranked.

    Best PER PERSON, not per submission: a leaderboard of raw submissions is a
    list of whoever submitted most often. Which score decides it depends on
    whether the competition has closed — that is the entire mechanism, so it is
    read from the competition rather than passed in by a caller who could get it
    wrong.
    """
    from model.Slip import Slip

    rows = (
        db.session.query(MlSubmission, Slip.name)
        .join(Slip, Slip.id == MlSubmission.slip_id)
        .filter(MlSubmission.competition_id == competition.id)
        .all()
    )
    final = competition.closed_at is not None
    lower = lower_is_better(competition.metric)

    best = {}
    for submission, name in rows:
        score = submission.private_score if final else submission.public_score
        current = best.get(submission.slip_id)
        if current is None or (score < current["score"] if lower else score > current["score"]):
            best[submission.slip_id] = {
                "name": name, "score": score, "at": submission.created_at,
                "note": submission.note,
            }
    ranked = sorted(best.values(), key=lambda row: row["score"], reverse=not lower)
    for index, row in enumerate(ranked, start=1):
        row["rank"] = index
    return ranked[:limit], final


def close(competition):
    """Reveal the private standings. One way, on purpose.

    Reopening would let a host who dislikes the result take more submissions and
    close again on a different one, which makes every leaderboard on the site
    provisional.
    """
    import datetime

    if competition.closed_at is not None:
        raise ContestError("This competition is already closed.")
    competition.closed_at = datetime.datetime.utcnow()
    db.session.commit()
    return competition


def submission_count(competition_id):
    return int(
        db.session.query(db.func.count(MlSubmission.id))
        .filter(MlSubmission.competition_id == competition_id).scalar() or 0
    )
