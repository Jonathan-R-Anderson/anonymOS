"""Machine-learning competitions and the datasets they run on.

A competition is: a host publishes a task and a training file, keeps an answer
key private, and people submit predictions that the site scores against it. The
scores go on a leaderboard.

THE PUBLIC/PRIVATE SPLIT IS THE WHOLE POINT
-------------------------------------------
Scoring every submission against the entire answer key and showing the result
sounds like the obvious design and quietly destroys the competition. With
unlimited submissions against a visible score, the leaderboard becomes a
gradient: people tune against it until they have fitted the answer key itself,
and the winner is whoever submitted most, not whoever built the best model.

So the key is split by a hash of each row's id into a PUBLIC part, which is what
the live leaderboard scores, and a PRIVATE part, which nobody sees until the
competition closes and which decides the actual result. It is the same mechanism
Kaggle uses and it exists for the same reason. The split is deterministic — a
hash of the id, not a shuffle — so it survives a restart, a re-upload of the same
key, and anything else that would otherwise silently re-roll which rows are
public.

WHY THE FILES LIVE IN THE DATABASE
----------------------------------
Same reasoning as the lab's build contexts (model/LabChallenge.py): the site has
no general blob store it can rely on, the sizes here are capped small, and a
dataset that outlives the row describing it is worse than one that costs a few
megabytes in Postgres. Both blobs are deferred, so listing pages never load them.
"""

import csv
import datetime as _datetime
import hashlib
import io

from shared import db

# Deliberately small. This is a teaching-scale competition board, not a place to
# host ImageNet, and an unbounded blob column in the primary database is a way to
# take the whole site down with one upload.
DATASET_MAX_BYTES = 25 * 1024 * 1024
ANSWER_KEY_MAX_BYTES = 8 * 1024 * 1024
SUBMISSION_MAX_BYTES = 8 * 1024 * 1024

# Fraction of the answer key held back to decide the final result.
PRIVATE_FRACTION = 0.5

# Scoring metrics. Each is (key, label, lower_is_better).
METRICS = (
    ("accuracy", "Accuracy", False),
    ("rmse", "RMSE", True),
    ("mae", "MAE", True),
    ("logloss", "Log loss", True),
)
METRIC_KEYS = tuple(key for key, _label, _lower in METRICS)


def metric_label(key):
    for name, label, _lower in METRICS:
        if name == key:
            return label
    return key


def lower_is_better(key):
    for name, _label, lower in METRICS:
        if name == key:
            return lower
    return True


class MlDataset(db.Model):
    __tablename__ = "ml_dataset"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    # Free text. A licence field that only accepts a list of licences means
    # somebody with an unusual one either lies or does not publish.
    licence = db.Column(db.String(120), nullable=False, default="", server_default="")
    filename = db.Column(db.String(160), nullable=False, default="data.csv")
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    rows = db.Column(db.Integer, nullable=False, default=0)
    columns = db.Column(db.String(500), nullable=False, default="", server_default="")
    downloads = db.Column(db.Integer, nullable=False, default=0)
    blob = db.deferred(db.Column(db.LargeBinary, nullable=False))
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


class MlCompetition(db.Model):
    __tablename__ = "ml_competition"

    id = db.Column(db.Integer, primary_key=True)
    host_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    metric = db.Column(db.String(16), nullable=False, default="accuracy")
    # The training data people work from. Optional: a competition can point at a
    # dataset hosted elsewhere and describe it in prose.
    dataset_id = db.Column(db.Integer, db.ForeignKey("ml_dataset.id"), nullable=True)

    # The private answer key. NEVER served — see services/ml_contest.py.
    answer_key = db.deferred(db.Column(db.LargeBinary, nullable=False))
    id_column = db.Column(db.String(64), nullable=False, default="id")
    target_column = db.Column(db.String(64), nullable=False, default="target")
    key_rows = db.Column(db.Integer, nullable=False, default=0)

    closes_at = db.Column(db.DateTime, nullable=True)
    # Set when the private scores have been revealed. Separate from the deadline
    # so a host can extend one without the final standings having already been
    # published under the old one.
    closed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    dataset = db.relationship("MlDataset", foreign_keys=[dataset_id])

    @property
    def is_open(self):
        if self.closed_at is not None:
            return False
        if self.closes_at is not None and _datetime.datetime.utcnow() >= self.closes_at:
            return False
        return True


class MlSubmission(db.Model):
    """One scored submission.

    The predictions themselves are NOT kept — only the two scores. A competition
    with a hundred entrants and unlimited submissions would otherwise accumulate
    thousands of prediction files, and nothing ever reads them again.
    """

    __tablename__ = "ml_submission"

    id = db.Column(db.Integer, primary_key=True)
    competition_id = db.Column(db.Integer, db.ForeignKey("ml_competition.id", ondelete="CASCADE"),
                               nullable=False, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    public_score = db.Column(db.Float, nullable=False, default=0.0)
    # Computed at submission time and simply not shown until the competition
    # closes. Computing it later would mean keeping every prediction file.
    private_score = db.Column(db.Float, nullable=False, default=0.0)
    rows_scored = db.Column(db.Integer, nullable=False, default=0)
    note = db.Column(db.String(200), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def is_private_row(row_id, salt):
    """Whether an answer-key row is held back from the live leaderboard.

    Deterministic in the id, so the split survives a restart or a re-upload of
    the same key. A random shuffle would re-roll which rows are public every
    time anything touched the competition, and a leaderboard that silently
    changes meaning is worse than no leaderboard.
    """
    digest = hashlib.sha256(("%s|%s" % (salt, row_id)).encode("utf-8")).digest()
    # First two bytes as a fraction of 65536 — plenty of resolution for a split.
    return ((digest[0] << 8) | digest[1]) < int(PRIVATE_FRACTION * 65536)


def read_csv(data, limit_rows=200000):
    """Parse CSV bytes into (headers, rows). Raises ValueError with a reason.

    Tolerant about encoding because a spreadsheet export is very often not
    UTF-8, and rejecting somebody's data over a byte-order mark helps nobody.
    """
    if not data:
        raise ValueError("The file is empty.")
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError("That file is not text this can read.")

    reader = csv.reader(io.StringIO(text))
    try:
        headers = next(reader)
    except StopIteration:
        raise ValueError("The file has no header row.")
    headers = [h.strip() for h in headers]
    if not any(headers):
        raise ValueError("The header row is blank.")

    rows = []
    for row in reader:
        if not row or not any(cell.strip() for cell in row):
            continue  # blank line, common at the end of an export
        rows.append(row)
        if len(rows) > limit_rows:
            raise ValueError("That file has more than %d rows." % limit_rows)
    if not rows:
        raise ValueError("The file has a header but no data.")
    return headers, rows
