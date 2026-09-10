"""Per-slip up/down votes on media, keyed by CONTENT HASH rather than row id.

WHY THE HASH AND NOT THE MEDIA ROW
----------------------------------
The same video gets uploaded repeatedly here — reposted to another board,
re-attached to a new thread, re-imported by a scraper after the original thread
was pruned. Each of those creates a fresh Media row with a fresh id, and a vote
keyed on that id dies with it. The judgement the votes represent ("this clip is
good", "this clip is a repost of garbage") is about the FILE, not about one
row's lifetime, so the vote is keyed on `Media.sha256`.

The practical consequence, and the point of the design: re-uploading a video
does not launder its score. It arrives carrying whatever the site already
decided about it.

That also means a vote intentionally OUTLIVES the media row. There is no FK to
media.id and no cascade from it — deleting one copy of a video must not erase
the votes that the other copies still display. Rows are keyed only by the hash,
which is why `media_hash` is not nullable: a Media row with no sha256 (older
rows predating hashing, or a failed hash) is simply not votable, rather than
collapsing every unhashed file into one shared vote bucket.

The slip FK does cascade: if a slip is deleted its votes go with it, same as
PostVote.

One row per (media_hash, slip); changing your mind updates it and withdrawing
deletes it, so `value` is only ever +1 or -1 and a score is a SUM.
"""
import datetime as _datetime

from sqlalchemy.exc import SQLAlchemyError

from shared import app, db


UPVOTE = 1
DOWNVOTE = -1
VALID_VALUES = (UPVOTE, DOWNVOTE)

SHA256_LENGTH = 64


class MediaVote(db.Model):
    __tablename__ = "media_vote"

    id = db.Column(db.Integer, primary_key=True)
    # Media.sha256. Deliberately NOT a FK — votes outlive any single copy.
    media_hash = db.Column(db.String(SHA256_LENGTH), nullable=False, index=True)
    slip_id = db.Column(
        db.Integer, db.ForeignKey("slip.id", ondelete="CASCADE"), nullable=False, index=True
    )
    value = db.Column(db.SmallInteger, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=_datetime.datetime.utcnow,
        onupdate=_datetime.datetime.utcnow,
    )

    __table_args__ = (
        db.UniqueConstraint("media_hash", "slip_id", name="uq_media_vote_hash_slip"),
    )


def normalize_vote_value(raw):
    """Coerce a request value to +1 / -1 / 0 (withdraw). Raises ValueError."""
    # bool is a subclass of int, so True would otherwise slip through as an
    # upvote; a fractional value must not round INTO a legal vote either
    # (int(1.5) == 1, which would make {"value": 1.5} an upvote).
    if isinstance(raw, bool):
        raise ValueError("Vote value must be 1, -1, or 0.")
    if isinstance(raw, float) and not raw.is_integer():
        raise ValueError("Vote value must be 1, -1, or 0.")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError("Vote value must be 1, -1, or 0.")
    if value not in (UPVOTE, DOWNVOTE, 0):
        raise ValueError("Vote value must be 1, -1, or 0.")
    return value


def normalize_media_hash(raw):
    """Validate a hex sha256. Raises ValueError.

    Strict because this is the whole key: anything that is not a real digest
    would create an unreachable vote bucket that nothing can ever read back.
    """
    value = (raw or "").strip().lower()
    if len(value) != SHA256_LENGTH or not all(c in "0123456789abcdef" for c in value):
        raise ValueError("Not a valid media hash.")
    return value


def hash_for_media(media):
    """The vote key for a Media row, or None if it has no usable hash.

    None means "not votable" — see the module docstring on why unhashed media
    must not share a bucket.
    """
    if media is None:
        return None
    try:
        return normalize_media_hash(getattr(media, "sha256", None))
    except ValueError:
        return None


def cast_vote(media_hash, slip_id, value):
    """Record (or withdraw) one slip's vote on one file. Returns the new score.
    Caller commits."""
    existing = (
        db.session.query(MediaVote)
        .filter(MediaVote.media_hash == media_hash, MediaVote.slip_id == slip_id)
        .one_or_none()
    )
    if value == 0:
        if existing is not None:
            db.session.delete(existing)
    elif existing is None:
        db.session.add(MediaVote(media_hash=media_hash, slip_id=slip_id, value=value))
    else:
        existing.value = value
    db.session.flush()
    return score_for_hash(media_hash)


def score_for_hash(media_hash):
    total = (
        db.session.query(db.func.coalesce(db.func.sum(MediaVote.value), 0))
        .filter(MediaVote.media_hash == media_hash)
        .scalar()
    )
    return int(total or 0)


def scores_for_hashes(hashes):
    """{media_hash: score} — one query for a whole listing page.

    Hashes with no votes are absent and default to 0.
    """
    keys = [h for h in {h for h in hashes if h} ]
    if not keys:
        return {}
    try:
        rows = (
            db.session.query(MediaVote.media_hash, db.func.sum(MediaVote.value))
            .filter(MediaVote.media_hash.in_(keys))
            .group_by(MediaVote.media_hash)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("media votes: score lookup failed")
        return {}
    return {media_hash: int(total or 0) for media_hash, total in rows}


def tallies_for_hashes(hashes):
    """{media_hash: {"up": n, "down": n}} — the split, for controversy display.

    A bare score cannot distinguish 0 votes from 50 up and 50 down.
    """
    keys = [h for h in {h for h in hashes if h}]
    if not keys:
        return {}
    try:
        rows = (
            db.session.query(MediaVote.media_hash, MediaVote.value, db.func.count(MediaVote.id))
            .filter(MediaVote.media_hash.in_(keys))
            .group_by(MediaVote.media_hash, MediaVote.value)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("media votes: tally lookup failed")
        return {}
    tallies = {}
    for media_hash, value, count in rows:
        bucket = tallies.setdefault(media_hash, {"up": 0, "down": 0})
        bucket["up" if int(value) > 0 else "down"] += int(count or 0)
    return tallies


def viewer_votes_for_hashes(hashes, slip_id):
    """{media_hash: value} for one slip. Empty for anonymous visitors."""
    if slip_id is None:
        return {}
    keys = [h for h in {h for h in hashes if h}]
    if not keys:
        return {}
    try:
        rows = (
            db.session.query(MediaVote.media_hash, MediaVote.value)
            .filter(MediaVote.media_hash.in_(keys), MediaVote.slip_id == slip_id)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("media votes: viewer lookup failed")
        return {}
    return {media_hash: int(value) for media_hash, value in rows}
