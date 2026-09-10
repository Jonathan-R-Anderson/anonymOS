"""Per-slip up/down votes on news stories.

Voting is tied to a slip, not an IP or a cookie: a slip is the only identity on
this site that costs something to make, so it is the only one where "one person,
one vote" means anything. Anonymous visitors can read scores but not cast.

WHY THE TARGET IS A PLAIN FK, UNLIKE PostVote
----------------------------------------------
`PostVote` cannot use a post id because half the posts here have no Post row --
imported posts carry a synthetic id that shifts if the source deletes something.
A story has no such problem: every story is a `news_story` row this site wrote,
so the id IS the identity and the FK is the honest column.

Nor is this keyed on a content hash the way `MediaVote` is. That was right for
files, where re-uploading the same video must not launder its score. It is wrong
for stories: the same text filed again is a different story with a different
byline and a different approval, and it must not inherit the first one's
reception.

One row per (story, slip); changing your mind updates it and withdrawing deletes
it, so `value` is only ever +1 or -1 and a score is a SUM. The uniqueness of
that pair is a DATABASE constraint rather than something every write path has to
remember -- a double vote is an error the storage layer refuses, not a bug that
only shows up in a leaderboard months later.

The slip FK cascades, same as PostVote and MediaVote: deleting a slip takes its
votes with it.
"""
import datetime as _datetime

from sqlalchemy.exc import SQLAlchemyError

from shared import app, db


UPVOTE = 1
DOWNVOTE = -1
VALID_VALUES = (UPVOTE, DOWNVOTE)


class StoryVote(db.Model):
    __tablename__ = "story_vote"

    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(
        db.Integer, db.ForeignKey("news_story.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    slip_id = db.Column(
        db.Integer, db.ForeignKey("slip.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    value = db.Column(db.SmallInteger, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=_datetime.datetime.utcnow,
        onupdate=_datetime.datetime.utcnow,
    )

    __table_args__ = (
        db.UniqueConstraint("story_id", "slip_id",
                            name="uq_story_vote_story_slip"),
    )


def normalize_vote_value(raw):
    """Map request input to +1, -1, or 0 (meaning "withdraw my vote")."""
    # bool subclasses int (True -> 1), and int(1.5) == 1, so without these two
    # guards {"value": true} and {"value": 1.5} both become upvotes.
    if isinstance(raw, bool):
        raise ValueError("A vote must be 1, -1, or 0.")
    if isinstance(raw, float) and not raw.is_integer():
        raise ValueError("A vote must be 1, -1, or 0.")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError("A vote must be 1, -1, or 0.")
    if value not in (UPVOTE, DOWNVOTE, 0):
        raise ValueError("A vote must be 1, -1, or 0.")
    return value


def cast_vote(story_id, slip_id, value):
    """Record (or withdraw) one slip's vote on one story. Returns the new score.
    Caller commits."""
    existing = (
        db.session.query(StoryVote)
        .filter(StoryVote.story_id == story_id, StoryVote.slip_id == slip_id)
        .one_or_none()
    )
    if value == 0:
        if existing is not None:
            db.session.delete(existing)
    elif existing is None:
        row = StoryVote()
        row.story_id = story_id
        row.slip_id = slip_id
        row.value = value
        db.session.add(row)
    else:
        existing.value = value
    db.session.flush()
    return score_for_story(story_id)


def score_for_story(story_id):
    total = (
        db.session.query(db.func.coalesce(db.func.sum(StoryVote.value), 0))
        .filter(StoryVote.story_id == story_id)
        .scalar()
    )
    return int(total or 0)


def scores_for_stories(story_ids):
    """{story_id: score} — one query for a whole feed page.

    Stories with no votes are absent and default to 0. A feed must never issue
    one COUNT per card; NewsStory.score exists for the same reason.
    """
    keys = [sid for sid in {sid for sid in story_ids if sid}]
    if not keys:
        return {}
    try:
        rows = (
            db.session.query(StoryVote.story_id, db.func.sum(StoryVote.value))
            .filter(StoryVote.story_id.in_(keys))
            .group_by(StoryVote.story_id)
            .all()
        )
    except SQLAlchemyError:
        # A feed must still render if the vote table is unavailable — e.g. this
        # deployment has not built the table yet. Scores are decoration; the
        # stories are the page.
        db.session.rollback()
        app.logger.exception("story votes: score lookup failed")
        return {}
    return {story_id: int(total or 0) for story_id, total in rows}


def viewer_votes_for_stories(story_ids, slip_id):
    """{story_id: +1/-1} for one slip. Empty for anonymous visitors."""
    if slip_id is None:
        return {}
    keys = [sid for sid in {sid for sid in story_ids if sid}]
    if not keys:
        return {}
    try:
        rows = (
            db.session.query(StoryVote.story_id, StoryVote.value)
            .filter(StoryVote.story_id.in_(keys), StoryVote.slip_id == slip_id)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("story votes: viewer lookup failed")
        return {}
    return {story_id: int(value) for story_id, value in rows}
