"""Per-slip up/down votes on posts, local and scraped alike.

Voting is tied to a slip, not an IP or a cookie: a slip is the only identity on
this site that costs something to make, so it is the only one where "one person,
one vote" means anything. Anonymous visitors can read scores but not cast.

WHY THE TARGET IS A STRING AND NOT A post.id FK
-----------------------------------------------
Half the posts on this site have no Post row. An imported thread's posts are
read straight out of the scraper's SQLite (ThreadPosts._json_friendly_imported)
and handed a SYNTHETIC id, `thread.id * 1_000_000 + index`, purely so markdown
render-caching has something to key on. Those ids are unusable as a vote target
twice over: they can collide with a genuine post id, and the `index` half shifts
if the source deletes a post, so a vote would silently move to its neighbour.

So a vote targets `(thread_id, target_key)`:

    local post     ->  "p<post.id>"
    imported post  ->  "s<source_post_id>"     (the source's own id, stable)

Thread-scoped, so a target only has to be unique within its thread, and votes
can be swept when a thread goes. `post_id` is still carried for local posts,
purely so the FK cascade cleans up when a post is deleted.

One row per (thread, target, slip); changing your mind updates it and
withdrawing deletes it, so `value` is only ever +1 or -1 and a score is a SUM.

The score also drives the radial TF-IDF tree: a post's node radius scales with
its score relative to the rest of the thread (see ThreadSemanticTree.jsx).
"""
import datetime as _datetime

from sqlalchemy.exc import SQLAlchemyError

from shared import app, db


UPVOTE = 1
DOWNVOTE = -1
VALID_VALUES = (UPVOTE, DOWNVOTE)

LOCAL_TARGET_PREFIX = "p"
IMPORTED_TARGET_PREFIX = "s"
MAX_TARGET_KEY_LENGTH = 160


class PostVote(db.Model):
    __tablename__ = "post_vote"

    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(db.Integer, nullable=False, index=True)
    # "p<post_id>" or "s<source_post_id>" — see the module docstring.
    target_key = db.Column(db.String(MAX_TARGET_KEY_LENGTH), nullable=False)
    # Local posts only, and only so the cascade cleans up after a deletion.
    post_id = db.Column(
        db.Integer, db.ForeignKey("post.id", ondelete="CASCADE"), nullable=True, index=True
    )
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
        db.UniqueConstraint(
            "thread_id", "target_key", "slip_id", name="uq_post_vote_thread_target_slip"
        ),
    )


def local_target_key(post_id):
    return "%s%s" % (LOCAL_TARGET_PREFIX, post_id)


def imported_target_key(source_post_id):
    key = "%s%s" % (IMPORTED_TARGET_PREFIX, source_post_id)
    return key[:MAX_TARGET_KEY_LENGTH]


def target_key_for_payload(post_payload):
    """The vote target for one rendered post, or None if it cannot be voted on.

    Local posts are identified by the is_local_post flag rather than by
    inspecting the id, because an imported post's synthetic id is also an int
    and can collide with a real one.
    """
    if post_payload.get("is_local_post"):
        post_id = post_payload.get("id")
        return local_target_key(post_id) if isinstance(post_id, int) else None
    source_post_id = post_payload.get("source_post_id")
    if source_post_id in (None, ""):
        return None
    return imported_target_key(source_post_id)


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


def normalize_target_key(raw):
    key = (raw or "").strip()
    if not key or len(key) > MAX_TARGET_KEY_LENGTH:
        raise ValueError("Unknown vote target.")
    if key[0] not in (LOCAL_TARGET_PREFIX, IMPORTED_TARGET_PREFIX) or len(key) < 2:
        raise ValueError("Unknown vote target.")
    return key


def local_post_id_from_target(target_key):
    """The Post id a local target refers to, or None for an imported target."""
    if not target_key.startswith(LOCAL_TARGET_PREFIX):
        return None
    try:
        return int(target_key[1:])
    except (TypeError, ValueError):
        return None


def cast_vote(thread_id, target_key, slip_id, value, post_id=None):
    """Record (or withdraw) one slip's vote on one post. Returns the new score.
    Caller commits."""
    existing = (
        db.session.query(PostVote)
        .filter(
            PostVote.thread_id == thread_id,
            PostVote.target_key == target_key,
            PostVote.slip_id == slip_id,
        )
        .one_or_none()
    )
    if value == 0:
        if existing is not None:
            db.session.delete(existing)
    elif existing is None:
        db.session.add(PostVote(
            thread_id=thread_id,
            target_key=target_key,
            post_id=post_id,
            slip_id=slip_id,
            value=value,
        ))
    else:
        existing.value = value
    db.session.flush()
    return score_for_target(thread_id, target_key)


def score_for_target(thread_id, target_key):
    total = (
        db.session.query(db.func.coalesce(db.func.sum(PostVote.value), 0))
        .filter(PostVote.thread_id == thread_id, PostVote.target_key == target_key)
        .scalar()
    )
    return int(total or 0)


def scores_for_thread(thread_id):
    """{target_key: score} for every voted target in a thread.

    One query for the whole thread rather than one per post; targets with no
    votes are simply absent and default to 0.
    """
    try:
        rows = (
            db.session.query(PostVote.target_key, db.func.sum(PostVote.value))
            .filter(PostVote.thread_id == thread_id)
            .group_by(PostVote.target_key)
            .all()
        )
    except SQLAlchemyError:
        # A thread must still render if the vote table is unavailable — e.g. the
        # migration has not been applied on this deployment yet.
        db.session.rollback()
        app.logger.exception("Failed loading vote scores for thread %s", thread_id)
        return {}
    return {target_key: int(total or 0) for (target_key, total) in rows}


def vote_tallies_for_thread(thread_id):
    """{target_key: {"up": n, "down": n}} for every voted target in a thread.

    Separate from scores_for_thread because a net score cannot express
    controversy: +10/-10 and 0/0 both sum to zero, and only one of them is a
    fight. The radial tree needs the split to shape its nodes.
    """
    try:
        rows = (
            db.session.query(
                PostVote.target_key,
                db.func.sum(db.case((PostVote.value > 0, 1), else_=0)),
                db.func.sum(db.case((PostVote.value < 0, 1), else_=0)),
            )
            .filter(PostVote.thread_id == thread_id)
            .group_by(PostVote.target_key)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed loading vote tallies for thread %s", thread_id)
        return {}
    return {
        target_key: {"up": int(up or 0), "down": int(down or 0)}
        for (target_key, up, down) in rows
    }


def viewer_votes_for_thread(thread_id, slip_id):
    """{target_key: +1/-1} for the votes this slip has cast in this thread."""
    if slip_id is None:
        return {}
    try:
        rows = (
            db.session.query(PostVote.target_key, PostVote.value)
            .filter(PostVote.thread_id == thread_id, PostVote.slip_id == slip_id)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed loading viewer votes for thread %s", thread_id)
        return {}
    return {target_key: int(value) for (target_key, value) in rows}
