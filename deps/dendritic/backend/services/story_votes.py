"""Votes on stories, and the short list of things a vote is allowed to decide.

WHAT A SCORE MAY DO
-------------------
    * influence ORDERING within the article rail.

WHAT A SCORE MAY NEVER DO
-------------------------
    * unpublish, hide, collapse, blur, de-list or auto-archive a story;
    * trigger a review, a re-review, or any editorial state change;
    * remove a story from the front page. AGE does that, and only age.

There is no threshold anywhere in this module, and the absence is the feature.
These articles name police departments, employers and landlords. Organised
downvoting of civil-rights reporting is the obvious failure mode here, not a
hypothetical one: the cheapest way to suppress a story about a department is to
send fifty accounts at it, and any threshold -- however high, however well
intentioned -- is a published price list for doing so.

If readers should be able to suppress an article, that is a decision somebody
makes in the open and writes down, not an emergent property of a number nobody
discussed. Until then a brigade is a signal for a human: vote velocity is worth
showing a moderator, because a hundred downvotes in four minutes is information.
It is never worth acting on automatically.

WHY THERE IS NO CACHE INVALIDATION IN THIS FILE
------------------------------------------------
`/` is a cached render and this codebase has already been bitten by making that
route do work. Publication clears the front-page cache (see
`services/newsroom._invalidate_front_page`); a vote must NOT, because votes
arrive constantly and invalidating per vote turns a cached front page into an
uncached one at a rate set by whoever is clicking. Vote-driven reordering is
therefore eventually consistent, by design: `recompute_all()` runs on the
background pass and the rail picks the new numbers up on its next render.

`NewsStory.score` and `vote_count` are denormalised for that reason -- the front
page must never COUNT() votes per request. They are recomputed from the rows
rather than incremented, so a lost update, a deleted slip or a half-applied
transaction heals on the next pass instead of drifting forever.
"""

from sqlalchemy.exc import SQLAlchemyError

from shared import app, db

from model.NewsStory import NewsStory, PUBLIC_STATUSES, STATUS_RETRACTED
from model.StoryVote import (
    StoryVote, VALID_VALUES, cast_vote,
)


class VoteRefused(ValueError):
    """A vote that will not be counted, with a reason fit to show a reader.

    Subclasses ValueError so a caller that already catches the ValueError from
    `StoryVote.normalize_vote_value` catches this too, rather than turning a
    refused vote into a 500.
    """


# How many stories one background pass refreshes. Small on purpose: the pass
# runs often, and a sweep that tried to touch every story ever published would
# hold a transaction open long enough to matter on a site whose outages have
# historically been one long-running query.
RECOMPUTE_LIMIT = 500


def _story_id(story):
    return getattr(story, "id", story)


def _slip_id(slip):
    if slip is None:
        return None
    return getattr(slip, "id", slip)


def _totals_for_stories(story_ids):
    """{story_id: (score, vote_count)} for a batch, in ONE query.

    Both numbers together, because they are always wanted together and two
    passes over the same rows can disagree if a vote lands between them.
    """
    keys = list({sid for sid in story_ids if sid})
    if not keys:
        return {}
    try:
        rows = (
            db.session.query(StoryVote.story_id,
                             db.func.coalesce(db.func.sum(StoryVote.value), 0),
                             db.func.count(StoryVote.id))
            .filter(StoryVote.story_id.in_(keys))
            .group_by(StoryVote.story_id)
            .all()
        )
    except SQLAlchemyError:
        # Scores are decoration; the stories are the page. A vote table that is
        # unavailable (or not yet built in this deployment) must not take a
        # story listing down with it.
        db.session.rollback()
        app.logger.exception("story votes: totals lookup failed")
        return {}
    return {story_id: (int(total or 0), int(count or 0))
            for story_id, total, count in rows}


def _open_for_voting(story):
    """Whether this story accepts votes at all.

    Unpublished work does not: a vote on a draft would be a judgement nobody
    could have read, and a vote endpoint that accepted one would confirm the
    story exists to anyone who guessed its id.

    A retracted story does not either. The page is a notice now; there is
    nothing left to rate, and letting a retraction collect votes invites a
    scoreboard on somebody's worst day.
    """
    if story is None or not _story_id(story):
        return False
    if getattr(story, "status", None) == STATUS_RETRACTED:
        return False
    if getattr(story, "status", None) not in PUBLIC_STATUSES:
        return False
    return bool(story.is_displayable)


def cast(story, slip, value):
    """Record one slip's vote. Updates the existing row; never inserts a second.

    The `UniqueConstraint(story_id, slip_id)` is the backstop, not the plan --
    `StoryVote.cast_vote` looks the row up and assigns to it, so changing your
    mind is an UPDATE. Relying on the constraint alone would mean every second
    vote arrives as an IntegrityError that some caller has to interpret.

    Refuses 0. Withdrawing is `clear()`, so a caller whose arithmetic produced a
    zero cannot silently delete somebody's vote while looking like it cast one.

    Returns the story's new score. That recount is one aggregate on an indexed
    column, on a POST -- the rule against counting votes per request is about the
    cached front page, not about the request that just changed the number and has
    to show the person the result.
    """
    slip_id = _slip_id(slip)
    if slip_id is None:
        raise VoteRefused("Sign in with a slip to vote.")
    if value not in VALID_VALUES:
        raise VoteRefused("A vote must be an up or a down.")
    if not _open_for_voting(story):
        raise VoteRefused("This story is not open for voting.")

    cast_vote(_story_id(story), slip_id, value)
    score = recompute(story)
    _commit()
    return score


def clear(story, slip):
    """Withdraw this slip's vote. Silent when there was not one.

    No `_open_for_voting` check: somebody must always be able to take a vote
    back, including from a story that has since been retracted or pulled from
    display. A withdrawal that can be refused is not a withdrawal.
    """
    slip_id = _slip_id(slip)
    if slip_id is None:
        raise VoteRefused("Sign in with a slip to vote.")

    cast_vote(_story_id(story), slip_id, 0)
    score = recompute(story)
    _commit()
    return score


def recompute(story, commit=False):
    """Refresh `score` and `vote_count` from the rows. Returns the score.

    Recomputed, not adjusted. An increment is only ever as correct as every path
    that ever touched a vote, and the failure mode of a drifting counter is that
    nobody notices until the ordering it feeds looks arbitrary.

    Does not commit by default: the callers here are already inside a
    transaction that owns the vote row, and a commit in the middle of one would
    split the vote from the total it produced.
    """
    story_id = _story_id(story)
    if not story_id:
        return 0
    score, count = _totals_for_stories([story_id]).get(story_id, (0, 0))
    story.score = score
    story.vote_count = count
    db.session.add(story)
    if commit:
        _commit()
    return score


def recompute_all(limit=RECOMPUTE_LIMIT):
    """The background pass. Returns how many stories actually moved.

    Scans the most recently published stories rather than everything, in two
    queries: one for the batch, one grouped aggregate for all their totals. A
    per-story COUNT here would be the same mistake as a per-request one, just
    somewhere nobody is watching.

    Recomputing changes ORDERING INPUTS ONLY. Nothing in this function reads a
    threshold, changes a status, or touches display -- see the module docstring
    on why that absence is deliberate.
    """
    try:
        stories = (
            db.session.query(NewsStory)
            .filter(NewsStory.status.in_(PUBLIC_STATUSES))
            .order_by(NewsStory.published_at.desc())
            .limit(limit)
            .all()
        )
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("story votes: recompute pass could not read stories")
        return 0

    stories = list(stories)
    totals = _totals_for_stories([story.id for story in stories])

    changed = 0
    for story in stories:
        score, count = totals.get(story.id, (0, 0))
        if story.score == score and story.vote_count == count:
            continue
        story.score = score
        story.vote_count = count
        db.session.add(story)
        changed += 1

    if changed:
        _commit()
    return changed


def _commit():
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("story votes: commit failed")
        raise VoteRefused("That vote could not be saved. Please try again.")
