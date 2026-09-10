"""The front page's article rail, computed before anybody asks for it.

THE OUTAGE THIS IS SHAPED BY
----------------------------
`/` is a cached render (`firehose-v4-<theme>-<rank_mode>-render`; see
`blueprints/main.py index()`), and this codebase has already been taken down by
making that route do work. An inline news sync inside the front-page render
produced 504s on `/` while every API route stayed healthy, which made it look
like a network fault rather than a render one. So `/` stays read-only and
anything the rail costs is paid somewhere else.

WHAT "PRECOMPUTED" BUYS, EXACTLY
--------------------------------
The rail is built once and cached under its own key with its own timestamp, so a
front-page render is a key read and a JSON parse. `refresh()` exists for a
background pass to keep that key warm; it is the only thing here meant to run on
a schedule.

The cache earns most of its keep on the SIGNED-IN front page, which is never
render-cached (`viewer_can_use_public_cache()` returns False the moment a slip is
present). Without this key every signed-in visit would rebuild the rail.

A cold cache still computes inline rather than showing nothing, and that is safe
because the computation is bounded by construction: one indexed query returning
at most CANDIDATE_POOL rows, plus at most three `IN (...)` lookups to resolve
bylines. No network I/O, no unbounded scan, nothing proportional to the size of
the site. That is the line the sync crossed -- it was network I/O of unbounded
duration -- and a rail that showed nothing whenever its cache was cold would be
invisible exactly on the deploys where somebody is watching.

Every path here fails to an EMPTY RAIL rather than to an exception. The front
page must not be able to 500 because the newsroom has a problem.

WHY A VOTE DOES NOT INVALIDATE ANYTHING
---------------------------------------
Publication must clear the front page, or an editor presses approve, sees
nothing, and concludes approval is broken. A vote must NOT, because votes arrive
constantly and invalidating per vote turns a cached front page into an uncached
one at a rate set by whoever is clicking.

So vote-driven reordering is EVENTUALLY CONSISTENT, BY DESIGN: a score changes
what the rail looks like the next time the rail is built, not the moment
somebody clicks. `services/story_votes.py` deliberately has no invalidation call
in it, and neither does anything reachable from one.

`invalidate()` is here for publication to call. CACHE_TTL_SECONDS is the backstop
for every path that forgets: a story published while nobody clears this key still
appears within the TTL, so the worst case is a short delay rather than an article
that never runs.

ORDERING: UPVOTES LIFT, DOWNVOTES DO NOTHING
--------------------------------------------
Recency is the spine. A score can lift a story by at most MAX_LIFT_HOURS, which
lets a well-received piece hold its place for the rest of the day and no longer.

Negative scores are ignored ENTIRELY -- not clamped to a small effect, ignored.
The rail shows six stories, so anything able to push a story down is able to push
it off the front page, and "removed from the front page by a score" is precisely
what the vote design forbids. These articles name police departments, employers
and landlords; organised downvoting is the cheapest way to bury one, and a bury
that works is worth buying. Age removes a story from this rail. Nothing else
does.

WHAT LEAVES THIS MODULE
-----------------------
Dicts built by `services/bylines.py`. Resolving a SLIP byline into a public name
means reading `NewsStory.slip_id` here -- there is no other way to find the
author's profile -- but that id dies inside `_contributors_for()`. It is never a
key, never a value and never a template variable in anything `rail_stories()`
returns, which is the property the leak tests are actually asserting.

ANONYMOUS stories DO appear here, without a byline. The invariant is that they
appear on no AUTHOR surface -- no author page, no author feed, no "more from this
author" rail -- because those surfaces are what link a story to a person. A
front-page listing is not one of them, and excluding anonymous work from it would
mean the reporting that most needed cover is the reporting that never reaches the
front page. `bylines.serialise_for_feed()` is built to serialise an anonymous
story precisely because unattributed work is still meant to be published.
"""

import datetime as _datetime
import json
from collections import namedtuple
import time

from flask import url_for
from sqlalchemy.exc import SQLAlchemyError

from shared import app, db

from model.Contributor import Contributor
from model.NewsStory import (
    BYLINE_PEN_NAME, BYLINE_SLIP, NewsStory, PUBLIC_STATUSES, STATUS_RETRACTED,
)
from model.PenName import PenName
from model.Profile import Profile
from services import bylines
from services.bylines import displayable_only, serialise_for_feed


# How many cards the front page shows.
RAIL_LIMIT = 6

# How many rows the ranking pass gets to look at. Bigger than RAIL_LIMIT because
# `is_displayable` cannot be expressed in SQL (the hash is computed from the
# columns), so some candidates are dropped in Python after the query -- and a
# pool exactly the size of the rail would render four cards on a day when two
# stories had drifted from their approval.
CANDIDATE_POOL = 36

# Age, and only age, removes a story from the front page. The archive is the
# section front's job.
MAX_AGE_DAYS = 30

# The most a score can move a story, and how fast it gets there. Twelve hours is
# "still here this evening", not "still here next week".
MAX_LIFT_HOURS = 12
HOURS_PER_UPVOTE = 1.0

CACHE_KEY = "news-rail-v1"
CACHE_TS_KEY = "news-rail-v1-ts"
# Bumped by invalidate(). A build stamps the value it started under and its
# write is dropped if the counter has moved -- see _write for the race.
CACHE_GEN_KEY = "news-rail-v1-gen"

# Short, because it is the backstop for a publication path that forgot to call
# `invalidate()`. Long enough that the rail is not rebuilt per signed-in visit.
CACHE_TTL_SECONDS = 120

# Where the section front lives when its blueprint is not registered yet. See
# `_href()`.
SECTION_FRONT_PATH = "/news"


def _now():
    return _datetime.datetime.utcnow()


# -- links ------------------------------------------------------------------


def _href(endpoint, fallback, **values):
    """`url_for(endpoint)`, or a literal path when that cannot be built.

    Two ordinary situations break `url_for` here and neither may take the front
    page down with it: the news blueprint may not be registered in this
    deployment yet, and `refresh()` runs from a background pass with no request
    context. Both raise, several frames down, from a call that only exists to
    decorate a card.

    The fallbacks are the documented URL shapes, so once the real routes exist
    the two agree rather than quietly diverging.
    """
    try:
        return url_for(endpoint, **values)
    except Exception:
        return fallback


def section_href():
    """Where "all reporting" goes.

    Two endpoint names tried, then the literal path: the section front is
    somebody else's route, and this link existing must not depend on agreeing
    with them about what to call it.
    """
    for endpoint in ("news.front", "news.index"):
        built = _href(endpoint, None)
        if built is not None:
            return built
    return SECTION_FRONT_PATH


def _story_href(story):
    published = story.published_at or story.created_at or _now()
    fallback = "/news/%04d/%02d/%s" % (published.year, published.month,
                                       story.slug)
    built = _href("news.story", None, year=published.year,
                  month=published.month, slug=story.slug)
    # `url_for` does not refuse arguments a route has no place for -- it appends
    # them as a query string. So a "?" here does not mean "extra detail", it
    # means the real route takes the slug alone, and the year and month have
    # just been turned into noise on the end of every link in the rail.
    if built is None or "?" in built:
        built = _href("news.story", None, slug=story.slug) or built
    return built or fallback


def _author_href(slug):
    if not slug:
        return None
    return _href("news.author", "/news/author/%s" % slug, slug=slug)


# -- bylines ----------------------------------------------------------------

# What a pen name is allowed to be, once it has left the database. Five public
# fields would be generous; three is what the rail actually renders. There is no
# owner_slip_id on this type, so no code path downstream of the query can reach
# for one.
_PenNameView = namedtuple("_PenNameView", "id slug display_name")


def _pen_names_for(stories):
    ids = {story.pen_name_id for story in stories
           if story.byline_mode == BYLINE_PEN_NAME and story.pen_name_id}
    if not ids:
        return {}
    try:
        # PUBLIC COLUMNS ONLY -- owner_slip_id is deliberately not selected.
        # blueprints/news.py does the same and states the reason: a row that
        # never loaded the column cannot leak it, whatever anybody later writes
        # in a template or a serialiser. This is the surface that is CACHED and
        # served to every visitor, so it is the one where a future
        # entry["pen_name"] = row would be hardest to notice.
        rows = (db.session.query(PenName.id, PenName.slug, PenName.display_name)
                .filter(PenName.id.in_(ids)).all())
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("news rail: pen-name lookup failed")
        # See _candidates: a failure must not be cached as an answer.
        raise
    return {row.id: _PenNameView(id=row.id, slug=row.slug,
                                 display_name=row.display_name)
            for row in rows}


def _contributors_for(stories):
    """{slip_id: {"name", "slug"}} for the SLIP-bylined stories in this batch.

    The one place in this module that touches `slip_id`, and the id goes no
    further: `_entry()` hands the dict to `public_byline()` and keeps only what
    comes back. An entry is built only when a name can actually be resolved --
    a half-resolved contributor would make `public_byline()` return an
    attributed byline with no name in it, which renders as a story that looks
    unattributed but is filed as attributed.
    """
    ids = {story.slip_id for story in stories
           if story.byline_mode == BYLINE_SLIP and story.slip_id}
    if not ids:
        return {}
    # Slip.name is NOT queried, and that is the point of this function.
    #
    # Resolved by services/bylines.contributor_source, which is the ONE place a
    # slip becomes a byline. This module used to decide for itself and fell back
    # to Slip.name -- the LOGIN NAME -- when a contributor had set no
    # byline_name, which is the DEFAULT state. The front page published account
    # names, cached, while the article page for the same story showed none.
    #
    # It raises on a database failure rather than returning {}, which is what
    # this caller needs: a cached surface must be able to tell "nobody has a
    # byline" from "the lookup failed", or it persists a degraded answer for a
    # full TTL.
    return bylines.contributor_source(ids)


# -- ranking ----------------------------------------------------------------


def _lift_hours(score):
    """How far up a score may move a story. Never down -- see the docstring."""
    try:
        score = int(score or 0)
    except (TypeError, ValueError):
        return 0.0
    if score <= 0:
        return 0.0
    return min(MAX_LIFT_HOURS, score * HOURS_PER_UPVOTE)


def _rank_key(story):
    published = story.published_at or story.created_at or _now()
    return published + _datetime.timedelta(hours=_lift_hours(story.score))


def _candidates(limit):
    cutoff = _now() - _datetime.timedelta(days=MAX_AGE_DAYS)
    statuses = [status for status in PUBLIC_STATUSES if status != STATUS_RETRACTED]
    try:
        rows = (
            db.session.query(NewsStory)
            .filter(NewsStory.status.in_(statuses),
                    NewsStory.published_at.isnot(None),
                    NewsStory.published_at >= cutoff)
            .order_by(NewsStory.published_at.desc())
            .limit(max(CANDIDATE_POOL, limit))
            .all()
        )
    except SQLAlchemyError:
        # Includes the deployment where the news tables do not exist yet. The
        # front page is not a newsroom feature and must not fail like one.
        db.session.rollback()
        app.logger.exception("news rail: candidate query failed")
        return []

    # A retracted story keeps serving at its URL -- that is invariant, and it is
    # why RETRACTED is in PUBLIC_STATUSES. It does not keep a promoted slot on
    # the front page: leaving the URL live is about not breaking other people's
    # citations, not about advertising the notice.
    ranked = sorted(displayable_only(rows), key=_rank_key, reverse=True)
    return ranked[:limit]


# -- entries ----------------------------------------------------------------


def _published_label(published, now):
    """A date a reader can scan. Year only when it is not this one."""
    if published is None:
        return ""
    month = published.strftime("%B")
    if published.year == now.year:
        return "%d %s" % (published.day, month)
    return "%d %s %d" % (published.day, month, published.year)


def _entry(story, pen_names, contributors, now):
    byline = serialise_for_feed(
        story,
        pen_name=pen_names.get(story.pen_name_id),
        contributor=contributors.get(story.slip_id),
    )
    published = story.published_at
    entry = {
        "id": story.id,
        "slug": byline["slug"],
        "headline": byline["headline"],
        "standfirst": byline["standfirst"],
        "section": story.section or "",
        "hero_media_id": story.hero_media_id,
        "score": int(story.score or 0),
        "href": _story_href(story),
        "published_iso": published.isoformat() if published else "",
        "published_label": _published_label(published, now),
        "corrected": bool(story.correction_notice),
        "retracted": bool(byline["retracted"]),
    }
    # Present ONLY when there is an author to name, exactly as
    # `serialise_for_feed` decided. A key set to None still tells a consumer
    # that a byline field exists and is empty, which for a small set of stories
    # separates anonymous work from a serialiser that carries no authors.
    if "author" in byline:
        entry["author"] = byline["author"]
        entry["author_href"] = _author_href(byline.get("author_slug"))
    return entry


def _build(limit):
    now = _now()
    stories = _candidates(limit)
    if not stories:
        return []
    pen_names = _pen_names_for(stories)
    contributors = _contributors_for(stories)
    return [_entry(story, pen_names, contributors, now) for story in stories]


# -- the cache --------------------------------------------------------------


def _cache():
    try:
        import cache

        return cache.Cache()
    except Exception:
        app.logger.warning("news rail: no key store, computing inline")
        return None


def _fresh(store):
    stamp = store.get(CACHE_TS_KEY)
    if not stamp:
        return False
    try:
        return (time.time() - float(stamp)) < CACHE_TTL_SECONDS
    except (TypeError, ValueError):
        return False


def _read(store):
    raw = store.get(CACHE_KEY)
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, list) else None


def _generation(store):
    """The number `invalidate()` bumps. Missing or unreadable counts as 0."""
    try:
        return int(store.get(CACHE_GEN_KEY) or 0)
    except (TypeError, ValueError):
        return 0


def _write(store, entries, generation):
    """Store a rail, but only if the world has not moved since it was built.

    THE RACE THIS CLOSES. A request reads the cache, misses, and starts a build.
    While it is in the database, an editor publishes: `invalidate()` deletes the
    cached rail and clears the front-page render. Then the in-flight request
    finishes and writes its PRE-PUBLISH result with a FRESH timestamp. The
    render cache is empty, so the next `/` rebuilds from that stale rail and
    pins it again -- repeatedly, for the full TTL.

    That is not an exotic sequence. It is an editor pressing Publish and then
    loading the front page, which is exactly the "pressed approve, saw nothing,
    concluded approval is broken" case the invalidation exists to prevent.

    A timestamp cannot detect it, because the loser's timestamp is the newer
    one. A generation can: the build records the counter it started under, and
    a write whose generation is stale is dropped rather than stored. The cost of
    dropping is one uncached render; the cost of storing is two minutes of
    serving a story as though it had never been published.
    """
    if _generation(store) != generation:
        app.logger.debug("news rail: discarding a build the world moved past")
        return False
    store.set(CACHE_KEY, json.dumps(entries))
    store.set(CACHE_TS_KEY, str(time.time()))
    return True


def rail_stories(limit=RAIL_LIMIT):
    """The rail, byline-resolved and ready to render. Never raises.

    Returns a list of plain dicts, freshly parsed on every call so a caller can
    annotate them (the blueprint adds vote URLs) without editing what the next
    render sees.
    """
    try:
        limit = max(1, int(limit or RAIL_LIMIT))
    except (TypeError, ValueError):
        limit = RAIL_LIMIT

    try:
        store = _cache()
        if store is not None and _fresh(store):
            cached = _read(store)
            if cached is not None:
                return cached[:limit]
        # There is one cache and it is shared, so it always holds at least a
        # full rail. A caller asking for three cards must not leave the next
        # render with three to choose from until the TTL expires.
        # Read BEFORE the build, so a publication that lands during it is
        # detected by the write below.
        generation = _generation(store) if store is not None else 0
        entries = _build(max(limit, RAIL_LIMIT))
        if store is not None:
            _write(store, entries, generation)
        return entries[:limit]
    except Exception:
        # The front page is the most-visited route on the site. Whatever just
        # went wrong in the newsroom, it does not get to take that page with it.
        app.logger.exception("news rail: could not build the rail")
        return []


def refresh(limit=RAIL_LIMIT):
    """Rebuild the cache from scratch. For a background pass. Never raises.

    Ignores the TTL on purpose: this is the thing that keeps the TTL from ever
    mattering, so it must not defer to it.
    """
    try:
        store = _cache()
        generation = _generation(store) if store is not None else 0
        entries = _build(max(1, int(limit or RAIL_LIMIT)))
        if store is not None:
            _write(store, entries, generation)
        return entries
    except Exception:
        app.logger.exception("news rail: refresh failed")
        return []


def invalidate():
    """Drop the cached rail. Publication calls this; a vote never does.

    Not a rebuild. Clearing is cheap and cannot fail halfway, and it means
    publication does not pay for a query inside whatever transaction it is
    finishing.
    """
    try:
        store = _cache()
        if store is None:
            return
        # Bump BEFORE deleting. A build already in flight reads the counter at
        # its start and compares at its write; bumping first means a build that
        # began before this line cannot win the race, whichever order the
        # deletes land in.
        try:
            store.set(CACHE_GEN_KEY, str(_generation(store) + 1))
        except Exception:
            app.logger.debug("news rail: generation not bumped")
        store.delete(CACHE_KEY)
        store.delete(CACHE_TS_KEY)
    except Exception:
        # Publication must not fail because the cache would not clear. The
        # worst case is a rail up to one TTL stale, which is the thing this
        # function improves on rather than the thing it guarantees.
        app.logger.exception("news rail: could not invalidate")