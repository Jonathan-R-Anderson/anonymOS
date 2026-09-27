"""What a reader is allowed to see about who wrote something.

ONE MODULE, ASKED BY EVERY PUBLIC SURFACE
------------------------------------------
The leak in a system like this is never the story page -- that is the one place
somebody remembers to check. It is the RSS feed, the sitemap, the "more from this
author" rail, the JSON API, the OpenGraph tag, the search index, the admin
export somebody pointed at a public route. Each is written by a different person
on a different day, and each independently reimplements "should this be shown".

So the rule is: no surface reads `NewsStory.slip_id` or `pen_name.owner_slip_id`
directly. Every one of them calls `public_byline()` or filters through
`visible_to_readers()`, and the tests assert the absence of those columns from
rendered output rather than trusting the convention.

WHAT ANONYMITY MEANS HERE, EXACTLY
-----------------------------------
From READERS, not from the newsroom. `slip_id` is recorded on every story in
every mode because editors must know who filed. Nothing in this module can hide
a story from the people running the site, and the contributor UI must say so --
a writer who believes otherwise will take risks on a guarantee nobody made.

THE COUNT IS AN ORACLE
----------------------
`author_story_count()` counts only what is publicly listed. A total that included
unlisted work would say "this author has an anonymous story, filed around now",
which is most of what an attacker needs. There is deliberately no function here
that returns a total including hidden stories; if one is ever needed for an
admin screen, it belongs in an admin module behind the wallet gate, not here.
"""

from shared import db

from model.NewsStory import (
    ATTRIBUTED_MODES, BYLINE_ANONYMOUS, BYLINE_PEN_NAME, BYLINE_SLIP,
    NewsStory, PUBLIC_STATUSES,
)


def visible_to_readers(query=None):
    """Base query for stories a reader may see.

    Status alone is not enough: `is_displayable` also requires the approval to
    still match the content, and that check cannot be expressed in SQL because
    the hash is computed from the columns. So this narrows in the database and
    `displayable_only()` finishes the job in Python.
    """
    query = query if query is not None else db.session.query(NewsStory)
    return query.filter(NewsStory.status.in_(PUBLIC_STATUSES))


def displayable_only(stories):
    """Drop anything whose approval no longer matches its content.

    The second half of the gate. A story edited after approval survives the SQL
    filter above and is removed here, which is why every listing must pass
    through this rather than rendering the query result directly.
    """
    return [story for story in stories if story.is_displayable]


def public_byline(story, pen_name=None, contributor=None):
    """What a reader may be told about authorship. Never raises.

    Returns a dict with a stable shape so a template cannot accidentally reveal
    something by testing for a key's absence:

        {"mode", "name", "href_slug", "attributed", "tip"}

    `name` is None and `attributed` is False for anonymous work. `href_slug` is
    None whenever there is no author page to link to.

    `tip` (roadmap P15) is a tip-availability dict or None, and is None for
    every unattributed byline. A tip button carries the recipient's on-chain
    WALLET, which is a permanent public identifier — so offering one on work
    the author chose not to sign would deanonymise them with a payment control.
    Anonymous work is therefore never tippable.
    """
    mode = getattr(story, "byline_mode", BYLINE_ANONYMOUS)

    if mode == BYLINE_PEN_NAME and pen_name is not None:
        return {
            "mode": BYLINE_PEN_NAME,
            "name": pen_name.display_name,
            "href_slug": pen_name.slug,
            "attributed": True,
            # NEVER tippable, even though a pen name is "attributed".
            #
            # A pen name exists to separate published work from the slip behind
            # it. A wallet does the opposite: it is one stable address, so two
            # pen names offering the same one would be provably the same
            # person, and a pen name plus its owner's profile likewise. The
            # separation a pen name buys cannot survive a shared payment
            # identifier, so this surface does not get a button at all.
            "tip": None,
        }

    if mode == BYLINE_SLIP and contributor is not None:
        slug = contributor.get("slug")
        return {
            "mode": BYLINE_SLIP,
            "name": contributor.get("name"),
            "href_slug": slug,
            "attributed": True,
            # Resolved from the PUBLIC slug this byline already shows, never
            # from story.slip_id — see tip_for_slug.
            "tip": _byline_tip(slug),
        }

    # Anonymous, or an attributed mode whose author record could not be loaded.
    # Falling back to "no byline" rather than to a partial one is deliberate: a
    # missing pen name must never degrade into showing the slip behind it.
    return {"mode": BYLINE_ANONYMOUS, "name": None, "href_slug": None,
            "attributed": False, "tip": None}


def _byline_tip(slug):
    """Tip availability for a slip-bylined author, by PUBLIC slug. Never raises.

    The slug lookup happens HERE rather than inside services/pooled_tips.py,
    which touches no ORM session at all and has a test pinning that. Keeping it
    that way costs one function and buys a module that provably cannot read or
    write anything about a payment.

    The slug is the one this byline already displays — `story.slip_id` is never
    consulted, which is the whole reason this module exists.
    """
    if not slug:
        return None
    try:
        from model.Profile import Profile
        from services.pooled_tips import tip_for

        profile = db.session.query(Profile).filter(Profile.slug == slug).one_or_none()
        if profile is None:
            return None
        return tip_for(profile.slip)
    except Exception:
        # A news page must not 500 because a payment feature could not answer.
        return None


def author_stories(slip_id=None, pen_name_id=None, limit=50):
    """Stories listed on an author page.

    ANONYMOUS work is excluded by the byline_mode filter, not by an `if` in a
    template. That is the difference between an invariant and a habit.

    A slip's page shows only SLIP-bylined work: a contributor's pen-named
    stories belong to the pen name's page, and listing them together on the slip
    page would join the two identities for anyone reading.
    """
    query = visible_to_readers()

    if pen_name_id is not None:
        query = query.filter(NewsStory.pen_name_id == pen_name_id,
                             NewsStory.byline_mode == BYLINE_PEN_NAME)
    elif slip_id is not None:
        query = query.filter(NewsStory.slip_id == slip_id,
                             NewsStory.byline_mode == BYLINE_SLIP)
    else:
        return []

    rows = query.order_by(NewsStory.published_at.desc()).limit(limit).all()
    return displayable_only(rows)


def author_story_count(slip_id=None, pen_name_id=None):
    """How many stories an author page LISTS. Never a total including hidden work.

    See the module docstring: a count that included unlisted stories is an
    oracle for the existence and rough timing of anonymous work.
    """
    return len(author_stories(slip_id=slip_id, pen_name_id=pen_name_id,
                              limit=10000))


def may_reveal_author(story):
    """False for anything a reader must not be able to attribute.

    A helper for templates and serialisers that want one boolean. It is
    intentionally conservative: anything that is not explicitly an attributed
    mode is treated as anonymous.
    """
    return getattr(story, "byline_mode", None) in ATTRIBUTED_MODES


def serialise_for_feed(story, pen_name=None, contributor=None):
    """One story as a feed or API entry, with authorship already decided.

    Feeds are where this leaks. Building the entry here rather than in each
    serialiser means the RSS writer, the JSON API and the sitemap cannot each
    invent their own author field -- and none of them ever sees `slip_id`.
    """
    byline = public_byline(story, pen_name=pen_name, contributor=contributor)
    entry = {
        "slug": story.slug,
        "headline": story.headline,
        "standfirst": story.standfirst,
        "published_at": story.published_at,
        "updated_at": story.updated_at,
        "retracted": story.is_retracted,
    }
    # The author key is present ONLY when there is an author to name. A key set
    # to None still tells a consumer that a byline field exists and is empty,
    # which for a small set of stories is enough to distinguish anonymous work
    # from a serialiser that simply does not carry authors.
    if byline["attributed"]:
        entry["author"] = byline["name"]
        entry["author_slug"] = byline["href_slug"]
    return entry


def contributor_source(slip_ids):
    """{slip_id: {"name", "slug"}} — the ONE place a slip becomes a byline.

    WHY THIS EXISTS. `public_byline()` receives an already-decided
    {"name","slug"} dict and copies it, so the module that is supposed to be the
    single decider was downstream of the decision. Three surfaces each built
    that dict their own way, and they disagreed: two fell back to `Slip.name`
    and one refused to. `Slip.name` is the LOGIN NAME -- profile-view already
    declines to print it -- so the front page published account names as bylines
    while the article page for the same story showed none.

    Resolving it here gives `Slip.name` exactly one place it can be rejected,
    and that place is a function nobody has to remember to call, because every
    surface needs what it returns.

    THE ORDER, AND WHY EACH STEP.
      1. `Contributor.byline_name` -- what the writer chose to be called.
      2. the PUBLIC profile slug -- already public by construction, and the
         thing the byline would link to anyway.
      3. nothing. A contributor with neither gets NO byline rather than a
         leaked one. That reads as unattributed, which is wrong-but-harmless;
         the alternative is wrong-and-irreversible.

    A private profile still yields a name if the contributor set one; it simply
    has no author page to point at, so `slug` is None and the byline does not
    link.

    Raises on a database failure rather than returning {}. A caller that caches
    (the front-page rail does) must be able to tell "nobody has a byline" from
    "the lookup failed", or it will persist a degraded answer for a full TTL.
    """
    ids = {int(slip_id) for slip_id in slip_ids if slip_id}
    if not ids:
        return {}

    from model.Contributor import Contributor
    from model.Profile import Profile

    # Slip.name is deliberately not queried. See the docstring.
    byline_names = dict(db.session.query(Contributor.slip_id,
                                         Contributor.byline_name)
                        .filter(Contributor.slip_id.in_(ids)).all())
    slugs = dict(db.session.query(Profile.slip_id, Profile.slug)
                 .filter(Profile.slip_id.in_(ids),
                         Profile.is_public.is_(True)).all())

    resolved = {}
    for slip_id in ids:
        slug = slugs.get(slip_id)
        name = (byline_names.get(slip_id) or "").strip() or slug
        if not name:
            continue
        resolved[slip_id] = {"name": name, "slug": slug}
    return resolved
