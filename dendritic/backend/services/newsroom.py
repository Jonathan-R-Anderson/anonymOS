"""The editorial state machine: the only module that moves a story.

THE LEGAL GRAPH IS DATA, NOT CONTROL FLOW
------------------------------------------
`ALLOWED_TRANSITIONS` is a table, so "can a retracted story be archived?" is a
question somebody can answer by reading one dict, and a test can assert on it
directly. The alternative -- a status check inside each function -- spreads the
graph across nine bodies where no reader can see its shape and no test can
assert its absence. The rule this module exists to hold is that display is
mechanical rather than remembered, and a graph nobody can see is remembered.

EVERY CALL WRITES A ROW, INCLUDING THE ONES THAT CHANGE NOTHING
---------------------------------------------------------------
A reviewer opening a story and deciding to leave it alone is a decision. An
approval clicked twice is a fact about the day. A refused transition is somebody
reaching for a control they were not allowed to use, which is the single most
interesting row in the table after a story goes wrong. So:

    a legal transition    -> mutate, record, commit
    a no-op self-repeat   -> record, commit, return unchanged
    an illegal transition -> record, commit, then raise NewsroomError

That is `model.EditorialAction`'s own discipline, applied here rather than
restated. A trail that records only successful mutations cannot reconstruct what
happened, which is the only thing it is for.

ONE COMMIT PER CALL
-------------------
The mutation and its audit row land in the same transaction. A crash between
them would leave either an action nobody recorded or a record of something that
never happened, and both are worse than the failure they came from. Callers do
not commit; they call one function per decision.

ANONYMITY IS FROM READERS, NOT FROM THIS MODULE
------------------------------------------------
`slip_id` is on every story in every byline mode and nothing here removes it.
Editors must know who filed. What a reader may learn is decided in exactly one
other place, `services/bylines.py`, and no function here is a substitute for it.

TWO DELIBERATE DEPARTURES FROM THE ROADMAP'S ARROW DIAGRAM
-----------------------------------------------------------
The roadmap draws `(CORRECTED | RETRACTED) -> ARCHIVED`. It is not implemented,
because `ARCHIVED` is not in `NewsStory.PUBLIC_STATUSES`: archiving a story that
has been public turns a URL already sitting in other people's citations into a
404, which is the exact outcome the retraction rule exists to forbid. So:

  * `archive_story()` is reachable only from the unpublished statuses. Archiving
    is for the draft nobody finished, not for the story somebody regrets.
  * `RETRACTED` is terminal. A retraction is the way to take published work out
    of circulation, and it leaves the URL serving a notice forever.

If a published story must genuinely disappear -- a court order, say -- that is a
deletion somebody performs deliberately and can be seen to have performed. It is
not a status transition with a friendly name.
"""

import datetime
import re
import uuid

from sqlalchemy.exc import SQLAlchemyError

from shared import app, db

from model import EditorialAction as editorial
from model import StoryRevision as revisions
from model.Contributor import Contributor, TIERS, TIER_READER
from model.NewsStory import (
    BYLINE_ANONYMOUS, BYLINE_MODES, BYLINE_PEN_NAME, BYLINE_SLIP, NewsStory,
    PUBLIC_STATUSES, STATUS_APPROVED, STATUS_ARCHIVED,
    STATUS_CHANGES_REQUESTED, STATUS_CORRECTED, STATUS_DRAFT,
    STATUS_IN_REVIEW, STATUS_PUBLISHED, STATUS_RETRACTED, STATUS_SUBMITTED,
)
from model.PenName import PenName
from model.Slip import slip_is_editor


class NewsroomError(Exception):
    """A refusal, phrased so it can be shown to whoever attempted it.

    Every message raised from this module is written for a contributor or an
    editor reading it on a form -- no status codes, no column names, no "which
    of these two secrets is missing". A caller may render `str(exc)` directly,
    which is the point: an error that has to be translated at every call site
    eventually gets translated wrongly, or leaked verbatim.
    """


# -- the graph --------------------------------------------------------------
#
# from-status -> statuses it may legally become. A status listed as its own
# target is a REAL repeat (a second round of requested changes, a second
# correction, a re-approval after an edit), not a no-op; anything else repeated
# is a no-op and is recorded as one. See `_begin`.

ALLOWED_TRANSITIONS = {
    STATUS_DRAFT: (STATUS_SUBMITTED, STATUS_APPROVED, STATUS_ARCHIVED),
    STATUS_SUBMITTED: (STATUS_IN_REVIEW, STATUS_CHANGES_REQUESTED,
                       STATUS_APPROVED, STATUS_ARCHIVED),
    STATUS_IN_REVIEW: (STATUS_CHANGES_REQUESTED, STATUS_APPROVED,
                       STATUS_ARCHIVED),
    STATUS_CHANGES_REQUESTED: (STATUS_SUBMITTED, STATUS_CHANGES_REQUESTED,
                               STATUS_APPROVED, STATUS_ARCHIVED),
    STATUS_APPROVED: (STATUS_APPROVED, STATUS_PUBLISHED,
                      STATUS_CHANGES_REQUESTED, STATUS_ARCHIVED),
    # Published work leaves display only through a correction or a retraction,
    # and neither of those is a disappearance. See the module docstring.
    STATUS_PUBLISHED: (STATUS_CORRECTED, STATUS_RETRACTED),
    STATUS_CORRECTED: (STATUS_CORRECTED, STATUS_RETRACTED),
    STATUS_RETRACTED: (),
    STATUS_ARCHIVED: (),
}

# Not one of model.EditorialAction's constants, because an edit is not a
# transition -- it changes bytes, not status. It is recorded anyway: an edit is
# what silently removes an approved story from display, and "who changed it and
# when" is unanswerable afterwards if only status changes were written down.
#
# The row names the FIELDS that changed and never their contents. A full draft
# history is a record of a reporter's thinking -- who they suspected before they
# had it, what they cut after a call from a lawyer -- and `model.StoryRevision`
# already refuses to keep one. This must not become one by the back door.
ACTION_EDITED = "edited"

# Story slugs are their own namespace (`/news/<year>/<month>/<slug>`), so this
# is deliberately NOT `PenName.normalise_slug`: that one caps at 64 characters
# because it shares the profile namespace, and reusing it here would silently
# truncate every headline to a third of the column.
_SLUG_PATTERN = re.compile(r"[^a-z0-9]+")
MAX_SLUG = 140          # NewsStory.slug is String(160); the rest is suffix room
SLUG_FALLBACK = "story"

# Column widths, enforced here so an over-long field is a sentence the author
# reads rather than a database error the view has to translate.
MAX_HEADLINE = 300
MAX_SECTION = 64


def _now():
    return datetime.datetime.utcnow()


def _text(value):
    return (value or "").strip()


def _commit():
    """One commit, and a database failure that reaches the user as English."""
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("newsroom: transaction failed")
        raise NewsroomError("That could not be saved. Please try again.")


def _refuse(story_id, action, actor, previous, target, message, detail=None):
    """Record the attempt, then raise.

    The audit write is best-effort and the refusal is not: if the trail cannot
    be written the user must still be told no. A refusal that turned into a
    server error because logging it failed would be a control that works less
    reliably than the thing it guards.
    """
    payload = {"refused": message, "attempted": target}
    payload.update(detail or {})
    try:
        editorial.record(story_id, action, actor, previous_status=previous,
                         new_status=None, detail=payload)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("newsroom: could not record a refused transition")
    raise NewsroomError(message)


def _begin(story, target, action, actor, detail=None):
    """Check the graph. Returns (previous_status, is_noop).

    On an illegal transition this raises. On a repeat that the graph does not
    list as meaningful it records the no-op, commits, and tells the caller to
    stop -- so a caller never has to remember that pressing publish twice must
    not write a second revision and count a second story.
    """
    previous = story.status
    allowed = ALLOWED_TRANSITIONS.get(previous, ())

    if target in allowed:
        return previous, False

    if target == previous:
        editorial.record(story.id, action, actor, previous_status=previous,
                         new_status=previous,
                         detail=dict(detail or {}, noop=True))
        _commit()
        return previous, True

    _refuse(story.id, action, actor, previous, target,
            "A story that is %s cannot become %s."
            % (_readable(previous), _readable(target)), detail)


def _readable(status):
    return (status or "unknown").replace("_", " ").lower()


def _finish(story, target, action, actor, previous, detail=None):
    """Apply the status and land it with its audit row in one transaction."""
    story.status = target
    story.updated_at = _now()
    editorial.record(story.id, action, actor, previous_status=previous,
                     new_status=target, detail=detail)
    db.session.add(story)
    _commit()
    return story


# -- people -----------------------------------------------------------------


def _slip_id(slip):
    """A slip row or a bare id, because background passes only have the id."""
    if slip is None:
        return None
    return getattr(slip, "id", slip)


def contributor_for(slip, create=False):
    """The newsroom's record for a slip, or None.

    `create=True` makes one at READER, which is the tier that buys nothing: a
    row exists so there is somewhere to record a suspension or a promotion, not
    because having one is a permission. Creating it commits, so the caller gets
    a row with an id it can hang an audit entry on.
    """
    slip_id = _slip_id(slip)
    if slip_id is None:
        return None

    existing = (db.session.query(Contributor)
                .filter(Contributor.slip_id == slip_id)
                .first())
    if existing is not None or not create:
        return existing

    contributor = Contributor()
    contributor.slip_id = slip_id
    contributor.tier = TIER_READER
    contributor.bio = ""
    contributor.published_count = 0
    contributor.suspended = False
    contributor.created_at = _now()
    contributor.updated_at = _now()
    db.session.add(contributor)
    _commit()
    return contributor


def may_edit(story, slip):
    """Whether this slip may change these words.

    The author, up until the moment the story is public -- after that the only
    way to change it is a correction, which says what changed. Editors may edit
    at any point, because somebody has to be able to fix a libel at 3am.
    """
    if story is None or slip is None:
        return False
    if slip_is_editor(slip):
        return True
    if story.slip_id != _slip_id(slip):
        return False
    return story.status not in PUBLIC_STATUSES and story.status != STATUS_ARCHIVED


def may_publish_without_review(slip):
    """TRUSTED and above, plus editors. Suspension beats both.

    Note what this does NOT do: it never publishes anything by itself and
    nothing consults it automatically. It answers "should this person see a
    publish button", and `publish_story` still requires an approval bound to the
    exact bytes. There is no auto-publish path anywhere in this module.
    """
    if slip is None:
        return False
    contributor = contributor_for(slip)
    if contributor is not None and contributor.suspended:
        return False
    if slip_is_editor(slip):
        return True
    return contributor is not None and contributor.may_publish_directly


def _require_may_submit(story, action, actor):
    """Suspension stops work reaching the queue, and says so plainly."""
    contributor = contributor_for(story.slip_id)
    if contributor is not None and not contributor.may_submit:
        _refuse(story.id, action, actor, story.status, story.status,
                "Your contributor account is suspended, so stories cannot be "
                "filed or approved until an editor lifts it.")
    return contributor


# -- pen names --------------------------------------------------------------


def _pen_name(pen_name_id):
    """One lookup, in one place, so the byline check can be tested."""
    if not pen_name_id:
        return None
    try:
        return (db.session.query(PenName)
                .filter(PenName.id == pen_name_id)
                .first())
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("newsroom: pen name lookup failed")
        raise NewsroomError(
            "That pen name could not be checked just now. Please try again.")


def _validate_byline(story, byline_mode, pen_name_id):
    """Refuse a byline the story is not entitled to. Returns the pen name row.

    Checked on save AND again on approval, because a pen name can be retired
    between the two and a retired name must not acquire new work.

    "Not found" and "not yours" deliberately produce the SAME message. Different
    wording would turn this form into an oracle for which pen-name ids exist,
    and the whole point of a pen name is that its existence is not a fact about
    any particular person.
    """
    if byline_mode not in BYLINE_MODES:
        raise NewsroomError("Choose a byline: your name, a pen name, or none.")

    if byline_mode != BYLINE_PEN_NAME:
        return None

    pen_name = _pen_name(pen_name_id)
    if pen_name is None or pen_name.owner_slip_id != story.slip_id:
        raise NewsroomError("That pen name is not one of yours.")
    if pen_name.retired:
        raise NewsroomError(
            "That pen name has been retired and cannot carry new stories.")
    if not pen_name.approved:
        raise NewsroomError(
            "That pen name is still waiting for an editor to approve it.")
    return pen_name


# -- slugs ------------------------------------------------------------------


def _normalise_slug(headline):
    slug = _SLUG_PATTERN.sub("-", _text(headline).lower()).strip("-")
    return slug[:MAX_SLUG].strip("-") or SLUG_FALLBACK


def _taken_slugs(base):
    """Every slug already starting with this base, in ONE query.

    One query rather than a probe per candidate: the loop below would otherwise
    issue N round trips at publication time to answer a question one LIKE
    answers. `base` is [a-z0-9-] by construction, so it carries no LIKE
    metacharacters and needs no escaping -- which is only true because
    `_normalise_slug` runs first, and is why nothing here takes raw input.
    """
    try:
        rows = (db.session.query(NewsStory.slug)
                .filter(NewsStory.slug.like(base + "%"))
                .all())
        return {row[0] for row in rows}
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("newsroom: slug lookup failed")
        return set()


def slug_for(headline):
    """A url-safe slug that no story already holds.

    Deduped globally rather than per month. Story URLs carry a year and month,
    so a per-month check would be sufficient, but a globally unique slug means a
    lookup by slug alone can never return two rows -- which is the query every
    future feature will reach for first.
    """
    base = _normalise_slug(headline)
    taken = _taken_slugs(base)
    if base not in taken:
        return base
    for suffix in range(2, 200):
        candidate = "%s-%d" % (base, suffix)
        if candidate not in taken:
            return candidate
    # Two hundred stories with one headline means something is wrong upstream;
    # a random suffix still produces a working URL rather than a collision.
    return "%s-%s" % (base, uuid.uuid4().hex[:8])


# -- drafting ---------------------------------------------------------------


def draft_story(slip, actor):
    """A new, empty DRAFT owned by this slip.

    Empty on purpose, and this is the highest-consequence blank in the feature:
    there is no path that pre-fills a draft from a report or a tip. A pre-fill
    is how a complainant's legal name arrives in a published article through a
    field nobody remembered was populated. A reviewer who wants to write about a
    submission opens this, and types.
    """
    slip_id = _slip_id(slip)
    if slip_id is None:
        raise NewsroomError("Sign in with a slip before writing a story.")

    contributor = contributor_for(slip, create=True)
    if contributor is not None and not contributor.may_submit:
        raise NewsroomError(
            "Your contributor account is suspended, so new stories cannot be "
            "started until an editor lifts it.")

    story = NewsStory()
    story.slip_id = slip_id
    # No slug until publication: an unpublished story has no URL, and allocating
    # one early would put a headline nobody has approved into a namespace other
    # stories are deduped against.
    story.slug = ""
    story.headline = ""
    story.standfirst = ""
    story.body = ""
    story.byline_mode = BYLINE_SLIP
    story.pen_name_id = None
    story.status = STATUS_DRAFT
    story.section = None
    story.tags = ""
    story.score = 0
    story.vote_count = 0
    story.created_at = _now()
    story.updated_at = _now()
    # Set explicitly rather than left for the ORM to default on insert. Every
    # field the workflow later READS is initialised here, so a story object that
    # has not yet been round-tripped through the database behaves the same as
    # one that has -- `correct_story` appends to `correction_notice`, and
    # appending to whatever an un-flushed attribute happens to hold is how a
    # notice gets lost.
    story.published_at = None
    story.correction_notice = None
    story.corrected_at = None
    story.retraction_notice = None
    story.retracted_at = None
    db.session.add(story)
    # Flushed rather than committed, so the audit row can carry the story id and
    # both land together.
    db.session.flush()

    editorial.record(story.id, editorial.ACTION_CREATED, actor,
                     new_status=STATUS_DRAFT, detail={"slip_id": slip_id})
    _commit()
    return story


def save_draft(story, headline, standfirst, body, section=None, tags=None,
               byline_mode=None, pen_name_id=None, actor=None):
    """Write the whole document. The form posts all of it, so all of it is set.

    `section` and `tags` are written from the arguments every time rather than
    merged: an edit form holds the entire state of a story, and "None means
    leave it alone" is how a field silently survives a user clearing it.
    `byline_mode` is the exception -- None keeps the current mode -- and
    `pen_name_id` is read only when the resulting mode is PEN_NAME, so there is
    no ambiguity between "no pen name" and "unchanged".

    Two refusals live here rather than in the view:

    * A story that has been published changes through `correct_story`, never
      through this. `is_displayable` would already drop a silently edited story
      from every surface, but silently vanishing is not what a reader is owed:
      they are owed a dated note saying what changed.
    * A published SLIP byline cannot become ANONYMOUS. The name has already been
      in feeds, caches, archives and scrapers -- and this site scrapes other
      sites for a living, so it of all places knows that published is published.
      Offering the button would be offering a guarantee nobody can keep.

    `invalidate_approval()` is called only when the words an editor actually
    read have changed. A retag is not a re-write, and re-queuing a story because
    somebody fixed a category teaches editors to click approve without reading.
    """
    if story.status in PUBLIC_STATUSES:
        raise NewsroomError(
            "This story is published. Publish a correction instead, so readers "
            "can see what changed.")
    if story.status == STATUS_ARCHIVED:
        raise NewsroomError("This story is archived and cannot be edited.")

    mode = byline_mode or story.byline_mode or BYLINE_SLIP
    if (mode == BYLINE_ANONYMOUS and story.byline_mode == BYLINE_SLIP
            and story.published_at is not None):
        raise NewsroomError(
            "A byline that has already been published cannot be withdrawn. "
            "Anonymity has to be chosen before a story runs, not after.")

    # Prose is refused when it is too long; a taxonomy field is trimmed. Nobody
    # loses a sentence they wrote to a silent truncation, and nobody is stopped
    # by a section name that was always going to be a dropdown. Checked before
    # the pen-name lookup, so a bad form costs no database round trip.
    if len(_text(headline)) > MAX_HEADLINE:
        raise NewsroomError(
            "Headlines are capped at %d characters." % MAX_HEADLINE)

    pen_name = _validate_byline(story, mode, pen_name_id)

    before = story.current_hash
    changed = []
    for field, value in (("headline", _text(headline)),
                         ("standfirst", _text(standfirst)),
                         ("body", body or "")):
        if getattr(story, field) != value:
            changed.append(field)
        setattr(story, field, value)

    story.section = _text(section)[:MAX_SECTION] or None
    story.tags = _normalise_tags(tags)

    # The BYLINE is part of what an editor approves, even though it is not part
    # of the content hash.
    #
    # An editor's review screen shows the byline precisely so that the byline
    # they approved is the byline that ships. Without this check the author
    # could approve-then-switch: the hash covers headline, standfirst and body
    # only, so changing the mode alone left `approved_hash` intact, the status
    # at APPROVED, and the story publishable under a byline no editor ever saw.
    #
    # The damaging direction is not vanity. An editor approves an allegation ON
    # CONDITION that it carries a name; the author flips it to ANONYMOUS before
    # publication and the accountability the approval was conditioned on is
    # gone. Swapping between two approved pen names is the same defect.
    #
    # Not folded into content_hash() because that hash is also what a
    # correction re-binds and what StoryRevision records -- it is the identity
    # of the TEXT. This is a separate fact about the same artifact, so it gets
    # its own comparison.
    byline_changed = (story.byline_mode != mode
                      or story.pen_name_id != (pen_name.id if pen_name else None))

    story.byline_mode = mode
    # Cleared whenever the mode is not PEN_NAME, so a story cannot keep a stale
    # pointer at a pseudonym it no longer publishes under.
    story.pen_name_id = pen_name.id if pen_name is not None else None
    story.updated_at = _now()

    content_changed = story.current_hash != before
    if content_changed or byline_changed:
        story.invalidate_approval()

    db.session.add(story)
    editorial.record(story.id, ACTION_EDITED, actor,
                     previous_status=story.status, new_status=story.status,
                     detail={"fields": changed,
                             "byline_mode": mode,
                             "approval_invalidated": content_changed})
    _commit()
    return story


def _normalise_tags(tags):
    """A comma string, from either a list or a comma string.

    Order is preserved and duplicates dropped. Sorting would be tidier to
    compare, but the first tag is the one that shows on a card, and reordering
    what somebody typed is a change to the story they did not ask for.
    """
    if tags is None:
        return ""
    parts = tags.split(",") if isinstance(tags, str) else list(tags)
    seen = []
    for part in parts:
        tag = _text(part)
        if tag and tag not in seen:
            seen.append(tag)
    return ",".join(seen)


# -- the queue --------------------------------------------------------------


def _require_filed_content(story, action, actor):
    if not _text(story.headline) or not _text(story.body):
        _refuse(story.id, action, actor, story.status, story.status,
                "A story needs a headline and a body before it can go further.")


def submit_story(story, actor):
    """DRAFT or CHANGES_REQUESTED -> SUBMITTED. The author hands it over."""
    _require_may_submit(story, editorial.ACTION_SUBMITTED, actor)
    _require_filed_content(story, editorial.ACTION_SUBMITTED, actor)
    # Re-checked here: a pen name can be retired between drafting and filing.
    _validate_byline(story, story.byline_mode, story.pen_name_id)

    previous, noop = _begin(story, STATUS_SUBMITTED, editorial.ACTION_SUBMITTED,
                            actor)
    if noop:
        return story
    return _finish(story, STATUS_SUBMITTED, editorial.ACTION_SUBMITTED, actor,
                   previous)


def start_review(story, actor):
    """SUBMITTED -> IN_REVIEW. Recorded because it names who has it.

    Two editors opening the same story is wasted work; one editor holding a
    story for a week without saying so is worse. Both are only visible if
    picking a story up is written down.
    """
    previous, noop = _begin(story, STATUS_IN_REVIEW,
                            editorial.ACTION_REVIEW_STARTED, actor)
    if noop:
        return story
    return _finish(story, STATUS_IN_REVIEW, editorial.ACTION_REVIEW_STARTED,
                   actor, previous)


def request_changes(story, actor, note):
    """-> CHANGES_REQUESTED, with a note the author can act on.

    The note is required. "Changes requested" with nothing attached is a story
    stopped by somebody who left no way to unstop it, and the author's only move
    is to guess. Requesting changes on an APPROVED story also drops the approval:
    an editor who wants something changed is an editor who no longer stands
    behind the version they signed.
    """
    note = _text(note)
    if not note:
        raise NewsroomError(
            "Say what needs to change. An author cannot act on an empty note.")

    previous, noop = _begin(story, STATUS_CHANGES_REQUESTED,
                            editorial.ACTION_CHANGES_REQUESTED, actor,
                            detail={"note": note})
    if noop:
        return story

    if previous == STATUS_APPROVED:
        story.invalidate_approval()

    return _finish(story, STATUS_CHANGES_REQUESTED,
                   editorial.ACTION_CHANGES_REQUESTED, actor, previous,
                   detail={"note": note})


def approve_story(story, actor):
    """-> APPROVED, with the approval BOUND to the current bytes.

    `NewsStory.approve()` records the content hash of what was read. That is the
    whole mechanism: an approval is a one-time key to publish the exact text an
    editor approved, and a story whose hash no longer matches is not displayable
    by construction. Nothing here has to remember to re-queue an edited story,
    because nothing here is what keeps it out.
    """
    _require_may_submit(story, editorial.ACTION_APPROVED, actor)
    _require_filed_content(story, editorial.ACTION_APPROVED, actor)
    _validate_byline(story, story.byline_mode, story.pen_name_id)

    previous, noop = _begin(story, STATUS_APPROVED, editorial.ACTION_APPROVED,
                            actor)
    if noop:
        return story

    story.approve(actor, now=_now())
    return _finish(story, STATUS_APPROVED, editorial.ACTION_APPROVED, actor,
                   previous, detail={"content_hash": story.approved_hash})


def publish_story(story, actor):
    """APPROVED -> PUBLISHED. Allocates the URL and keeps the version.

    The approval is re-checked against the live bytes rather than trusted: the
    status says an editor approved something, and only the hash says they
    approved THIS. A story edited between approval and publication is refused
    here, not published and then quietly hidden by the display gate.

    The slug is allocated once and never recomputed. A corrected headline does
    not move the story, because the URL is already in other people's citations
    and a link that stops working is indistinguishable from a story somebody
    made go away.

    Timing correlation is NOT solved here and is not pretended to be: an
    anonymous story published ninety seconds after the same author's bylined one
    is weakly linked, and `published_at` is exact.
    """
    previous, noop = _begin(story, STATUS_PUBLISHED,
                            editorial.ACTION_PUBLISHED, actor)
    if noop:
        return story

    # Fetched BEFORE anything is mutated: creating a missing contributor row
    # commits, and a commit in the middle of this function would land a half
    # published story -- a revision and a published_at with the status still
    # APPROVED -- if the write that follows failed.
    contributor = contributor_for(story.slip_id, create=True)

    if not story.approval_matches_content:
        _refuse(story.id, editorial.ACTION_PUBLISHED, actor, previous,
                STATUS_PUBLISHED,
                "This story changed after it was approved, so the approval no "
                "longer covers it. It needs approving again.")

    # Consent, if this story cites a submission. Checked at PUBLISH and not only
    # at approval: consent is revocable up to publication, and a story approved
    # last week can be one whose complainant has since withdrawn.
    from services import report_consent

    permitted, reason = report_consent.check_story(story)
    if not permitted:
        _refuse(story.id, editorial.ACTION_PUBLISHED, actor, previous,
                STATUS_PUBLISHED, reason)

    # The pen name is re-validated HERE and not only at save time, because the
    # two are separated by a review that can take days. A pen name approved when
    # the story was filed may have been retired since -- by its owner, or by an
    # editor who withdrew it -- and publishing under a retired pseudonym hands
    # a byline back to a name somebody deliberately gave up. Retirement is
    # permanent precisely so a released name is never reused; shipping one after
    # the fact would undo that.
    if story.byline_mode == BYLINE_PEN_NAME:
        pen_name = _pen_name(story.pen_name_id)
        if pen_name is None or not pen_name.usable:
            _refuse(story.id, editorial.ACTION_PUBLISHED, actor, previous,
                    STATUS_PUBLISHED,
                    "The pen name this story was filed under is no longer "
                    "available, so it cannot publish under that byline. Choose "
                    "another byline and have it approved again.")

    if not story.slug:
        story.slug = slug_for(story.headline)
    if story.published_at is None:
        story.published_at = _now()

    revision = revisions.record_revision(story, editor=actor)

    if contributor is not None:
        contributor.published_count = int(contributor.published_count or 0) + 1
        db.session.add(contributor)

    story_row = _finish(story, STATUS_PUBLISHED, editorial.ACTION_PUBLISHED,
                        actor, previous,
                        detail={"slug": story.slug,
                                "version": revision.version,
                                "content_hash": story.approved_hash})
    _invalidate_front_page()
    return story_row


def correct_story(story, actor, notice, headline=None, standfirst=None,
                  body=None):
    """PUBLISHED -> CORRECTED. Additive, dated, and never silent.

    The new text is passed in here rather than saved first, because `save_draft`
    refuses to touch published work: if this did not accept the corrected words,
    the only way to fix a published error would be to write to the row from
    outside the service, which is precisely the silent edit this whole path
    exists to prevent. Omitted fields are unchanged.

    Three things happen together, and the point is that none can happen without
    the others:

      * the previous wording is kept as a `StoryRevision`, so "an earlier version
        of this story said the council voted unanimously" is checkable rather
        than something readers must take on trust at the moment the publication
        has just admitted being wrong;
      * a dated notice is APPENDED to the story -- appended, because a second
        correction that overwrote the first would erase the record while
        appearing to add to it. The date lives in the text as well as in
        `corrected_at`, since one column cannot date two notices;
      * the approval is re-bound to the corrected bytes, by the editor making the
        correction. A correction is a new editorial decision, so it is signed.
    """
    notice = _text(notice)
    if not notice:
        raise NewsroomError(
            "A correction has to say what changed. Write the notice readers "
            "will see.")

    previous, noop = _begin(story, STATUS_CORRECTED,
                            editorial.ACTION_CORRECTED, actor,
                            detail={"notice": notice})
    if noop:
        return story

    if headline is not None:
        story.headline = _text(headline)
    if standfirst is not None:
        story.standfirst = _text(standfirst)
    if body is not None:
        story.body = body

    now = _now()
    dated = "%s: %s" % (now.strftime("%Y-%m-%d"), notice)
    existing = _text(story.correction_notice)
    story.correction_notice = (existing + "\n\n" + dated) if existing else dated
    story.corrected_at = now

    revision = revisions.record_revision(story, editor=actor, note=dated)
    story.approve(actor, now=now)        # re-binds the hash; status set below

    story_row = _finish(story, STATUS_CORRECTED, editorial.ACTION_CORRECTED,
                        actor, previous,
                        detail={"notice": notice, "version": revision.version,
                                "content_hash": story.approved_hash})
    _invalidate_front_page()
    return story_row


def retract_story(story, actor, notice):
    """-> RETRACTED. The URL keeps serving, with a notice instead of the story.

    Never a 404. The link is already in other people's citations, and a story
    that vanishes reads as one somebody made go away -- which is worse for the
    publication than the retraction it was trying to be discreet about.

    RETRACTED is inside `PUBLIC_STATUSES` for that reason, and the approval is
    re-bound here so `is_displayable` cannot turn false on the way: a story whose
    hash had drifted before retraction would 404 exactly when the notice matters
    most. The editor retracting signs for the bytes that will be served.
    """
    notice = _text(notice)
    if not notice:
        raise NewsroomError(
            "A retraction has to say why. Write the notice readers will see.")

    previous, noop = _begin(story, STATUS_RETRACTED,
                            editorial.ACTION_RETRACTED, actor,
                            detail={"notice": notice})
    if noop:
        return story

    now = _now()
    story.retraction_notice = notice
    story.retracted_at = now
    story.approve(actor, now=now)        # keeps the URL displayable; see above

    story_row = _finish(story, STATUS_RETRACTED, editorial.ACTION_RETRACTED,
                        actor, previous, detail={"notice": notice})
    _invalidate_front_page()
    return story_row


def archive_story(story, actor):
    """-> ARCHIVED. Unpublished work only.

    Reachable from the drafting statuses and no others. ARCHIVED is not a public
    status, so archiving a story that has been public would 404 a cited URL --
    see the module docstring on why that is refused rather than allowed with a
    warning.
    """
    previous, noop = _begin(story, STATUS_ARCHIVED, editorial.ACTION_ARCHIVED,
                            actor)
    if noop:
        return story
    return _finish(story, STATUS_ARCHIVED, editorial.ACTION_ARCHIVED, actor,
                   previous)


# -- people, again ----------------------------------------------------------


def promote(contributor, tier, actor):
    """Move somebody between newsroom tiers. Recorded even when nothing moves.

    Deliberately does NOT set `Slip.is_editor`, even for TIER_EDITOR. The tier
    is the newsroom's record of what somebody does; `is_editor` is a site
    appointment made by an admin in the admin panel. One person may hold both,
    but they are different grants made by different people, and a service that
    quietly handed out the second one while recording the first would make the
    appointment chain unauditable.
    """
    if tier not in TIERS:
        raise NewsroomError("That is not a contributor tier.")

    previous = contributor.tier
    detail = {"slip_id": contributor.slip_id, "tier": tier,
              "previous_tier": previous}
    if previous == tier:
        detail["noop"] = True
    else:
        contributor.tier = tier
        contributor.updated_at = _now()
        db.session.add(contributor)

    # story_id is None: this is about a person, not a story.
    editorial.record(None, editorial.ACTION_TIER_CHANGED, actor,
                     previous_status=previous, new_status=tier, detail=detail)
    _commit()
    return contributor


def suspend(contributor, actor, reason):
    """Stop somebody publishing without deleting them or their work.

    The reason is required, because a suspension nobody wrote a reason for
    cannot be reviewed, appealed or lifted by a second editor who was not there.
    """
    reason = _text(reason)
    if not reason:
        raise NewsroomError(
            "Say why. A suspension without a reason cannot be reviewed or "
            "appealed.")

    contributor.suspended = True
    contributor.suspended_reason = reason[:500]
    contributor.updated_at = _now()
    db.session.add(contributor)
    editorial.record(None, editorial.ACTION_SUSPENDED, actor,
                     detail={"slip_id": contributor.slip_id, "suspended": True,
                             "reason": contributor.suspended_reason})
    _commit()
    return contributor


def unsuspend(contributor, actor):
    """Lift a suspension. The reason is cleared; the trail keeps it."""
    contributor.suspended = False
    contributor.suspended_reason = None
    contributor.updated_at = _now()
    db.session.add(contributor)
    editorial.record(None, editorial.ACTION_SUSPENDED, actor,
                     detail={"slip_id": contributor.slip_id,
                             "suspended": False})
    _commit()
    return contributor


def approve_pen_name(pen_name, actor):
    """Let a pseudonym carry a byline.

    Approved rather than self-serve, because unmoderated somebody registers a
    real journalist's name, or "Syndichan Editorial", and every story filed
    under it inherits credibility it was never granted.

    The audit detail names the SLUG and never `owner_slip_id`. The row already
    exists in `pen_name` for anyone with database access; copying the one join
    this feature exists to keep private into a second, append-only, longer-lived
    table that an admin screen renders is how it ends up in a screenshot.
    """
    if pen_name.retired:
        raise NewsroomError(
            "That pen name has been retired and cannot be approved.")

    pen_name.approved = True
    pen_name.approved_by = actor
    db.session.add(pen_name)
    editorial.record(None, editorial.ACTION_PEN_NAME_APPROVED, actor,
                     detail={"pen_name_id": pen_name.id, "slug": pen_name.slug})
    _commit()
    return pen_name


# -- the front page ---------------------------------------------------------


def _invalidate_front_page():
    """Publication changes the front page. A VOTE never does.

    `/` is a cached render, and this codebase has already been bitten by making
    that route do work -- an inline news sync once made the whole site look down.
    So publication clears the cache and nothing else here does: votes arrive
    constantly, and invalidating per vote turns a cached front page into an
    uncached one at a rate set by whoever is clicking. See
    `services/story_votes.py`, which deliberately has no equivalent of this.

    Imported late and failing quietly: `blueprints.admin` imports half the
    application, so importing it at module scope would make a background pass
    depend on the web tier. A stale front page for one recompute cycle is a much
    smaller harm than a publication that fails because a cache was unreachable.

    The import guard catches Exception rather than ImportError, because pulling
    in that graph outside a configured application does not fail politely -- it
    fails somewhere down inside SQLAlchemy, several modules away. A story must
    still publish when it does.

    TWO CACHES, CLEARED IN TWO STEPS, AND THE ORDER MATTERS. The rendered front
    page is one cache; the news rail that page is built from is another, with
    its own key and its own TTL. Clearing the render while leaving the rail
    would rebuild the page from the stale rail and cache THAT, which is worse
    than not clearing at all -- it converts a 120-second delay into a fresh
    20-second render of the old rail. So the rail goes first and each clear is
    guarded separately: the rail lives in `services/`, the render behind a
    blueprint, and a background pass that cannot reach the web tier must still
    get the rail cleared.
    """
    try:
        from services import news_rail
    except Exception:
        app.logger.debug("newsroom: no news rail to invalidate")
    else:
        try:
            news_rail.invalidate()
        except Exception:
            app.logger.exception("newsroom: news rail cache not invalidated")

    try:
        from blueprints.admin import invalidate_front_page_cache
    except Exception:
        app.logger.debug("newsroom: no web tier to invalidate the front page")
        return
    try:
        invalidate_front_page_cache()
    except Exception:
        app.logger.exception("newsroom: front page cache not invalidated")
