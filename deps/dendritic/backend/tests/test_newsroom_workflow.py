"""The editorial state machine, and what an approval is a key to.

Two properties carry this file, and neither of them shows up in a happy-path
test.

**The legal graph is data, so the tests walk it.** `ALLOWED_TRANSITIONS` is a
table, so every pair it lists is driven here and must succeed, and every pair it
does not list is driven here and must be refused. A test that hand-listed the
interesting transitions would agree with the code on the day it was written and
would then quietly stop covering the status somebody adds next year -- which is
the failure the table exists to prevent, reintroduced in the tests.

**Display is mechanical, not remembered.** An approval binds to the bytes an
editor read. So the tests that matter mutate `story.body` DIRECTLY -- no service
call, no `invalidate_approval()`, nothing that could have remembered to re-queue
the story -- and then read the gate. Going through `save_draft` would test the
belt (`invalidate_approval`, which any future caller can forget) instead of the
braces (`is_displayable`, which holds when they do).

Everything here runs against a fake session rather than a database. The subject
is a decision graph, and a graph is worth testing at the speed that lets it be
walked exhaustively.
"""

import datetime
import os
import sys
import types
import unittest
from unittest import mock
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _install_stubs():
    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        db = MagicMock()
        db.Model = object
        shared.db = db
        shared.app = MagicMock()
        shared.app.config = {}
        sys.modules["shared"] = shared


_install_stubs()

from model import Contributor as contrib          # noqa: E402
from model import EditorialAction as editorial    # noqa: E402
from model import NewsStory as ns                 # noqa: E402
from model import PenName as pen_names            # noqa: E402
from model import StoryRevision as revisions      # noqa: E402
from services import newsroom                     # noqa: E402


AUTHOR_SLIP = 101
OTHER_SLIP = 202
EDITOR = "0xEDITOR"
AUTHOR = "0xAUTHOR"

HEADLINE = "Council votes to close the library"
STANDFIRST = "Papers released under FOI show the decision was taken in March."
BODY = "The council voted on Tuesday to close the branch library.\n"


# -- the fake session -------------------------------------------------------


class _Session(object):
    """Enough SQLAlchemy shape to drive the state machine without a database.

    Deliberately not a MagicMock. `first()` on a MagicMock is a truthy Mock, so
    "this slip has no contributor row yet" -- the branch that decides whether a
    suspension exists -- would be untestable, and a pen name that does not exist
    would be indistinguishable from one that does, which is the exact confusion
    `_validate_byline` is written to refuse.

    Filters are ignored, because they carry nothing to filter on: `db.Model` is
    `object` here, so `Contributor.slip_id == 101` is a MagicMock comparison
    that has already collapsed to a bool by the time `filter()` sees it. Each
    test therefore holds at most one contributor and one pen name, which is all
    a single story's workflow ever looks up.
    """

    def __init__(self):
        self.rows = []              # everything add()ed, in order
        self.commits = 0
        self.rollbacks = 0
        self.contributor = None
        self.pen_name = None
        self.taken_slugs = []
        self._next_id = 1000

    # -- session API used by the module under test ------------------------

    def add(self, row):
        if not any(existing is row for existing in self.rows):
            self.rows.append(row)
        # contributor_for(create=True) adds a row and expects the next lookup
        # to find it; without this, every call would create another one.
        if isinstance(row, contrib.Contributor):
            self.contributor = row

    def flush(self):
        """Hand out primary keys.

        `draft_story` flushes so its audit row can carry the story id. Without
        real ids the trail would record the class-level MagicMock that stands in
        for every column, and "which story is this row about" would be
        unanswerable in exactly the tests written to answer it.
        """
        for row in self.rows:
            if row.__dict__.get("id") is None:
                row.id = self.next_id()

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def query(self, *entities):
        return _Query(self, entities[0] if entities else None)

    # -- helpers for the tests --------------------------------------------

    def next_id(self):
        self._next_id += 1
        return self._next_id

    def trail(self):
        return [row for row in self.rows
                if isinstance(row, editorial.EditorialAction)]

    def revisions(self):
        return [row for row in self.rows
                if isinstance(row, revisions.StoryRevision)]


class _Query(object):
    """One query object for the three shapes services/newsroom.py issues."""

    def __init__(self, session, entity):
        self._session = session
        self._entity = entity

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        if self._entity is contrib.Contributor:
            return self._session.contributor
        if self._entity is pen_names.PenName:
            return self._session.pen_name
        return None

    def all(self):
        # The only column query in the module: NewsStory.slug LIKE 'base%'.
        return [(slug,) for slug in self._session.taken_slugs]

    def scalar(self):
        # The only aggregate: max(StoryRevision.version) for one story.
        versions = [row.version for row in self._session.revisions()]
        return max(versions) if versions else None


class _Slip(object):
    """A slip row's shape.

    Not `model.Slip`: `slip_is_editor` reaches for Flask's request context, and
    every decision in this module is taken outside one (a background pass, a
    test). Building the shape rather than the model keeps that honest.
    """

    def __init__(self, slip_id=AUTHOR_SLIP, is_editor=False):
        self.id = slip_id
        self.is_editor = is_editor
        self.is_admin = False


# -- drivers ----------------------------------------------------------------
#
# One function per target status, so the table walk below can drive any edge in
# ALLOWED_TRANSITIONS without knowing which function owns it.

NOTE = "Call the council press office before this runs."
CORRECTION = "The vote was 5-4, not unanimous."
RETRACTION = "The document the story relied on was not authentic."


def _drive(target, story, actor=EDITOR):
    if target == ns.STATUS_SUBMITTED:
        return newsroom.submit_story(story, actor)
    if target == ns.STATUS_IN_REVIEW:
        return newsroom.start_review(story, actor)
    if target == ns.STATUS_CHANGES_REQUESTED:
        return newsroom.request_changes(story, actor, NOTE)
    if target == ns.STATUS_APPROVED:
        return newsroom.approve_story(story, actor)
    if target == ns.STATUS_PUBLISHED:
        return newsroom.publish_story(story, actor)
    if target == ns.STATUS_CORRECTED:
        return newsroom.correct_story(story, actor, CORRECTION)
    if target == ns.STATUS_RETRACTED:
        return newsroom.retract_story(story, actor, RETRACTION)
    if target == ns.STATUS_ARCHIVED:
        return newsroom.archive_story(story, actor)
    raise AssertionError("no driver for target status %r" % (target,))


DRIVEABLE = (ns.STATUS_SUBMITTED, ns.STATUS_IN_REVIEW,
             ns.STATUS_CHANGES_REQUESTED, ns.STATUS_APPROVED,
             ns.STATUS_PUBLISHED, ns.STATUS_CORRECTED, ns.STATUS_RETRACTED,
             ns.STATUS_ARCHIVED)


class _NewsroomCase(unittest.TestCase):

    def setUp(self):
        self.session = _Session()
        self.now = datetime.datetime(2026, 3, 4, 9, 30)

        self._patches = [
            mock.patch.object(newsroom.db, "session", self.session),
            mock.patch.object(newsroom, "_now", lambda: self.now),
            mock.patch.object(newsroom, "_invalidate_front_page", MagicMock()),
        ]
        for patch in self._patches:
            patch.start()
        self.front_page = newsroom._invalidate_front_page

    def tearDown(self):
        for patch in reversed(self._patches):
            patch.stop()

    def _reset(self):
        """A clean session mid-test, for the walks over the whole graph.

        Each edge has to be driven against a story nobody has touched and a
        trail nobody has written to, or "did this transition record a row" would
        be answered by the previous edge's row.
        """
        self.session = _Session()
        newsroom.db.session = self.session      # inside the patch, not past it
        self.front_page.reset_mock()

    # -- builders ---------------------------------------------------------

    def _story(self, status=ns.STATUS_DRAFT, slip_id=AUTHOR_SLIP,
               headline=HEADLINE, body=BODY, slug=""):
        story = ns.NewsStory()
        story.id = self.session.next_id()
        story.slug = slug
        story.headline = headline
        story.standfirst = STANDFIRST
        story.body = body
        story.slip_id = slip_id
        story.byline_mode = ns.BYLINE_SLIP
        story.pen_name_id = None
        # Explicit, because the `shared` stub makes an UNSET column read back as
        # the Column object rather than None -- so a story that cites no
        # submission would look like one that does, and the consent gate would
        # refuse every publish in this file.
        story.source_report_id = None
        story.section = None
        story.tags = ""
        story.score = 0
        story.vote_count = 0
        story.created_at = self.now
        story.updated_at = self.now
        story.published_at = None
        story.correction_notice = None
        story.corrected_at = None
        story.retraction_notice = None
        story.retracted_at = None
        story.approved_hash = None
        story.approved_by = None
        story.approved_at = None
        story.status = status

        # Anything at APPROVED or beyond got there through an approval, so the
        # fixture carries one. Set after the status, because approve() moves it.
        if status in (ns.STATUS_APPROVED,) + ns.PUBLIC_STATUSES:
            story.approve(EDITOR, now=self.now)
            story.status = status
        if status in ns.PUBLIC_STATUSES:
            story.published_at = self.now
            story.slug = slug or "council-votes-to-close-the-library"
        return story

    def _contributor(self, tier=contrib.TIER_READER, suspended=False,
                     published_count=0, slip_id=AUTHOR_SLIP):
        person = contrib.Contributor()
        person.id = self.session.next_id()
        person.slip_id = slip_id
        person.tier = tier
        person.bio = ""
        person.published_count = published_count
        person.suspended = suspended
        person.suspended_reason = "Filed a story that named a minor." if suspended else None
        person.created_at = self.now
        person.updated_at = self.now
        self.session.contributor = person
        return person

    def _pen_name(self, owner=AUTHOR_SLIP, approved=True, retired=False):
        row = pen_names.PenName()
        row.id = self.session.next_id()
        row.slug = "housing-desk"
        row.display_name = "The Housing Desk"
        row.owner_slip_id = owner
        row.bio = ""
        row.approved = approved
        row.approved_by = EDITOR if approved else None
        row.retired = retired
        row.retired_at = self.now if retired else None
        row.created_at = self.now
        self.session.pen_name = row
        return row

    # -- trail readers ----------------------------------------------------

    def _trail(self):
        return self.session.trail()

    def _last(self):
        trail = self._trail()
        self.assertTrue(trail, "nothing was written to the editorial trail")
        return trail[-1]


# -- the graph --------------------------------------------------------------


class LegalTransitionTest(_NewsroomCase):
    """Every edge the table lists, driven for real."""

    def test_every_target_status_has_a_driver(self):
        """A status added to the table without a way to reach it would make the
        walk below silently skip it, which is worse than no walk."""
        targets = set()
        for allowed in newsroom.ALLOWED_TRANSITIONS.values():
            targets.update(allowed)
        self.assertEqual(targets - set(DRIVEABLE), set())

    def test_every_edge_in_the_table_is_walkable(self):
        edges = [(source, target)
                 for source, targets in newsroom.ALLOWED_TRANSITIONS.items()
                 for target in targets]
        self.assertEqual(len(edges), 22, "the graph changed shape; read it")

        for source, target in edges:
            with self.subTest(source=source, target=target):
                self._reset()
                story = self._story(status=source)
                _drive(target, story)
                self.assertEqual(story.status, target)

    def test_every_edge_writes_a_row_naming_both_ends(self):
        for source, targets in newsroom.ALLOWED_TRANSITIONS.items():
            for target in targets:
                with self.subTest(source=source, target=target):
                    self._reset()
                    story = self._story(status=source)
                    _drive(target, story)

                    written = self._trail()
                    self.assertTrue(written, "no trail row for this edge")
                    row = written[-1]
                    self.assertEqual(row.previous_status, source)
                    self.assertEqual(row.new_status, target)
                    self.assertEqual(row.actor, EDITOR)
                    self.assertNotIn("noop", row.detail)

    def test_a_legal_transition_commits_once(self):
        story = self._story(status=ns.STATUS_SUBMITTED)
        self.session.commits = 0
        newsroom.start_review(story, EDITOR)
        self.assertEqual(self.session.commits, 1,
                         "the status change and its audit row must land "
                         "together, in one transaction")


class IllegalTransitionTest(_NewsroomCase):
    """Every edge the table does NOT list, driven for real."""

    def test_every_edge_outside_the_table_is_refused(self):
        for source in newsroom.ALLOWED_TRANSITIONS:
            allowed = newsroom.ALLOWED_TRANSITIONS[source]
            for target in DRIVEABLE:
                if target == source or target in allowed:
                    continue        # a repeat is a no-op, tested separately
                with self.subTest(source=source, target=target):
                    self._reset()
                    story = self._story(status=source)
                    with self.assertRaises(newsroom.NewsroomError):
                        _drive(target, story)
                    self.assertEqual(story.status, source)

    def test_a_refusal_is_written_down(self):
        """Somebody reaching for a control they were not allowed to use is the
        most interesting row in the table after a story goes wrong."""
        story = self._story(status=ns.STATUS_DRAFT)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.publish_story(story, EDITOR)

        row = self._last()
        self.assertEqual(row.action, editorial.ACTION_PUBLISHED)
        self.assertEqual(row.previous_status, ns.STATUS_DRAFT)
        self.assertIsNone(row.new_status)
        self.assertEqual(row.detail["attempted"], ns.STATUS_PUBLISHED)
        self.assertIn("refused", row.detail)

    def test_a_draft_cannot_be_published_without_an_approval(self):
        story = self._story(status=ns.STATUS_DRAFT)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.publish_story(story, EDITOR)
        self.assertIsNone(story.published_at)
        self.assertEqual(story.slug, "")

    def test_a_retracted_story_is_terminal(self):
        """Not archived, not corrected, not re-published: a retraction is the
        end of the road and the URL keeps serving the notice."""
        self.assertEqual(newsroom.ALLOWED_TRANSITIONS[ns.STATUS_RETRACTED], ())
        for target in (ns.STATUS_CORRECTED, ns.STATUS_ARCHIVED,
                       ns.STATUS_PUBLISHED, ns.STATUS_APPROVED):
            story = self._story(status=ns.STATUS_RETRACTED)
            with self.assertRaises(newsroom.NewsroomError):
                _drive(target, story)
            self.assertEqual(story.status, ns.STATUS_RETRACTED)

    def test_published_work_cannot_be_archived(self):
        """ARCHIVED is not a public status, so archiving public work would 404 a
        URL that is already in other people's citations."""
        self.assertNotIn(ns.STATUS_ARCHIVED, ns.PUBLIC_STATUSES)
        for status in ns.PUBLIC_STATUSES:
            story = self._story(status=status)
            with self.assertRaises(newsroom.NewsroomError):
                newsroom.archive_story(story, EDITOR)
            self.assertEqual(story.status, status)

    def test_an_archived_draft_cannot_be_resubmitted(self):
        story = self._story(status=ns.STATUS_ARCHIVED)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.submit_story(story, AUTHOR)
        self.assertEqual(story.status, ns.STATUS_ARCHIVED)

    def test_a_story_with_no_body_cannot_be_filed_or_approved(self):
        for driver in (newsroom.submit_story, newsroom.approve_story):
            story = self._story(status=ns.STATUS_DRAFT, body="")
            with self.assertRaises(newsroom.NewsroomError):
                driver(story, EDITOR)
            self.assertEqual(story.status, ns.STATUS_DRAFT)
            self.assertIsNone(story.approved_hash)


class NoOpTransitionTest(_NewsroomCase):
    """A repeat that the graph does not list is recorded, not refused."""

    def _noop_statuses(self):
        return [status for status in DRIVEABLE
                if status not in newsroom.ALLOWED_TRANSITIONS.get(status, ())]

    def test_repeating_a_status_changes_nothing_and_raises_nothing(self):
        for status in self._noop_statuses():
            with self.subTest(status=status):
                self._reset()
                story = self._story(status=status)
                _drive(status, story)
                self.assertEqual(story.status, status)

    def test_a_no_op_is_still_written_down(self):
        """An approval clicked twice is a fact about the day. A trail that
        records only successful mutations cannot reconstruct what happened."""
        for status in self._noop_statuses():
            with self.subTest(status=status):
                self._reset()
                story = self._story(status=status)
                _drive(status, story)

                written = self._trail()
                self.assertEqual(len(written), 1)
                self.assertTrue(written[0].detail.get("noop"))
                self.assertEqual(written[0].previous_status, status)
                self.assertEqual(written[0].new_status, status)

    def test_publishing_twice_does_not_count_the_story_twice(self):
        person = self._contributor(published_count=0)
        story = self._story(status=ns.STATUS_APPROVED)

        newsroom.publish_story(story, EDITOR)
        self.assertEqual(person.published_count, 1)
        first_published_at = story.published_at
        first_slug = story.slug

        newsroom.publish_story(story, EDITOR)
        self.assertEqual(person.published_count, 1)
        self.assertEqual(story.published_at, first_published_at)
        self.assertEqual(story.slug, first_slug)
        self.assertEqual(len(self.session.revisions()), 1,
                         "a second publish must not write a second version")

    def test_re_approving_an_approved_story_is_a_real_repeat_not_a_no_op(self):
        """APPROVED lists itself, because re-approving after an edit is the
        whole point of the mechanism."""
        self.assertIn(ns.STATUS_APPROVED,
                      newsroom.ALLOWED_TRANSITIONS[ns.STATUS_APPROVED])
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.approve_story(story, EDITOR)
        self.assertNotIn("noop", self._last().detail)


# -- the approval ----------------------------------------------------------


class ApprovalBindingTest(_NewsroomCase):
    """An approval is a one-time key to publish the exact text that was read."""

    def test_approving_binds_the_hash_of_what_was_read(self):
        story = self._story(status=ns.STATUS_SUBMITTED)
        newsroom.approve_story(story, EDITOR)
        self.assertEqual(story.approved_hash, story.current_hash)
        self.assertEqual(story.approved_by, EDITOR)
        self.assertEqual(story.approved_at, self.now)
        self.assertEqual(self._last().detail["content_hash"],
                         story.approved_hash)

    def test_editing_after_approval_closes_the_gate_with_nobody_watching(self):
        """The mechanism, not the bookkeeping.

        The body is mutated directly -- no service call, no
        `invalidate_approval()` -- and the approval is left exactly as the
        editor granted it. The story still stops being displayable, which is the
        property that survives a future caller who forgets to re-queue.
        """
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        self.assertTrue(story.is_displayable)

        granted_hash, granted_by = story.approved_hash, story.approved_by
        story.body = BODY + "\nA paragraph the editor never read."

        self.assertFalse(story.is_displayable)
        self.assertEqual(story.status, ns.STATUS_PUBLISHED)
        # Nobody cleared the approval. The gate closed on its own.
        self.assertEqual(story.approved_hash, granted_hash)
        self.assertEqual(story.approved_by, granted_by)
        self.assertIsNotNone(story.approved_hash)

    def test_editing_the_headline_closes_the_gate_too(self):
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        story.headline = "Council accused of hiding library closure"
        self.assertFalse(story.is_displayable)

    def test_publishing_a_story_edited_after_approval_is_refused(self):
        """Refused at the gate, not published and then quietly hidden. The
        author is told it needs approving again; a silent 404 tells them
        nothing."""
        story = self._story(status=ns.STATUS_APPROVED)
        story.body = BODY + "\nAdded after the editor signed it off."

        with self.assertRaises(newsroom.NewsroomError) as caught:
            newsroom.publish_story(story, EDITOR)

        self.assertIn("approv", str(caught.exception).lower())
        self.assertEqual(story.status, ns.STATUS_APPROVED)
        self.assertIsNone(story.published_at)
        self.assertIn("refused", self._last().detail)

    def test_a_refused_publish_does_not_count_the_story(self):
        person = self._contributor(published_count=4)
        story = self._story(status=ns.STATUS_APPROVED)
        story.body = BODY + "\nAdded after approval."
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.publish_story(story, EDITOR)
        self.assertEqual(person.published_count, 4)
        self.assertEqual(self.session.revisions(), [])

    def test_re_approving_after_an_edit_restores_display(self):
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.save_draft(story, HEADLINE, STANDFIRST,
                            BODY + "\nA second source confirmed it.",
                            actor=AUTHOR)
        self.assertIsNone(story.approved_hash)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.publish_story(story, EDITOR)

        newsroom.approve_story(story, EDITOR)
        newsroom.publish_story(story, EDITOR)

        self.assertEqual(story.status, ns.STATUS_PUBLISHED)
        self.assertTrue(story.is_displayable)

    def test_saving_new_words_invalidates_the_approval_and_says_so(self):
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.save_draft(story, "A sharper headline", STANDFIRST, BODY,
                            actor=AUTHOR)
        self.assertIsNone(story.approved_hash)
        self.assertIsNone(story.approved_by)

        row = self._last()
        self.assertEqual(row.action, newsroom.ACTION_EDITED)
        self.assertTrue(row.detail["approval_invalidated"])
        self.assertEqual(row.detail["fields"], ["headline"])

    def test_the_trail_names_the_fields_that_changed_never_their_contents(self):
        """A full draft history is a record of a reporter's thinking, and that
        is a file worth subpoenaing."""
        story = self._story(status=ns.STATUS_DRAFT)
        secret = "The source is the deputy chief executive."
        newsroom.save_draft(story, HEADLINE, STANDFIRST, secret, actor=AUTHOR)
        self.assertNotIn(secret, self._last().detail_json)

    def test_a_tag_change_does_not_invalidate_an_approval(self):
        """Nobody approves a story on the strength of its tags, and re-queueing
        a story because somebody fixed a category teaches editors to click
        approve without reading."""
        story = self._story(status=ns.STATUS_APPROVED)
        granted = story.approved_hash

        newsroom.save_draft(story, HEADLINE, STANDFIRST, BODY,
                            tags="housing,courts", actor=AUTHOR)

        self.assertEqual(story.approved_hash, granted)
        self.assertTrue(story.approval_matches_content)
        self.assertEqual(story.tag_list, ["housing", "courts"])
        self.assertFalse(self._last().detail["approval_invalidated"])

        # The approval is still a usable key, not merely a surviving string.
        newsroom.publish_story(story, EDITOR)
        self.assertTrue(story.is_displayable)

    def test_a_section_change_does_not_invalidate_an_approval_either(self):
        story = self._story(status=ns.STATUS_APPROVED)
        granted = story.approved_hash
        newsroom.save_draft(story, HEADLINE, STANDFIRST, BODY,
                            section="Local government", actor=AUTHOR)
        self.assertEqual(story.approved_hash, granted)
        self.assertEqual(story.section, "Local government")

    def test_requesting_changes_on_an_approved_story_drops_the_approval(self):
        """An editor who wants something changed is an editor who no longer
        stands behind the version they signed."""
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.request_changes(story, EDITOR, NOTE)
        self.assertEqual(story.status, ns.STATUS_CHANGES_REQUESTED)
        self.assertIsNone(story.approved_hash)
        self.assertEqual(self._last().detail["note"], NOTE)

    def test_requesting_changes_needs_a_note(self):
        story = self._story(status=ns.STATUS_SUBMITTED)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.request_changes(story, EDITOR, "   ")
        self.assertEqual(story.status, ns.STATUS_SUBMITTED)


# -- publication -----------------------------------------------------------


class PublicationTest(_NewsroomCase):

    def test_publishing_counts_the_story_for_whoever_filed_it(self):
        person = self._contributor(tier=contrib.TIER_TRUSTED,
                                   published_count=2)
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        self.assertEqual(person.published_count, 3)

    def test_publishing_counts_a_story_filed_anonymously(self):
        """The count is the newsroom's record of what somebody has done, and
        anonymity is from readers. A contributor whose anonymous work did not
        count would be penalised for needing cover."""
        person = self._contributor(published_count=0)
        story = self._story(status=ns.STATUS_APPROVED)
        story.byline_mode = ns.BYLINE_ANONYMOUS
        newsroom.publish_story(story, EDITOR)
        self.assertEqual(person.published_count, 1)
        self.assertEqual(story.slip_id, AUTHOR_SLIP)

    def test_publishing_creates_the_contributor_row_if_there_is_none(self):
        self.session.contributor = None
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        self.assertIsNotNone(self.session.contributor)
        self.assertEqual(self.session.contributor.published_count, 1)
        self.assertEqual(self.session.contributor.tier, contrib.TIER_READER)

    def test_publishing_keeps_the_published_version(self):
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        kept = self.session.revisions()
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].version, 1)
        self.assertEqual(kept[0].body, BODY)
        self.assertEqual(kept[0].content_hash, story.approved_hash)

    def test_publishing_allocates_a_slug_nothing_else_holds(self):
        self.session.taken_slugs = ["council-votes-to-close-the-library"]
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        self.assertEqual(story.slug, "council-votes-to-close-the-library-2")

    def test_reaching_readers_clears_the_front_page_cache(self):
        """Publication, a correction and a retraction all change what the front
        page should be showing. A vote never does -- see the module docstring on
        why invalidating per vote turns a cached front page into an uncached
        one at a rate set by whoever is clicking."""
        story = self._story(status=ns.STATUS_APPROVED)
        for act in (lambda: newsroom.publish_story(story, EDITOR),
                    lambda: newsroom.correct_story(story, EDITOR, CORRECTION),
                    lambda: newsroom.retract_story(story, EDITOR, RETRACTION)):
            self.front_page.reset_mock()
            act()
            self.assertEqual(self.front_page.call_count, 1)


# -- corrections and retractions -------------------------------------------


class CorrectionTest(_NewsroomCase):

    def _published(self):
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        return story

    def test_a_correction_is_additive_the_first_wording_survives(self):
        """"An earlier version of this story said the council voted
        unanimously" is unverifiable if the earlier version is gone."""
        story = self._published()
        newsroom.correct_story(story, EDITOR, CORRECTION,
                               body=BODY + "\nThe vote was 5-4.")

        kept = self.session.revisions()
        self.assertEqual([row.version for row in kept], [1, 2])
        self.assertEqual(kept[0].body, BODY)
        self.assertIn("5-4", kept[1].body)
        self.assertEqual(story.status, ns.STATUS_CORRECTED)

    def test_a_correction_sets_a_dated_notice(self):
        story = self._published()
        newsroom.correct_story(story, EDITOR, CORRECTION)
        self.assertEqual(story.corrected_at, self.now)
        self.assertIn(self.now.strftime("%Y-%m-%d"), story.correction_notice)
        self.assertIn(CORRECTION, story.correction_notice)

    def test_a_second_correction_appends_rather_than_overwrites(self):
        """A correction that erased the first would erase the record while
        appearing to add to it."""
        story = self._published()
        newsroom.correct_story(story, EDITOR, CORRECTION)
        self.now = self.now + datetime.timedelta(days=1)
        newsroom.correct_story(story, EDITOR, "The library is a branch, not the "
                                              "central library.")

        self.assertIn(CORRECTION, story.correction_notice)
        self.assertIn("branch", story.correction_notice)
        self.assertEqual(story.correction_notice.count("2026-03-0"), 2)
        self.assertEqual([row.version for row in self.session.revisions()],
                         [1, 2, 3])

    def test_a_correction_needs_a_notice(self):
        story = self._published()
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.correct_story(story, EDITOR, "")
        self.assertEqual(story.status, ns.STATUS_PUBLISHED)
        self.assertIsNone(story.correction_notice)

    def test_a_corrected_story_keeps_serving(self):
        story = self._published()
        newsroom.correct_story(story, EDITOR, CORRECTION,
                               headline="Council votes 5-4 to close library")
        self.assertTrue(story.is_displayable)
        self.assertEqual(story.approved_hash, story.current_hash)
        self.assertEqual(story.approved_by, EDITOR)

    def test_a_corrected_headline_does_not_move_the_url(self):
        """The link is already in other people's citations."""
        story = self._published()
        original = story.slug
        newsroom.correct_story(story, EDITOR, CORRECTION,
                               headline="An entirely different headline")
        self.assertEqual(story.slug, original)

    def test_correcting_restores_a_story_whose_words_had_drifted(self):
        """The path back for a story edited from outside the service: a dated
        notice, not a silent re-approval."""
        story = self._published()
        story.body = BODY + "\nSomething changed behind the service's back."
        self.assertFalse(story.is_displayable)

        newsroom.correct_story(story, EDITOR, CORRECTION)
        self.assertTrue(story.is_displayable)

    def test_published_words_cannot_be_changed_by_saving_over_them(self):
        """Silently vanishing is not what a reader is owed: they are owed a
        dated note saying what changed."""
        for status in ns.PUBLIC_STATUSES:
            story = self._story(status=status)
            with self.assertRaises(newsroom.NewsroomError):
                newsroom.save_draft(story, "A quietly different headline",
                                    STANDFIRST, BODY, actor=AUTHOR)
            self.assertEqual(story.headline, HEADLINE)


class RetractionTest(_NewsroomCase):

    def _published(self):
        story = self._story(status=ns.STATUS_APPROVED)
        newsroom.publish_story(story, EDITOR)
        return story

    def test_a_retracted_story_stays_displayable(self):
        """Never a 404. The URL keeps serving, with a notice instead of the
        story: a story that vanishes reads as one somebody made go away."""
        story = self._published()
        newsroom.retract_story(story, EDITOR, RETRACTION)

        self.assertEqual(story.status, ns.STATUS_RETRACTED)
        self.assertIn(ns.STATUS_RETRACTED, ns.PUBLIC_STATUSES)
        self.assertTrue(story.is_displayable)
        self.assertTrue(story.is_retracted)
        self.assertEqual(story.retraction_notice, RETRACTION)
        self.assertEqual(story.retracted_at, self.now)

    def test_retracting_a_drifted_story_still_serves_the_notice(self):
        """A story whose hash had drifted would 404 exactly when the notice
        matters most, so the retracting editor signs for the bytes served."""
        story = self._published()
        story.body = BODY + "\nEdited from outside the service."
        self.assertFalse(story.is_displayable)

        newsroom.retract_story(story, EDITOR, RETRACTION)
        self.assertTrue(story.is_displayable)
        self.assertEqual(story.approved_by, EDITOR)

    def test_a_retraction_needs_a_notice(self):
        story = self._published()
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.retract_story(story, EDITOR, "  ")
        self.assertEqual(story.status, ns.STATUS_PUBLISHED)
        self.assertIsNone(story.retraction_notice)

    def test_a_corrected_story_can_still_be_retracted(self):
        story = self._published()
        newsroom.correct_story(story, EDITOR, CORRECTION)
        newsroom.retract_story(story, EDITOR, RETRACTION)
        self.assertEqual(story.status, ns.STATUS_RETRACTED)
        self.assertTrue(story.is_displayable)
        self.assertIn(CORRECTION, story.correction_notice)


# -- pen names --------------------------------------------------------------


class PenNameBylineTest(_NewsroomCase):

    def _save_under_pen_name(self, story, pen_name_id=None):
        return newsroom.save_draft(
            story, HEADLINE, STANDFIRST, BODY,
            byline_mode=ns.BYLINE_PEN_NAME,
            pen_name_id=pen_name_id if pen_name_id is not None
            else self.session.pen_name.id,
            actor=AUTHOR)

    def test_an_owned_approved_pen_name_carries_the_byline(self):
        pen_name = self._pen_name()
        story = self._story()
        self._save_under_pen_name(story)
        self.assertEqual(story.byline_mode, ns.BYLINE_PEN_NAME)
        self.assertEqual(story.pen_name_id, pen_name.id)

    def test_somebody_elses_pen_name_is_refused(self):
        self._pen_name(owner=OTHER_SLIP)
        story = self._story()
        with self.assertRaises(newsroom.NewsroomError):
            self._save_under_pen_name(story)
        self.assertEqual(story.byline_mode, ns.BYLINE_SLIP)
        self.assertIsNone(story.pen_name_id)

    def test_an_unapproved_pen_name_is_refused(self):
        """Unmoderated, somebody registers a real journalist's name and every
        story filed under it inherits credibility it was never granted."""
        self._pen_name(approved=False)
        story = self._story()
        with self.assertRaises(newsroom.NewsroomError) as caught:
            self._save_under_pen_name(story)
        self.assertIn("approve", str(caught.exception).lower())

    def test_a_retired_pen_name_cannot_carry_new_work(self):
        self._pen_name(retired=True)
        story = self._story()
        with self.assertRaises(newsroom.NewsroomError) as caught:
            self._save_under_pen_name(story)
        self.assertIn("retired", str(caught.exception).lower())

    def test_a_missing_pen_name_reads_exactly_like_somebody_elses(self):
        """Different wording would turn the form into an oracle for which pen
        name ids exist, and the whole point of a pen name is that its existence
        is not a fact about any particular person."""
        self.session.pen_name = None
        with self.assertRaises(newsroom.NewsroomError) as missing:
            self._save_under_pen_name(self._story(), pen_name_id=999)

        self._pen_name(owner=OTHER_SLIP)
        with self.assertRaises(newsroom.NewsroomError) as theirs:
            self._save_under_pen_name(self._story())

        self.assertEqual(str(missing.exception), str(theirs.exception))

    def test_a_refused_byline_leaves_the_words_untouched(self):
        """The check runs before anything is written, so a rejected save is not
        a half-applied one."""
        self._pen_name(retired=True)
        story = self._story(headline="The headline as filed")
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.save_draft(story, "A new headline", "New standfirst",
                                "New body", byline_mode=ns.BYLINE_PEN_NAME,
                                pen_name_id=self.session.pen_name.id,
                                actor=AUTHOR)
        self.assertEqual(story.headline, "The headline as filed")
        self.assertEqual(story.body, BODY)

    def test_a_pen_name_retired_after_drafting_blocks_filing(self):
        """Re-checked on the way to the queue, because a pen name can be retired
        between drafting and filing and a retired name must not take new work."""
        self._pen_name()
        story = self._story()
        self._save_under_pen_name(story)

        self.session.pen_name.retired = True
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.submit_story(story, AUTHOR)
        self.assertEqual(story.status, ns.STATUS_DRAFT)

        with self.assertRaises(newsroom.NewsroomError):
            newsroom.approve_story(story, EDITOR)
        self.assertEqual(story.status, ns.STATUS_DRAFT)

    def test_choosing_no_byline_still_records_who_filed(self):
        """Anonymity is from READERS, not from the newsroom. Nothing in this
        module removes slip_id, in any mode."""
        story = self._story()
        newsroom.save_draft(story, HEADLINE, STANDFIRST, BODY,
                            byline_mode=ns.BYLINE_ANONYMOUS, actor=AUTHOR)
        self.assertEqual(story.byline_mode, ns.BYLINE_ANONYMOUS)
        self.assertEqual(story.slip_id, AUTHOR_SLIP)
        self.assertIsNone(story.pen_name_id)

    def test_a_byline_that_has_run_cannot_be_withdrawn(self):
        """The name has already been in feeds, caches, archives and scrapers,
        and offering the button would be offering a guarantee nobody can keep."""
        story = self._story(status=ns.STATUS_PUBLISHED)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.save_draft(story, HEADLINE, STANDFIRST, BODY,
                                byline_mode=ns.BYLINE_ANONYMOUS, actor=AUTHOR)
        self.assertEqual(story.byline_mode, ns.BYLINE_SLIP)

    def test_an_unknown_byline_mode_is_refused(self):
        story = self._story()
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.save_draft(story, HEADLINE, STANDFIRST, BODY,
                                byline_mode="SOMETHING_NEW", actor=AUTHOR)


# -- suspension -------------------------------------------------------------


class SuspensionTest(_NewsroomCase):
    """Suspension beats tier, everywhere it is consulted."""

    def test_suspension_beats_tier_for_publishing_rights(self):
        person = self._contributor(tier=contrib.TIER_EDITOR)
        slip = _Slip(AUTHOR_SLIP)
        self.assertTrue(newsroom.may_publish_without_review(slip))

        person.suspended = True
        self.assertFalse(newsroom.may_publish_without_review(slip),
                         "a rank granted last year must not outrank a "
                         "suspension imposed this morning")

    def test_suspension_beats_the_site_editor_grant_too(self):
        self._contributor(tier=contrib.TIER_READER, suspended=True)
        self.assertFalse(newsroom.may_publish_without_review(
            _Slip(AUTHOR_SLIP, is_editor=True)))

    def test_a_suspended_contributor_cannot_file(self):
        self._contributor(tier=contrib.TIER_TRUSTED, suspended=True)
        story = self._story(status=ns.STATUS_DRAFT)
        with self.assertRaises(newsroom.NewsroomError) as caught:
            newsroom.submit_story(story, AUTHOR)
        self.assertIn("suspended", str(caught.exception).lower())
        self.assertEqual(story.status, ns.STATUS_DRAFT)

    def test_a_suspended_contributors_story_cannot_be_approved(self):
        """The check is on whoever FILED it, not on the editor holding it: the
        point of a suspension is that the work stops moving."""
        self._contributor(tier=contrib.TIER_TRUSTED, suspended=True)
        story = self._story(status=ns.STATUS_SUBMITTED)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.approve_story(story, EDITOR)
        self.assertEqual(story.status, ns.STATUS_SUBMITTED)
        self.assertIsNone(story.approved_hash)

    def test_a_suspended_contributor_cannot_start_a_story(self):
        self._contributor(suspended=True)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.draft_story(_Slip(AUTHOR_SLIP), AUTHOR)

    def test_a_refused_filing_is_written_down(self):
        self._contributor(suspended=True)
        story = self._story(status=ns.STATUS_DRAFT)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.submit_story(story, AUTHOR)
        row = self._last()
        self.assertEqual(row.action, editorial.ACTION_SUBMITTED)
        self.assertIn("refused", row.detail)

    def test_lifting_a_suspension_lets_the_work_move_again(self):
        person = self._contributor(tier=contrib.TIER_TRUSTED)
        newsroom.suspend(person, EDITOR, "Filed a story that named a minor.")
        self.assertTrue(person.suspended)

        story = self._story(status=ns.STATUS_DRAFT)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.submit_story(story, AUTHOR)

        newsroom.unsuspend(person, EDITOR)
        newsroom.submit_story(story, AUTHOR)
        self.assertEqual(story.status, ns.STATUS_SUBMITTED)

    def test_a_suspension_needs_a_reason(self):
        """A suspension nobody wrote a reason for cannot be reviewed, appealed
        or lifted by a second editor who was not there."""
        person = self._contributor()
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.suspend(person, EDITOR, "   ")
        self.assertFalse(person.suspended)

    def test_lifting_clears_the_reason_but_the_trail_keeps_it(self):
        person = self._contributor()
        newsroom.suspend(person, EDITOR, "Filed a story that named a minor.")
        newsroom.unsuspend(person, EDITOR)
        self.assertIsNone(person.suspended_reason)
        reasons = [row.detail.get("reason") for row in self._trail()]
        self.assertIn("Filed a story that named a minor.", reasons)


# -- tiers ------------------------------------------------------------------


class TierChangeTest(_NewsroomCase):

    def test_a_promotion_is_recorded_with_both_ends(self):
        person = self._contributor(tier=contrib.TIER_READER)
        newsroom.promote(person, contrib.TIER_TRUSTED, EDITOR)
        self.assertEqual(person.tier, contrib.TIER_TRUSTED)

        row = self._last()
        self.assertEqual(row.action, editorial.ACTION_TIER_CHANGED)
        self.assertIsNone(row.story_id, "a tier change is about a person")
        self.assertEqual(row.previous_status, contrib.TIER_READER)
        self.assertEqual(row.new_status, contrib.TIER_TRUSTED)

    def test_promoting_to_the_tier_somebody_already_holds_is_recorded(self):
        person = self._contributor(tier=contrib.TIER_TRUSTED)
        newsroom.promote(person, contrib.TIER_TRUSTED, EDITOR)
        self.assertTrue(self._last().detail.get("noop"))

    def test_an_invented_tier_is_refused(self):
        person = self._contributor(tier=contrib.TIER_READER)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.promote(person, "PUBLISHER", EDITOR)
        self.assertEqual(person.tier, contrib.TIER_READER)

    def test_promotion_does_not_hand_out_the_site_editor_grant(self):
        """The tier is the newsroom's record of what somebody does; is_editor is
        a site appointment made by an admin. A service that quietly granted the
        second while recording the first would make the chain unauditable."""
        person = self._contributor(tier=contrib.TIER_READER)
        slip = _Slip(AUTHOR_SLIP)
        newsroom.promote(person, contrib.TIER_EDITOR, EDITOR)
        self.assertFalse(slip.is_editor)

        source = open(os.path.join(BACKEND, "services", "newsroom.py"),
                      encoding="utf-8").read()
        self.assertNotIn("is_editor =", source)


# -- pen name approval ------------------------------------------------------


class PenNameApprovalTest(_NewsroomCase):

    def test_approving_a_pen_name_lets_it_carry_a_byline(self):
        pen_name = self._pen_name(approved=False)
        newsroom.approve_pen_name(pen_name, EDITOR)
        self.assertTrue(pen_name.approved)
        self.assertEqual(pen_name.approved_by, EDITOR)
        self.assertTrue(pen_name.usable)

    def test_a_retired_pen_name_cannot_be_approved(self):
        pen_name = self._pen_name(approved=False, retired=True)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.approve_pen_name(pen_name, EDITOR)
        self.assertFalse(pen_name.approved)

    def test_the_trail_never_records_who_owns_a_pen_name(self):
        """Copying the one join this feature exists to keep private into a
        second, longer-lived table that an admin screen renders is how it ends
        up in a screenshot."""
        pen_name = self._pen_name(approved=False)
        newsroom.approve_pen_name(pen_name, EDITOR)

        row = self._last()
        self.assertEqual(row.detail["slug"], "housing-desk")
        self.assertNotIn("owner_slip_id", row.detail_json)
        self.assertNotIn(str(AUTHOR_SLIP), row.detail_json)


# -- drafting ---------------------------------------------------------------


class DraftTest(_NewsroomCase):

    def test_a_new_draft_is_empty(self):
        """No path pre-fills a draft from a report or a tip: a pre-fill is how a
        complainant's legal name arrives in a published article through a field
        nobody remembered was populated."""
        story = newsroom.draft_story(_Slip(AUTHOR_SLIP), AUTHOR)
        self.assertEqual(story.headline, "")
        self.assertEqual(story.standfirst, "")
        self.assertEqual(story.body, "")
        self.assertEqual(story.status, ns.STATUS_DRAFT)
        self.assertEqual(story.slip_id, AUTHOR_SLIP)

    def test_a_new_draft_has_no_url_yet(self):
        """Allocating a slug early would put a headline nobody has approved into
        the namespace other stories are deduped against."""
        story = newsroom.draft_story(_Slip(AUTHOR_SLIP), AUTHOR)
        self.assertEqual(story.slug, "")
        self.assertIsNone(story.published_at)

    def test_a_new_draft_is_recorded_against_the_story_it_created(self):
        story = newsroom.draft_story(_Slip(AUTHOR_SLIP), AUTHOR)
        row = self._last()
        self.assertEqual(row.action, editorial.ACTION_CREATED)
        self.assertEqual(row.story_id, story.id)
        self.assertEqual(row.new_status, ns.STATUS_DRAFT)

    def test_a_signed_out_visitor_cannot_start_a_story(self):
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.draft_story(None, AUTHOR)

    def test_an_archived_draft_cannot_be_edited(self):
        story = self._story(status=ns.STATUS_ARCHIVED)
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.save_draft(story, "A new headline", STANDFIRST, BODY,
                                actor=AUTHOR)
        self.assertEqual(story.headline, HEADLINE)

    def test_an_over_long_headline_is_refused_not_truncated(self):
        """Nobody loses a sentence they wrote to a silent truncation."""
        story = self._story()
        with self.assertRaises(newsroom.NewsroomError):
            newsroom.save_draft(story, "x" * (newsroom.MAX_HEADLINE + 1),
                                STANDFIRST, BODY, actor=AUTHOR)
        self.assertEqual(story.headline, HEADLINE)


if __name__ == "__main__":
    unittest.main()
