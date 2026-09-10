"""Bylines: what a reader may learn about who wrote something.

These are the leak tests. A byline system that works for the happy path and
leaks through the RSS feed has failed at the only thing it was for, so most of
this file is about surfaces OTHER than the story page, and about the count that
is an oracle.
"""

import datetime
import os
import sys
import types
import unittest
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _install_stubs():
    """Stub `shared` only long enough to import the module under test.

    RETURNS A RESTORE FUNCTION, and calling it is the point. A stub left in
    sys.modules replaces `shared` for every test module pytest imports
    afterwards -- and it imports them all during COLLECTION, before any test
    runs. This stub carries `db` and `app` and nothing else, so a later module
    doing `from shared import db, db_retry` gets an ImportError naming neither
    this file nor the stub, and a collection error is fatal to the whole run.
    """
    if "shared" in sys.modules:
        return lambda: None
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    shared.db = db
    shared.app = MagicMock()
    shared.app.config = {}
    sys.modules["shared"] = shared

    def restore():
        sys.modules.pop("shared", None)

    return restore


_restore_stubs = _install_stubs()

from model import NewsStory as ns  # noqa: E402
from model import Contributor as contrib  # noqa: E402
from services import bylines  # noqa: E402

_restore_stubs()



def _story(mode=ns.BYLINE_SLIP, status=ns.STATUS_PUBLISHED, headline="A headline"):
    story = ns.NewsStory()
    story.slug = "a-headline"
    story.headline = headline
    story.standfirst = "The standfirst."
    story.body = "The body of the story."
    story.slip_id = 4242
    story.byline_mode = mode
    story.pen_name_id = 7 if mode == ns.BYLINE_PEN_NAME else None
    story.status = status
    story.published_at = datetime.datetime(2026, 3, 4)
    story.updated_at = datetime.datetime(2026, 3, 4)
    story.correction_notice = None
    story.retraction_notice = None
    story.approve("0xEDITOR")
    story.status = status
    return story


class _PenName(object):
    slug = "housing-desk"
    display_name = "The Housing Desk"
    owner_slip_id = 4242


class PublicBylineTest(unittest.TestCase):

    def test_an_anonymous_story_names_nobody(self):
        byline = bylines.public_byline(_story(ns.BYLINE_ANONYMOUS))
        self.assertFalse(byline["attributed"])
        self.assertIsNone(byline["name"])
        self.assertIsNone(byline["href_slug"])

    def test_a_pen_name_story_shows_the_pen_name_not_the_slip(self):
        byline = bylines.public_byline(_story(ns.BYLINE_PEN_NAME),
                                       pen_name=_PenName())
        self.assertEqual(byline["name"], "The Housing Desk")
        self.assertEqual(byline["href_slug"], "housing-desk")
        self.assertNotIn("4242", str(byline))

    def test_a_missing_pen_name_degrades_to_anonymous_not_to_the_slip(self):
        """The dangerous failure: a lookup returns nothing and the code falls
        back to whatever it does have, which is the real identity."""
        byline = bylines.public_byline(_story(ns.BYLINE_PEN_NAME), pen_name=None)
        self.assertFalse(byline["attributed"])
        self.assertIsNone(byline["name"])

    def test_a_missing_contributor_degrades_to_anonymous(self):
        byline = bylines.public_byline(_story(ns.BYLINE_SLIP), contributor=None)
        self.assertFalse(byline["attributed"])

    def test_the_shape_is_stable_across_modes(self):
        """A template must not be able to reveal something by testing for a
        key's absence."""
        keys = None
        for mode in ns.BYLINE_MODES:
            byline = bylines.public_byline(_story(mode), pen_name=_PenName(),
                                           contributor={"name": "A", "slug": "a"})
            if keys is None:
                keys = set(byline)
            self.assertEqual(set(byline), keys)

    def test_may_reveal_author_is_conservative(self):
        self.assertFalse(bylines.may_reveal_author(_story(ns.BYLINE_ANONYMOUS)))
        self.assertTrue(bylines.may_reveal_author(_story(ns.BYLINE_SLIP)))
        # Anything unrecognised is treated as anonymous.
        junk = _story()
        junk.byline_mode = "SOMETHING_NEW"
        self.assertFalse(bylines.may_reveal_author(junk))


class FeedTest(unittest.TestCase):
    """Feeds are where this leaks."""

    def test_an_anonymous_entry_has_no_author_key_at_all(self):
        """Not even set to None: a present-but-empty author field distinguishes
        anonymous work from a serialiser that carries no authors."""
        entry = bylines.serialise_for_feed(_story(ns.BYLINE_ANONYMOUS))
        self.assertNotIn("author", entry)
        self.assertNotIn("author_slug", entry)

    def test_no_feed_entry_ever_carries_the_slip_id(self):
        for mode in ns.BYLINE_MODES:
            entry = bylines.serialise_for_feed(
                _story(mode), pen_name=_PenName(),
                contributor={"name": "Real Name", "slug": "real-name"})
            self.assertNotIn("slip_id", entry)
            self.assertNotIn("4242", str(entry))

    def test_a_pen_name_entry_carries_the_pen_name(self):
        entry = bylines.serialise_for_feed(_story(ns.BYLINE_PEN_NAME),
                                           pen_name=_PenName())
        self.assertEqual(entry["author"], "The Housing Desk")


class DisplayGateTest(unittest.TestCase):
    """An approval is a key to publish what was submitted."""

    def test_an_approved_unedited_story_is_displayable(self):
        self.assertTrue(_story().is_displayable)

    def test_editing_after_approval_removes_it_from_display(self):
        story = _story()
        self.assertTrue(story.is_displayable)
        story.body = "Something the editor never read."
        self.assertFalse(story.is_displayable)

    def test_editing_the_headline_also_invalidates(self):
        story = _story()
        story.headline = "A different, worse headline"
        self.assertFalse(story.is_displayable)

    def test_an_unapproved_story_is_never_displayable(self):
        story = _story()
        story.approved_hash = None
        self.assertFalse(story.is_displayable)

    def test_a_draft_is_not_displayable_even_when_approved(self):
        story = _story(status=ns.STATUS_DRAFT)
        self.assertFalse(story.is_displayable)

    def test_a_retracted_story_still_serves(self):
        """The URL keeps working with a notice: the link is already in other
        people's citations, and a story that vanishes reads as one somebody
        made go away."""
        self.assertTrue(_story(status=ns.STATUS_RETRACTED).is_displayable)

    def test_displayable_only_drops_drifted_stories_from_a_listing(self):
        good, drifted = _story(), _story()
        drifted.body = "edited after approval"
        self.assertEqual(bylines.displayable_only([good, drifted]), [good])

    def test_re_approving_after_an_edit_restores_display(self):
        story = _story()
        story.body = "a revised body"
        self.assertFalse(story.is_displayable)
        story.approve("0xEDITOR")
        story.status = ns.STATUS_PUBLISHED
        self.assertTrue(story.is_displayable)

    def test_a_tag_change_does_not_invalidate_an_approval(self):
        """Nobody approves a story on the strength of its tags."""
        story = _story()
        story.tags = "housing,courts"
        self.assertTrue(story.is_displayable)

    def test_the_hash_separates_fields(self):
        """headline='a', body='b' must not hash like headline='ab', body=''."""
        self.assertNotEqual(ns.content_hash("a", "", "b"),
                            ns.content_hash("ab", "", ""))


class NoCountOracleTest(unittest.TestCase):

    def test_there_is_no_function_returning_a_total_including_hidden_work(self):
        """A count including unlisted stories says 'this author filed something
        anonymous, around now', which is most of what an attacker needs."""
        source = open(os.path.join(BACKEND, "services", "bylines.py"),
                      encoding="utf-8").read()
        self.assertIn("author_story_count", source)
        for forbidden in ("total_story_count", "all_story_count",
                          "count_including_hidden"):
            self.assertNotIn(forbidden, source)

    def test_author_listings_filter_by_byline_mode_not_by_template_logic(self):
        source = open(os.path.join(BACKEND, "services", "bylines.py"),
                      encoding="utf-8").read()
        listing = source[source.index("def author_stories"):
                         source.index("def author_story_count")]
        self.assertIn("byline_mode == BYLINE_SLIP", listing)
        self.assertIn("byline_mode == BYLINE_PEN_NAME", listing)


class TierTest(unittest.TestCase):

    def test_tiers_are_ordered(self):
        self.assertTrue(contrib.tier_at_least(contrib.TIER_EDITOR,
                                              contrib.TIER_TRUSTED))
        self.assertFalse(contrib.tier_at_least(contrib.TIER_READER,
                                               contrib.TIER_TRUSTED))

    def test_only_trusted_and_above_publish_without_review(self):
        person = contrib.Contributor()
        person.suspended = False
        for tier in (contrib.TIER_READER, contrib.TIER_CONTRIBUTOR):
            person.tier = tier
            self.assertFalse(person.may_publish_directly)
        for tier in (contrib.TIER_TRUSTED, contrib.TIER_EDITOR):
            person.tier = tier
            self.assertTrue(person.may_publish_directly)

    def test_suspension_beats_tier(self):
        """An editor suspending somebody expects that to take effect now, not
        to be overridden by a rank granted last year."""
        person = contrib.Contributor()
        person.tier = contrib.TIER_EDITOR
        person.suspended = True
        self.assertFalse(person.may_publish_directly)
        self.assertFalse(person.may_submit)
        self.assertFalse(person.may_edit_others)

    def test_promotion_eligibility_is_advisory_only(self):
        person = contrib.Contributor()
        person.tier = contrib.TIER_READER
        person.suspended = False
        person.published_count = contrib.CONTRIBUTOR_THRESHOLD
        self.assertTrue(person.eligible_for_promotion)
        # Eligible is not promoted: the tier is unchanged until a human acts.
        self.assertEqual(person.tier, contrib.TIER_READER)


if __name__ == "__main__":
    unittest.main()
