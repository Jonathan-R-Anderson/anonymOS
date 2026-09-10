"""Permission to publish. The gate that must fail closed.

Consent to be helped is not consent to be named, and the failure mode being
guarded against is not malice -- it is a story reaching publication because a
field was populated and nobody asked.
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

from model import ReportConsent as rc  # noqa: E402
from services import report_consent as service  # noqa: E402


def _row(level, report_id="SR-AAAAAAAAAAAA", scope="what would be published"):
    row = rc.ReportConsent()
    row.report_id = report_id
    row.level = level
    row.scope = scope
    row.request_token = None
    row.created_at = datetime.datetime(2026, 3, 4)
    return row


class _Story(object):
    def __init__(self, source_report_id=None):
        self.source_report_id = source_report_id


class TheGateFailsClosedTest(unittest.TestCase):

    def test_a_story_citing_nothing_is_allowed(self):
        """Most of the newsroom never touches the intake queue. A gate that
        applied to everything would be meaningless by being universal."""
        allowed, reason = service.check_story(_Story())
        self.assertTrue(allowed)
        self.assertIsNone(reason)

    def test_no_consent_record_is_a_refusal_not_a_maybe(self):
        """The ordinary case: almost every report will never be written about,
        so 'no record' must not read as 'not yet decided'."""
        with mock.patch.object(service, "current_for", return_value=None):
            allowed, reason = service.check_story(_Story("SR-AAAAAAAAAAAA"))
        self.assertFalse(allowed)
        self.assertIn("no record", reason)

    def test_an_explicit_none_is_a_refusal(self):
        with mock.patch.object(service, "current_for",
                               return_value=_row(rc.LEVEL_NONE)):
            allowed, _ = service.check_story(_Story("SR-AAAAAAAAAAAA"))
        self.assertFalse(allowed)

    def test_anonymous_consent_permits_publication(self):
        with mock.patch.object(service, "current_for",
                               return_value=_row(rc.LEVEL_ANONYMOUS)):
            allowed, _ = service.check_story(_Story("SR-AAAAAAAAAAAA"))
        self.assertTrue(allowed)

    def test_named_consent_permits_publication(self):
        with mock.patch.object(service, "current_for",
                               return_value=_row(rc.LEVEL_NAMED)):
            allowed, _ = service.check_story(_Story("SR-AAAAAAAAAAAA"))
        self.assertTrue(allowed)

    def test_a_withdrawal_refuses_again(self):
        """Revocable up to publication is the whole point of the middle state."""
        with mock.patch.object(service, "current_for",
                               return_value=_row(rc.LEVEL_NONE)):
            allowed, reason = service.check_story(_Story("SR-AAAAAAAAAAAA"))
        self.assertFalse(allowed)
        self.assertIn("withdrawn", reason)


class NamingIsASeparateQuestionTest(unittest.TestCase):
    """Most people who agree to publication do not agree to being named."""

    def test_anonymous_consent_does_not_permit_naming(self):
        with mock.patch.object(service, "current_for",
                               return_value=_row(rc.LEVEL_ANONYMOUS)):
            self.assertFalse(service.naming_allowed(_Story("SR-A")))

    def test_named_consent_permits_naming(self):
        with mock.patch.object(service, "current_for",
                               return_value=_row(rc.LEVEL_NAMED)):
            self.assertTrue(service.naming_allowed(_Story("SR-A")))

    def test_a_story_citing_nothing_has_no_answer_rather_than_a_false_one(self):
        self.assertIsNone(service.naming_allowed(_Story()))


class ThreeLevelsTest(unittest.TestCase):

    def test_the_middle_level_exists(self):
        """A two-level permission forces a choice between silence and exposure,
        and people pick silence."""
        self.assertIn(rc.LEVEL_ANONYMOUS, rc.LEVELS)
        self.assertIn(rc.LEVEL_ANONYMOUS, rc.PUBLISHABLE_LEVELS)
        self.assertNotIn(rc.LEVEL_NONE, rc.PUBLISHABLE_LEVELS)

    def test_may_publish_defaults_to_no(self):
        with mock.patch.object(rc, "current_for", return_value=None):
            allowed, level = rc.may_publish("SR-A")
        self.assertFalse(allowed)
        self.assertEqual(level, rc.LEVEL_NONE)


class RequestTest(unittest.TestCase):

    def setUp(self):
        self.added = []
        session = MagicMock()
        session.add.side_effect = self.added.append
        self._patch = mock.patch.object(service.db, "session", session)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_asking_without_describing_what_would_be_published_is_refused(self):
        """A yes to an unrecorded question is not consent."""
        with self.assertRaises(service.ConsentError):
            service.request_consent("SR-A", "   ", "0xEDITOR")

    def test_a_request_records_the_scope_and_mints_a_token(self):
        row = service.request_consent("SR-A", "We would quote your account.",
                                      "0xEDITOR")
        self.assertEqual(row.level, rc.LEVEL_NONE)
        self.assertIn("quote your account", row.scope)
        self.assertTrue(row.request_token)

    def test_the_token_is_not_the_reference_code(self):
        """A reference code overheard once must not also carry the power to
        grant permission to publish."""
        row = service.request_consent("SR-AAAAAAAAAAAA", "scope", "0xEDITOR")
        self.assertNotIn("SR-AAAAAAAAAAAA", row.request_token)
        self.assertGreater(len(row.request_token), 20)


class AnswerAppendsTest(unittest.TestCase):

    def setUp(self):
        self.added = []
        session = MagicMock()
        session.add.side_effect = self.added.append
        self._patch = mock.patch.object(service.db, "session", session)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_an_answer_is_a_new_row_not_an_edit(self):
        """'Consented then withdrew' and 'never consented' are different facts,
        and only one means somebody made a mistake."""
        pending = _row(rc.LEVEL_NONE)
        pending.request_token = "tok"
        with mock.patch.object(service, "current_for", return_value=pending):
            service.answer("SR-A", rc.LEVEL_NAMED, "complainant", token="tok")
        rows = [r for r in self.added if isinstance(r, rc.ReportConsent)]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].level, rc.LEVEL_NAMED)
        # The original row was not mutated.
        self.assertEqual(pending.level, rc.LEVEL_NONE)

    def test_the_answer_carries_the_scope_it_was_given_against(self):
        pending = _row(rc.LEVEL_NONE, scope="We would name you.")
        pending.request_token = "tok"
        with mock.patch.object(service, "current_for", return_value=pending):
            service.answer("SR-A", rc.LEVEL_NAMED, "complainant", token="tok")
        rows = [r for r in self.added if isinstance(r, rc.ReportConsent)]
        self.assertEqual(rows[0].scope, "We would name you.")

    def test_a_superseded_link_is_refused(self):
        """Otherwise an older, broader scope could be accepted after a reviewer
        had narrowed it."""
        pending = _row(rc.LEVEL_NONE)
        pending.request_token = "current"
        with mock.patch.object(service, "current_for", return_value=pending):
            with self.assertRaises(service.ConsentError):
                service.answer("SR-A", rc.LEVEL_NAMED, "complainant",
                               token="stale")

    def test_an_unknown_level_is_refused(self):
        with self.assertRaises(service.ConsentError):
            service.answer("SR-A", "MAYBE", "complainant")


class PublishIsGatedTest(unittest.TestCase):

    def test_the_publish_path_checks_consent(self):
        source = open(os.path.join(BACKEND, "services", "newsroom.py"),
                      encoding="utf-8").read()
        publish = source[source.index("def publish_story"):
                         source.index("def correct_story")]
        self.assertIn("report_consent.check_story", publish)

    def test_it_is_checked_at_publish_and_not_only_at_approval(self):
        """Consent is revocable up to publication, so a story approved last week
        can be one whose complainant has since withdrawn."""
        source = open(os.path.join(BACKEND, "services", "newsroom.py"),
                      encoding="utf-8").read()
        approve = source[source.index("def approve_story"):
                         source.index("def publish_story")]
        self.assertNotIn("check_story", approve)


# These tests read files removed with the stripped features: blueprints/news.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_NEWS_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/news.py",
    )
)
_NEWS_PRESENT_GONE = "the newsroom blueprint was removed; this reads it"

class TheLinkIsInternalTest(unittest.TestCase):

    @unittest.skipUnless(_NEWS_PRESENT, _NEWS_PRESENT_GONE)
    def test_no_public_surface_reads_the_source_report(self):
        """The set of stories drawn from the intake queue is small, so knowing a
        story came from a report narrows who could have filed it."""
        for name in ("services/bylines.py", "services/news_rail.py",
                     "blueprints/news.py"):
            body = open(os.path.join(BACKEND, name), encoding="utf-8").read()
            code = "\n".join(line for line in body.splitlines()
                             if not line.strip().startswith("#"))
            self.assertNotIn("source_report_id", code,
                             "%s reads the source submission" % name)


if __name__ == "__main__":
    unittest.main()
