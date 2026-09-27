"""Reviewing a submission: reading it, moving it, and recording both.

Reading is the sensitive action in this subsystem, so most of these are about
the audit trail rather than about what is displayed. The specific properties
worth holding:

* a read is recorded BEFORE the plaintext is handed over, so a failure later
  cannot leave a read unrecorded;
* a status change that changes nothing is still recorded, because a reviewer
  deciding to leave a case alone is a decision;
* a status change restarts the retention clock, so CLOSED -> ARCHIVED is kept
  rather than deleted on the older schedule;
* reviewer notes never reach the payload.
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

from model import PublicInterestReport as pir  # noqa: E402
from model import PublicInterestReportAudit as audit_model  # noqa: E402


def _report(status=pir.STATUS_NEW, stored=True, kind=pir.KIND_CIVIL_RIGHTS):
    report = pir.PublicInterestReport()
    report.report_id = "SR-REVIEW000001"
    report.kind = kind
    report.status = status
    report.pinned = False
    report.story_source = False
    report.dht_version = 1
    report.content_hash = "b" * 64
    report.created_at = datetime.datetime(2026, 1, 1)
    report.updated_at = datetime.datetime(2026, 1, 1)
    report.status_changed_at = datetime.datetime(2026, 1, 1)
    report.stored_at = datetime.datetime(2026, 1, 1) if stored else None
    report.recompute_expiry()
    return report


class ReviewTest(unittest.TestCase):

    def setUp(self):
        from services import public_interest_reports as reports
        self.reports = reports
        self.added = []
        session = MagicMock()
        session.add.side_effect = self.added.append
        self._patch = mock.patch.object(reports.db, "session", session)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def _audits(self):
        return [row for row in self.added
                if isinstance(row, audit_model.PublicInterestReportAudit)]

    # -- reading -----------------------------------------------------------

    def test_reading_a_report_records_who_read_it(self):
        report = _report()
        with mock.patch.object(self.reports.report_dht, "fetch",
                               return_value=b"blob"), \
             mock.patch.object(self.reports.report_crypto, "unseal",
                               return_value={"fields": {}}):
            self.reports.read_payload(report, "0xREVIEWER")

        rows = self._audits()
        self.assertTrue(rows)
        self.assertEqual(rows[0].action, audit_model.ACTION_VIEWED)
        self.assertEqual(rows[0].actor, "0xREVIEWER")

    def test_a_read_is_recorded_even_when_the_fetch_then_fails(self):
        """The audit row lands before the payload is produced, so a failure
        afterwards cannot leave the attempt unrecorded."""
        report = _report()
        with mock.patch.object(self.reports.report_dht, "fetch",
                               return_value=None):
            with self.assertRaises(self.reports.SubmissionFailed):
                self.reports.read_payload(report, "0xREVIEWER")
        self.assertEqual([row.action for row in self._audits()],
                         [audit_model.ACTION_VIEWED])

    def test_a_read_verifies_the_content_hash(self):
        """unseal is handed the recorded hash, so a substituted object is caught."""
        report = _report()
        with mock.patch.object(self.reports.report_dht, "fetch",
                               return_value=b"blob"), \
             mock.patch.object(self.reports.report_crypto, "unseal") as unseal:
            unseal.return_value = {"fields": {}}
            self.reports.read_payload(report, "0xREVIEWER")
        self.assertEqual(unseal.call_args.kwargs["expected_hash"], "b" * 64)

    def test_a_never_stored_report_cannot_be_read(self):
        report = _report(stored=False)
        with self.assertRaises(self.reports.SubmissionFailed):
            self.reports.read_payload(report, "0xREVIEWER")

    # -- moving ------------------------------------------------------------

    def test_a_status_change_is_recorded_with_both_ends(self):
        report = _report(status=pir.STATUS_NEW)
        self.reports.set_status(report, pir.STATUS_UNDER_REVIEW, "0xREVIEWER")
        row = self._audits()[0]
        self.assertEqual(row.previous_status, pir.STATUS_NEW)
        self.assertEqual(row.new_status, pir.STATUS_UNDER_REVIEW)

    def test_a_no_op_status_change_is_still_recorded(self):
        """A reviewer deciding to leave a case where it is, is a decision."""
        report = _report(status=pir.STATUS_UNDER_REVIEW)
        self.reports.set_status(report, pir.STATUS_UNDER_REVIEW, "0xREVIEWER")
        rows = self._audits()
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0].detail["changed"])

    def test_a_status_change_restarts_the_retention_clock(self):
        report = _report(status=pir.STATUS_CLOSED)
        closed_expiry = report.expires_at
        self.reports.set_status(report, pir.STATUS_ARCHIVED, "0xREVIEWER")
        self.assertGreater(report.expires_at, closed_expiry)

    def test_moving_to_an_open_state_clears_the_expiry(self):
        report = _report(status=pir.STATUS_CLOSED)
        self.assertIsNotNone(report.expires_at)
        self.reports.set_status(report, pir.STATUS_UNDER_REVIEW, "0xREVIEWER")
        self.assertIsNone(report.expires_at)

    def test_the_audit_row_records_the_resulting_expiry(self):
        """A record disappearing on schedule and one somebody deleted must be
        distinguishable afterwards."""
        report = _report(status=pir.STATUS_NEW)
        self.reports.set_status(report, pir.STATUS_CLOSED, "0xREVIEWER")
        self.assertIn("expires_at", self._audits()[0].detail)


# These tests read files removed with the stripped features: blueprints/report_review.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_REPORT_REVIEW_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/report_review.py",
    )
)
_REPORT_REVIEW_PRESENT_GONE = "the report-review blueprint was removed; these read it"

class NotesStaySeparateTest(unittest.TestCase):
    """Reviewer notes must not be able to reach the submitter's payload."""

    def test_notes_are_a_separate_table(self):
        from model.PublicInterestReportNote import PublicInterestReportNote
        self.assertNotEqual(PublicInterestReportNote.__tablename__,
                            pir.PublicInterestReport.__tablename__)

    def test_the_report_row_has_no_notes_column(self):
        import ast
        source = os.path.join(BACKEND, "model", "PublicInterestReport.py")
        tree = ast.parse(open(source, encoding="utf-8").read())
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "PublicInterestReport":
                for statement in node.body:
                    if isinstance(statement, ast.Assign):
                        for target in statement.targets:
                            if isinstance(target, ast.Name):
                                names.append(target.id)
        for forbidden in ("notes", "note", "reviewer_notes", "internal_notes"):
            self.assertNotIn(forbidden, names)

    @unittest.skipUnless(_REPORT_REVIEW_PRESENT, _REPORT_REVIEW_PRESENT_GONE)
    def test_the_review_module_never_writes_notes_to_storage(self):
        """A note reaching report_dht would put a reviewer's assessment of a
        complainant into the network alongside their own account."""
        source = open(os.path.join(BACKEND, "blueprints", "report_review.py"),
                      encoding="utf-8").read()
        note_section = source[source.index("def add_note"):]
        note_section = note_section[:note_section.index("def toggle_pin")]
        for forbidden in ("report_dht", "report_crypto", "seal("):
            self.assertNotIn(forbidden, note_section)


class QueueCannotFilterOnPiiTest(unittest.TestCase):

    @unittest.skipUnless(_REPORT_REVIEW_PRESENT, _REPORT_REVIEW_PRESENT_GONE)
    def test_the_queue_offers_no_city_filter(self):
        """The city is encrypted with the payload on purpose; a filter for it
        would mean putting it back in the index."""
        source = open(os.path.join(BACKEND, "blueprints", "report_review.py"),
                      encoding="utf-8").read()
        queue = source[source.index("def queue"):source.index("def _load")]
        self.assertNotIn('args.get("city")', queue)
        self.assertIn('args.get("state")', queue)


if __name__ == "__main__":
    unittest.main()
