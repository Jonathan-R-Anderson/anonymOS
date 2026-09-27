"""The sweep that actually deletes.

This is the one part of the feature that destroys data irrecoverably, so the
tests are mostly about what it must REFUSE to do: delete a pinned submission,
clear a pointer to a payload it could not remove, or leave a deletion
unrecorded.
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


def _expired_report(pinned=False, story_source=False):
    report = pir.PublicInterestReport()
    report.report_id = "SR-EXPIRE000001"
    report.kind = pir.KIND_NEWS_TIP
    report.status = pir.STATUS_CLOSED
    report.pinned = pinned
    report.story_source = story_source
    report.dht_version = 1
    report.dht_key = "civil-rights-reports/SR-EXPIRE000001/v1"
    report.content_hash = "c" * 64
    report.created_at = datetime.datetime(2026, 1, 1)
    report.updated_at = datetime.datetime(2026, 1, 1)
    report.status_changed_at = datetime.datetime(2026, 1, 1)
    report.stored_at = datetime.datetime(2026, 1, 1)
    report.expires_at = datetime.datetime(2026, 2, 1)
    return report


class ExpireOneTest(unittest.TestCase):

    def setUp(self):
        from services import report_retention
        self.retention = report_retention
        self.added = []
        session = MagicMock()
        session.add.side_effect = self.added.append
        self._patch = mock.patch.object(report_retention.db, "session", session)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def _audits(self):
        return [row for row in self.added
                if isinstance(row, audit_model.PublicInterestReportAudit)]

    def test_the_payload_is_deleted_and_the_pointer_cleared(self):
        report = _expired_report()
        with mock.patch.object(self.retention.report_dht, "delete",
                               return_value=["civil-rights-reports/SR-EXPIRE000001/v1"]):
            self.assertTrue(self.retention.expire_one(report))
        self.assertIsNone(report.content_hash)
        self.assertIsNone(report.dht_key)
        self.assertIsNone(report.stored_at)
        self.assertIsNone(report.expires_at)

    def test_the_tombstone_keeps_the_reference_and_the_dates(self):
        """A submitter quoting their code after expiry should be told it was
        deleted on schedule, not that it never existed."""
        report = _expired_report()
        with mock.patch.object(self.retention.report_dht, "delete",
                               return_value=["k"]):
            self.retention.expire_one(report)
        self.assertEqual(report.report_id, "SR-EXPIRE000001")
        self.assertIsNotNone(report.created_at)
        self.assertFalse(report.is_stored)

    def test_a_deletion_is_recorded_as_scheduled_not_human(self):
        """A record disappearing on schedule and one somebody deleted are
        indistinguishable afterwards unless it was written down."""
        report = _expired_report()
        with mock.patch.object(self.retention.report_dht, "delete",
                               return_value=["k"]):
            self.retention.expire_one(report)
        row = self._audits()[0]
        self.assertEqual(row.action, audit_model.ACTION_EXPIRED)
        self.assertEqual(row.actor, "retention-sweep")
        self.assertTrue(row.detail["scheduled"])

    def test_a_failed_storage_delete_leaves_the_row_alone(self):
        """A row whose payload is still out there must not look expired."""
        report = _expired_report()
        with mock.patch.object(self.retention.report_dht, "delete",
                               side_effect=RuntimeError("gateway down")):
            self.assertFalse(self.retention.expire_one(report))
        self.assertEqual(report.content_hash, "c" * 64)
        self.assertIsNotNone(report.dht_key)
        self.assertTrue(report.is_stored)
        self.assertEqual(self._audits(), [])

    def test_removing_nothing_is_treated_as_failure_not_success(self):
        """'Already gone' and 'the gateway refused' are indistinguishable from
        here, and guessing the first would orphan real data."""
        report = _expired_report()
        with mock.patch.object(self.retention.report_dht, "delete",
                               return_value=[]):
            self.assertFalse(self.retention.expire_one(report))
        self.assertIsNotNone(report.dht_key)
        self.assertEqual(self._audits(), [])


class DueSelectionTest(unittest.TestCase):
    """`due()` builds a query; these assert the filters it applies."""

    def test_pinned_and_story_source_are_excluded_at_deletion_time(self):
        """`expires_at` is a stored value, so a row pinned AFTER its expiry was
        computed still carries the old date. The pin has to win here too."""
        source = open(os.path.join(BACKEND, "services", "report_retention.py"),
                      encoding="utf-8").read()
        due = source[source.index("def due"):source.index("def expire_one")]
        self.assertIn("pinned.is_(False)", due)
        self.assertIn("story_source.is_(False)", due)

    def test_rows_with_no_expiry_are_never_selected(self):
        source = open(os.path.join(BACKEND, "services", "report_retention.py"),
                      encoding="utf-8").read()
        due = source[source.index("def due"):source.index("def expire_one")]
        self.assertIn("expires_at.isnot(None)", due)


class SweepTest(unittest.TestCase):

    def setUp(self):
        from services import report_retention
        self.retention = report_retention
        self._patch = mock.patch.object(report_retention.db, "session", MagicMock())
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def test_a_sweep_counts_expired_and_deferred_separately(self):
        rows = [_expired_report(), _expired_report()]
        with mock.patch.object(self.retention, "due", return_value=rows), \
             mock.patch.object(self.retention, "expire_one",
                               side_effect=[True, False]):
            summary = self.retention.sweep()
        self.assertEqual(summary, {"due": 2, "expired": 1, "deferred": 1})

    def test_one_failure_does_not_abandon_the_rest_of_the_batch(self):
        rows = [_expired_report(), _expired_report()]
        with mock.patch.object(self.retention, "due", return_value=rows), \
             mock.patch.object(self.retention, "expire_one",
                               side_effect=[RuntimeError("boom"), True]):
            summary = self.retention.sweep()
        self.assertEqual(summary["expired"], 1)
        self.assertEqual(summary["deferred"], 1)

    def test_an_empty_sweep_is_quiet(self):
        with mock.patch.object(self.retention, "due", return_value=[]):
            self.assertEqual(self.retention.sweep(),
                             {"due": 0, "expired": 0, "deferred": 0})


if __name__ == "__main__":
    unittest.main()
