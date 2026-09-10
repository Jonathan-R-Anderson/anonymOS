"""The submission path: what happens when storage fails.

`public_interest_reports.submit` is the only place that decides a submission
succeeded, and the requirement it exists to hold is that a person is never told
their report was stored when it was not. These tests drive it with storage
broken in each of the ways it can break and assert that the row is left in the
state the confirmation page treats as failure.

The database is stubbed. What is under test is the ORDER of operations -- create
the row, seal, store, verify, only then stamp `stored_at` -- not SQLAlchemy.
"""

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

from services import report_schema  # noqa: E402


VALUES = {
    "full_name": "A. Complainant",
    "email": "a@example.org",
    "description": "An account of what happened.",
    "incident_date": "2026-03-04",
    "state": "CA",
}


class SubmitOrderingTest(unittest.TestCase):
    """Drives submit() with a stubbed session and a controllable store."""

    def setUp(self):
        # Imported here so the stubs above are installed first.
        from services import public_interest_reports as reports
        self.reports = reports

        self.added = []
        session = MagicMock()
        session.add.side_effect = self.added.append
        # No row exists yet, so the uniqueness probe always says "free".
        session.query.return_value.filter.return_value.first.return_value = None

        self._patches = [
            mock.patch.object(reports.db, "session", session),
            mock.patch.object(reports, "intake_available", return_value=True),
            mock.patch.object(reports.report_crypto, "seal",
                              return_value=(b"SCE1-blob", "a" * 64)),
        ]
        for patch in self._patches:
            patch.start()
        self.session = session

    def tearDown(self):
        for patch in reversed(self._patches):
            patch.stop()

    def _report_rows(self):
        from model.PublicInterestReport import PublicInterestReport
        return [row for row in self.added
                if isinstance(row, PublicInterestReport)]

    def _audit_rows(self):
        from model.PublicInterestReportAudit import PublicInterestReportAudit
        return [row for row in self.added
                if isinstance(row, PublicInterestReportAudit)]

    # -- success -----------------------------------------------------------

    def test_a_stored_submission_is_marked_stored(self):
        with mock.patch.object(self.reports.report_dht, "store",
                               return_value="civil-rights-reports/SR-X/v1"):
            report = self.reports.submit(report_schema.KIND_CIVIL_RIGHTS, VALUES,
                                         categories=["excessive_force"],
                                         acknowledgements=report_schema.ACKNOWLEDGEMENT_KEYS)
        self.assertTrue(report.is_stored)
        self.assertEqual(report.content_hash, "a" * 64)
        self.assertTrue(report.report_id.startswith("SR-"))

    def test_a_successful_submission_writes_a_submitted_audit_row(self):
        from model import PublicInterestReportAudit as audit
        with mock.patch.object(self.reports.report_dht, "store",
                               return_value="key"):
            self.reports.submit(report_schema.KIND_CIVIL_RIGHTS, VALUES,
                                categories=["excessive_force"],
                                acknowledgements=report_schema.ACKNOWLEDGEMENT_KEYS)
        actions = [row.action for row in self._audit_rows()]
        self.assertIn(audit.ACTION_SUBMITTED, actions)

    # -- failure -----------------------------------------------------------

    def _submit_expecting_failure(self, store_side_effect):
        with mock.patch.object(self.reports.report_dht, "store",
                               side_effect=store_side_effect):
            with self.assertRaises(self.reports.SubmissionFailed):
                self.reports.submit(report_schema.KIND_CIVIL_RIGHTS, VALUES,
                                    categories=["excessive_force"],
                                    acknowledgements=report_schema.ACKNOWLEDGEMENT_KEYS)

    def test_a_storage_failure_raises_rather_than_returning(self):
        """A caller cannot accidentally treat this as success."""
        from services.report_dht import ReportStorageError
        self._submit_expecting_failure(ReportStorageError("readback failed"))

    def test_a_failed_submission_leaves_stored_at_unset(self):
        """`stored_at` NULL is the structural definition of a failed submission,
        and the confirmation page reads exactly this."""
        from services.report_dht import ReportStorageError
        self._submit_expecting_failure(ReportStorageError("readback failed"))
        rows = self._report_rows()
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0].stored_at)
        self.assertFalse(rows[0].is_stored)

    def test_a_failed_submission_records_the_attempt(self):
        """Eleven people losing what they wrote during an outage is a fact worth
        being able to establish afterwards."""
        from model import PublicInterestReportAudit as audit
        from services.report_dht import ReportStorageError
        self._submit_expecting_failure(ReportStorageError("readback failed"))
        actions = [row.action for row in self._audit_rows()]
        self.assertIn(audit.ACTION_STORE_FAILED, actions)
        self.assertNotIn(audit.ACTION_SUBMITTED, actions)

    def test_an_unexpected_exception_is_still_a_failure_not_a_success(self):
        """Storage can break in ways report_dht did not anticipate."""
        self._submit_expecting_failure(RuntimeError("socket exploded"))
        self.assertIsNone(self._report_rows()[0].stored_at)

    def test_the_failure_message_does_not_leak_the_submission(self):
        from services.report_dht import ReportStorageError
        secret = VALUES["description"]
        with mock.patch.object(self.reports.report_dht, "store",
                               side_effect=ReportStorageError(secret)):
            with self.assertRaises(self.reports.SubmissionFailed) as caught:
                self.reports.submit(report_schema.KIND_CIVIL_RIGHTS, VALUES,
                                    categories=["excessive_force"],
                                    acknowledgements=report_schema.ACKNOWLEDGEMENT_KEYS)
        self.assertNotIn(secret, str(caught.exception))

    # -- what reaches the index -------------------------------------------

    def test_the_index_row_carries_no_free_text_or_contact_details(self):
        """Everything the submitter typed belongs in the encrypted payload."""
        with mock.patch.object(self.reports.report_dht, "store",
                               return_value="key"):
            report = self.reports.submit(
                report_schema.KIND_CIVIL_RIGHTS, VALUES,
                categories=["excessive_force"],
                acknowledgements=report_schema.ACKNOWLEDGEMENT_KEYS)
        serialised = " ".join(
            str(getattr(report, column, "")) for column in
            ("report_id", "kind", "status", "categories", "country", "state",
             "content_hash", "dht_key"))
        for leaked in ("A. Complainant", "a@example.org",
                       "An account of what happened."):
            self.assertNotIn(leaked, serialised)

    def test_the_city_is_not_copied_into_the_index(self):
        with mock.patch.object(self.reports.report_dht, "store",
                               return_value="key"):
            report = self.reports.submit(
                report_schema.KIND_CIVIL_RIGHTS, dict(VALUES, city="Barstow"),
                categories=["excessive_force"],
                acknowledgements=report_schema.ACKNOWLEDGEMENT_KEYS)
        self.assertFalse(hasattr(report, "city"))
        self.assertEqual(report.state, "CA")

    # -- refusal -----------------------------------------------------------

    def test_intake_closed_refuses_before_anything_is_written(self):
        with mock.patch.object(self.reports, "intake_available",
                               return_value=False):
            with self.assertRaises(self.reports.SubmissionRefused):
                self.reports.submit(report_schema.KIND_CIVIL_RIGHTS, VALUES,
                                    categories=["excessive_force"],
                                    acknowledgements=report_schema.ACKNOWLEDGEMENT_KEYS)
        self.assertEqual(self._report_rows(), [])

    def test_an_invalid_form_never_reaches_storage(self):
        with mock.patch.object(self.reports.report_dht, "store") as store:
            with self.assertRaises(report_schema.ValidationError):
                self.reports.submit(report_schema.KIND_CIVIL_RIGHTS,
                                    {"full_name": "only a name"},
                                    acknowledgements=())
        store.assert_not_called()
        self.assertEqual(self._report_rows(), [])


if __name__ == "__main__":
    unittest.main()
