"""The index row, reference codes and the retention schedule.

The most valuable test here is the one that asserts what the schema does NOT
contain. The index is the unencrypted half of the design, so every column added
to it is a column readable by anyone with database access -- and the way that
protection erodes is not a decision to abandon it, it is somebody adding a
`submitter_email` column years later for a good reason. That test makes the
addition visible.
"""

import datetime
import os
import sys
import types
import unittest
from unittest.mock import MagicMock


def _install_stubs():
    """Stub `shared` so the model can be imported without a live database.

    `db.Column` has to build something that records the column name, since the
    PII test inspects the declared schema. A MagicMock would let every
    assertion pass vacuously, which for this file would be worse than no test.
    """
    if "shared" in sys.modules:
        return

    class _Column(object):
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class _Model(object):
        pass

    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = _Model
    db.Column = _Column
    for name in ("Integer", "String", "Text", "DateTime", "Boolean", "SmallInteger"):
        setattr(db, name, MagicMock(name=name))
    shared.db = db
    shared.app = MagicMock()
    shared.app.config = {}
    sys.modules["shared"] = shared


_install_stubs()

from model import PublicInterestReport as pir  # noqa: E402


class ReferenceCodeTest(unittest.TestCase):

    def test_codes_are_unguessable_and_well_formed(self):
        code = pir.generate_report_id()
        self.assertTrue(code.startswith("SR-"))
        body = code.split("-", 1)[1]
        self.assertEqual(len(body), pir._CODE_LENGTH)
        self.assertTrue(all(c in pir._ALPHABET for c in body))

    def test_codes_do_not_repeat(self):
        codes = {pir.generate_report_id() for _ in range(2000)}
        self.assertEqual(len(codes), 2000)

    def test_codes_avoid_ambiguous_characters(self):
        """I, L, O and U are excluded so a code survives being read aloud and
        written down -- for a source this may be the only way back to their own
        submission."""
        for letter in "ILOU":
            self.assertNotIn(letter, pir._ALPHABET)

    def test_the_code_does_not_reveal_the_kind(self):
        """A code found written down must not announce that its holder sent a
        press tip."""
        self.assertNotIn("TIP", pir._PREFIX.upper())
        self.assertNotIn("CR", pir._PREFIX.upper())


class RetentionTest(unittest.TestCase):

    def test_open_states_never_expire(self):
        """A clock on an open case deletes work in progress."""
        for status in pir.OPEN_STATUSES:
            if status == pir.STATUS_NEW:
                continue  # tips deliberately expire from NEW; checked below
            self.assertIsNone(
                pir.retention_seconds(pir.KIND_CIVIL_RIGHTS, status),
                "%s should not expire while open" % status)

    def test_a_civil_rights_report_does_not_expire_from_new(self):
        self.assertIsNone(
            pir.retention_seconds(pir.KIND_CIVIL_RIGHTS, pir.STATUS_NEW))

    def test_an_untriaged_tip_does_expire(self):
        """A tip nobody pursued has no advocate, unlike a complainant's report."""
        self.assertEqual(
            pir.retention_seconds(pir.KIND_NEWS_TIP, pir.STATUS_NEW),
            90 * 86400)

    def test_unverified_is_kept_the_shortest_of_the_closed_states(self):
        unverified = pir.retention_seconds(pir.KIND_CIVIL_RIGHTS, pir.STATUS_UNVERIFIED)
        verified = pir.retention_seconds(pir.KIND_CIVIL_RIGHTS, pir.STATUS_VERIFIED)
        archived = pir.retention_seconds(pir.KIND_CIVIL_RIGHTS, pir.STATUS_ARCHIVED)
        self.assertLess(unverified, verified)
        self.assertLess(verified, archived)

    def test_pinning_overrides_the_schedule(self):
        """A live investigation owns its source material."""
        self.assertIsNotNone(
            pir.retention_seconds(pir.KIND_NEWS_TIP, pir.STATUS_NEW))
        self.assertIsNone(
            pir.retention_seconds(pir.KIND_NEWS_TIP, pir.STATUS_NEW, pinned=True))

    def test_story_source_material_outlives_the_story(self):
        self.assertIsNone(
            pir.retention_seconds(pir.KIND_NEWS_TIP, pir.STATUS_CLOSED,
                                  story_source=True))

    def test_every_status_has_a_policy_for_every_kind(self):
        """A status with no entry silently means 'never expires'."""
        for kind in pir.KINDS:
            for status in pir.STATUSES:
                self.assertIn(status, pir.RETENTION_SECONDS[kind],
                              "%s/%s has no retention policy" % (kind, status))

    def test_recompute_expiry_runs_from_the_status_change_not_creation(self):
        """The clock restarts on a transition, so CLOSED -> ARCHIVED is kept
        rather than deleted on the older schedule."""
        report = pir.PublicInterestReport()
        report.kind = pir.KIND_CIVIL_RIGHTS
        report.status = pir.STATUS_CLOSED
        report.pinned = False
        report.story_source = False
        changed = datetime.datetime(2026, 1, 1)
        report.status_changed_at = changed
        report.recompute_expiry()
        self.assertEqual(report.expires_at,
                         changed + datetime.timedelta(seconds=365 * 86400))

        # Re-filed as archived, later: the new clock runs from the new
        # transition, not from the original close.
        later = datetime.datetime(2026, 6, 1)
        report.status = pir.STATUS_ARCHIVED
        report.status_changed_at = later
        report.recompute_expiry()
        self.assertEqual(report.expires_at,
                         later + datetime.timedelta(seconds=7 * 365 * 86400))

    def test_an_open_report_has_no_expiry_set(self):
        report = pir.PublicInterestReport()
        report.kind = pir.KIND_CIVIL_RIGHTS
        report.status = pir.STATUS_UNDER_REVIEW
        report.pinned = False
        report.story_source = False
        report.status_changed_at = datetime.datetime(2026, 1, 1)
        self.assertIsNone(report.recompute_expiry())


class IndexHoldsNoPiiTest(unittest.TestCase):
    """The index is the readable half. It must stay free of identifying data."""

    FORBIDDEN = (
        "name", "email", "phone", "address", "street", "city", "postcode",
        "zip", "contact", "description", "witness", "dob", "ssn", "ip",
        "full_name", "narrative", "body",
    )

    def _declared_columns(self):
        """Column names, read from the SOURCE rather than from the class.

        Introspecting the imported class does not work reliably here. Whichever
        test module runs first decides what `shared` is -- a stub whose
        `db.Column` is a MagicMock, a different stub, or the real SQLAlchemy --
        and under a MagicMock every column becomes an anonymous mock with no
        name. A version of this test that inspected that would find nothing and
        pass, which for the one assertion standing between the unencrypted index
        and a complainant's email address is the worst possible failure mode.

        Parsing the declaration with `ast` answers the question actually being
        asked -- what does this schema say it stores -- and gives the same answer
        no matter how the suite is ordered or whether the model imports at all.
        """
        import ast

        source_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "model", "PublicInterestReport.py")
        tree = ast.parse(open(source_path, encoding="utf-8").read())

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "PublicInterestReport":
                names = []
                for statement in node.body:
                    if not isinstance(statement, ast.Assign):
                        continue
                    value = statement.value
                    if not (isinstance(value, ast.Call)
                            and isinstance(value.func, ast.Attribute)
                            and value.func.attr == "Column"):
                        continue
                    for target in statement.targets:
                        if isinstance(target, ast.Name):
                            names.append(target.id)
                return names
        return []

    def test_the_schema_declares_no_identifying_column(self):
        columns = self._declared_columns()
        self.assertTrue(columns, "no columns found -- the stub is not working")
        for column in columns:
            for forbidden in self.FORBIDDEN:
                self.assertNotIn(
                    forbidden, column.lower(),
                    "column %r looks like PII; the index is unencrypted and "
                    "everything the submitter typed belongs in the payload"
                    % column)

    def test_city_specifically_is_absent(self):
        """'Excessive force, 2026-03-04, Barstow' identifies a person to anyone
        who was there. Reviewers filter by state."""
        columns = [c.lower() for c in self._declared_columns()]
        self.assertNotIn("city", columns)
        self.assertIn("state", columns)

    def test_the_columns_a_queue_needs_are_present(self):
        columns = self._declared_columns()
        for needed in ("report_id", "kind", "status", "content_hash", "dht_key",
                       "stored_at", "expires_at", "categories"):
            self.assertIn(needed, columns)


class StoredGateTest(unittest.TestCase):

    def test_is_stored_is_false_until_readback_sets_it(self):
        """A row with stored_at NULL is a failed submission by construction."""
        report = pir.PublicInterestReport()
        report.stored_at = None
        self.assertFalse(report.is_stored)
        report.stored_at = datetime.datetime.utcnow()
        self.assertTrue(report.is_stored)


if __name__ == "__main__":
    unittest.main()
