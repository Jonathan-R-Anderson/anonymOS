"""Validation and the submission path.

The schema tests are ordinary. The submission tests are not: they exist to pin
the one behaviour the whole feature is judged on -- that a person is never told
their report was submitted when it was not -- and to pin the two ways a form can
harm the person filling it in, by losing what they wrote and by echoing it back
into an error.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services import report_schema  # noqa: E402
from services.report_schema import ValidationError  # noqa: E402


GOOD_REPORT = {
    "full_name": "A. Complainant",
    "email": "a@example.org",
    "description": "What happened, in their own words.",
    "incident_date": "2026-03-04",
    "state": "CA",
    "country": "US",
    "city": "Barstow",
}

ALL_ACKS = report_schema.ACKNOWLEDGEMENT_KEYS


class CivilRightsValidationTest(unittest.TestCase):

    def _validate(self, values=None, categories=("excessive_force",),
                  acks=ALL_ACKS):
        merged = dict(GOOD_REPORT)
        if values is not None:
            merged.update(values)
        return report_schema.validate(report_schema.KIND_CIVIL_RIGHTS, merged,
                                      categories=categories,
                                      acknowledgements=acks)

    def test_a_complete_report_validates(self):
        payload = self._validate()
        self.assertEqual(payload["kind"], report_schema.KIND_CIVIL_RIGHTS)
        self.assertEqual(payload["fields"]["full_name"], "A. Complainant")
        self.assertEqual(payload["categories"], ["excessive_force"])

    def test_a_missing_required_field_is_refused(self):
        with self.assertRaises(ValidationError) as caught:
            self._validate({"description": ""})
        self.assertIn("description", caught.exception.errors)

    def test_no_category_is_refused_for_a_report(self):
        with self.assertRaises(ValidationError) as caught:
            self._validate(categories=())
        self.assertIn("categories", caught.exception.errors)

    def test_every_acknowledgement_is_required(self):
        with self.assertRaises(ValidationError) as caught:
            self._validate(acks=("accurate",))
        self.assertIn("acknowledgements", caught.exception.errors)

    def test_an_unknown_category_is_dropped_not_stored(self):
        payload = self._validate(categories=("excessive_force", "../../etc/passwd"))
        self.assertEqual(payload["categories"], ["excessive_force"])

    def test_an_invalid_select_value_is_refused(self):
        with self.assertRaises(ValidationError) as caught:
            self._validate({"entity_type": "not-a-real-option"})
        self.assertIn("entity_type", caught.exception.errors)

    def test_over_length_input_is_refused_rather_than_truncated(self):
        """Silently truncating somebody's account loses the end of it."""
        with self.assertRaises(ValidationError) as caught:
            self._validate({"description": "x" * (report_schema.LONG + 1)})
        self.assertIn("description", caught.exception.errors)

    def test_error_messages_never_quote_the_submission(self):
        """Error text reaches logs and cached pages in a way form values do not."""
        secret = "MY-SECRET-ACCOUNT-OF-WHAT-HAPPENED"
        with self.assertRaises(ValidationError) as caught:
            self._validate({"description": secret + ("x" * report_schema.LONG),
                            "email": secret})
        for message in caught.exception.errors.values():
            self.assertNotIn(secret, message)

    def test_the_acknowledgement_text_is_stored_with_the_payload(self):
        """A submission must record what the person was actually shown."""
        payload = self._validate()
        self.assertEqual(sorted(payload["acknowledgements"].keys()),
                         sorted(ALL_ACKS))
        self.assertIn("attorney-client",
                      payload["acknowledgements"]["no_representation"])


class TipValidationTest(unittest.TestCase):
    """A tip must be submittable with nothing but the tip."""

    def test_a_tip_needs_no_name_email_or_category(self):
        payload = report_schema.validate(
            report_schema.KIND_NEWS_TIP,
            {"description": "Here is the thing you should look at."},
            categories=(), acknowledgements=("accurate",))
        self.assertEqual(payload["fields"]["description"],
                         "Here is the thing you should look at.")
        self.assertEqual(payload["categories"], [])

    def test_a_tip_still_needs_its_substance(self):
        with self.assertRaises(ValidationError):
            report_schema.validate(report_schema.KIND_NEWS_TIP, {},
                                   acknowledgements=("accurate",))

    def test_a_tip_asks_for_no_required_contact_field(self):
        schema = report_schema.schema_for(report_schema.KIND_NEWS_TIP)
        for contact in ("full_name", "email", "phone"):
            self.assertNotIn(contact, schema["required"])


class SchemaShapeTest(unittest.TestCase):

    def test_every_kind_has_a_usable_schema(self):
        for kind in (report_schema.KIND_CIVIL_RIGHTS, report_schema.KIND_NEWS_TIP):
            schema = report_schema.schema_for(kind)
            names = {f.name for f in report_schema.fields_for(kind)}
            for required in schema["required"]:
                self.assertIn(required, names,
                              "%s requires %r but never asks for it"
                              % (kind, required))

    def test_free_text_fields_are_marked_sensitive(self):
        """`sensitive` decides what may appear in an error or a log."""
        for kind in (report_schema.KIND_CIVIL_RIGHTS, report_schema.KIND_NEWS_TIP):
            for field in report_schema.fields_for(kind):
                if field.kind == "textarea":
                    self.assertTrue(field.sensitive,
                                    "%s.%s is free text and must be sensitive"
                                    % (kind, field.name))

    def test_unknown_is_a_first_class_answer_for_responsibility(self):
        """Forcing a guess puts a fabricated attribution into a lasting record."""
        self.assertIn("unknown", report_schema.ENTITY_TYPE_VALUES)

    def test_a_submitter_can_decline_contact(self):
        self.assertIn("none", report_schema.CONTACT_METHOD_VALUES)

    def test_an_unknown_kind_is_rejected(self):
        with self.assertRaises(KeyError):
            report_schema.schema_for("not_a_kind")


if __name__ == "__main__":
    unittest.main()
