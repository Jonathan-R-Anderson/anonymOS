"""The sealing layer for public-interest submissions.

These run without a database or a network, because `services.content_keys` was
written to be testable that way and `report_crypto` adds no I/O of its own.

The tests that matter here are the negative ones. A round trip passing proves
the happy path; what protects a complainant is that the wrong key, a flipped
byte and a substituted object all FAIL, and each of those is a silent success in
a naive implementation.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services import content_keys  # noqa: E402
from services import report_crypto  # noqa: E402


# Two distinct masters, so "reports do not use the storage key" is testable.
REPORT_MASTER = "11" * 32
STORAGE_MASTER = "22" * 32

PAYLOAD = {
    "contact": {"full_name": "A. Complainant", "email": "a@example.org"},
    "incident": {"date": "2026-03-04", "city": "Barstow", "state": "CA"},
    "description": "Unicode survives: Ανώνυμος 匿名 مجهول",
    "categories": ["excessive_force", "unlawful_detention"],
}


class ReportCryptoTest(unittest.TestCase):

    def setUp(self):
        self._saved = {
            report_crypto.ENV_MASTER: os.environ.get(report_crypto.ENV_MASTER),
            "STORAGE_CONTENT_MASTER_SECRET":
                os.environ.get("STORAGE_CONTENT_MASTER_SECRET"),
        }
        os.environ[report_crypto.ENV_MASTER] = REPORT_MASTER
        os.environ["STORAGE_CONTENT_MASTER_SECRET"] = STORAGE_MASTER

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # -- the happy path ----------------------------------------------------

    def test_round_trip_preserves_the_submission(self):
        blob, digest = report_crypto.seal("SR-TEST00000001", PAYLOAD)
        out = report_crypto.unseal("SR-TEST00000001", blob, expected_hash=digest)
        self.assertEqual(out, PAYLOAD)

    def test_the_plaintext_is_not_in_the_ciphertext(self):
        """The whole point. If a name survives into the blob, nodes can read it."""
        blob, _ = report_crypto.seal("SR-TEST00000002", PAYLOAD)
        for secret in (b"A. Complainant", b"a@example.org", b"Barstow"):
            self.assertNotIn(secret, blob)

    # -- key separation (roadmap D2) ---------------------------------------

    def test_the_storage_master_cannot_read_a_report(self):
        """Reports must not be readable by the key that reads site media."""
        blob, _ = report_crypto.seal("SR-TEST00000003", PAYLOAD)
        with self.assertRaises(Exception):
            content_keys.decrypt(blob, secret=STORAGE_MASTER)

    def test_no_master_refuses_rather_than_falling_back(self):
        """An unset report key must NOT silently use the storage key."""
        os.environ.pop(report_crypto.ENV_MASTER, None)
        self.assertFalse(report_crypto.enabled())
        with self.assertRaises(report_crypto.ReportCryptoError):
            report_crypto.seal("SR-TEST00000004", PAYLOAD)

    def test_content_keys_default_behaviour_is_unchanged(self):
        """The `secret` parameter must not alter existing callers.

        content_keys is used for site media; threading a parameter through it
        would be a bad trade if the default path moved.
        """
        blob = content_keys.encrypt("media:1", b"hello")
        self.assertEqual(content_keys.decrypt(blob), b"hello")

    # -- integrity ---------------------------------------------------------

    def test_a_flipped_byte_fails_to_decrypt(self):
        """The AEAD tag: a node cannot alter a report without it being detected."""
        blob, _ = report_crypto.seal("SR-TEST00000005", PAYLOAD)
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(Exception):
            report_crypto.unseal("SR-TEST00000005", bytes(tampered))

    def test_a_substituted_valid_object_is_rejected_by_the_hash(self):
        """A different report's ciphertext is internally valid. The hash is what
        catches it being served in this report's place."""
        _, digest_a = report_crypto.seal("SR-TEST0000000A", PAYLOAD)
        blob_b, _ = report_crypto.seal("SR-TEST0000000B", PAYLOAD)
        with self.assertRaises(report_crypto.ReportCryptoError):
            report_crypto.unseal("SR-TEST0000000A", blob_b, expected_hash=digest_a)

    def test_a_payload_cannot_be_replayed_as_another_report(self):
        """Even without the hash, the AEAD's additional data binds the id."""
        blob_b, _ = report_crypto.seal("SR-TEST0000000C", PAYLOAD)
        with self.assertRaises(Exception):
            report_crypto.unseal("SR-TEST0000000D", blob_b)

    def test_a_version_cannot_be_rolled_back(self):
        """v1 must not be servable as v2: a correction that can be silently
        reverted is not a correction."""
        blob_v1, _ = report_crypto.seal("SR-TEST0000000E", PAYLOAD, version=1)
        report_crypto.unseal("SR-TEST0000000E", blob_v1, version=1)
        with self.assertRaises(Exception):
            report_crypto.unseal("SR-TEST0000000E", blob_v1, version=2)

    # -- determinism -------------------------------------------------------

    def test_canonical_payload_is_stable_across_key_order(self):
        a = report_crypto.canonical_payload({"b": 2, "a": 1})
        b = report_crypto.canonical_payload({"a": 1, "b": 2})
        self.assertEqual(a, b)

    def test_canonical_payload_keeps_unicode_as_utf8(self):
        raw = report_crypto.canonical_payload({"t": "匿名"})
        self.assertIn("匿名".encode("utf-8"), raw)


if __name__ == "__main__":
    unittest.main()
