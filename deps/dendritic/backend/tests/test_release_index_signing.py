"""The published release index must be signed (§18.14).

WHY
---
`/api/v1/node/releases` publishes the sha256 of each node binary, and its
docstring is careful about why that is separate from the download: "checking a
file against a value that arrived in the same response proves only that they
agree." That separation defends against a tampered DOWNLOAD. It does nothing
against a tampered INDEX -- an adversary who can answer for the origin serves
the hash of the binary they want trusted, and every check the client then
performs succeeds. §18.14 names the update channel as the strongest adversary
against a real deployment, so this is the case that matters most.

A signature alone is not enough either: without a version inside the signed
bytes it stops forgery and not REPLAY, so an older genuinely-signed index naming
a binary whose flaw is now public still verifies. The serial is therefore inside
the signed object, and it only ever rises.
"""

import json
import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


class ReleaseIndexSigningTest(unittest.TestCase):
    def _source(self):
        with open(os.path.join(BACKEND, "blueprints", "main.py"),
                  encoding="utf-8") as handle:
            return handle.read()

    def _endpoint(self):
        src = self._source()
        start = src.index("def node_releases():")
        return src[start:start + 4000]

    def test_the_index_is_signed(self):
        body = self._endpoint()
        self.assertIn("sign_object", body,
                      "the release index is served unsigned; an adversary who "
                      "can answer for the origin chooses the hash a client "
                      "trusts, and every check the client makes then passes")

    def test_the_serial_is_inside_the_signature(self):
        """Replay is the failure a bare signature leaves open."""
        body = self._endpoint()
        self.assertIn("index_serial()", body)
        self.assertRegex(
            body, r"sign_object\(\s*\"api/v1/node/releases\",\s*index_serial\(\)",
            "the serial is not the signed version, so an older signed index "
            "naming a since-broken binary still verifies")

    def test_an_unsigned_response_omits_the_field_rather_than_nulling_it(self):
        """`"signature": null` reads as 'this one is fine unsigned'."""
        body = self._endpoint()
        self.assertIn('if signed:', body)
        self.assertNotIn('"signature": None', body)
        self.assertNotIn('"signature": signed or None', body)

    def test_the_signed_bytes_are_reconstructible_by_a_client(self):
        """A client can only check what it can rebuild byte for byte."""
        body = self._endpoint()
        self.assertIn('sort_keys=True', body)
        self.assertIn('separators=(",", ":")', body)
        self.assertIn('"index": body', body,
                      "the signed object must be served under a key of its own, "
                      "or a client cannot tell which bytes were signed")

    def test_the_serial_only_rises(self):
        """publish() must bump it, in the same write as the index."""
        with open(os.path.join(BACKEND, "services", "node_release.py"),
                  encoding="utf-8") as handle:
            src = handle.read()
        self.assertIn("SETTING_RELEASES_SERIAL", src)
        publish = src[src.index("def publish("):]
        self.assertIn("serial + 1", publish,
                      "publish() does not bump the serial, so two different "
                      "indexes can be signed under the same version")

    def test_the_canonical_form_round_trips(self):
        """The serialisation the endpoint promises is stable and reproducible."""
        body = {"platforms": [{"os": "linux", "arch": "amd64", "sha256": "ab"}],
                "serial": 3}
        once = json.dumps(body, sort_keys=True, separators=(",", ":"))
        twice = json.dumps(json.loads(once), sort_keys=True, separators=(",", ":"))
        self.assertEqual(once, twice)
        self.assertNotIn(" ", once, "whitespace makes the bytes ambiguous")
