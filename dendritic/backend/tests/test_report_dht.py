"""Storing sealed submissions, and refusing to claim success when storage failed.

The central requirement of the feature is that a person is NEVER told their
report was submitted when it was not. `report_dht.store` is where that is
enforced, so most of this file is about making the write succeed and the read
fail in various ways and checking that each one raises.

A fake S3 client stands in for the storage node's gateway. What is being tested
is this module's control flow -- write, read back, compare, refuse -- which is
where the bug would be; the gateway's own behaviour is not in scope here.
"""

import hashlib
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
    """Stub `shared` so this runs without a database or flask_migrate.

    Same approach as tests/test_storage_offload.py. `config` must be a real dict
    rather than a MagicMock attribute, because the module under test reads it
    with .get() and writes are what these tests use to toggle S3_ENDPOINT.
    """
    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        db = MagicMock()
        db.Model = object
        shared.db = db
        shared.app = MagicMock()
        shared.app.config = {}
        sys.modules["shared"] = shared


_install_stubs()

from shared import app  # noqa: E402,F401  (kept so the stub is installed)
from services import report_dht  # noqa: E402


class _FakeApp(object):
    """An app whose `config` is a plain dict and whose logger swallows output."""

    def __init__(self):
        self.config = {}
        self.logger = MagicMock()


class _Body(object):
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class FakeGateway(object):
    """An in-memory stand-in for the node's S3 gateway."""

    def __init__(self):
        self.objects = {}
        self.buckets = set()
        self.put_calls = 0
        # Test hooks.
        self.fail_put = False
        self.swallow_writes = False   # accept a put, store nothing
        self.corrupt_on_read = False  # return different bytes than were stored

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise RuntimeError("no such bucket")

    def create_bucket(self, Bucket):
        self.buckets.add(Bucket)

    def put_object(self, Bucket, Key, Body, Metadata=None):
        self.put_calls += 1
        if self.fail_put:
            raise RuntimeError("gateway refused the write")
        if not self.swallow_writes:
            self.objects[(Bucket, Key)] = (Body, Metadata or {})

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise RuntimeError("no such key")
        body, _ = self.objects[(Bucket, Key)]
        if self.corrupt_on_read:
            body = b"not the bytes you stored"
        return {"Body": _Body(body)}

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise RuntimeError("no such key")

    def delete_object(self, Bucket, Key):
        self.objects.pop((Bucket, Key), None)


BLOB = b"SCE1-pretend-ciphertext"
DIGEST = hashlib.sha256(BLOB).hexdigest()


class ReportDhtTest(unittest.TestCase):

    def setUp(self):
        self.gateway = FakeGateway()
        # Swap in an app whose config is a REAL dict for the duration.
        #
        # Whichever test module imports first decides what `shared` is, and at
        # least one installs a stub whose `app.config` is a MagicMock -- on
        # which `.get()` returns a truthy mock and `.pop()` does nothing. A test
        # for "refuses when no object store is configured" then silently tests
        # nothing, and passes. Owning the app object here makes these tests say
        # the same thing whatever ran before them.
        self._patch = mock.patch.object(report_dht, "app", _FakeApp())
        self._patch.start()
        report_dht.app.config["S3_ENDPOINT"] = "https://storage.invalid:9000"

    def tearDown(self):
        self._patch.stop()

    # -- the gate ----------------------------------------------------------

    def test_a_successful_write_that_reads_back_returns_the_key(self):
        key = report_dht.store("SR-AAAAAAAAAAAA", BLOB, DIGEST,
                               client=self.gateway)
        self.assertEqual(key, "civil-rights-reports/SR-AAAAAAAAAAAA/v1")

    def test_a_write_the_gateway_refuses_raises(self):
        self.gateway.fail_put = True
        with self.assertRaises(report_dht.ReportStorageError):
            report_dht.store("SR-BBBBBBBBBBBB", BLOB, DIGEST, client=self.gateway)

    def test_a_write_that_succeeds_but_cannot_be_read_back_raises(self):
        """THE test. The gateway said yes and the object is not there.

        This is the failure the whole readback gate exists for: without it the
        submitter gets a confirmation page and a reference number for a report
        that does not exist anywhere.
        """
        self.gateway.swallow_writes = True
        with self.assertRaises(report_dht.ReportStorageError):
            report_dht.store("SR-CCCCCCCCCCCC", BLOB, DIGEST, client=self.gateway)

    def test_a_readback_returning_different_bytes_raises(self):
        self.gateway.corrupt_on_read = True
        with self.assertRaises(report_dht.ReportStorageError):
            report_dht.store("SR-DDDDDDDDDDDD", BLOB, DIGEST, client=self.gateway)

    def test_no_object_store_configured_raises_rather_than_pretending(self):
        report_dht.app.config.pop("S3_ENDPOINT", None)
        self.assertFalse(report_dht.enabled())
        with self.assertRaises(report_dht.ReportStorageError):
            report_dht.store("SR-EEEEEEEEEEEE", BLOB, DIGEST, client=self.gateway)

    # -- the key namespace -------------------------------------------------

    def test_the_key_carries_no_descriptive_metadata(self):
        """A DHT key is visible to every node that routes for it."""
        key = report_dht.key_for("SR-FFFFFFFFFFFF", 3)
        self.assertEqual(key, "civil-rights-reports/SR-FFFFFFFFFFFF/v3")
        for leak in ("civil_rights", "news_tip", "2026", "CA", "discrimination"):
            self.assertNotIn(leak, key)

    def test_both_kinds_share_one_prefix(self):
        """The key must not reveal that a submission is a press tip."""
        self.assertTrue(report_dht.key_for("SR-1", 1).startswith(report_dht.KEY_PREFIX))
        self.assertTrue(report_dht.key_for("SR-2", 1).startswith(report_dht.KEY_PREFIX))

    # -- versioning --------------------------------------------------------

    def test_versions_are_append_only(self):
        report_dht.store("SR-GGGGGGGGGGGG", BLOB, DIGEST, version=1,
                         client=self.gateway)
        second = b"SCE1-a-correction"
        report_dht.store("SR-GGGGGGGGGGGG", second,
                         hashlib.sha256(second).hexdigest(), version=2,
                         client=self.gateway)
        self.assertEqual(report_dht.fetch("SR-GGGGGGGGGGGG", 1, client=self.gateway),
                         BLOB)
        self.assertEqual(report_dht.fetch("SR-GGGGGGGGGGGG", 2, client=self.gateway),
                         second)

    def test_latest_version_finds_the_top(self):
        for version in (1, 2, 3):
            body = b"v%d" % version
            report_dht.store("SR-HHHHHHHHHHHH", body,
                             hashlib.sha256(body).hexdigest(), version=version,
                             client=self.gateway)
        self.assertEqual(
            report_dht.latest_version("SR-HHHHHHHHHHHH", client=self.gateway), 3)

    def test_latest_version_of_an_unknown_report_is_zero(self):
        self.assertEqual(
            report_dht.latest_version("SR-NOTHERE00000", client=self.gateway), 0)

    # -- deletion ----------------------------------------------------------

    def test_delete_removes_every_version(self):
        for version in (1, 2):
            body = b"v%d" % version
            report_dht.store("SR-IIIIIIIIIIII", body,
                             hashlib.sha256(body).hexdigest(), version=version,
                             client=self.gateway)
        removed = report_dht.delete("SR-IIIIIIIIIIII", client=self.gateway)
        self.assertEqual(len(removed), 2)
        self.assertIsNone(report_dht.fetch("SR-IIIIIIIIIIII", 1, client=self.gateway))

    def test_expiry_metadata_is_carried_on_the_object(self):
        report_dht.store("SR-JJJJJJJJJJJJ", BLOB, DIGEST, expires_at=1800000000,
                         client=self.gateway)
        _, metadata = self.gateway.objects[
            (report_dht._bucket(), "civil-rights-reports/SR-JJJJJJJJJJJJ/v1")]
        self.assertEqual(metadata["expires-at"], "1800000000")
        self.assertEqual(metadata["content-hash"], DIGEST)


if __name__ == "__main__":
    unittest.main()
