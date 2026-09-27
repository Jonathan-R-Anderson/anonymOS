"""Verification semantics for the DHT offload.

The property that matters is not "did the upload return 200" but "can the bytes
be read back identically". A later reclaim step deletes the local copy on the
strength of dht_offloaded_at, so anything that sets that flag without a genuine
byte-for-byte readback is a data-loss bug, not a cosmetic one.

These tests pin the failure paths, which are the ones that would otherwise be
discovered only after an archive had already been deleted.
"""
import sys
import types
import unittest
from unittest.mock import MagicMock


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

import shared  # noqa: E402
from services import storage_offload  # noqa: E402


class FakeMedia(object):
    def __init__(self, media_id=1, ext="png"):
        self.id = media_id
        self.ext = ext
        self.dht_offloaded_at = None


class FakeStore(object):
    """Minimal stand-in for S3Storage with controllable failure modes."""

    def __init__(self, data=b"hello-bytes", fail_read=False, fail_write=False, corrupt=False):
        self._data = data
        self.fail_read = fail_read
        self.fail_write = fail_write
        self.corrupt = corrupt
        self.written = None

    def read_attachment_bytes(self, media_id, ext=None):
        if self.fail_read:
            raise IOError("boom")
        if self.written is not None:
            return b"CORRUPT" if self.corrupt else self.written
        return self._data

    def read_thumbnail_bytes(self, media_id):
        return b""

    def read_video_preview_bytes(self, media_id):
        return b""

    def _ensure_buckets(self, *a, **k):
        return None

    def _write_attachment(self, data, media_id, ext):
        if self.fail_write:
            raise IOError("write boom")
        # Mirror boto3's real contract. upload_fileobj raises
        # "Fileobj must implement read" on bytes, and the original FakeStore
        # accepted anything -- so the tests passed while production failed every
        # single write. A stub that is more permissive than the real thing
        # tests nothing.
        if not hasattr(data, "read"):
            raise ValueError("Fileobj must implement read")
        self.written = data.read()

    def _write_thumbnail(self, data, media_id):
        return None

    def _write_video_preview(self, data, media_id):
        return None


class OffloadVerificationTest(unittest.TestCase):
    def setUp(self):
        # Force config to be a REAL dict every time. Another test module may
        # have installed the `shared` stub first with a bare MagicMock app,
        # whose .config is itself a MagicMock -- so .get() returns a truthy
        # Mock and dht_enabled() is True no matter what we set. That made these
        # tests pass alone and fail in the suite, which is worse than failing.
        shared.app.config = {"DHT_S3_ENDPOINT": "http://127.0.0.1:9000"}
        storage_offload._DHTStorage.reset()

    def tearDown(self):
        storage_offload._DHTStorage.reset()

    def _run(self, primary, target):
        media_mod = types.ModuleType("model.Media")
        media_mod.storage = primary
        media_mod.S3Storage = object
        sys.modules["model.Media"] = media_mod
        storage_offload._DHTStorage._instance = target
        try:
            return storage_offload.offload_media(FakeMedia(), include_derived=False)
        finally:
            sys.modules.pop("model.Media", None)

    def test_happy_path_reports_ok(self):
        ok, detail = self._run(FakeStore(), FakeStore())
        self.assertTrue(ok)
        self.assertEqual(detail, "ok")

    def test_readback_mismatch_is_not_marked_offloaded(self):
        # THE test. A write that "succeeds" but reads back different bytes must
        # never be recorded as offloaded -- a later reclaim would delete the
        # only good copy.
        ok, detail = self._run(FakeStore(), FakeStore(corrupt=True))
        self.assertFalse(ok)
        self.assertEqual(detail, "verify_mismatch")

    def test_write_failure_is_reported(self):
        ok, detail = self._run(FakeStore(), FakeStore(fail_write=True))
        self.assertFalse(ok)
        self.assertEqual(detail, "write_failed")

    def test_unreadable_source_is_reported_not_raised(self):
        ok, detail = self._run(FakeStore(fail_read=True), FakeStore())
        self.assertFalse(ok)
        self.assertEqual(detail, "source_unreadable")

    def test_empty_source_is_never_treated_as_success(self):
        # A zero-byte read from a flaky store must not be "successfully"
        # offloaded as an empty object, which would then verify fine.
        ok, detail = self._run(FakeStore(data=b""), FakeStore())
        self.assertFalse(ok)
        self.assertEqual(detail, "source_empty")

    def test_disabled_when_no_endpoint_configured(self):
        shared.app.config.pop("DHT_S3_ENDPOINT")
        self.assertFalse(storage_offload.dht_enabled())
        ok, detail = storage_offload.offload_media(FakeMedia())
        self.assertFalse(ok)
        self.assertEqual(detail, "dht_disabled")

    def test_blank_endpoint_counts_as_disabled(self):
        # Guards against an empty env var silently pointing the "DHT" store at
        # nothing and reporting success.
        shared.app.config["DHT_S3_ENDPOINT"] = "   "
        self.assertFalse(storage_offload.dht_enabled())

    def test_primary_gateway_is_not_offloaded_to_itself(self):
        shared.app.config["S3_ENDPOINT"] = "https://syndichan-node:9000/"
        shared.app.config["DHT_S3_ENDPOINT"] = "https://syndichan-node:9000"
        self.assertTrue(storage_offload.dht_enabled())
        self.assertFalse(storage_offload.dht_write_enabled())


if __name__ == "__main__":
    unittest.main()


class EligibilityGateTest(unittest.TestCase):
    """What may leave the server, and what may not.

    Publishing to the DHT is irreversible in practice -- encrypted shards are
    scattered across volunteer machines with no recall. These assertions are
    about the SQL filter's intent, expressed as a readable contract, because a
    regression here means banned or unscanned material is replicated to third
    parties and cannot be pulled back.
    """

    def test_unscanned_is_not_the_same_as_safe(self):
        # nsfw_score IS NULL means the classifier never ran -- typically because
        # it was down. Treating NULL as safe would push every file that arrived
        # during that outage. The filter requires nsfw_score IS NOT NULL.
        import inspect

        from services import storage_offload

        src = inspect.getsource(storage_offload._pending_query)
        self.assertIn("nsfw_score.isnot(None)", src)
        self.assertIn("nsfw_score < threshold()", src)

    def test_banned_hashes_are_excluded(self):
        import inspect

        from services import storage_offload

        src = inspect.getsource(storage_offload._pending_query)
        self.assertIn("BlockedMediaHash", src)
        self.assertIn("notin_(banned)", src)

    def test_admin_blocked_media_is_excluded(self):
        # An admin blocking something must not be silently replicated outward.
        import inspect

        from services import storage_offload

        src = inspect.getsource(storage_offload._pending_query)
        self.assertIn("overlay_blocked.is_(False)", src)
