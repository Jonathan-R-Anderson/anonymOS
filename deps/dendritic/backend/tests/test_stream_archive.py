"""Deletion safety for the stream-archive offload.

publish_one() deletes the local recording. That is the whole point of it -- the
archive is supposed to LIVE on the DHT, not to be mirrored there -- but it also
means every path that reaches the unlink has to have proven the object reads
back first. A recording deleted against a write that silently lost bytes is
gone; there is no second copy by design.

These tests pin the paths where the local file must SURVIVE, which are the ones
that would otherwise be discovered only after a broadcast had been destroyed.
"""
import io
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch


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

from services import stream_archive  # noqa: E402


class FakeMedia(object):
    def __init__(self, media_id=7, ext="mp4"):
        self.id = media_id
        self.ext = ext


class PublishDeletionTest(unittest.TestCase):
    """What must and must not be deleted, per outcome of the readback."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "session.mp4")
        self.payload = b"a recorded broadcast" * 64
        with open(self.path, "wb") as handle:
            handle.write(self.payload)
        self.addCleanup(self.tmp.cleanup)

    def _run(self, corrupt_chunk=None, raise_on_put=None):
        """publish_one against a fake gateway whose readback we control.

        `corrupt_chunk` is the index whose readback comes back damaged, standing
        in for a gateway that accepted a write it did not durably store.
        `raise_on_put` makes the upload itself fail.
        """
        store = {}
        client = MagicMock()

        def put_object(Bucket=None, Key=None, Body=None, **kw):
            if raise_on_put is not None:
                raise raise_on_put
            store[Key] = Body

        def get_object(Bucket=None, Key=None, **kw):
            data = store[Key]
            index = int(Key.rsplit("/", 1)[-1])
            if corrupt_chunk is not None and index == corrupt_chunk:
                data = data[:-5]
            return {"Body": io.BytesIO(data)}

        client.put_object.side_effect = put_object
        client.get_object.side_effect = get_object

        with patch.object(stream_archive, "_client", return_value=client), \
                patch.object(stream_archive, "_ensure_bucket", return_value="b"), \
                patch.object(stream_archive, "_remember") as remember:
            ok, detail = stream_archive.publish_one("0xabc", self.path)
        return ok, detail, remember, store

    def test_verified_chunks_publish_and_remove_the_local_copy(self):
        ok, detail, remember, store = self._run()
        self.assertTrue(ok, detail)
        self.assertFalse(
            os.path.exists(self.path),
            "the local copy must be gone once every chunk is verified -- "
            "leaving it grows the volume exactly as before",
        )
        self.assertTrue(remember.called, "the archive must be indexed")
        self.assertEqual(
            sum(len(v) for v in store.values()), len(self.payload),
            "the chunks must reassemble to exactly the source bytes",
        )

    def test_a_damaged_chunk_keeps_the_local_copy(self):
        """One chunk reads back short.

        This is the case that costs a broadcast if it is not caught: the write
        reported success, so nothing upstream looks wrong.
        """
        ok, detail, remember, _ = self._run(corrupt_chunk=0)
        self.assertFalse(ok)
        self.assertEqual(detail, "chunk_readback_mismatch")
        self.assertTrue(
            os.path.exists(self.path),
            "a damaged chunk must NOT delete the only remaining copy",
        )
        self.assertFalse(
            remember.called,
            "a recording that did not verify must not be advertised as archived",
        )

    def test_a_failed_upload_keeps_the_local_copy(self):
        ok, detail, remember, _ = self._run(raise_on_put=RuntimeError("closed"))
        self.assertFalse(ok)
        self.assertTrue(detail.startswith("upload_failed"), detail)
        self.assertTrue(os.path.exists(self.path))
        self.assertFalse(remember.called)

    def test_a_range_read_fetches_only_the_chunks_it_needs(self):
        """The payoff of chunking: seeking pulls two small objects, not the file."""
        stream_archive.CHUNK_BYTES  # documents the dependency
        entry = {
            "bucket": "b",
            "chunks": [{"key": "a/f/000000", "len": 10},
                       {"key": "a/f/000001", "len": 10},
                       {"key": "a/f/000002", "len": 10}],
            "size": 30,
        }
        blobs = {"a/f/000000": b"0123456789",
                 "a/f/000001": b"abcdefghij",
                 "a/f/000002": b"ABCDEFGHIJ"}
        fetched = []

        client = MagicMock()

        def get_object(Bucket=None, Key=None, **kw):
            fetched.append(Key)
            return {"Body": io.BytesIO(blobs[Key])}

        client.get_object.side_effect = get_object
        with patch.object(stream_archive, "_client", return_value=client):
            # Wholly inside the MIDDLE chunk, so the first and last must not be
            # fetched at all. A range spanning everything would pass even if the
            # skip logic were missing.
            got = stream_archive.read_range(entry, 12, 15)

        self.assertEqual(got, b"cdef")
        self.assertEqual(
            fetched, ["a/f/000001"],
            "only the chunks covering the range may be fetched",
        )

    def test_a_range_spanning_a_chunk_boundary_stitches_correctly(self):
        entry = {
            "bucket": "b",
            "chunks": [{"key": "a/f/000000", "len": 10},
                       {"key": "a/f/000001", "len": 10}],
            "size": 20,
        }
        blobs = {"a/f/000000": b"0123456789", "a/f/000001": b"abcdefghij"}
        client = MagicMock()
        client.get_object.side_effect = lambda Bucket=None, Key=None, **kw: {
            "Body": io.BytesIO(blobs[Key])
        }
        with patch.object(stream_archive, "_client", return_value=client):
            self.assertEqual(stream_archive.read_range(entry, 8, 11), b"89ab")


class NewestOrderingTest(unittest.TestCase):
    """newest() orders by the recording's own mtime, not by publish order."""

    def test_a_backlog_sweep_does_not_advertise_an_old_broadcast_as_latest(self):
        index = {
            "old.mp4": {"media_id": 1, "ext": "mp4", "size": 10, "mtime": 100},
            "new.mp4": {"media_id": 2, "ext": "mp4", "size": 10, "mtime": 900},
        }
        with patch.object(stream_archive, "published", return_value=index):
            # Publish order here is old-last, which is what a backlog sweep
            # produces; ordering by it would surface the wrong recording.
            self.assertEqual(stream_archive.newest("0xabc")["media_id"], 2)

    def test_no_archive_yet_is_none_rather_than_an_error(self):
        with patch.object(stream_archive, "published", return_value={}):
            self.assertIsNone(stream_archive.newest("0xabc"))


if __name__ == "__main__":
    unittest.main()
