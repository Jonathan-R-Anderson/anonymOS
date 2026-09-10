"""Key handling for hash-keyed media votes.

The property that matters, and the reason the votes are keyed on a content hash
at all: re-uploading a video must NOT launder its score. A repost produces a new
Media row with a new id, so an id-keyed vote would silently reset to zero. The
hash is identical, so the vote key is identical.

These tests cover the key layer (validation + derivation), which is pure — the
storage layer needs a live session and is exercised in the app's integration
path, not here.

model.MediaVote imports the Flask app stack, so `shared` is stubbed the same way
test_board_sources does it (see that file for why ONLY `shared` is stubbed).
"""
import sys
import types
import unittest
from unittest.mock import MagicMock


def _install_shared_stub():
    if "shared" in sys.modules:
        return lambda: None
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    shared.db = db
    shared.app = MagicMock()
    sys.modules["shared"] = shared

    # RESTORE, so the stub does not outlive the import it exists for. pytest
    # imports every test module during COLLECTION, so a stub left in place
    # replaces `shared` for every module collected afterwards; this one carries
    # `db` and `app` and nothing else, and a later `from shared import db,
    # db_retry` then fails with an ImportError naming neither this file nor the
    # stub. A collection error is fatal to the entire run.
    def restore():
        sys.modules.pop("shared", None)

    return restore


_restore_stubs = _install_shared_stub()

from model.MediaVote import (  # noqa: E402
    DOWNVOTE,
    UPVOTE,
    hash_for_media,
    normalize_media_hash,
    normalize_vote_value,
)

_restore_stubs()



class FakeMedia(object):
    def __init__(self, sha256):
        self.sha256 = sha256


VALID = "a" * 64
MIXED_CASE = "A1B2" + "c" * 60


class NormalizeVoteValueTest(unittest.TestCase):
    def test_accepts_the_three_legal_values(self):
        self.assertEqual(normalize_vote_value(1), UPVOTE)
        self.assertEqual(normalize_vote_value(-1), DOWNVOTE)
        self.assertEqual(normalize_vote_value(0), 0)

    def test_accepts_string_forms_from_a_form_post(self):
        self.assertEqual(normalize_vote_value("1"), UPVOTE)
        self.assertEqual(normalize_vote_value("-1"), DOWNVOTE)

    def test_rejects_out_of_range_and_junk(self):
        # A "+5" vote would let one slip outweigh five others.
        for bad in (5, -2, 2, "yes", None, "", 1.5):
            with self.assertRaises(ValueError):
                normalize_vote_value(bad)


class NormalizeMediaHashTest(unittest.TestCase):
    def test_accepts_a_real_digest(self):
        self.assertEqual(normalize_media_hash(VALID), VALID)

    def test_lowercases_so_one_file_has_one_key(self):
        # Two spellings of the same digest must not become two vote buckets.
        self.assertEqual(normalize_media_hash(MIXED_CASE), MIXED_CASE.lower())

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(normalize_media_hash("  " + VALID + "\n"), VALID)

    def test_rejects_anything_that_is_not_a_digest(self):
        for bad in (None, "", "abc", VALID[:-1], VALID + "a", "z" * 64, "../etc/passwd"):
            with self.assertRaises(ValueError):
                normalize_media_hash(bad)


class HashForMediaTest(unittest.TestCase):
    def test_returns_the_normalized_hash(self):
        self.assertEqual(hash_for_media(FakeMedia(MIXED_CASE)), MIXED_CASE.lower())

    def test_unhashed_media_is_not_votable_rather_than_sharing_a_bucket(self):
        # The whole point: media with no usable hash returns None so the caller
        # refuses the vote. If these collapsed to a shared key (e.g. ""), every
        # unhashed file on the site would share one score.
        self.assertIsNone(hash_for_media(FakeMedia(None)))
        self.assertIsNone(hash_for_media(FakeMedia("")))
        self.assertIsNone(hash_for_media(FakeMedia("not-a-hash")))
        self.assertIsNone(hash_for_media(None))

    def test_a_reupload_of_the_same_bytes_yields_the_same_key(self):
        # The property the feature exists for: same content -> same vote key,
        # even though these are two different Media rows.
        original = FakeMedia(VALID)
        reupload = FakeMedia(VALID)
        self.assertEqual(hash_for_media(original), hash_for_media(reupload))

    def test_different_content_yields_different_keys(self):
        self.assertNotEqual(hash_for_media(FakeMedia("a" * 64)), hash_for_media(FakeMedia("b" * 64)))


if __name__ == "__main__":
    unittest.main()
