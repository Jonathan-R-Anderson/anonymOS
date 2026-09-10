"""Intake rate limiting.

Two properties matter more than the arithmetic:

* it stores no IP address -- the bucket is keyed by the existing non-reversible
  HMAC token, so the abuse control does not build the list of "people who
  reported the police" that the rest of the design exists to avoid;
* it fails OPEN -- a key store outage must not take intake offline. For a board
  post, failing closed is fine. For somebody reporting an assault, losing the
  submission is not.
"""

import json
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

from services import report_rate_limit as rl  # noqa: E402


class FakeStore(object):
    def __init__(self, fail=False):
        self.data = {}
        self.fail = fail

    def get(self, key):
        if self.fail:
            raise RuntimeError("key store down")
        return self.data.get(key)

    def set(self, key, value):
        if self.fail:
            raise RuntimeError("key store down")
        self.data[key] = value


class RateLimitTest(unittest.TestCase):

    def setUp(self):
        self.store = FakeStore()
        self._patches = [
            mock.patch.object(rl, "_token", return_value="ip-abcdef123456"),
            mock.patch.dict(sys.modules, {"keystore": MagicMock(
                Keystore=lambda: self.store)}),
        ]
        for patch in self._patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self._patches):
            patch.stop()

    def test_a_first_submission_is_allowed(self):
        allowed, retry = rl.check(now=1000.0)
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)

    def test_the_hourly_limit_eventually_refuses(self):
        for i in range(rl.MAX_PER_WINDOW):
            rl.record(now=1000.0 + i)
        allowed, retry = rl.check(now=1000.0 + rl.MAX_PER_WINDOW)
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    def test_the_window_slides(self):
        for i in range(rl.MAX_PER_WINDOW):
            rl.record(now=1000.0 + i)
        # An hour and change later, the old submissions no longer count.
        allowed, _ = rl.check(now=1000.0 + rl.WINDOW_SECONDS + 60)
        self.assertTrue(allowed)

    def test_the_daily_cap_catches_a_paced_script(self):
        """Spread just under the hourly limit, all day."""
        now = 1000.0
        for i in range(rl.MAX_PER_DAY):
            rl.record(now=now + i * 600)
        allowed, retry = rl.check(now=now + rl.MAX_PER_DAY * 600)
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    # -- the two properties that matter ------------------------------------

    def test_no_raw_ip_is_stored(self):
        rl.record(now=1000.0)
        blob = json.dumps(self.store.data)
        for key in self.store.data:
            self.assertNotIn("192.168", key)
            self.assertNotIn("10.0.", key)
        self.assertNotIn("192.168", blob)
        # The key is the HMAC token, which is what poster_privacy produces.
        self.assertTrue(any("ip-abcdef123456" in key for key in self.store.data))

    def test_a_key_store_outage_allows_rather_than_blocks(self):
        self.store.fail = True
        allowed, retry = rl.check(now=1000.0)
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)

    def test_recording_during_an_outage_does_not_raise(self):
        self.store.fail = True
        rl.record(now=1000.0)  # must not raise

    def test_a_corrupt_bucket_is_treated_as_empty(self):
        self.store.data[rl._KEY_PREFIX + "ip-abcdef123456"] = "not json"
        allowed, _ = rl.check(now=1000.0)
        self.assertTrue(allowed)

    def test_the_bucket_does_not_grow_without_bound(self):
        """The key store has no TTL, so pruning happens on write."""
        for i in range(rl.MAX_PER_DAY * 3):
            rl.record(now=1000.0 + i)
        stored = json.loads(self.store.data[rl._KEY_PREFIX + "ip-abcdef123456"])
        self.assertLessEqual(len(stored), rl.MAX_PER_DAY + 5)

    def test_no_token_means_no_limiting_rather_than_no_service(self):
        with mock.patch.object(rl, "_token", return_value=None):
            allowed, _ = rl.check(now=1000.0)
            self.assertTrue(allowed)
            rl.record(now=1000.0)  # must not raise

    def test_the_refusal_message_does_not_blame_the_submitter(self):
        message = rl.message(600)
        self.assertNotIn("abuse", message.lower())
        self.assertNotIn("spam", message.lower())
        self.assertIn("not a judgement", message)


# These tests read files removed with the stripped features: blueprints/civil_rights.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_CIVIL_RIGHTS_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/civil_rights.py",
    )
)
_CIVIL_RIGHTS_PRESENT_GONE = "the civil-rights blueprint was removed; these read it"

class WiringTest(unittest.TestCase):
    """Where the limiter sits in the request relative to everything else."""

    def _source(self):
        return open(os.path.join(BACKEND, "blueprints", "civil_rights.py"),
                    encoding="utf-8").read()

    @unittest.skipUnless(_CIVIL_RIGHTS_PRESENT, _CIVIL_RIGHTS_PRESENT_GONE)
    def test_the_quota_is_only_spent_on_a_successful_submission(self):
        """A submission that failed for our reasons must not cost the person
        their ability to retry."""
        source = self._source()
        self.assertLess(source.index("reports.submit("),
                        source.index("rate_limit.record()"))

    @unittest.skipUnless(_CIVIL_RIGHTS_PRESENT, _CIVIL_RIGHTS_PRESENT_GONE)
    def test_the_captcha_is_checked_before_the_quota(self):
        """Otherwise a bot exhausts the bucket that real visitors behind the
        same address share."""
        source = self._source()
        self.assertLess(source.index("validate_solution(request.form)"),
                        source.index("rate_limit.check()"))


if __name__ == "__main__":
    unittest.main()
