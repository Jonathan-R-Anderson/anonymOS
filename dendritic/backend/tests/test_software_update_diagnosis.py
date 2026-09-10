"""The admin card must explain a stuck queue, not just report it.

"Queued -- waiting for the updater" was shown identically whether the updater
was 30 seconds from its next tick or had not run for a week, so the one state
an operator actually needs to debug was the one state that carried no
information. These tests pin the distinction.
"""
import json
import os
import sys
import time
import types
import unittest
from unittest.mock import MagicMock


def _install_shared_stub():
    """Same stub as test_software_update.py: this module needs none of the app,
    only shared.app.logger, and importing the real one drags in the whole ORM."""
    if "shared" in sys.modules:
        return
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    shared.db = db
    shared.app = MagicMock()
    sys.modules["shared"] = shared


_install_shared_stub()

from services import software_update  # noqa: E402


class SoftwareUpdateDiagnosisTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.request_dir = os.path.join(self.tmp.name, "deploy-requests")
        self.status_dir = os.path.join(self.tmp.name, "deploy")
        os.makedirs(self.request_dir)
        os.makedirs(self.status_dir)

        self._saved = (software_update.REQUEST_DIR, software_update.STATUS_DIR)
        software_update.REQUEST_DIR = self.request_dir
        software_update.STATUS_DIR = self.status_dir

    def tearDown(self):
        software_update.REQUEST_DIR, software_update.STATUS_DIR = self._saved

    def _queue(self, age_seconds=0):
        path = os.path.join(self.request_dir, "request-abc123.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"id": "abc123", "force": False}, handle)
        if age_seconds:
            old = time.time() - age_seconds
            os.utime(path, (old, old))
        return path

    def _heartbeat(self, age_seconds=0, text="updater alive, no change\n"):
        path = os.path.join(self.status_dir, software_update.HEARTBEAT_FILE)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        if age_seconds:
            old = time.time() - age_seconds
            os.utime(path, (old, old))
        return path

    def test_fresh_queue_with_live_updater_is_only_informational(self):
        self._queue()
        self._heartbeat(age_seconds=20)
        payload = software_update.admin_payload()
        self.assertTrue(payload["queued"])
        self.assertFalse(payload["updater_stale"])
        self.assertEqual("info", payload["diagnosis_severity"])
        self.assertIn("next updater tick", payload["diagnosis"])

    def test_queue_with_dead_updater_is_reported_as_an_error(self):
        # The real-world stuck case: the CronJob is suspended or not scheduled.
        self._queue(age_seconds=3600)
        self._heartbeat(age_seconds=86400)
        payload = software_update.admin_payload()
        self.assertTrue(payload["queued"])
        self.assertTrue(payload["updater_stale"])
        self.assertEqual("error", payload["diagnosis_severity"])
        self.assertIn("should tick every minute", payload["diagnosis"])

    def test_updater_that_never_published_is_distinguished_from_a_stale_one(self):
        self._queue()
        payload = software_update.admin_payload()
        self.assertFalse(payload["updater_seen"])
        self.assertEqual("error", payload["diagnosis_severity"])
        self.assertIn("never published", payload["diagnosis"])
        self.assertEqual("never", payload["updater_age"])

    def test_live_updater_that_ignores_the_request_points_at_the_mount(self):
        # The updater is ticking, but the request has outlived several ticks:
        # it is running against a different directory than the backend writes.
        self._queue(age_seconds=3600)
        self._heartbeat(age_seconds=10)
        payload = software_update.admin_payload()
        self.assertFalse(payload["updater_stale"])
        self.assertEqual("error", payload["diagnosis_severity"])
        self.assertIn("hostPath", payload["diagnosis"])

    def test_status_json_alone_counts_as_liveness(self):
        # A busy updater rewrites status.json and writes no heartbeat.
        with open(os.path.join(self.status_dir, software_update.STATUS_FILE), "w",
                  encoding="utf-8") as handle:
            json.dump({"result": "ok"}, handle)
        payload = software_update.admin_payload()
        self.assertTrue(payload["updater_seen"])
        self.assertFalse(payload["updater_stale"])

    def test_missing_request_dir_explains_the_mount_rather_than_the_updater(self):
        software_update.REQUEST_DIR = os.path.join(self.tmp.name, "absent")
        payload = software_update.admin_payload()
        self.assertFalse(payload["available"])
        self.assertEqual("warn", payload["diagnosis_severity"])
        self.assertIn("not mounted", payload["diagnosis"])

    def test_payload_reports_the_queue_age_and_both_directories(self):
        self._queue(age_seconds=125)
        self._heartbeat(age_seconds=5)
        payload = software_update.admin_payload()
        self.assertGreaterEqual(payload["queued_seconds"], 125)
        self.assertEqual("2m ago", payload["queued_age"])
        self.assertEqual(self.request_dir, payload["request_dir"])
        self.assertEqual(self.status_dir, payload["status_dir"])

    def test_cancel_clears_a_wedged_request_and_reenables_queueing(self):
        self._queue(age_seconds=3600)
        self._heartbeat(age_seconds=86400)
        self.assertTrue(software_update.admin_payload()["queued"])
        # While queued, a second request is refused -- which is what wedges the
        # button with no way out.
        ok, _ = software_update.request_update()
        self.assertFalse(ok)

        removed, message = software_update.cancel_requests()
        self.assertEqual(1, removed)
        self.assertIn("Cleared", message)
        self.assertFalse(software_update.admin_payload()["queued"])
        ok, _ = software_update.request_update()
        self.assertTrue(ok)

    def test_cancel_on_an_empty_queue_is_harmless(self):
        removed, message = software_update.cancel_requests()
        self.assertEqual(0, removed)
        self.assertIn("nothing queued", message)

    def test_heartbeat_text_is_surfaced_verbatim(self):
        self._heartbeat(text="updater alive, last poll 2026-07-28, deployed sha abc\n")
        payload = software_update.admin_payload()
        self.assertIn("deployed sha abc", payload["updater_heartbeat"])


if __name__ == "__main__":
    unittest.main()
