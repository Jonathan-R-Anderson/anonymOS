"""Result classification for the admin software-update card.

The bug this pins down: admin_payload() tested `result in ("failed",
"rolled_back")` -- two strings the updater NEVER emits. update.sh publishes ~33
distinct values (verify_failed_backend, halted_data_tier, rollout_failed_*, ...),
so a deploy that failed and rolled back rendered as a GREEN "Last update:
verify_failed_backend" with the failure log suppressed. The whole point of the
feature is a readable error log without SSH, so a failure that renders as
success is the worst possible outcome.

The rule enforced here: anything not explicitly known-good is a failure. A new
result value added to update.sh must surface its log by default, never hide it.
"""
import sys
import types
import unittest
from unittest.mock import MagicMock


def _install_shared_stub():
    if "shared" in sys.modules:
        return
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    shared.db = db
    shared.app = MagicMock()
    sys.modules["shared"] = shared


_install_shared_stub()

from services.software_update import classify_result  # noqa: E402


# Every RESULT= value in k8s/updater/update.sh, split by what it means.
GOOD = ["ok", "no_change", "adopted", "up_to_date", "no_op", "held"]

BAD = [
    "build_failed", "apply_failed", "apply_failed_nginx", "import_failed",
    "migrate_failed", "migration_failed",
    "verify_failed_backend", "verify_failed_edge", "verify_failed_pvc",
    "rollout_failed_nginx", "rollout_failed_statefulset_maniwani",
    "rollback_failed", "rolled_back", "failed_preflight", "failed_build",
    "halted_data_tier", "halted_bootstrap", "halted_disk", "halted_glados",
    "halted_edge_invariant", "halted_no_alembic_read", "halted_no_dump",
    "halted_no_postgres", "halted_non_fastforward", "halted_pvc_drift",
    "halted_pvc_unbound", "halted_resumed_rollback", "halted_unsigned",
    "halted_updater_objects", "error", "unknown",
]


class ClassifyResultTest(unittest.TestCase):
    def test_successful_outcomes_are_ok(self):
        for value in GOOD:
            self.assertEqual(classify_result(value), "ok", value)

    def test_every_failure_the_updater_can_emit_is_classified_failed(self):
        # This is the regression: these all rendered green before.
        for value in BAD:
            self.assertEqual(classify_result(value), "failed", value)

    def test_running_is_distinct_from_both(self):
        for value in ("running", "in_progress"):
            self.assertEqual(classify_result(value), "running", value)

    def test_never_run_is_unknown_not_failed(self):
        # No status file yet must not render as a failure -- there is nothing
        # to show a log for, and the card says "never run".
        for value in (None, "", "   "):
            self.assertEqual(classify_result(value), "unknown")

    def test_an_unrecognised_result_fails_loud(self):
        # The important property: a value added to update.sh later that nobody
        # taught this module about must surface its failure log, not hide it.
        self.assertEqual(classify_result("some_future_failure_mode"), "failed")

    def test_classification_is_case_insensitive_and_trimmed(self):
        self.assertEqual(classify_result("  OK  "), "ok")
        self.assertEqual(classify_result("Verify_Failed_Edge"), "failed")


if __name__ == "__main__":
    unittest.main()
