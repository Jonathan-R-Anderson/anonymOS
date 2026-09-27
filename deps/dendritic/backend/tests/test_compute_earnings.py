"""Paying the node that ran the work.

The share arithmetic is loaded standalone, so the rules that decide what a
volunteer earns can be tested without a database.
"""

import importlib.util
import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def load():
    spec = importlib.util.spec_from_file_location(
        "earnings_under_test", os.path.join(BACKEND, "services", "compute_earnings.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class ShareTest(unittest.TestCase):
    def setUp(self):
        self.e = load()

    def test_provider_gets_the_majority_of_the_work_charge(self):
        # A provider who feels the split is unfair stops providing, and the
        # network then has no compute.
        self.assertEqual(self.e.provider_share(100), 80)
        self.assertGreater(self.e.PROVIDER_SHARE, 0.5)

    def test_priority_tier_is_excluded_from_the_provider_share(self):
        # The tier buys queue POSITION, which the network provides — not
        # compute, which the node provides. Paying it out would mean a submitter
        # who jumped the queue paid the node more for identical work.
        self.assertEqual(self.e.provider_share(150, priority_cost=50), 80)

    def test_a_failed_job_still_pays_but_less(self):
        # The electricity was spent either way. Refusing to pay would make
        # running risky-looking work irrational, so nodes would cherry-pick —
        # and the jobs nobody takes are the ones that most need running.
        failed = self.e.provider_share(100, succeeded=False)
        self.assertGreater(failed, 0)
        self.assertLess(failed, self.e.provider_share(100))

    def test_failing_is_not_a_strategy(self):
        # Low enough that failing on purpose earns meaningfully less than
        # succeeding.
        self.assertLess(self.e.FAILED_SHARE, self.e.PROVIDER_SHARE / 2)

    def test_zero_and_negative_charges_do_not_produce_earnings(self):
        self.assertEqual(self.e.provider_share(0), 0)
        self.assertEqual(self.e.provider_share(None), 0)
        # A priority cost exceeding the charge must not produce a negative
        # earning — a payment ledger that can go backwards is not a ledger.
        self.assertEqual(self.e.provider_share(10, priority_cost=50), 0)

    def test_the_site_keeps_a_margin(self):
        # The margin funds the network's own work. Asserted so a future change
        # to PROVIDER_SHARE cannot silently make the network unfunded.
        self.assertLess(self.e.PROVIDER_SHARE, 1.0)


class VerdictTest(unittest.TestCase):
    """A verdict that did not change payment would make verification
    decorative — the cheapest strategy would still be returning garbage."""

    def setUp(self):
        self.e = load()

    def test_a_contradicted_result_is_not_paid(self):
        self.assertFalse(self.e.payable("disagreed"))

    def test_everything_else_is_paid(self):
        # Unverified and insufficient are statements about the NETWORK, not
        # accusations against the node. A GPU result cannot be compared and a
        # CPU result with no second node available was never checked — refusing
        # to pay either would punish providers for the network being small.
        for verdict in ("agreed", "unverified", "insufficient", None):
            self.assertTrue(self.e.payable(verdict), verdict)


if __name__ == "__main__":
    unittest.main()
