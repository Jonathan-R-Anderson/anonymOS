"""Selection and pricing: who runs a job, and what it costs.

Loaded standalone with its database-touching lookups stubbed, so the maths that
decides who gets paid can be tested without a database. The two properties that
matter most are here: a draw that is reproducible by whoever was NOT picked, and
a price that moves with what the network actually has.
"""

import importlib.util
import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def load_market():
    spec = importlib.util.spec_from_file_location(
        "compute_market_under_test",
        os.path.join(BACKEND, "services", "compute_market.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pool_of(n, cores=4):
    return [{"id": "n%d" % i, "cpu": True, "gpu": True, "cores": cores}
            for i in range(n)]


class SelectionTest(unittest.TestCase):
    def setUp(self):
        self.cm = load_market()
        self.pool = pool_of(5)
        self.cm.eligible_providers = lambda device: self.pool
        self.cm.demand = lambda device: 0

    def test_draw_is_reproducible_whatever_order_the_pool_arrives_in(self):
        # Payment follows selection, so the person NOT picked must be able to
        # re-derive the result. A draw that depends on database row order is not
        # reproducible and therefore not auditable.
        a = self.cm.select_provider("cpu", "job-1", self.pool)
        b = self.cm.select_provider("cpu", "job-1", list(reversed(self.pool)))
        self.assertEqual(a["id"], b["id"])

    def test_draw_spreads_across_the_pool(self):
        # A "random" draw that concentrates on one node is the configured-node
        # problem wearing a hash function.
        picked = {self.cm.select_provider("cpu", "job-%d" % i, self.pool)["id"]
                  for i in range(60)}
        self.assertGreaterEqual(len(picked), 4, "draw is concentrated: %s" % picked)

    def test_empty_pool_selects_nobody(self):
        self.assertIsNone(self.cm.select_provider("cpu", "j", []))


class PricingTest(unittest.TestCase):
    def setUp(self):
        self.cm = load_market()
        self.pool = pool_of(5)
        self.cm.eligible_providers = lambda device: self.pool
        self.cm.demand = lambda device: 0

    def test_a_busy_network_costs_more(self):
        idle = self.cm.scarcity_multiplier("cpu", 1)
        self.cm.demand = lambda device: 18
        busy = self.cm.scarcity_multiplier("cpu", 1)
        self.assertGreater(busy, idle)

    def test_asking_for_more_costs_more(self):
        # Pricing against demand that excludes your own request lets a job
        # asking for half the network pay the one-core rate.
        self.assertGreater(self.cm.scarcity_multiplier("cpu", 16),
                           self.cm.scarcity_multiplier("cpu", 1))

    def test_multiplier_is_clamped_at_both_ends(self):
        self.cm.demand = lambda device: 10 ** 6
        self.assertLessEqual(self.cm.scarcity_multiplier("cpu", 1), self.cm.MAX_MULTIPLIER)
        self.cm.demand = lambda device: 0
        self.assertGreaterEqual(self.cm.scarcity_multiplier("cpu", 1), self.cm.MIN_MULTIPLIER)

    def test_gpu_is_dearer_than_cpu(self):
        self.assertGreater(self.cm.quote("gpu", 1, 60)["credits"],
                           self.cm.quote("cpu", 1, 60)["credits"])

    def test_an_empty_network_quotes_the_ceiling_and_says_so(self):
        self.cm.eligible_providers = lambda device: []
        self.assertEqual(self.cm.scarcity_multiplier("gpu", 1), self.cm.MAX_MULTIPLIER)
        quote = self.cm.quote("gpu", 2, 60)
        self.assertGreaterEqual(quote["credits"], 1)
        self.assertIn("queued", quote["advisory"])

    def test_a_single_provider_is_reported_as_not_meaningfully_random(self):
        # The honest case: a verifiable draw from a pool of one picks that one
        # every time, correctly and uselessly.
        self.cm.eligible_providers = lambda device: [self.pool[0]]
        self.assertIn("not meaningfully random", self.cm.advisory("cpu"))

    def test_a_healthy_pool_carries_no_advisory(self):
        self.assertEqual(self.cm.advisory("cpu"), "")


if __name__ == "__main__":
    unittest.main()
