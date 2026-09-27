"""Placement: which node runs a job, and the rule that decides it.

Loaded standalone with the database lookup stubbed, so the rule that governs
whether arbitrary code may run can be tested without a database.
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
        "placement_under_test", os.path.join(BACKEND, "services", "compute_placement.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def node(nid, cpu=True, gpu=False, microvm=False):
    return {"id": nid, "cpu": cpu, "gpu": gpu, "microvm": microvm}


class IsolationRuleTest(unittest.TestCase):
    def setUp(self):
        self.p = load()

    def test_arbitrary_code_needs_a_microvm(self):
        # THE rule. A container is not a boundary for code somebody else wrote.
        self.assertEqual(self.p.required_isolation(True), self.p.ISOLATION_MICROVM)
        self.assertEqual(self.p.required_isolation(False), self.p.ISOLATION_CONTAINER)

    def test_container_nodes_are_excluded_from_arbitrary_work(self):
        pool = [node("a"), node("b"), node("c")]
        self.p.eligible_nodes = lambda d, arb: [
            n for n in pool if self.p.isolation_of(n) >= self.p.required_isolation(arb)]
        with self.assertRaises(self.p.NoEligibleNode):
            self.p.place("job1", "cpu", True, self.p.eligible_nodes("cpu", True))

    def test_a_microvm_node_can_take_arbitrary_work(self):
        pool = [node("a"), node("vm1", microvm=True)]
        eligible = [n for n in pool if self.p.isolation_of(n) >= self.p.ISOLATION_MICROVM]
        chosen, iso = self.p.place("job1", "cpu", True, eligible)
        self.assertEqual(chosen["id"], "vm1")
        self.assertEqual(iso, "microvm")

    def test_catalogue_work_still_runs_on_container_nodes(self):
        # Refusing this would empty the compute pool: most volunteers have no KVM.
        pool = [node("a"), node("b")]
        chosen, iso = self.p.place("job1", "cpu", False, pool)
        self.assertIn(chosen["id"], ("a", "b"))
        self.assertEqual(iso, "container")

    def test_refusal_explains_why_rather_than_failing_generically(self):
        with self.assertRaises(self.p.NoEligibleNode) as ctx:
            self.p.place("job1", "cpu", True, [])
        self.assertIn("virtual machine", str(ctx.exception))
        self.assertIn("queued", str(ctx.exception))


class SelectionTest(unittest.TestCase):
    def setUp(self):
        self.p = load()
        self.pool = [node("n%d" % i, microvm=True) for i in range(5)]

    def test_placement_is_reproducible_whatever_order_the_pool_arrives_in(self):
        a, _ = self.p.place("job-1", "cpu", True, self.pool)
        b, _ = self.p.place("job-1", "cpu", True, list(reversed(self.pool)))
        self.assertEqual(a["id"], b["id"])

    def test_placement_spreads_across_the_pool(self):
        picked = {self.p.place("job-%d" % i, "cpu", True, self.pool)[0]["id"]
                  for i in range(60)}
        self.assertGreaterEqual(len(picked), 4, "placement is concentrated: %s" % picked)


class SummaryTest(unittest.TestCase):
    """The summary reads the same listing the bootstrap document publishes.

    Stubbing that one source rather than the database is the point: if what the
    network advertises and what the site dispatches to ever came from different
    queries, they would drift, and the symptom would be work sent to nodes that
    publicly say they do not take it.
    """

    def setUp(self):
        self.p = load()

    def _publish(self, peers):
        import types
        fake = types.ModuleType("services.storage_coordination")
        fake.live_compute_peers = lambda limit=32, device=None, microvm_only=False: [
            x for x in peers
            if (not microvm_only or x.get("microvm"))
            and (device is None
                 or (device == "cpu" and x.get("cpu"))
                 or (device.startswith("gpu") and x.get("gpu")))
        ]
        # Put the real module back afterwards. Leaving the stub in sys.modules
        # made import order load-bearing for the whole suite: anything that
        # later imported services.storage_coordination for real -- or a module
        # that imports it, such as blueprints.storage_nodes -- got this
        # five-line fake instead and failed with "cannot import name ...
        # (unknown location)", a very long way from here.
        saved = sys.modules.get("services.storage_coordination")
        self.addCleanup(
            lambda: sys.modules.__setitem__("services.storage_coordination", saved)
            if saved is not None
            else sys.modules.pop("services.storage_coordination", None))
        sys.modules["services.storage_coordination"] = fake

    def test_summary_reports_both_numbers(self):
        # A submitter choosing "arbitrary" needs the microVM count; one running a
        # catalogue image needs the total. Collapsing them hides the choice.
        self._publish([
            {"node_id": "a", "cpu": True, "gpu": False, "microvm": False, "destination": "d1"},
            {"node_id": "b", "cpu": True, "gpu": False, "microvm": False, "destination": "d2"},
            {"node_id": "vm", "cpu": True, "gpu": False, "microvm": True, "destination": "d3"},
        ])
        s = self.p.capability_summary("cpu")
        self.assertEqual(s["nodes"], 3)
        self.assertEqual(s["microvm_nodes"], 1)
        self.assertTrue(s["arbitrary_possible"])

    def test_summary_says_so_when_arbitrary_is_impossible(self):
        self._publish([
            {"node_id": "a", "cpu": True, "gpu": False, "microvm": False, "destination": "d1"},
        ])
        s = self.p.capability_summary("cpu")
        self.assertFalse(s["arbitrary_possible"])
        self.assertIn("hardware isolation", s["note"])

    def test_eligible_nodes_carry_a_dialable_address(self):
        # A node listed without a destination cannot be reached, so placing work
        # on it would only produce failures at dispatch.
        self._publish([
            {"node_id": "vm", "cpu": True, "gpu": False, "microvm": True, "destination": "d3"},
        ])
        nodes = self.p.eligible_nodes("cpu", True)
        self.assertEqual(len(nodes), 1)
        self.assertTrue(nodes[0]["i2p_destination"])


if __name__ == "__main__":
    unittest.main()
