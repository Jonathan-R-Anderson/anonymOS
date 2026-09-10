"""The levelling plan. Read-only, so these test arithmetic and exclusions."""
import time
import unittest

from services.pool_levelling import (
    DEADBAND, MIN_MOVE_BYTES, Node, eligible, plan, target_bytes,
)

GB = 1 << 30
NOW = 1_800_000_000


def node(nid, used_gb, cap_gb, age=0):
    return Node(nid, int(used_gb * GB), int(cap_gb * GB), NOW - age)


class EligibilityTest(unittest.TestCase):
    def test_a_node_that_never_reported_usage_is_excluded_not_treated_as_empty(self):
        # The whole reason used_bytes is nullable. Treating absent as empty would
        # aim every surplus byte at a node merely running an older build.
        n = Node("old-build", None, 100 * GB, NOW)
        self.assertEqual(eligible([n], now=NOW), [])

    def test_a_measured_empty_node_IS_eligible(self):
        n = node("empty", 0, 100)
        self.assertEqual([x.node_id for x in eligible([n], now=NOW)], ["empty"])

    def test_a_stale_node_is_excluded(self):
        # Production carries 21 rows for 9 running machines; including the dead
        # ones computes the mean over machines that do not exist.
        self.assertEqual(eligible([node("gone", 5, 100, age=3600)], now=NOW), [])

    def test_a_node_donating_no_disk_is_not_in_the_set(self):
        self.assertEqual(eligible([node("gateway", 0, 0)], now=NOW), [])


class TargetTest(unittest.TestCase):
    def test_the_target_is_the_mean_when_nothing_is_capacity_bound(self):
        nodes = [node("a", 30, 100), node("b", 0, 100)]
        self.assertEqual(target_bytes(nodes), 15 * GB)

    def test_a_node_smaller_than_the_mean_is_pinned_and_the_rest_absorb_it(self):
        # 90 GB across a 10 GB node and two 500 GB nodes: the small one cannot
        # hold 30, so it is pinned at 10 and the others carry 40 each. Without
        # this the plan would never converge.
        nodes = [node("small", 0, 10), node("big1", 90, 500), node("big2", 0, 500)]
        self.assertEqual(target_bytes(nodes), 40 * GB)

    def test_no_nodes_is_zero_rather_than_a_division_error(self):
        self.assertEqual(target_bytes([]), 0)


class PlanTest(unittest.TestCase):
    def test_a_fat_node_and_a_thin_node_produce_one_move(self):
        result = plan([node("fat", 80, 500), node("thin", 0, 500)], now=NOW)
        self.assertEqual(len(result["moves"]), 1)
        move = result["moves"][0]
        self.assertEqual((move["from"], move["to"]), ("fat", "thin"))
        self.assertEqual(move["bytes"], 40 * GB)

    def test_a_balanced_fleet_moves_nothing(self):
        result = plan([node("a", 50, 500), node("b", 50, 500)], now=NOW)
        self.assertEqual(result["moves"], [])
        self.assertTrue(all(r["role"] == "balanced" for r in result["nodes"]))

    def test_the_deadband_stops_trivial_churn(self):
        # A few bytes apart must not trade shards forever; every trade costs a
        # lease and two I2P round trips.
        result = plan([node("a", 50, 500), node("b", 49.9, 500)], now=NOW)
        self.assertEqual(result["moves"], [])

    def test_a_sink_is_never_sent_more_than_its_headroom(self):
        # 200 GB of surplus, but the only sink has 10 GB of room.
        result = plan([node("fat", 200, 4000), node("tiny", 0, 10)], now=NOW)
        for move in result["moves"]:
            self.assertLessEqual(move["bytes"], 10 * GB, move)

    def test_small_pools_fill_before_large_ones_are_touched(self):
        # The point of equal-BYTES: the 20 GB volunteer takes its share rather
        # than a proportional sliver.
        result = plan([node("fat", 300, 4000), node("small", 0, 20),
                       node("mid", 0, 500)], now=NOW)
        by_dest = {m["to"]: m["bytes"] for m in result["moves"]}
        self.assertIn("small", by_dest)
        self.assertGreaterEqual(by_dest["small"], 19 * GB,
                                "the small pool should be filled, not given a fraction")

    def test_stale_and_unmeasured_nodes_are_counted_as_excluded(self):
        result = plan([
            node("live", 10, 100),
            node("stale", 90, 100, age=7200),
            Node("silent", None, 100, NOW),
        ], now=NOW)
        self.assertEqual(result["excluded"], 2)

    def test_a_retiring_node_is_never_proposed_as_a_destination(self):
        # Phase 2b step 4. A draining node is emptied by its shards' OWNERS, and
        # the nodes have already stopped writing to it -- so a site report that
        # proposed it as the emptiest sink would contradict the fleet, and an
        # operator comparing the two would have to work out which was lying.
        #
        # Reverted to prove it fails: the `if node.draining` skip in eligible().
        # The empty retiring node is then the largest deficit on the network and
        # collects every surplus byte in the plan.
        retiring = Node("leaving", 0, 500 * GB, NOW, draining=True)
        result = plan([node("fat", 300, 4000), node("mid", 40, 500), retiring], now=NOW)
        for move in result["moves"]:
            self.assertNotEqual(move["to"], "leaving",
                                "the plan sends bytes to a machine being switched off")
        self.assertNotIn("leaving", [r["node_id"] for r in result["nodes"]])
        # Named rather than silently dropped: "being emptied on purpose" and
        # "stopped checking in" need opposite reactions from a reader.
        self.assertEqual(result["draining"], ["leaving"])

    def test_a_retiring_node_does_not_drag_the_target_down(self):
        # Its bytes are on their way back to the machines that remain, so
        # including its empty pool in the mean would set a target the rest of the
        # fleet cannot hold once they arrive.
        without = plan([node("a", 100, 500), node("b", 40, 500)], now=NOW)["target"]
        with_leaver = plan([
            node("a", 100, 500), node("b", 40, 500),
            Node("leaving", 0, 500 * GB, NOW, draining=True),
        ], now=NOW)["target"]
        self.assertEqual(without, with_leaver)

    def test_the_plan_says_it_does_not_pick_shards(self):
        # A plan that looks shard-level but is not would invite someone to build
        # the mover against the wrong contract.
        self.assertIn("shard selection happens on the node", plan([], now=NOW)["note"])


if __name__ == "__main__":
    unittest.main()
