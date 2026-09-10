"""Who holds a copy of the backup.

The artifact is opaque, so a custodian learns nothing by holding it. What they
gain is the ability to WITHHOLD it — and the moment that matters is exactly the
moment this server is gone. So these tests are about independence, not score.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


CU = _load_pure("services/backup_custody.py",
                {"DEFAULTS", "choose", "_operator_of", "challenge"})

MB = 1024 * 1024
LIMITS = {"backup_replicas": 5, "backup_distinct_operators": 3,
          "backup_minimum_reputation": 0.4, "backup_capacity_headroom": 2.0}


def gateway(identifier, operator=None, reputation=0.9, free_mb=500):
    return {"id": identifier, "operator": operator,
            "reputation": reputation, "free_bytes": free_mb * MB}


class SpreadTest(unittest.TestCase):
    """Reputation says who is reliable. It says nothing about who is a
    different somebody."""

    def test_one_operator_does_not_take_every_slot(self):
        # The obvious approach — five highest-reputation gateways — puts all
        # five copies with one person, who can then withhold all of them.
        candidates = [gateway("a%d" % i, operator="alice", reputation=0.99)
                      for i in range(5)]
        candidates += [gateway("b1", operator="bob", reputation=0.5),
                       gateway("c1", operator="carol", reputation=0.45)]
        result = CU["choose"](candidates, 10 * MB, LIMITS)
        operators = {c["operator"] for c in result["chosen"]}
        self.assertIn("bob", operators)
        self.assertIn("carol", operators)
        self.assertEqual(result["distinct_operators"], 3)

    def test_spread_is_secured_before_the_count_is_filled(self):
        """Filling by score and hoping for variety is how five slots go to one
        person's five machines."""
        candidates = [gateway("a%d" % i, operator="alice", reputation=0.99)
                      for i in range(10)]
        candidates.append(gateway("z", operator="zoe", reputation=0.41))
        result = CU["choose"](candidates, 10 * MB, LIMITS)
        self.assertIn("z", [c["id"] for c in result["chosen"]])

    def test_remaining_slots_are_filled_after_spread(self):
        candidates = [gateway("a1", operator="alice"),
                      gateway("a2", operator="alice"),
                      gateway("b1", operator="bob")]
        result = CU["choose"](candidates, 10 * MB, LIMITS)
        self.assertEqual(len(result["chosen"]), 3)

    def test_too_few_operators_warns_but_still_places_copies(self):
        """Refusing would leave a young network with NO copies, which is worse:
        the artifact is opaque either way, so the risk here is availability."""
        result = CU["choose"]([gateway("a1", operator="alice"),
                               gateway("a2", operator="alice")],
                              10 * MB, LIMITS)
        self.assertEqual(len(result["chosen"]), 2)
        self.assertTrue(any("withhold" in w for w in result["warnings"]))

    def test_an_unknown_operator_counts_as_its_own(self):
        """Treating unknowns as one shared operator would collapse them into a
        single slot and place fewer copies than intended."""
        result = CU["choose"]([gateway("a1"), gateway("a2"), gateway("a3")],
                              10 * MB, LIMITS)
        self.assertEqual(result["distinct_operators"], 3)

    def test_no_custodians_is_said_plainly(self):
        result = CU["choose"]([], 10 * MB, LIMITS)
        self.assertEqual(result["chosen"], [])
        self.assertTrue(any("only copy" in w for w in result["warnings"]))


class EligibilityTest(unittest.TestCase):
    def test_low_reputation_is_excluded_with_a_reason(self):
        """Not a judgement about the person — a node that keeps disappearing
        cannot be relied on to still have the file on the day it is needed."""
        result = CU["choose"]([gateway("bad", operator="x", reputation=0.1)],
                              10 * MB, LIMITS)
        self.assertEqual(result["chosen"], [])
        self.assertIn("reputation", result["skipped"][0]["why"])

    def test_a_gateway_without_room_is_excluded(self):
        result = CU["choose"]([gateway("tight", operator="x", free_mb=15)],
                              10 * MB, LIMITS)
        self.assertEqual(result["chosen"], [])
        self.assertIn("free", result["skipped"][0]["why"])

    def test_headroom_is_applied_not_just_the_raw_size(self):
        """A custodian filled to exactly the artifact size has no room for the
        next one, and replacing a backup means holding both briefly."""
        candidates = [gateway("exact", operator="x", free_mb=10)]
        self.assertEqual(CU["choose"](candidates, 10 * MB, LIMITS)["chosen"], [])
        candidates = [gateway("roomy", operator="x", free_mb=21)]
        self.assertEqual(len(CU["choose"](candidates, 10 * MB, LIMITS)["chosen"]), 1)

    def test_a_candidate_with_no_id_is_ignored_not_crashed_on(self):
        result = CU["choose"]([{"operator": "x"}, gateway("ok", operator="y")],
                              10 * MB, LIMITS)
        self.assertEqual([c["id"] for c in result["chosen"]], ["ok"])

    def test_it_never_raises_on_junk(self):
        """This runs on a schedule. A selection that threw would stop backups
        being placed at all rather than placing fewer."""
        for candidates in (None, [], [{}], [{"id": "a", "reputation": None,
                                             "free_bytes": None}]):
            with self.subTest(candidates=candidates):
                CU["choose"](candidates, 10 * MB, LIMITS)


class StabilityTest(unittest.TestCase):
    def test_the_same_input_chooses_the_same_custodians(self):
        """A list that churns every cycle means copies are constantly being
        moved rather than held."""
        candidates = [gateway("g%d" % i, operator="op%d" % i, reputation=0.9)
                      for i in range(8)]
        first = [c["id"] for c in CU["choose"](candidates, 10 * MB, LIMITS)["chosen"]]
        shuffled = list(reversed(candidates))
        second = [c["id"] for c in CU["choose"](shuffled, 10 * MB, LIMITS)["chosen"]]
        self.assertEqual(first, second)


class ChallengeTest(unittest.TestCase):
    def test_a_matching_digest_passes(self):
        self.assertTrue(CU["challenge"]("AB" * 32, "ab" * 32))

    def test_a_mismatch_fails(self):
        self.assertFalse(CU["challenge"]("ab" * 32, "cd" * 32))

    def test_empty_answers_never_pass(self):
        """Otherwise a custodian that holds nothing answers with nothing and
        is recorded as holding a good copy."""
        self.assertFalse(CU["challenge"]("", ""))
        self.assertFalse(CU["challenge"](None, None))
        self.assertFalse(CU["challenge"]("", "ab" * 32))


if __name__ == "__main__":
    unittest.main()
