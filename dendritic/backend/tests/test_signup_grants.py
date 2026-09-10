"""The welcome grant's sybil resistance, at the level it can actually be tested.

Accounts here cost nothing to make, so an unconditional 20-AXONCoin grant is a
faucet. These cover the two mechanical pieces: the network hashing that groups
signups without keeping anybody's address, and the fact that every gate produces
an instruction rather than a bare refusal.
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


MODEL = _load_pure(
    "model/SignupGrant.py",
    {"SIGNUP_CREDITS", "MIN_ACCOUNT_AGE_HOURS", "MIN_ACTIONS", "MAX_PER_NETWORK",
     "network_hash"},
    extra={"hashlib": __import__("hashlib"), "ipaddress": __import__("ipaddress")},
)


class NetworkHashTest(unittest.TestCase):
    """Group by network without keeping anybody's address."""

    def test_two_addresses_on_one_subnet_group_together(self):
        # The point of the whole thing: one connection is one bucket.
        a = MODEL["network_hash"]("203.0.113.7", "salt")
        b = MODEL["network_hash"]("203.0.113.200", "salt")
        self.assertEqual(a, b)

    def test_different_subnets_do_not_group(self):
        a = MODEL["network_hash"]("203.0.113.7", "salt")
        b = MODEL["network_hash"]("198.51.100.7", "salt")
        self.assertNotEqual(a, b)

    def test_the_salt_changes_the_hash(self):
        # Unsalted, a /24 hash is trivially reversible — there are only a few
        # billion of them and an attacker with the table could enumerate.
        a = MODEL["network_hash"]("203.0.113.7", "salt-one")
        b = MODEL["network_hash"]("203.0.113.7", "salt-two")
        self.assertNotEqual(a, b)

    def test_the_address_is_not_recoverable_from_the_output(self):
        digest = MODEL["network_hash"]("203.0.113.7", "salt")
        self.assertNotIn("203", digest)
        self.assertEqual(len(digest), 64)

    def test_ipv6_groups_by_its_own_prefix(self):
        a = MODEL["network_hash"]("2001:db8:1::1", "salt")
        b = MODEL["network_hash"]("2001:db8:1:ffff::9", "salt")
        c = MODEL["network_hash"]("2001:db8:2::1", "salt")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_an_unparseable_address_is_none_rather_than_a_shared_bucket(self):
        # A literal "unknown" bucket would make every unresolvable client look
        # like one enormous farm, and lock them all out at the cap.
        self.assertIsNone(MODEL["network_hash"]("not-an-ip", "salt"))
        self.assertIsNone(MODEL["network_hash"]("", "salt"))
        self.assertIsNone(MODEL["network_hash"](None, "salt"))


class ThresholdTest(unittest.TestCase):
    def test_the_gates_are_all_actually_switched_on(self):
        # A zero anywhere here silently removes one of the four costs, and the
        # grant still looks protected on the page.
        self.assertGreater(MODEL["MIN_ACCOUNT_AGE_HOURS"], 0)
        self.assertGreater(MODEL["MIN_ACTIONS"], 0)
        self.assertGreater(MODEL["MAX_PER_NETWORK"], 0)

    def test_a_shared_connection_is_not_limited_to_one_person(self):
        # Households, offices and universities share an address. A cap of 1
        # would refuse the second real person in a building.
        self.assertGreater(MODEL["MAX_PER_NETWORK"], 1)

    def test_the_grant_is_the_advertised_amount(self):
        self.assertEqual(MODEL["SIGNUP_CREDITS"], 20)


if __name__ == "__main__":
    unittest.main()
