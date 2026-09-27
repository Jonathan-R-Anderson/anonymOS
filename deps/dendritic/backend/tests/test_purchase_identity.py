"""The hashes that go on chain with a purchase.

Two things carry real consequence and both are easy to get wrong invisibly:
capturing the buyer's address at the wrong moment, and hashing it without a
pepper. Neither failure looks like a failure — the first records plausible
values that are all Stripe's, the second publishes a reversible hash forever.
"""

import ast
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path.insert(0, BACKEND)


def _load(pepper=""):
    """Load services/purchase_identity.py with `shared` stubbed."""
    path = os.path.join(BACKEND, "services", "purchase_identity.py")
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)

    shared = types.ModuleType("shared")
    shared.app = types.SimpleNamespace(config={"PURCHASE_ORIGIN_PEPPER": pepper})

    saved = sys.modules.get("shared")
    sys.modules["shared"] = shared
    try:
        module = types.ModuleType("purchase_identity_pure")
        exec(compile(tree, path, "exec"), module.__dict__)
        return module
    finally:
        if saved is None:
            sys.modules.pop("shared", None)
        else:
            sys.modules["shared"] = saved


class OrderIdTest(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def test_it_is_a_hash_not_the_session_id(self):
        # A raw session id on a public chain ties a wallet to a payment for
        # anyone to read, forever. It filters exactly as well hashed.
        got = self.mod.order_id("cs_live_a1b2c3")
        self.assertTrue(got.startswith("0x"))
        self.assertEqual(len(got), 66)
        self.assertNotIn("cs_live", got)

    def test_the_same_session_always_hashes_the_same(self):
        # The delivery path re-derives nothing; but if it ever did, it must
        # land on the value already recorded.
        self.assertEqual(self.mod.order_id("cs_x"), self.mod.order_id("cs_x"))

    def test_different_sessions_differ(self):
        self.assertNotEqual(self.mod.order_id("cs_a"), self.mod.order_id("cs_b"))

    def test_a_missing_session_is_zero_not_a_hash_of_nothing(self):
        # Zero is what the contract reads as "not recorded".
        for empty in ("", None, "   "):
            self.assertEqual(self.mod.order_id(empty), self.mod.ZERO)


class OriginHashTest(unittest.TestCase):
    def test_without_a_pepper_nothing_is_recorded(self):
        # THE important one. Degrading to an unsalted hash would publish,
        # permanently, exactly what the hashing exists to protect: IPv4 is 2^32
        # addresses, so an unpeppered keccak is reversible in an afternoon.
        mod = _load(pepper="")
        self.assertEqual(mod.origin_hash("203.0.113.7"), mod.ZERO)

    def test_with_a_pepper_it_hashes(self):
        mod = _load(pepper="secret")
        got = mod.origin_hash("203.0.113.7")
        self.assertTrue(got.startswith("0x"))
        self.assertEqual(len(got), 66)
        self.assertNotEqual(got, mod.ZERO)

    def test_the_address_never_appears_in_the_output(self):
        mod = _load(pepper="secret")
        self.assertNotIn("203.0.113.7", mod.origin_hash("203.0.113.7"))

    def test_the_pepper_changes_the_hash(self):
        # Which is what makes it unguessable, and also why rotating it makes
        # older purchases unsearchable by origin.
        a = _load(pepper="one").origin_hash("203.0.113.7")
        b = _load(pepper="two").origin_hash("203.0.113.7")
        self.assertNotEqual(a, b)

    def test_different_addresses_differ_under_one_pepper(self):
        mod = _load(pepper="secret")
        self.assertNotEqual(mod.origin_hash("203.0.113.7"),
                            mod.origin_hash("198.51.100.4"))

    def test_no_address_is_zero(self):
        mod = _load(pepper="secret")
        for empty in ("", None, "  "):
            self.assertEqual(mod.origin_hash(empty), mod.ZERO)


class CaptureMomentTest(unittest.TestCase):
    """The IP must be taken at checkout, never at the webhook.

    A webhook is an HTTP request from STRIPE's servers, so its remote address is
    Stripe's. Recording it would look entirely plausible and be worthless —
    every purchase would appear to originate from the same few egress IPs.
    """

    def _source(self, *parts):
        with open(os.path.join(BACKEND, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_checkout_records_the_origin(self):
        source = self._source("blueprints", "credits.py")
        body = source[source.index("def checkout()"):source.index("def webhook()")]
        self.assertIn("origin_hash", body)
        self.assertIn("purchase_identity", body)

    def test_the_webhook_does_not(self):
        source = self._source("blueprints", "credits.py")
        start = source.index("def webhook()")
        end = source.index("def subscribe()", start)
        self.assertNotIn("origin_hash", source[start:end],
                         "the webhook's remote address is Stripe's, not the buyer's")

    def test_the_order_id_is_set_once_stripe_issues_a_session(self):
        source = self._source("blueprints", "credits.py")
        body = source[source.index("def checkout()"):source.index("def webhook()")]
        self.assertIn("purchase.order_id = purchase_identity.order_id(", body)

    def test_both_columns_exist_on_the_purchase(self):
        source = self._source("model", "CreditPurchase.py")
        self.assertIn("order_id = db.Column", source)
        self.assertIn("origin_hash = db.Column", source)

    def test_the_client_ip_helper_is_not_a_second_implementation(self):
        # threat_watch already knows how this deployment is fronted. Two
        # answers to "who is this request from" is one more than a system can
        # afford.
        source = self._source("services", "purchase_identity.py")
        self.assertIn("threat_watch", source)




class PepperSourceTest(unittest.TestCase):
    """The pepper is read from os.environ first, and that is not a preference.

    It arrives in .env, which shared.py loads into os.environ. app.config comes
    from a DIFFERENT file, mounted into the container from the cluster and not
    the copy in this repo — so a key added to deploy-configs/maniwani.cfg never
    reaches it. That happened: the value sat in os.environ while app.config
    returned "", origins recorded as zero, and the site stayed perfectly green.
    """

    def test_the_environment_wins(self):
        import os as _os
        mod = _load(pepper="from-config")
        _os.environ["PURCHASE_ORIGIN_PEPPER"] = "from-environment"
        try:
            self.assertEqual(mod.pepper(), "from-environment")
        finally:
            _os.environ.pop("PURCHASE_ORIGIN_PEPPER", None)

    def test_config_still_works_when_the_environment_is_empty(self):
        import os as _os
        _os.environ.pop("PURCHASE_ORIGIN_PEPPER", None)
        self.assertEqual(_load(pepper="from-config").pepper(), "from-config")

    def test_neither_means_origins_are_not_recorded(self):
        import os as _os
        _os.environ.pop("PURCHASE_ORIGIN_PEPPER", None)
        mod = _load(pepper="")
        self.assertEqual(mod.origin_hash("203.0.113.7"), mod.ZERO)


if __name__ == "__main__":
    unittest.main()
