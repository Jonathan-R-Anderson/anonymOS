"""Automatic delivery of purchased AXON from the Treasury.

This module puts a key that can move the treasury on a public web server, which
blueprints/credits.py calls the largest single risk in the system. The tests
that matter are therefore the ones about NOT delivering: off by default,
bounded per call, and never twice for one payment.
"""

import ast
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path.insert(0, BACKEND)


def tearDownModule():
    # Never leave a treasury key in the environment for whatever test module
    # runs next.
    os.environ.pop("TREASURY_DELIVERY_KEY", None)


class Purchase:
    def __init__(self, credits=60, wallet="0x" + "ab" * 20,
                 order_id="0x" + "11" * 32, origin_hash=None,
                 stripe_session_id=None):
        # Subscription months arrive with no order_id but a Stripe INVOICE id,
        # which deliver() now derives one from. The fixture carries the field so
        # the "no id at all" case stays testable.
        self.stripe_session_id = stripe_session_id
        self.credits = credits
        self.wallet = wallet
        self.order_id = order_id
        self.origin_hash = origin_hash
        self.id = 1


def _load(key="", treasury="0x" + "cd" * 20, filled=False):
    """Load the module with its chain and app dependencies stubbed."""
    path = os.path.join(BACKEND, "services", "token_delivery.py")
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)

    shared = types.ModuleType("shared")
    shared.app = types.SimpleNamespace(
        logger=types.SimpleNamespace(exception=lambda *a, **k: None,
                                     info=lambda *a, **k: None),
        config={})

    chain = types.ModuleType("services.pof_chain")
    chain.CHAIN_ID = 1
    chain.pof_addresses = lambda: ({"Treasury": treasury} if treasury else {})
    chain.selector = lambda sig: b"\x00\x00\x00\x00"
    chain._rpc = lambda method, params: "0x1" if filled else "0x0"

    # deliver() lazily imports purchase_identity to derive an order id from a
    # Stripe invoice. Stubbed too, or the import pulls in the real package and
    # takes shared/flask_migrate with it.
    identity = types.ModuleType("services.purchase_identity")
    identity.ZERO = "0x" + "00" * 32
    identity.order_id = lambda s: ("0x" + ("%064x" % (abs(hash(s)) or 1))) if s else identity.ZERO

    services = types.ModuleType("services")
    services.pof_chain = chain
    services.purchase_identity = identity

    global _LAST
    saved = {n: sys.modules.get(n) for n in
             ("shared", "services", "services.pof_chain", "services.purchase_identity")}
    sys.modules["shared"] = shared
    sys.modules["services"] = services
    sys.modules["services.pof_chain"] = chain
    sys.modules["services.purchase_identity"] = identity
    _LAST = saved
    # The key stays set for the LIFETIME of the test, not just the load:
    # delivery_key() reads os.environ when deliver() is called, so restoring it
    # here would make every test run against a disabled module. tearDownModule
    # removes it.
    if key:
        os.environ["TREASURY_DELIVERY_KEY"] = key
    else:
        os.environ.pop("TREASURY_DELIVERY_KEY", None)
    module = types.ModuleType("token_delivery_pure")
    exec(compile(tree, path, "exec"), module.__dict__)
    module.pof_chain = chain
    module._saved = saved
    return module


def tearDownModule():
    # Restored HERE, not in _load: deliver() imports purchase_identity lazily,
    # so a stub removed at load time is gone by the time it is needed — and the
    # real package pulls in shared. Same trap that broke the rental tests.
    for name, prev in (_LAST or {}).items():
        if prev is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prev
    os.environ.pop("TREASURY_DELIVERY_KEY", None)


_LAST = None


class OffByDefaultTest(unittest.TestCase):
    """Enabling this must be a deliberate act, never a consequence of deploying."""

    def test_no_key_means_disabled(self):
        self.assertFalse(_load(key="").enabled())

    def test_disabled_delivery_refuses_rather_than_half_working(self):
        mod = _load(key="")
        with self.assertRaises(mod.DeliveryError):
            mod.deliver(Purchase())

    def test_no_treasury_address_means_disabled(self):
        # A key with nowhere to send to is not "enabled", it is a
        # misconfiguration that would otherwise fail per purchase.
        self.assertFalse(_load(key="0x" + "11" * 32, treasury="").enabled())


class RefusalTest(unittest.TestCase):
    def setUp(self):
        self.mod = _load(key="0x" + "11" * 32)

    def test_a_purchase_over_the_ceiling_is_not_delivered(self):
        # A bug that can send anything sends everything. A bug bounded to one
        # pack is a bad day.
        big = Purchase(credits=self.mod.MAX_AUTO_DELIVERY + 1)
        with self.assertRaises(self.mod.DeliveryError) as caught:
            self.mod.deliver(big)
        self.assertIn("by hand", str(caught.exception))

    def test_a_purchase_with_no_order_id_is_not_delivered(self):
        # Without one there is no idempotency guard, and a webhook retry would
        # deliver twice. An operator can still send it by hand.
        # No order id AND no invoice to derive one from.
        with self.assertRaises(self.mod.DeliveryError):
            self.mod.deliver(Purchase(order_id=None, stripe_session_id=None))


    def test_a_purchase_with_no_wallet_is_not_delivered(self):
        with self.assertRaises(self.mod.DeliveryError):
            self.mod.deliver(Purchase(wallet=""))

    def test_zero_credits_is_not_delivered(self):
        with self.assertRaises(self.mod.DeliveryError):
            self.mod.deliver(Purchase(credits=0))


class IdempotencyTest(unittest.TestCase):
    def test_an_already_filled_order_is_not_sent_again(self):
        # Stripe retries on any non-2xx or timeout, so this arrives more than
        # once in normal operation.
        mod = _load(key="0x" + "11" * 32, filled=True)
        with self.assertRaises(mod.DeliveryError) as caught:
            mod.deliver(Purchase())
        self.assertIn("already been delivered", str(caught.exception))

    def test_an_unreachable_chain_fails_closed(self):
        # Failing open would attempt a delivery the contract then refuses —
        # safe but wasteful. Failing closed leaves the purchase queued, which
        # is the state it was in before this feature existed.
        mod = _load(key="0x" + "11" * 32)

        def explode(method, params):
            raise RuntimeError("rpc unreachable")

        mod.pof_chain._rpc = explode
        self.assertTrue(mod.already_filled("0x" + "11" * 32),
                        "an unreadable chain must be treated as already filled")


class WebhookWiringTest(unittest.TestCase):
    """Where delivery is called from, checked by reading the source."""

    def setUp(self):
        with open(os.path.join(BACKEND, "blueprints", "credits.py"),
                  encoding="utf-8") as handle:
            self.source = handle.read()
        start = self.source.index("def webhook()")
        self.body = self.source[start:self.source.index("def subscribe()", start)]

    def test_delivery_happens_after_the_paid_commit(self):
        # A delivery that succeeds while the transaction rolls back would send
        # tokens for a purchase the database does not think was paid — the one
        # failure retrying cannot repair, because the chain does not roll back.
        paid = self.body.index("mark_paid(purchase")
        commit = self.body.index("db.session.commit()", paid)
        deliver = self.body.index("token_delivery.deliver")
        self.assertLess(commit, deliver)

    def test_it_is_gated_on_being_enabled(self):
        self.assertIn("token_delivery.enabled()", self.body)

    def test_a_delivery_failure_does_not_fail_the_webhook(self):
        # A non-2xx tells Stripe the webhook failed and it retries everything,
        # when the payment was recorded correctly and only delivery did not
        # happen. That is an operator's problem to finish, not Stripe's to
        # repeat.
        after = self.body[self.body.index("token_delivery.enabled()"):]
        self.assertIn("except Exception:", after)
        self.assertIn('return jsonify({"ok": True})', after)


if __name__ == "__main__":
    unittest.main()
