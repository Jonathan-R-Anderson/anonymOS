"""Stripe's fiat-to-crypto onramp: what it may be asked for, and where it lands.

The onramp moves real money to an address that cannot be recalled, so the two
things worth testing are the two that cannot be corrected afterwards: that an
unsupported currency or network is refused before a customer commits, and that
the destination address comes from the session rather than the request.

Loaded with the ast-extraction pattern used across these tests, so the module's
constants and validation can be exercised without a database or a Stripe key.
"""

import ast
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)


def _load_pure():
    """Import services/stripe_onramp.py with its two dependencies stubbed.

    `shared` pulls in the whole app and `stripe_api` wants keys. Both stubs are
    removed from sys.modules afterwards — a leaked stub here broke four
    unrelated test modules once, because whichever test ran next imported the
    fake instead of the real thing.
    """
    path = os.path.join(BACKEND, "services", "stripe_onramp.py")
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)

    shared = types.ModuleType("shared")
    shared.app = types.SimpleNamespace(
        logger=types.SimpleNamespace(exception=lambda *a, **k: None),
        config={})

    api = types.ModuleType("services.stripe_api")
    api.configured = lambda: True
    api.secret_key = lambda: "sk_live_store"
    api.publishable_key = lambda: "pk_live_store"
    api._post = (lambda path, data, headers=None, api_key=None:
                 {"client_secret": "cs_test", "id": "cos_test"})

    saved = {name: sys.modules.get(name) for name in ("shared", "services.stripe_api")}
    sys.modules["shared"] = shared
    sys.modules["services.stripe_api"] = api
    try:
        module = types.ModuleType("stripe_onramp_pure")
        module.__dict__["__name__"] = "stripe_onramp_pure"
        exec(compile(tree, path, "exec"), module.__dict__)
        module._api = api
        return module
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


onramp = _load_pure()


class SupportedListsTest(unittest.TestCase):
    def test_the_default_lands_on_the_chain_the_contracts_are_on(self):
        # The whole reason this module became worth finishing: Ethereum mainnet
        # is on Stripe's list, so the ETH arrives on the chain AXON lives on and
        # nothing has to be bridged. If the default drifts off that chain, the
        # page's three-step explanation silently becomes wrong.
        self.assertEqual(onramp.DEFAULT_NETWORK, "ethereum")
        self.assertIn(onramp.DEFAULT_NETWORK, onramp.SUPPORTED_NETWORKS)
        self.assertIn(onramp.DEFAULT_CURRENCY, onramp.SUPPORTED_CURRENCIES)

    def test_gas_is_paid_in_eth_so_eth_is_the_default(self):
        # USDC is also deliverable and is the tempting default for "buy $20 of
        # crypto". It is the wrong one: a wallet holding only USDC cannot move
        # it, which is the exact problem this page exists to solve.
        self.assertEqual(onramp.DEFAULT_CURRENCY, "eth")

    def test_anon_is_not_claimed_to_be_deliverable(self):
        self.assertNotIn("anon", onramp.SUPPORTED_CURRENCIES)


class RefusalsTest(unittest.TestCase):
    """Refused here, with a readable reason, rather than by Stripe's API later."""

    def test_an_unsupported_currency_is_refused(self):
        with self.assertRaises(onramp.OnrampError) as caught:
            onramp.create_session("0x" + "a" * 40, currency="anon")
        self.assertIn("anon", str(caught.exception))

    def test_an_unsupported_network_is_refused(self):
        # "cardano" is the example because it is genuinely absent from
        # SUPPORTED_NETWORKS. This test used to name "ethereum", which was true
        # when the stack targeted zkSync and became FALSE when it moved to
        # Ethereum mainnet -- at which point the test was asserting that the
        # site must refuse purchases on the very chain it deploys to. A stale
        # refusal test does not fail safe: it argues for breaking the thing it
        # is meant to protect.
        with self.assertRaises(onramp.OnrampError) as caught:
            onramp.create_session("0x" + "a" * 40, network="cardano")
        self.assertIn("cardano", str(caught.exception))

    def test_ethereum_is_supported_because_that_is_where_the_stack_deploys(self):
        """The contracts are on Ethereum mainnet, so buying on `ethereum` has to
        work -- it is the path a user takes to get the token they then spend on
        domains and TLD proposals. Asserted explicitly so that a future tidy-up
        of SUPPORTED_NETWORKS cannot quietly remove it."""
        self.assertIn("ethereum", onramp.SUPPORTED_NETWORKS)

    def test_the_lists_match_what_the_api_actually_reports(self):
        # Read off a live session's transaction_details, not the docs prose —
        # the prose was narrower than reality and refused purchases Stripe
        # would have completed. If Stripe adds a network, widen these from a
        # real response rather than from a docs page.
        for network in ("base", "optimism", "avalanche", "worldchain"):
            self.assertIn(network, onramp.SUPPORTED_NETWORKS)
        for currency in ("avax", "wld"):
            self.assertIn(currency, onramp.SUPPORTED_CURRENCIES)

    def test_no_wallet_is_refused_before_any_money_moves(self):
        for empty in ("", "   ", None):
            with self.assertRaises(onramp.OnrampError):
                onramp.create_session(empty)

    def test_case_and_whitespace_do_not_defeat_the_check(self):
        session = onramp.create_session("0x" + "a" * 40, currency="  ETH  ",
                                        network=" Ethereum ")
        self.assertEqual(session["currency"], "eth")
        self.assertEqual(session["network"], "ethereum")


class DestinationTest(unittest.TestCase):
    def _capture(self):
        sent = {}
        onramp._api._post = (
            lambda path, data, headers=None, api_key=None:
            sent.update(data) or {"client_secret": "cs"})
        return sent

    def test_the_wallet_is_locked_into_the_session_payload(self):
        sent = self._capture()
        wallet = "0x" + "b" * 40
        onramp.create_session(wallet)
        self.assertEqual(
            sent["wallet_addresses[ethereum]"], wallet,
            "the destination address must be the one passed in — a customer-typed "
            "address is how a phishing paste gets funded, with no chargeback")
        self.assertEqual(
            sent["lock_wallet_address"], "true",
            "passing an address is not the same as locking the field the customer "
            "can edit; the API has a flag for it and it must be set")

    def test_the_parameters_are_top_level_not_the_response_shape(self):
        # `transaction_details` is what comes BACK. Sending it as the request is
        # the mistake this module shipped with, and the endpoint refused it.
        sent = self._capture()
        onramp.create_session("0x" + "e" * 40, amount="1")
        for key in sent:
            self.assertFalse(
                key.startswith("transaction_details"),
                "%s is a response field, not a request parameter" % key)
        self.assertIn("destination_currency", sent)
        self.assertIn("destination_network", sent)

    def test_the_amount_is_only_sent_when_given(self):
        sent = self._capture()
        onramp.create_session("0x" + "c" * 40)
        self.assertNotIn("destination_amount", sent)

        sent.clear()
        onramp.create_session("0x" + "c" * 40, amount="0.05")
        self.assertEqual(sent["destination_amount"], "0.05")

    def test_a_missing_client_secret_is_an_error_not_a_broken_widget(self):
        onramp._api._post = lambda path, data, headers=None, api_key=None: {"id": "cos_x"}
        with self.assertRaises(onramp.OnrampError):
            onramp.create_session("0x" + "d" * 40)


class OneAccountTest(unittest.TestCase):
    """The onramp uses the site's own Stripe keys, on one account.

    A separate key pair lived here briefly, on a wrong diagnosis:
    "Unrecognized request URL" was read as the account lacking the feature.
    It was not — the request body was the response's shape, and the site's
    domain was not on the onramp's allowed list. The live account answers
    HTTP 200 once both are fixed.

    Asserted rather than assumed, because a second credential is a plausible
    enough reading of that error that somebody will reach for it again, and two
    key pairs is two places to rotate and one to forget.
    """

    def test_the_onramp_uses_the_sites_own_keys(self):
        self.assertEqual(onramp.secret_key(), "sk_live_store")
        self.assertEqual(onramp.publishable_key(), "pk_live_store")

    def test_no_separate_credential_is_read_from_config(self):
        onramp.app.config["STRIPE_ONRAMP_SECRET_KEY"] = "sk_test_elsewhere"
        try:
            self.assertEqual(
                onramp.secret_key(), "sk_live_store",
                "a stale STRIPE_ONRAMP_SECRET_KEY must not quietly redirect the "
                "onramp to another account")
        finally:
            onramp.app.config.clear()

    def test_the_session_is_minted_with_the_sites_key(self):
        # No api_key override: _post uses the site's key, like every other call.
        seen = {}
        onramp._api._post = (
            lambda path, data, headers=None, api_key=None:
            seen.update(key=api_key, headers=headers) or {"client_secret": "cs"})
        onramp.create_session("0x" + "a" * 40)
        self.assertIsNone(seen["key"], "the onramp overrode the account's key")
        self.assertIsNone(seen["headers"], "the onramp pinned an API version")

    def test_an_unrecognised_url_names_the_two_real_causes(self):
        explained = onramp._explain(RuntimeError(
            "Unrecognized request URL (POST: /v1/crypto/onramp_sessions)."))
        self.assertIn("not a typo", explained)
        self.assertIn("transaction_details", explained)
        self.assertIn("allowed-domains", explained)

    def test_other_errors_are_passed_through(self):
        self.assertIn("card declined", onramp._explain(RuntimeError("card declined")))


class PageAndRouteTest(unittest.TestCase):
    """The wiring, checked statically — a service nothing calls is not finished.

    This module had a complete create_session() and no route and no template for
    long enough to be reported as unfinished. Reading the files is enough to
    catch that recurring.
    """

    def setUp(self):
        with open(os.path.join(BACKEND, "blueprints", "credits.py"), encoding="utf-8") as h:
            self.routes = h.read()
        with open(os.path.join(BACKEND, "templates", "credits-onramp.html"), encoding="utf-8") as h:
            self.page = h.read()

    def test_both_routes_are_registered(self):
        self.assertIn('@credits_blueprint.route("/onramp")', self.routes)
        self.assertIn('@credits_blueprint.route("/onramp/session", methods=["POST"])', self.routes)

    def test_the_route_reads_the_wallet_from_the_session(self):
        # `slip_wallet_address(slip)`, never request data. This is the assertion
        # the whole endpoint exists to satisfy.
        start = self.routes.index("def onramp_session()")
        body = self.routes[start:start + 2000]
        self.assertIn("slip_wallet_address(slip)", body)
        self.assertNotIn('payload.get("wallet")', body)
        self.assertNotIn('payload.get("address")', body)

    def test_the_page_says_a_card_cannot_buy_anon(self):
        self.assertIn("does <strong>not</strong> buy AXONCoins", self.page)

    def test_the_page_handles_a_widget_that_never_loads(self):
        # Stripe's script is third-party and blockable. Without this the page
        # throws "StripeOnramp is not defined" at somebody trying to pay.
        self.assertIn('typeof StripeOnramp === "undefined"', self.page)

    def test_the_credits_page_links_to_it(self):
        with open(os.path.join(BACKEND, "templates", "credits.html"), encoding="utf-8") as h:
            self.assertIn("url_for('credits.onramp')", h.read())


if __name__ == "__main__":
    unittest.main()
