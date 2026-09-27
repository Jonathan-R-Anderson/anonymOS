"""Awards on posts: who may receive one, and what an award actually costs.

An award moves real AXONCoins between two wallets, so the parts worth testing are
the ones that decide WHETHER a transfer is offered and HOW MUCH it is for. Get
either wrong and somebody's money goes to the wrong place, or an anonymous
author's wallet is published to whoever clicked the button.
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


MODEL = _load_pure("model/PostAward.py", {"TIERS", "TIER_ORDER", "tier_credits"})
SERVICE = _load_pure("services/post_awards.py", {"wallet_for_slip", "tiers_payload"},
                     extra={"TIERS": MODEL["TIERS"], "TIER_ORDER": MODEL["TIER_ORDER"]})


class _Profile:
    def __init__(self, **over):
        self.is_public = True
        self.link_on_comments = True
        self.eth_address = "0xAbC0000000000000000000000000000000000001"
        self.__dict__.update(over)


class _Slip:
    def __init__(self, profile):
        self.id = 1
        self.profile = profile


class TierTest(unittest.TestCase):
    def test_the_three_tiers_cost_different_amounts(self):
        # Three names for the same price would make the choice meaningless.
        costs = [MODEL["TIERS"][name]["credits"] for name in MODEL["TIER_ORDER"]]
        self.assertEqual(len(set(costs)), 3)

    def test_they_are_ordered_cheapest_first(self):
        costs = [MODEL["TIERS"][name]["credits"] for name in MODEL["TIER_ORDER"]]
        self.assertEqual(costs, sorted(costs))

    def test_an_unknown_tier_has_no_price(self):
        # Must be None, never a default: a bad tier from a request has to fail
        # the request rather than silently bill the cheapest amount.
        self.assertIsNone(MODEL["tier_credits"]("platinum"))
        self.assertIsNone(MODEL["tier_credits"](""))
        self.assertIsNone(MODEL["tier_credits"](None))

    def test_tier_names_are_matched_case_insensitively(self):
        self.assertEqual(MODEL["tier_credits"](" Gold "), MODEL["TIERS"]["gold"]["credits"])


class PayloadTest(unittest.TestCase):
    def test_wei_is_sent_as_a_string(self):
        # 100 AXONCoins is 1e20 wei, past Number.MAX_SAFE_INTEGER. Sent as a JSON
        # number the browser would round it and transfer the wrong amount.
        for row in SERVICE["tiers_payload"]():
            self.assertIsInstance(row["wei"], str)

    def test_wei_matches_the_advertised_price(self):
        for row in SERVICE["tiers_payload"]():
            self.assertEqual(int(row["wei"]), row["credits"] * (10 ** 18))


class RecipientTest(unittest.TestCase):
    """Who may be paid. Every None here is also a wallet NOT published."""

    def test_an_author_who_links_their_posts_can_be_paid(self):
        wallet = SERVICE["wallet_for_slip"](_Slip(_Profile()))
        self.assertEqual(wallet, "0xabc0000000000000000000000000000000000001")

    def test_the_address_is_lowercased(self):
        # It is compared against a log topic, which is lowercase hex. A
        # checksummed address would never match and every award would be refused.
        wallet = SERVICE["wallet_for_slip"](_Slip(_Profile()))
        self.assertEqual(wallet, wallet.lower())

    def test_an_author_who_does_not_link_their_posts_is_not_payable(self):
        # THE important one. This author's posts are anonymous; offering an award
        # would publish the wallet behind them to anyone who clicked.
        self.assertIsNone(SERVICE["wallet_for_slip"](_Slip(_Profile(link_on_comments=False))))

    def test_a_private_profile_is_not_payable(self):
        self.assertIsNone(SERVICE["wallet_for_slip"](_Slip(_Profile(is_public=False))))

    def test_an_author_with_no_wallet_is_not_payable(self):
        self.assertIsNone(SERVICE["wallet_for_slip"](_Slip(_Profile(eth_address=""))))
        self.assertIsNone(SERVICE["wallet_for_slip"](_Slip(_Profile(eth_address=None))))

    def test_an_author_with_no_profile_is_not_payable(self):
        self.assertIsNone(SERVICE["wallet_for_slip"](_Slip(None)))

    def test_a_post_with_no_author_is_not_payable(self):
        self.assertIsNone(SERVICE["wallet_for_slip"](None))


if __name__ == "__main__":
    unittest.main()
