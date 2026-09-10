"""Awards paid over a channel: what counts as payment, and what cannot be faked.

The parts worth testing here are the ones that decide whether somebody gets
credited for money they did not actually send. Get the high-water rule wrong and
two colluding accounts manufacture gold awards for free — which is exactly what
becomes possible the moment payments stop costing gas.

Same pure-loading approach as test_post_awards.py: the functions under test are
extracted without importing Flask, so the decisions can be checked without a
database or a running app.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services.channel_state import decode_state, derive_channel_id  # noqa: E402


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


SERVICE = _load_pure(
    "services/channel_awards.py",
    {"unawarded_value", "_channel_endpoint", "_anon", "_slip_wallet"},
    extra={"received_by": __import__(
        "services.channel_state", fromlist=["received_by"]).received_by},
)

AXON = 10 ** 18
AUTHOR = "0x1111111111111111111111111111111111111111"
GIVER = "0x2222222222222222222222222222222222222222"


def state(balance_a="0", balance_b="0", withdraw_a=None, withdraw_b=None, nonce=1):
    wire = {
        "channel": derive_channel_id(AUTHOR, GIVER).hex(),
        "nonce": nonce, "balance_a": balance_a, "balance_b": balance_b,
    }
    if withdraw_a:
        wire["withdraw_a"] = withdraw_a
    if withdraw_b:
        wire["withdraw_b"] = withdraw_b
    return decode_state(wire)


# AUTHOR is 0x1111... and GIVER is 0x2222..., so the author is party A. Asserted
# rather than assumed: party A is the lower address and has nothing to do with
# who is paying, and a test that silently had it backwards would still pass for
# the wrong reason.
AUTHOR_IS_A = True


class UnawardedValue(unittest.TestCase):
    """The rule that stops free payments becoming free awards."""

    def test_a_fresh_channel_offers_what_was_paid(self):
        paid = state(balance_a=str(100 * AXON))
        self.assertEqual(
            SERVICE["unawarded_value"](paid, AUTHOR_IS_A, 0), 100 * AXON)

    def test_awarded_value_is_not_offered_twice(self):
        paid = state(balance_a=str(100 * AXON))
        self.assertEqual(
            SERVICE["unawarded_value"](paid, AUTHOR_IS_A, 100 * AXON), 0)

    def test_partially_awarded_value_offers_the_remainder(self):
        paid = state(balance_a=str(100 * AXON))
        self.assertEqual(
            SERVICE["unawarded_value"](paid, AUTHOR_IS_A, 25 * AXON), 75 * AXON)

    def test_paying_value_back_and_forth_earns_nothing(self):
        """The attack the high-water mark exists to stop.

        Two accounts pass the same 100 AXON back and forth. Off chain each pass
        is free, so without the mark each one would buy another gold award.
        """
        already = 0

        # Pass one: the author is 100 up. Worth 100 of awards.
        first = SERVICE["unawarded_value"](state(balance_a=str(100 * AXON)), AUTHOR_IS_A, already)
        self.assertEqual(first, 100 * AXON)
        already += first

        # The author sends it all back. Nothing to award — and, importantly, not
        # a negative that some later comparison would read as a credit.
        returned = state(balance_a="0", balance_b=str(100 * AXON), nonce=2)
        self.assertEqual(SERVICE["unawarded_value"](returned, AUTHOR_IS_A, already), 0)

        # And round it goes again. Still nothing: the mark is already there.
        second = state(balance_a=str(100 * AXON), balance_b="0", nonce=3)
        self.assertEqual(SERVICE["unawarded_value"](second, AUTHOR_IS_A, already), 0)

    def test_genuinely_new_value_is_offered(self):
        """The other half: the rule must not block real payments."""
        already = 100 * AXON
        topped_up = state(balance_a=str(175 * AXON), nonce=9)
        self.assertEqual(
            SERVICE["unawarded_value"](topped_up, AUTHOR_IS_A, already), 75 * AXON)

    def test_a_checkpoint_does_not_re_offer_drawn_down_value(self):
        """An author withdrawing must not look like a fresh payment.

        A checkpoint moves value out of the balance and into the withdrawal. If
        only the balance were counted the author would appear to have lost it,
        and every AXON would be creditable a second time on the way back up.
        """
        already = 100 * AXON
        drawn = state(balance_a="0", withdraw_a=str(100 * AXON), nonce=10)
        self.assertEqual(SERVICE["unawarded_value"](drawn, AUTHOR_IS_A, already), 0)

        # New value after the withdrawal is still creditable.
        after = state(balance_a=str(30 * AXON), withdraw_a=str(100 * AXON), nonce=11)
        self.assertEqual(
            SERVICE["unawarded_value"](after, AUTHOR_IS_A, already), 30 * AXON)

    def test_the_giver_side_is_not_credited(self):
        """Reading the wrong party would credit the giver's own balance."""
        paid = state(balance_a=str(100 * AXON), balance_b=str(400 * AXON))
        self.assertEqual(
            SERVICE["unawarded_value"](paid, AUTHOR_IS_A, 0), 100 * AXON)
        # Had the author been party B, the same state would offer 400 — which is
        # why the party is resolved from the addresses and never assumed.
        self.assertEqual(
            SERVICE["unawarded_value"](paid, False, 0), 400 * AXON)

    def test_amounts_stay_exact_past_the_float_range(self):
        # 1e20 is already past Number.MAX_SAFE_INTEGER, and these add up.
        huge = state(balance_a=str(10 ** 24 + 7))
        self.assertEqual(
            SERVICE["unawarded_value"](huge, AUTHOR_IS_A, 10 ** 24), 7)


class _Profile:
    def __init__(self, endpoint=None, is_public=True, eth_address=None):
        self.channel_endpoint = endpoint
        self.is_public = is_public
        self.eth_address = eth_address


class _Slip:
    def __init__(self, profile):
        self.profile = profile


class ChannelEndpoint(unittest.TestCase):
    """Where a channel award would be sent, and when there is nowhere."""

    def endpoint(self, profile):
        return SERVICE["_channel_endpoint"](_Slip(profile))

    def test_a_published_https_endpoint_is_used(self):
        self.assertEqual(
            self.endpoint(_Profile("https://node.example/scpp/v1")),
            "https://node.example/scpp/v1")

    def test_no_endpoint_means_no_channel_path(self):
        # The normal answer. It means "fall back to the on-chain award", not
        # "this author cannot be awarded".
        self.assertIsNone(self.endpoint(_Profile(None)))
        self.assertIsNone(self.endpoint(_Profile("   ")))

    def test_a_private_profile_publishes_nothing(self):
        self.assertIsNone(
            self.endpoint(_Profile("https://node.example/scpp/v1", is_public=False)))

    def test_plain_http_is_refused(self):
        # A tip flow pointed at http:// lets a network attacker rewrite the
        # state the browser is about to sign against.
        self.assertIsNone(self.endpoint(_Profile("http://node.example/scpp/v1")))

    def test_a_missing_profile_is_not_an_error(self):
        self.assertIsNone(SERVICE["_channel_endpoint"](None))
        self.assertIsNone(SERVICE["_channel_endpoint"](_Slip(None)))


class Formatting(unittest.TestCase):
    def test_anon_floors_so_it_never_overstates(self):
        # Telling somebody they have 5 AXON available when they have 4.9 would
        # send them into a refusal they were just told would succeed.
        self.assertEqual(SERVICE["_anon"](5 * AXON - 1), 4)
        self.assertEqual(SERVICE["_anon"](5 * AXON), 5)
        self.assertEqual(SERVICE["_anon"](0), 0)


class GiverWallet(unittest.TestCase):
    def test_the_wallet_comes_from_the_givers_own_profile(self):
        self.assertEqual(
            SERVICE["_slip_wallet"](_Slip(_Profile(eth_address="0xABC"))), "0xabc")

    def test_no_profile_means_no_wallet(self):
        self.assertIsNone(SERVICE["_slip_wallet"](None))
        self.assertIsNone(SERVICE["_slip_wallet"](_Slip(None)))
        self.assertIsNone(SERVICE["_slip_wallet"](_Slip(_Profile(eth_address=""))))


if __name__ == "__main__":
    unittest.main()
