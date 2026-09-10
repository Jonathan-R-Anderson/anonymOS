"""The admin console's money paths, after the Treasury started existing.

Grants and credit deliveries were written when there was no Treasury contract,
so both sent a plain transfer from the operator's own wallet — the only place
credits could live. Once the allocation is genesis-minted into the Treasury that
becomes actively wrong: the allocation sits untouched while every grant and
delivery quietly drains the operator's personal balance.

The sharper hazard is the burn button. It used to take the treasury role first
(`setTreasury(me)`) so it could burn. Doing that now rotates the role away from
the deployed Treasury, which silently disables `fundEpoch` — epoch rewards stop
being mintable and every node stops being payable. A button labelled "burn"
must not be able to do that.

These are text assertions against the template, which is weak; it is what can be
checked without a browser and a funded wallet, and the failures they guard
against are all "the call went to the wrong contract", which is visible in the
source.
"""

import json
import os
import pathlib
import re
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

CONSOLE = pathlib.Path(BACKEND) / "templates" / "admin-contracts.html"
ARTIFACTS = pathlib.Path(BACKEND) / "static" / "pof" / "contracts.json"


class ConsoleTreasuryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = CONSOLE.read_text()
        cls.artifacts = json.loads(ARTIFACTS.read_text())

    def test_grants_and_deliveries_can_pay_from_the_treasury(self):
        # release() moves an already-minted allocation and cannot mint, which is
        # what keeps the supply cap meaningful.
        self.assertIn("treasury.release.populateTransaction", self.html)
        self.assertGreaterEqual(self.html.count("release.populateTransaction"), 2,
                                "both grants and deliveries should be able to use release()")

    def test_the_direct_transfer_survives_as_a_fallback(self):
        # Until the stack is redeployed there is no Treasury, and a console that
        # refused to grant at all would be a regression.
        self.assertIn("transfer.populateTransaction", self.html)

    def test_burn_never_rotates_the_role_away_from_a_deployed_treasury(self):
        # The catastrophic case: setTreasury(me) unwires fundEpoch, so epoch
        # rewards can no longer be minted and nobody can be paid.
        self.assertIn("treasuryIsContract", self.html)
        # The refusal must mention what it would cost, not just decline.
        self.assertIn("nothing can mint epoch rewards", self.html)

    def test_burn_uses_the_one_argument_signature(self):
        # burn(from, amount) was replaced by burn(amount) so that holding the
        # treasury role no longer means being able to destroy anybody's tokens.
        # A leftover two-argument call reverts with a bare ABI mismatch.
        for call in re.findall(r"burn\.populateTransaction\(([^)]*)\)", self.html):
            self.assertNotIn(",", call, "burn() takes only an amount now: %r" % call)

    def test_the_burn_signature_matches_the_compiled_contracts(self):
        for contract in ("AxonToken", "Treasury"):
            entry = [e for e in self.artifacts[contract]["abi"]
                     if e.get("type") == "function" and e.get("name") == "burn"]
            self.assertTrue(entry, "%s has no burn()" % contract)
            self.assertEqual([i["type"] for i in entry[0]["inputs"]], ["uint256"],
                             "%s.burn should take exactly one amount" % contract)

    def test_self_delivery_is_only_a_no_op_without_a_treasury(self):
        # Delivering to the operator's own wallet is genuinely nothing when the
        # credits are already theirs. With a Treasury it is a real movement, and
        # short-circuiting it would clear the debt without paying it.
        self.assertIn("!addresses.Treasury && d.wallet.toLowerCase() === me", self.html)

    def test_treasury_is_in_the_deploy_order_after_the_distributor(self):
        # fundEpoch mints INTO the RewardDistributor, so the Treasury's
        # constructor needs its address.
        match = re.search(r"const ORDER = \[(.*?)\];", self.html, re.S)
        self.assertIsNotNone(match)
        order = [n.strip().strip('"') for n in match.group(1).split(",")]
        self.assertIn("Treasury", order)
        self.assertLess(order.index("RewardDistributor"), order.index("Treasury"))
        self.assertLess(order.index("AxonToken"), order.index("Treasury"))

    def test_every_deployable_contract_has_an_artifact(self):
        # The drift this is here to stop: SettlementKeeper was added to ORDER
        # and to the constructor map but its artifact was never copied in, so
        # the one contract the console claimed it could deploy was the one it
        # could not — invisible until somebody clicked deploy.
        match = re.search(r"const ORDER = \[(.*?)\];", self.html, re.S)
        order = [n.strip().strip('"') for n in match.group(1).split(",")]
        for name in order:
            self.assertIn(name, self.artifacts, "%s is offered but has no artifact" % name)
            self.assertTrue(self.artifacts[name].get("bytecode"), "%s has no bytecode" % name)

    def test_constructor_args_match_each_compiled_constructor(self):
        # A missing or reordered argument produces a deployment that succeeds
        # and points somewhere wrong, which is worse than one that fails.
        specs = re.search(r"const CTORS = \{(.*?)\n  \};", self.html, re.S)
        self.assertIsNotNone(specs, "could not find the constructor map")
        for name, body in re.findall(r"(\w+):\s*\[(.*?)\],\n", specs.group(1), re.S):
            if name not in self.artifacts:
                continue
            declared = re.findall(r'n:\s*"(\w+)"', body)
            ctor = [e for e in self.artifacts[name]["abi"] if e.get("type") == "constructor"]
            expected = [i["name"] for i in ctor[0]["inputs"]] if ctor else []
            self.assertEqual(len(declared), len(expected),
                             "%s: console offers %s, constructor wants %s"
                             % (name, declared, expected))


if __name__ == "__main__":
    unittest.main()
