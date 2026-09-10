"""The claim page: the last step between "the network owes you" and "you were paid".

Everything underneath already worked. The aggregator computes a Merkle proof per
node, settlements are stored, and /api/v1/pof/claim/<epoch>/<node_id> has been
serving proofs to anybody who asks. Nothing consumed it, so a reward that had
been earned, settled and committed on-chain still required an operator to build
the transaction by hand — which is indistinguishable, from the outside, from not
being paid at all.

These tests cover the parts that are checkable without a browser: that the page
is wired to the real deployed addresses rather than guessing them, and that the
contract calls it makes match the ABIs it will be calling.
"""

import ast
import json
import os
import pathlib
import re
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

TEMPLATE = pathlib.Path(BACKEND) / "templates" / "claim.html"
ARTIFACTS = pathlib.Path(BACKEND) / "static" / "pof" / "contracts.json"


# The claim page was removed with the rest of the stripped blueprints, and the
# class(es) below read its files directly: templates/claim.html.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the treatment the
# civil-rights classes in test_evidence_upload.py already have. The assertions
# are still correct and still worth having; deleting them would mean rewriting
# them from scratch if the feature returns, and a skipUnless brings them back
# the moment the files exist again.
_CLAIM_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "templates/claim.html",
    )
)
_CLAIM_PRESENT_GONE = "the claim page was removed; these classes read its template"

@unittest.skipUnless(_CLAIM_PRESENT, _CLAIM_PRESENT_GONE)
class ClaimTemplateTest(unittest.TestCase):
    def setUp(self):
        self.html = TEMPLATE.read_text()

    def test_refuses_to_render_a_claim_form_with_no_distributor(self):
        # Without a deployed RewardDistributor there is nothing to claim from,
        # and a form that submitted into the empty address would look like the
        # claim failed rather than like the contract is missing.
        self.assertIn("{% if not reward_distributor %}", self.html)
        self.assertIn("The contracts are not deployed yet", self.html)

    def test_addresses_come_from_the_server_not_the_page(self):
        # The contracts console is the record of what is deployed. A page that
        # hardcoded an address would keep pointing at it after a redeploy.
        for name in ("reward_distributor", "treasury", "epoch_manager", "token"):
            self.assertIn("{{ %s | tojson }}" % name, self.html)
        # No 40-hex literal anywhere: that would be a pasted address.
        self.assertFalse(re.search(r"0x[0-9a-fA-F]{40}", self.html),
                         "an address literal is baked into the template")

    def test_claim_uses_the_field_names_the_api_actually_serves(self):
        # These come from the aggregator's ClaimRow json tags and are stored
        # verbatim. Renaming one on either side breaks claiming silently: the
        # value arrives as undefined and the transaction reverts on a bad proof.
        for field in ("recipient", "amount", "service_breakdown_hash", "proof"):
            self.assertIn("claim." + field, self.html)

    def test_tries_the_node_id_and_the_public_key(self):
        # A node id is keccak256 of the node's public key, and both are 64 hex
        # characters, so which one an operator pasted cannot be told apart.
        self.assertIn("keccak256", self.html)

    def test_preflights_every_precondition_before_spending_gas(self):
        # A bare "execution reverted" does not say which of four unrelated
        # things went wrong, and each has a different fix.
        for check in ("finalize", "claimed", "balanceOf", "invalidated"):
            self.assertIn(check, self.html)

    def test_offers_the_permissionless_funding_call(self):
        # The commonest blocker: the epoch settled but nobody minted its rewards
        # into the distributor, so claim() fails on an ERC-20 balance check that
        # names nothing. fundEpoch takes no permission, so the page can offer it.
        self.assertIn("fundEpoch", self.html)
        self.assertIn("fundableAmount", self.html)



@unittest.skipUnless(_CLAIM_PRESENT, _CLAIM_PRESENT_GONE)
class AbiAgreementTest(unittest.TestCase):
    """The page's inline ABI fragments must match the compiled contracts.

    The page declares six functions by hand rather than downloading a fifth of a
    megabyte of artifacts. That is worth it, and it is exactly the kind of thing
    that rots the next time a signature changes.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = TEMPLATE.read_text()
        cls.artifacts = json.loads(ARTIFACTS.read_text())

    def signature_of(self, contract, name):
        for entry in self.artifacts[contract]["abi"]:
            if entry.get("type") == "function" and entry.get("name") == name:
                return [i["type"] for i in entry.get("inputs", [])]
        self.fail("%s.%s is not in the compiled ABI" % (contract, name))

    def declared_types(self, fragment):
        """Argument types from a human-readable ABI line in the template."""
        inside = fragment[fragment.index("(") + 1:fragment.rindex(")")]
        if not inside.strip():
            return []
        out = []
        for part in inside.split(","):
            out.append(part.strip().split(" ")[0])
        return out

    def fragment(self, name):
        # Up to the FIRST close paren: several of these fragments carry a
        # `returns (...)` clause, and a greedy match swallows it.
        match = re.search(r'"function %s\(([^)]*)\)' % re.escape(name), self.html)
        self.assertIsNotNone(match, "no inline fragment for %s" % name)
        return "f(" + match.group(1) + ")"

    def test_claim_signature_matches_the_distributor(self):
        self.assertEqual(self.declared_types(self.fragment("claim")),
                         self.signature_of("RewardDistributor", "claim"))

    def test_claimed_signature_matches_the_distributor(self):
        self.assertEqual(self.declared_types(self.fragment("claimed")),
                         self.signature_of("RewardDistributor", "claimed"))

    def test_fund_epoch_signature_matches_the_treasury(self):
        self.assertEqual(self.declared_types(self.fragment("fundEpoch")),
                         self.signature_of("Treasury", "fundEpoch"))

    def test_fundable_amount_signature_matches_the_treasury(self):
        self.assertEqual(self.declared_types(self.fragment("fundableAmount")),
                         self.signature_of("Treasury", "fundableAmount"))

    def test_epochs_signature_matches_the_epoch_manager(self):
        self.assertEqual(self.declared_types(self.fragment("epochs")),
                         self.signature_of("EpochManager", "epochs"))

    def test_the_page_reads_finalized_from_the_right_tuple_slot(self):
        # epochs() returns a 9-tuple; `finalized` is last and `rewardRoot` is
        # second. Reading the wrong index would let the page cheerfully offer a
        # claim on an unfinalized epoch.
        outputs = None
        for entry in self.artifacts["EpochManager"]["abi"]:
            if entry.get("type") == "function" and entry.get("name") == "epochs":
                outputs = [o["name"] for o in entry.get("outputs", [])]
        self.assertIsNotNone(outputs)
        self.assertEqual(outputs.index("finalized"), 8)
        self.assertEqual(outputs.index("rewardRoot"), 1)
        self.assertIn("row[8]", self.html)
        self.assertIn("row[1]", self.html)


class RouteTest(unittest.TestCase):
    def test_the_route_redirects_to_the_axoncoins_page(self):
        source = (pathlib.Path(BACKEND) / "blueprints" / "main.py").read_text()
        tree = ast.parse(source)
        found = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "claim":
                found = node
        self.assertIsNotNone(found, "main.claim is missing")
        body = ast.unparse(found)
        # The panel moved onto the AXONCoins page, so this route only
        # redirects now. Asserted rather than deleted: an existing link or
        # bookmark must land somewhere useful instead of 404ing.
        self.assertIn("redirect", body)
        self.assertIn("credits.index", body)
        self.assertIn("#claim", body)
        # The contract addresses moved with the panel — they are supplied by the
        # credits route now, and the same assertions follow them there rather
        # than being dropped.
        credits_src = (pathlib.Path(BACKEND) / "blueprints" / "credits.py").read_text()
        index_src = credits_src[credits_src.index("def index()"):
                                credits_src.index("def claim_signup()")]
        for key in ("RewardDistributor", "Treasury", "EpochManager"):
            self.assertIn(key, index_src, "%s no longer reaches the claim panel" % key)
        # The token key must survive the CreditToken -> AxonToken rename in
        # both directions until the stack is redeployed.
        self.assertIn("AxonToken", index_src)
        self.assertIn("CreditToken", index_src)


if __name__ == "__main__":
    unittest.main()
