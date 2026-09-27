"""Which token address the site reads, across the CreditToken -> AxonToken rename.

The rename is a NEW deployment, not an upgrade: `credit` is `immutable` in
RewardDistributor, StakeVault and DisputeManager, so the token cannot be
repointed and the whole stack is redeployed together. That leaves a window
between shipping this code and finishing that redeploy where the only token that
exists on-chain is the old one.

Reading only the new key during that window would report every holder's balance
as missing — the site would say zero, confidently, to people who hold tokens.
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
    """Exec just the named definitions, without importing the module.

    services/pof_chain.py imports the Flask app at module scope; pulling that in
    would make this test depend on the whole web stack to check a dictionary
    lookup.
    """
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


PC = _load_pure("services/pof_chain.py", {"TOKEN_KEYS", "token_address"})


class TokenAddressTest(unittest.TestCase):
    NEW = "0x1111111111111111111111111111111111111111"
    OLD = "0x2222222222222222222222222222222222222222"

    def resolve(self, addresses):
        PC["pof_addresses"] = lambda: addresses
        return PC["token_address"]()

    def test_prefers_the_new_token_once_it_is_deployed(self):
        self.assertEqual(
            self.resolve({"AxonToken": self.NEW, "CreditToken": self.OLD}), self.NEW)

    def test_falls_back_to_the_old_token_until_the_redeploy_lands(self):
        self.assertEqual(self.resolve({"CreditToken": self.OLD}), self.OLD)

    def test_new_token_alone_is_enough(self):
        self.assertEqual(self.resolve({"AxonToken": self.NEW}), self.NEW)

    def test_blank_entry_does_not_count_as_deployed(self):
        # The console writes "" for a contract it has not deployed yet. Treating
        # that as an address would send every balance read to the empty string
        # and return None, hiding an old token that is still perfectly readable.
        self.assertEqual(
            self.resolve({"AxonToken": "", "CreditToken": self.OLD}), self.OLD)

    def test_nothing_deployed_is_empty_not_an_error(self):
        self.assertEqual(self.resolve({}), "")


if __name__ == "__main__":
    unittest.main()
