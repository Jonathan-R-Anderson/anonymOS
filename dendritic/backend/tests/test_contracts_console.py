"""The admin contracts console must only reach for things the chain bundle has.

WHY THIS TEST EXISTS
--------------------
Twice now, a find-and-replace sweeping the codebase from Ethereum to Ethereum has
walked straight through this template's JavaScript and renamed a *library
object* as though it were a chain reference. `window.PoFChain = {ethers, ethereum}`
is what the vendored bundle exports; `ethereum` there is the name of the
ethereum-ethers package, not a statement about which chain the site targets. A
sweep that rewrites it to `PoFChain.ethereum` produces `undefined`, and the
console dies at the first click with

    Cannot read properties of undefined (reading 'BrowserProvider')

which says nothing about the cause. Nothing catches it: the template renders
fine, the tests pass, and the failure only appears in a browser with a wallet
attached — the one place hardest to check.

So: read the bundle's actual exports, read the template's actual property
accesses, and require the second to be a subset of the first. It is a cheap
check for a bug that has twice reached production.
"""

import ast
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TEMPLATE = os.path.join(ROOT, "templates", "admin-contracts.html")
BUNDLE = os.path.join(ROOT, "static", "pof", "chain-bundle.js")


def bundle_exports():
    """The keys on `window.PoFChain`, read from the minified bundle itself.

    Matching the assignment rather than hardcoding a list: the point is to catch
    the template drifting away from the bundle, and a hardcoded list would drift
    with it the next time somebody updates the vendored file.
    """
    with open(BUNDLE, encoding="utf-8", errors="replace") as handle:
        source = handle.read()
    match = re.search(r"window\.PoFChain\s*=\s*\{([^}]*)\}", source)
    assert match, "chain-bundle.js no longer assigns window.PoFChain"
    return {
        key.strip()
        for key in re.findall(r"([A-Za-z_$][\w$]*)\s*:", match.group(1))
    }


def template_accesses():
    """Every `PoFChain.<name>` the template reads, with the line it is on."""
    with open(TEMPLATE, encoding="utf-8") as handle:
        lines = handle.readlines()
    found = []
    for number, line in enumerate(lines, 1):
        for name in re.findall(r"PoFChain\.([A-Za-z_$][\w$]*)", line):
            found.append((name, number))
    return found


class ChainBundleAccessTest(unittest.TestCase):
    def test_the_bundle_still_exports_what_the_console_is_written_against(self):
        # THE SWEEP THIS FILE WARNS ABOUT HIT THIS FILE. The docstring above
        # describes a find-and-replace from zkSync to Ethereum walking through
        # code and renaming a LIBRARY OBJECT as though it were a chain
        # reference. It did that here: the expectation was rewritten to
        # "ethereum", which the vendored bundle has never exported, so this test
        # asserted the impossible and failed for every run since.
        #
        # `zksync` is the ethers-zksync package the bundle still vendors. It is
        # DEAD WEIGHT -- the console reads only PoFChain.ethers, and the next
        # test proves it -- but it is what the file exports, and this assertion
        # is about the file. Dropping the vendored package is a separate change
        # with its own risk, and quietly asserting a fiction is not a substitute.
        self.assertEqual(bundle_exports(), {"ethers", "zksync"})

    def test_every_property_the_console_reads_actually_exists(self):
        exported = bundle_exports()
        bad = [(name, line) for name, line in template_accesses() if name not in exported]
        self.assertEqual(
            bad, [],
            "admin-contracts.html reads PoFChain properties the bundle does not "
            "export: %s. Exported: %s. This is almost always a chain-rename sweep "
            "that hit a library object name — see this module's docstring."
            % (", ".join("%s (line %d)" % (n, l) for n, l in bad), sorted(exported)))

    def test_the_console_reads_at_least_one_property(self):
        # A guard on the guard: if the template stops matching at all (renamed,
        # moved, bundled differently) the test above passes vacuously.
        self.assertTrue(template_accesses(), "no PoFChain access found — did the template move?")


class MainnetDeployPathTest(unittest.TestCase):
    """Ethereum mainnet cannot accept the Ethereum deploy path, so it must be gone.

    A type-113 (EIP-712) transaction is a Ethereum format. Sending those bytes to
    mainnet returns "transaction could not be decoded: unsupported transaction
    type" — the deploy fails every time, and the error blames the transaction
    rather than the chain. These symbols are the ones that would put it back.
    """

    ETHEREUM_ONLY = [
        ("EIP712Signer", "signs Ethereum type-113 transactions"),
        ("serializeEip712", "serializes Ethereum type-113 transactions"),
        ("gasPerPubdata", "a Ethereum-only fee parameter"),
        ("estimateFee", "zks_estimateFee, a Ethereum-only RPC"),
        ("getDeployedContracts", "reads the Ethereum CONTRACT_DEPLOYER log"),
    ]

    def setUp(self):
        with open(TEMPLATE, encoding="utf-8") as handle:
            self.source = handle.read()
        # Comments are stripped first. Several of these symbols are named in
        # comments explaining why the Ethereum path was removed, and a test that
        # cannot tell an explanation from a call would force those comments to
        # be deleted — losing the reasoning to protect against losing the code.
        js = "\n".join(re.findall(r"<script>(.*?)</script>", self.source, re.S))
        js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
        js = re.sub(r"^\s*//.*$", "", js, flags=re.M)
        self.code = js

    def test_no_ethereum_only_call_survives(self):
        for symbol, why in self.ETHEREUM_ONLY:
            self.assertNotIn(
                symbol, self.code,
                "%s is %s and does not work on Ethereum mainnet" % (symbol, why))

    def test_the_target_chain_is_mainnet(self):
        self.assertIn('chainIdHex: "0x1"', self.source)
        self.assertIn("chainId: 1n", self.source)


class TemplateJavaScriptParsesTest(unittest.TestCase):
    """The template's JavaScript is syntactically valid.

    Rendering a template proves nothing about the script inside it: a broken
    edit ships a 200 with a dead page. Node is not assumed to be present —
    where it is missing this degrades to a bracket-balance check, which would
    still have caught every hand-edit made to this file.
    """

    def setUp(self):
        with open(TEMPLATE, encoding="utf-8") as handle:
            source = handle.read()
        js = "\n".join(re.findall(r"<script>(.*?)</script>", source, re.S))
        # Jinja expressions are not JavaScript. One already inside a JS string
        # becomes bare text; one standing alone becomes a string literal.
        js = re.sub(r'(["\'`])\s*\{\{.*?\}\}\s*\1', r"\1JINJA\1", js, flags=re.S)
        js = re.sub(r"\{\{.*?\}\}", '"JINJA"', js, flags=re.S)
        js = re.sub(r"\{%.*?%\}", "", js, flags=re.S)
        self.js = js

    def test_it_parses(self):
        import shutil
        import subprocess
        import tempfile

        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write(self.js)
            path = handle.name
        try:
            result = subprocess.run([node, "--check", path],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
