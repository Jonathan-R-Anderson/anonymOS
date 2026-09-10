"""Channel setup: the UI that gets a tipper from "no channel" to a funded one.

WHY THIS EXISTS
---------------
`tip-channel.js` has been able to open a payment channel since P8-b, and until
now nothing called it. A tipper with no channel was told they had no channel and
offered nothing — which made every other part of the tipping system unreachable
to anybody who had not opened one by hand, on Mainnet, with their own script.

These tests guard the pieces of that flow which live in this repository rather
than in the browser: the dialog markup, the ids the script binds to, and the
production configuration naming the deployed contract. The click-through
behaviour is covered by proof-of-facilitation/browser-test/channel-setup.test.mjs.

WHAT IS BEING PROTECTED
-----------------------
Opening a channel is two Ethereum Mainnet transactions against real AXON, and
the first of them is an ERC-20 `approve` — the transaction that hands a contract
power over a token balance. So the panel must show WHICH contract before either
wallet prompt appears. A funding UI that omits the address is asking somebody to
approve a stranger.
"""

import ast
import os
import pathlib
import re
import sys
import unittest

BACKEND = str(pathlib.Path(__file__).resolve().parent.parent)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import jinja2  # noqa: E402

ROOT = pathlib.Path(BACKEND).parent
TEMPLATES = pathlib.Path(BACKEND) / "templates"
STATIC = pathlib.Path(BACKEND) / "static" / "pof"

# The contract that is actually deployed and finalized on Ethereum Mainnet.
DEPLOYED_MANAGER = "0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c"
DEPLOYED_CHAIN_ID = "1"


def render_dialog():
    """The real macro, through Jinja, exactly as a page gets it."""
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(TEMPLATES)))
    env.globals["url_for"] = lambda ep, **kw: "/" + str(kw.get("path", ep))
    template = env.from_string(
        '{% import "_tip_button.html" as m with context %}{{ m.tip_dialog() }}')
    return template.render()


class ChannelSetupPanelTest(unittest.TestCase):
    """The panel exists, and says the things a person needs before signing."""

    def setUp(self):
        self.html = render_dialog()

    def test_the_setup_panel_is_rendered(self):
        self.assertIn('id="tip-setup-panel"', self.html)
        self.assertIn("Set up payment channel", self.html)

    def test_it_starts_hidden_so_the_tip_panel_is_what_opens(self):
        # Both panels ship in one dialog; setup is revealed only when the chain
        # says there is no channel. If it rendered visible, every tipper would
        # be invited to spend gas before anybody had checked whether they
        # needed to.
        panel = re.search(r'<div id="tip-setup-panel"[^>]*>', self.html)
        self.assertIsNotNone(panel, "the setup panel must be present")
        self.assertIn("hidden", panel.group(0))

    def test_it_names_the_network_and_that_tips_are_off_chain(self):
        # The honest framing: the first thing costs money, everything after is
        # free. A user told "one click to tip" and then shown a gas prompt feels
        # misled at exactly the wrong moment.
        self.assertIn("Ethereum Mainnet", self.html)
        self.assertIn("off-chain", self.html)

    def test_it_has_a_funding_amount_field_defaulting_to_one_anon(self):
        field = re.search(r'<input[^>]*id="tip-fund-amount"[^>]*>', self.html)
        self.assertIsNotNone(field, "there must be an editable funding amount")
        self.assertIn('value="1"', field.group(0))

    def test_it_has_an_explicit_open_button(self):
        self.assertIn('id="tip-open-channel"', self.html)
        self.assertIn("Open Payment Channel", self.html)

    def test_the_contract_address_has_somewhere_to_be_shown(self):
        # Filled by the script from the quote, so the id must exist for the
        # disclosure to land anywhere at all.
        self.assertIn('id="tip-setup-manager"', self.html)
        self.assertIn('id="tip-setup-token"', self.html)
        self.assertIn("ChannelManagerV2", self.html)

    def test_the_pay_panel_is_separable_from_setup(self):
        # One or the other, never both: one is free and off chain, the other is
        # two Mainnet transactions.
        self.assertIn('id="tip-pay-panel"', self.html)


class ScriptBindsWhatTheTemplateRendersTest(unittest.TestCase):
    """Every id the script reaches for must exist in the markup, and vice versa.

    This is the failure that a template test and a JavaScript test each miss on
    their own: both sides pass in isolation while the button does nothing,
    because one of them was renamed.
    """

    def setUp(self):
        self.html = render_dialog()
        self.script = (STATIC / "tip-init.js").read_text(encoding="utf-8")

    def test_every_id_the_script_queries_is_in_the_dialog(self):
        queried = set(re.findall(r'querySelector\("#([\w-]+)"\)', self.script))
        missing = sorted(i for i in queried if f'id="{i}"' not in self.html)
        self.assertEqual(
            missing, [],
            "tip-init.js binds to ids the dialog does not render: %s" % missing)

    def test_the_setup_controls_are_actually_bound(self):
        for element in ("tip-open-channel", "tip-fund-amount", "tip-setup-panel"):
            self.assertIn(
                element, self.script,
                "%s is rendered but nothing in tip-init.js uses it" % element)


# These tests read files removed with the stripped features: templates/post-view.html, templates/thread.html.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_POST_VIEWS_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "templates/post-view.html",
        "templates/thread.html",
    )
)
_POST_VIEWS_PRESENT_GONE = "the post and thread templates were removed; these read them"

class EveryButtonHasAPanelToOpenTest(unittest.TestCase):
    """A page with a Tip button must render the dialog exactly once.

    The bug this catches is silent and total: `bindTips` starts with

        const dialog = root.querySelector("#tip-dialog");
        if (!dialog) return () => {};

    so on a page with buttons and no dialog, every Tip click goes nowhere — no
    error, no message, nothing in the console. Thread pages were in exactly that
    state, which meant the main surface of the site had a tipping button that
    had never worked.

    Exactly once, not at least once: the dialog's elements are addressed by id,
    and two of them makes `querySelector` pick one and the other inert.
    """

    # Full pages: buttons AND the panel they open.
    PAGES = ("thread.html", "profile-view.html", "stream-watch.html")
    # Fragments injected into a page that already has one. A dialog here would
    # duplicate every id in it.
    FRAGMENTS = ("post-view.html", "post-view-single.html")

    def source(self, name):
        return (TEMPLATES / name).read_text(encoding="utf-8")

    @unittest.skipUnless(_POST_VIEWS_PRESENT, _POST_VIEWS_PRESENT_GONE)
    def test_pages_that_show_buttons_render_one_dialog(self):
        for name in self.PAGES:
            text = self.source(name)
            self.assertEqual(
                text.count("tip_dialog()"), 1,
                "%s must render the tip dialog exactly once — buttons without "
                "it are clicks that go nowhere" % name)

    @unittest.skipUnless(_POST_VIEWS_PRESENT, _POST_VIEWS_PRESENT_GONE)
    def test_fragments_do_not_render_a_second_dialog(self):
        for name in self.FRAGMENTS:
            text = self.source(name)
            self.assertEqual(
                text.count("tip_dialog()"), 0,
                "%s is injected into a page that already has the dialog; a "
                "second one duplicates every id in it" % name)


class ProductionConfigurationTest(unittest.TestCase):
    """The deployed address, as configuration rather than as a claim.

    `challengePeriod` is immutable and the contract is finalized, so this pair of
    values is not a preference — it is the identity of the thing every signed
    state is bound to. A state signed for one deployment cannot be replayed
    against another, which is exactly why it must not drift silently.
    """

    def test_dotenv_names_the_deployed_contract_on_chain_one(self):
        env_path = ROOT / ".env"
        if not env_path.exists():
            self.skipTest(".env is not present in this checkout")
        text = env_path.read_text(encoding="utf-8", errors="replace")
        manager = re.search(r"^CHANNEL_MANAGER_ADDRESS=(.+)$", text, re.M)
        chain = re.search(r"^CHANNEL_CHAIN_ID=(.+)$", text, re.M)
        self.assertIsNotNone(manager, "CHANNEL_MANAGER_ADDRESS is not configured")
        self.assertIsNotNone(chain, "CHANNEL_CHAIN_ID is not configured")
        self.assertEqual(manager.group(1).strip().lower(), DEPLOYED_MANAGER)
        self.assertEqual(chain.group(1).strip(), DEPLOYED_CHAIN_ID)

    def test_both_keys_reach_app_config(self):
        # Being in .env is not enough. `_apply_env_config_overrides` only applies
        # keys app.config already knows about, so a key absent from this set is
        # present on the pod and invisible to the application — the feature is
        # then silently off while the deployment looks correctly configured.
        #
        # READ FROM SOURCE, not imported. Several tests in this suite install a
        # stub `shared` into sys.modules to isolate the service under test, so
        # `import shared` here returns whichever one ran first and this assertion
        # would be about a fake. Parsing the file is the only way to be sure it
        # is the real declaration being checked.
        declared = set()
        tree = ast.parse((pathlib.Path(BACKEND) / "shared.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if any(getattr(t, "id", "") == "_EXTRA_ENV_CONFIG_KEYS" for t in node.targets):
                declared = {
                    e.value for e in node.value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                }
                break
        self.assertTrue(declared, "_EXTRA_ENV_CONFIG_KEYS was not found in shared.py")
        for key in ("CHANNEL_MANAGER_ADDRESS", "CHANNEL_CHAIN_ID"):
            self.assertIn(
                key, declared,
                "%s would never reach app.config, so deployment() stays None "
                "and every tip fails with 'not configured'" % key)


if __name__ == "__main__":
    unittest.main()
