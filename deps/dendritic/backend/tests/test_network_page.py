"""The network page's payment sections, and the claims they are allowed to make.

The page explains the payment-channel work to people deciding whether to trust
it with money. That makes two kinds of error expensive in different ways:

  a broken diagram   embarrassing
  a false claim      the reason somebody put funds into something unfinished

So these tests check both. The structural half is ordinary: the sections exist
and their inline SVG is well-formed XML. The half that matters is the status
half — every feature that is NOT running must still say so.

That second group is a regression guard with a specific failure in mind. A
badge saying "Not enabled" is one word away from saying nothing, and the diff
that removes it looks like tidying. If the feature ships, these tests should be
UPDATED, deliberately, in the same change that ships it — not quietly deleted.
"""

import os
import pathlib
import re
import unittest
import xml.etree.ElementTree as ET

from jinja2 import Environment, FileSystemLoader

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES = pathlib.Path(BACKEND) / "templates"
NETWORK = TEMPLATES / "network.html"


class NetworkPageStructure(unittest.TestCase):
    def setUp(self):
        self.html = NETWORK.read_text(encoding="utf-8")

    def test_template_parses(self):
        env = Environment(loader=FileSystemLoader(str(TEMPLATES)))
        env.parse(self.html)  # raises on malformed Jinja

    def test_payment_sections_are_present(self):
        """Each payment concept the page is supposed to explain has a heading."""
        for heading in [
            "How work turns into payment",
            "Why an off-chain payment is still safe",
            "One channel with the network",
            "Who watches while you are asleep",
            "If your device dies",
            "How we know the blockchain is telling the truth",
            "Giving an award without a transaction fee",
            "Splitting one payment across several routes",
            "Pooled tipping",
        ]:
            self.assertIn(heading, self.html, f"the page no longer explains: {heading}")

    def test_every_svg_is_well_formed(self):
        """A diagram that fails to parse renders as nothing, silently."""
        svgs = re.findall(r"<svg\b.*?</svg>", self.html, re.S)
        self.assertGreaterEqual(len(svgs), 10, "expected the page to carry its diagrams")
        for i, svg in enumerate(svgs):
            with self.subTest(svg=i):
                try:
                    ET.fromstring(svg)
                except ET.ParseError as exc:
                    self.fail(f"diagram {i} is not well-formed XML: {exc}")

    def test_every_diagram_has_an_accessible_label(self):
        """Every diagram carries a label — except the hidden <defs> holder.

        The page keeps its arrow marker in a zero-sized aria-hidden <svg>, which
        is presentational and correctly unlabelled. Exempting it by its own
        aria-hidden attribute rather than by index means the exemption stays
        correct if the markup moves.
        """
        labelled = 0
        for i, svg in enumerate(re.findall(r"<svg\b.*?</svg>", self.html, re.S)):
            if 'aria-hidden="true"' in svg:
                continue
            with self.subTest(svg=i):
                self.assertIn("aria-label", svg, f"diagram {i} has no aria-label")
            labelled += 1
        self.assertGreaterEqual(labelled, 10, "expected the page to carry its diagrams")


class NetworkPageClaims(unittest.TestCase):
    """The page must not describe unfinished work as if it were running."""

    def setUp(self):
        self.html = NETWORK.read_text(encoding="utf-8")

    def _section(self, heading):
        """The markup from one <h2> up to the next section."""
        start = self.html.index(heading)
        rest = self.html[start:]
        end = rest.find('<div class="nw__sec">')
        return rest if end == -1 else rest[:end]

    def test_multipath_is_marked_not_enabled(self):
        """Multi-path planning exists; the executor does not.

        doc/p13-multipath-security-table.md records ten GAP rows, all from the
        same missing piece: nothing coordinates fragments once they are in
        flight. Offering this to users would put real locks on real channels
        with no coordinated way to settle or unwind them.
        """
        section = self._section("Splitting one payment across several routes")
        self.assertIn("Not enabled", section,
                      "multi-path lost its 'Not enabled' badge — if it shipped, update "
                      "this test and doc/p13-multipath-security-table.md together")
        self.assertIn("switched off", section)

    def test_pooled_tipping_is_marked_design(self):
        section = self._section("Pooled tipping")
        self.assertIn("Design", section,
                      "pooled tipping is roadmap P15 and is not built")
        self.assertIn("design, not a running feature", section)

    def test_pooled_tipping_states_the_non_custodial_line(self):
        """The whole point of the design is that the pool is not a custodian."""
        section = self._section("Pooled tipping")
        self.assertIn("custodian", section)
        self.assertIn("never become", section)

    def test_watchtower_says_it_cannot_move_funds(self):
        """'Evidence, not authority' is the property, and it must be stated."""
        section = self._section("Who watches while you are asleep")
        self.assertIn("cannot", section)
        self.assertIn("evidence", section.lower())

    def test_reorg_budget_is_not_claimed_as_measured(self):
        """The reorg term is unmeasured, and an absence of events is not evidence.

        This is the single claim on the page most likely to drift into a
        falsehood, because the observation runs continuously and it is tempting
        to report 'no reorgs seen' as a result. It is not one.
        """
        section = self._section("Who watches while you are asleep")
        self.assertIn("still being observed", section)
        self.assertIn("absence of events", section)

    def test_verification_does_not_claim_provider_agreement_is_proof(self):
        """Multi-provider corroboration reduces risk; it proves nothing.

        The page is allowed to describe it. It is not allowed to call it
        verification — see doc/trust-anchor.md, option C, which was explicitly
        not built for this reason.
        """
        section = self._section("How we know the blockchain is telling the truth")
        self.assertIn("does not prove anything", section)


# These tests read files removed with the stripped features: templates/faq.html.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_FAQ_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "templates/faq.html",
    )
)
_FAQ_PRESENT_GONE = "the FAQ page was removed; these read templates/faq.html"

class FaqBlockchainClaims(unittest.TestCase):
    """The FAQ is where most people meet the blockchain part. It must be exact.

    The network page is read by people who went looking. The FAQ is read by
    people who did not, which makes an overstatement there more costly, not
    less.
    """

    def setUp(self):
        self.html = (TEMPLATES / "faq.html").read_text(encoding="utf-8")

    @unittest.skipUnless(_FAQ_PRESENT, _FAQ_PRESENT_GONE)
    def test_channels_section_exists_and_is_linked(self):
        self.assertIn('id="payment-channels"', self.html)
        self.assertIn("#payment-channels", self.html, "the section is not in the contents list")

    @unittest.skipUnless(_FAQ_PRESENT, _FAQ_PRESENT_GONE)
    def test_channels_are_not_described_as_live(self):
        """V2 is not deployed and tipping over channels is not switched on."""
        start = self.html.index('id="payment-channels"')
        section = self.html[start:self.html.index("<h1", start + 10)]
        self.assertIn("not live yet", section)
        self.assertIn("not switched on", section)
        self.assertIn("not deployed", section)

    @unittest.skipUnless(_FAQ_PRESENT, _FAQ_PRESENT_GONE)
    def test_channels_section_states_the_immutable_gate(self):
        """Why deployment is blocked is the part that makes the delay make sense."""
        start = self.html.index('id="payment-channels"')
        section = self.html[start:self.html.index("<h1", start + 10)]
        self.assertIn("never be changed once deployed", section)

    @unittest.skipUnless(_FAQ_PRESENT, _FAQ_PRESENT_GONE)
    def test_url_for_endpoints_in_faq_resolve(self):
        """A url_for naming a missing endpoint raises at render time, not import.

        Caught one: the route function is network_topology, so url_for('main.network')
        would have 500'd the page for every reader.
        """
        import re

        main_src = (pathlib.Path(BACKEND) / "blueprints" / "main.py").read_text(encoding="utf-8")
        defined = set(re.findall(r"^def (\w+)", main_src, re.M))
        for endpoint in sorted(set(re.findall(r"url_for\('([^']+)'", self.html))):
            blueprint, _, func = endpoint.partition(".")
            if blueprint != "main":
                continue  # other blueprints are out of this file's scope
            with self.subTest(endpoint=endpoint):
                self.assertIn(func, defined, f"{endpoint} names no view in main.py")


if __name__ == "__main__":
    unittest.main()
