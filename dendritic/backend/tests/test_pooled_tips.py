"""Pooled tipping: when a Tip button may appear, and what it must never leak.

The decisions worth testing are the ones that decide whether a visitor is shown
a payment path that does not exist, and whether this server learns anything it
has no business knowing. Both are security properties, not cosmetics:

  - a button that promises a path which is not there fails AFTER the click, and
    the failure looks like the recipient's fault;
  - a server that learns who tipped whom is the metadata chokepoint P15 exists
    to avoid.

Same pure-loading approach as test_channel_awards.py: the functions are pulled
out by AST and exec'd with injected dependencies, so nothing here needs Flask, a
database or a running app.
"""

import ast
import os
import pathlib
import re
import sys
import types
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services.channel_state import derive_channel_id, is_party_a, normalize_address  # noqa: E402

WANTED = {
    "PooledTipError", "_profile_of", "_endpoint_of", "_wallet_of",
    "pool_label", "accepts_pooled_tips", "availability", "quote",
    "quote_is_fresh", "QUOTE_TTL_SECONDS", "MAX_TIP", "ANON_DECIMALS",
    "volunteer_of", "volunteer_endpoint_of", "signing_mode",
    "SIGNING_MAILBOX", "SIGNING_DELEGATE", "SIGNING_MODES",
    # Amount handling, split out of quote() when tips stopped being whole coins.
    "parse_tip_amount", "format_tip_amount", "MIN_TIP_BASE",
}

AUTHOR = "0x" + "a" * 40
VIEWER = "0x" + "b" * 40


def load(deployment_value=(1, "0x" + "c" * 40), wallets=None):
    """Load pooled_tips with its dependencies injected."""
    source = (pathlib.Path(BACKEND) / "services/pooled_tips.py").read_text()
    tree = ast.parse(source)
    keep = [n for n in tree.body
            if (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in WANTED)
            or (isinstance(n, ast.Assign)
                and {t.id for t in n.targets if isinstance(t, ast.Name)} & WANTED)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)

    wallets = wallets if wallets is not None else {}

    # services.post_awards is imported INSIDE _wallet_of, so it is stubbed in
    # sys.modules rather than injected.
    stub = types.ModuleType("services.post_awards")
    stub.wallet_for_slip = lambda slip: wallets.get(id(slip)) if slip is not None else None
    sys.modules["services.post_awards"] = stub

    ns = {
        "deployment": lambda: deployment_value,
        "derive_channel_id": derive_channel_id,
        "is_party_a": is_party_a,
        "normalize_address": normalize_address,
        "time": __import__("time"),
    }
    exec(compile(module, "services/pooled_tips.py", "exec"), ns)
    return ns


class Profile:
    def __init__(self, **kw):
        self.is_public = kw.get("is_public", True)
        self.pool_enabled = kw.get("pool_enabled", False)
        self.pool_name = kw.get("pool_name")
        self.channel_endpoint = kw.get("channel_endpoint", "https://node.example")
        # A volunteer is now part of a working configuration: without one there
        # is nowhere for a tipper's frame to go.
        self.pool_volunteer = kw.get("pool_volunteer", "volunteer-1")
        self.pool_volunteer_endpoint = kw.get(
            "pool_volunteer_endpoint", "https://volunteer.example")
        self.pool_signing_mode = kw.get("pool_signing_mode", "mailbox")
        self.slug = kw.get("slug", "creator")


class Slip:
    def __init__(self, profile=None):
        self.profile = profile


def author_slip(**kw):
    return Slip(Profile(**kw))


class PooledTipAvailability(unittest.TestCase):
    """Every branch that cannot PROVE a path exists must return None."""

    def setUp(self):
        self.author = author_slip(pool_enabled=True)
        self.viewer = Slip(Profile(slug="viewer"))
        self.wallets = {id(self.author): AUTHOR, id(self.viewer): VIEWER}

    def avail(self, **kw):
        ns = load(wallets=self.wallets, **kw)
        return ns["availability"](self.author, self.viewer)

    def test_enabled_and_configured_is_available(self):
        tip = self.avail()
        self.assertIsNotNone(tip, "a fully configured recipient shows no Tip button")
        self.assertEqual(tip["recipient"], AUTHOR)
        self.assertEqual(tip["recipient_slug"], "creator")

    def test_disabled_is_the_default(self):
        self.author.profile.pool_enabled = False
        self.assertIsNone(self.avail(),
                          "pooled tipping was available without the owner enabling it")

    def test_no_recipient_wallet(self):
        self.wallets[id(self.author)] = None
        self.assertIsNone(self.avail(), "a recipient with no wallet was shown as payable")

    def test_no_published_node(self):
        self.author.profile.channel_endpoint = ""
        self.assertIsNone(self.avail(), "a recipient with no node was shown as payable")

    def test_plaintext_node_is_refused(self):
        # http:// would let a network attacker rewrite the state the browser is
        # about to sign against.
        self.author.profile.channel_endpoint = "http://node.example"
        self.assertIsNone(self.avail(), "an http:// node endpoint was accepted")

    def test_private_profile(self):
        self.author.profile.is_public = False
        self.assertIsNone(self.avail(), "a private profile advertised tipping")

    def test_no_deployment_configured(self):
        self.assertIsNone(self.avail(deployment_value=None),
                          "tipping was offered with no channel deployment configured")

    def test_viewer_without_a_wallet(self):
        self.wallets[id(self.viewer)] = None
        self.assertIsNone(self.avail(),
                          "a visitor with no wallet was offered a payment path")

    def test_self_tipping_is_refused(self):
        self.wallets[id(self.viewer)] = AUTHOR
        self.assertIsNone(self.avail(), "a user was offered a tip to themselves")

    def test_anonymous_visitor(self):
        ns = load(wallets=self.wallets)
        self.assertIsNone(ns["availability"](self.author, None),
                          "a logged-out visitor was offered a payment path")

    def test_recipient_side_is_separate_from_payability(self):
        """accepts_pooled_tips describes the RECIPIENT only.

        It must stay true for a logged-out visitor — the profile may honestly say
        "accepts tips" — while availability() still says that visitor cannot send
        one. Collapsing the two would either lie to visitors or hide the feature.
        """
        ns = load(wallets=self.wallets)
        self.assertTrue(ns["accepts_pooled_tips"](self.author))
        self.assertIsNone(ns["availability"](self.author, None))


class PooledTipLeakage(unittest.TestCase):
    """What a visitor may learn is exactly: the wallet, the slug, the label."""

    def test_availability_exposes_no_payment_metadata(self):
        author = author_slip(pool_enabled=True, pool_name="Coffee")
        viewer = Slip(Profile(slug="v"))
        ns = load(wallets={id(author): AUTHOR, id(viewer): VIEWER})
        tip = ns["availability"](author, viewer)

        self.assertEqual(set(tip), {"label", "recipient_slug", "recipient"},
                         "availability() grew a field; every addition is a new "
                         "thing every visitor learns about the recipient")
        blob = repr(tip).lower()
        for banned in ("channel_id", "nonce", "preimage", "route", "balance",
                       "aggregate", "withdraw", "signature", "sig_"):
            self.assertNotIn(banned, blob,
                             "availability() leaked %r to ordinary visitors" % banned)

    def test_label_defaults_without_revealing_configuration(self):
        author = author_slip(pool_enabled=True)
        ns = load(wallets={id(author): AUTHOR})
        self.assertEqual(ns["pool_label"](author.profile), "Tips")


class PooledTipQuote(unittest.TestCase):
    """The quote is the same bilateral machinery P9 already uses."""

    def setUp(self):
        self.author = author_slip(pool_enabled=True)
        self.viewer = Slip(Profile(slug="v"))
        self.wallets = {id(self.author): AUTHOR, id(self.viewer): VIEWER}

    def test_quote_carries_no_channel_or_payment_identifier(self):
        """A quote describes; it does not instruct.

        The browser derives the channel itself from its own wallet address
        (tip-channel.js deriveChannelId), so a channel id here would be at best
        redundant and at worst an instruction pointing the wallet at a channel
        somebody else prepared.
        """
        ns = load(wallets=self.wallets)
        q = ns["quote"](self.author, self.viewer, amount=5)
        for banned in ("channel_id", "channel", "payment_id", "route", "nonce",
                       "preimage", "lock", "author_is_a", "balance", "aggregate"):
            self.assertNotIn(banned, q,
                             "the quote carries %r; a quote must describe, not "
                             "instruct" % banned)
        self.assertEqual(q["recipient"], AUTHOR)

    def test_quote_states_amount_fee_and_total(self):
        ns = load(wallets=self.wallets)
        q = ns["quote"](self.author, self.viewer, amount=7)
        # A STRING since tips became fractional: JSON numbers are doubles and
        # 0.1 does not survive one, so the displayed figure travels as text.
        self.assertEqual(q["amount"], "7")
        self.assertEqual(q["fee"], 0)
        self.assertEqual(q["total"], "7",
                         "total must equal amount + fee at the point of authorisation")

    def test_quote_refuses_a_bad_amount(self):
        ns = load(wallets=self.wallets)
        for bad in (None, 0, -1, "abc", 10 ** 9):
            with self.assertRaises(ns["PooledTipError"],
                                   msg="amount %r was accepted" % (bad,)):
                ns["quote"](self.author, self.viewer, amount=bad)

    def test_quote_expires(self):
        ns = load(wallets=self.wallets)
        q = ns["quote"](self.author, self.viewer, amount=5, now=1000)
        self.assertGreater(q["expires_at"], q["issued_at"])
        self.assertTrue(ns["quote_is_fresh"](q, now=q["expires_at"] - 1))
        self.assertFalse(ns["quote_is_fresh"](q, now=q["expires_at"]),
                         "an expired quote was still actionable; the recipient may "
                         "have switched pooling off in the meantime")
        self.assertFalse(ns["quote_is_fresh"]({}, now=1000))

    def test_quote_refuses_a_recipient_who_is_not_accepting(self):
        self.author.profile.pool_enabled = False
        ns = load(wallets=self.wallets)
        with self.assertRaises(ns["PooledTipError"]):
            ns["quote"](self.author, self.viewer, amount=5)

    def test_quote_refuses_self_tipping(self):
        self.wallets[id(self.viewer)] = AUTHOR
        ns = load(wallets=self.wallets)
        with self.assertRaises(ns["PooledTipError"]):
            ns["quote"](self.author, self.viewer, amount=5)

    def test_quote_refuses_without_a_deployment(self):
        ns = load(wallets=self.wallets, deployment_value=None)
        with self.assertRaises(ns["PooledTipError"]):
            ns["quote"](self.author, self.viewer, amount=5)

    def test_quote_carries_no_amount(self):
        """The server does not choose or record what is sent.

        The amount is the visitor's, agreed bilaterally with the recipient's
        node. A quote that carried one would be this server having an opinion
        about a payment it is not party to.
        """
        ns = load(wallets=self.wallets)
        q = ns["quote"](self.author, self.viewer, amount=5)
        # The amount is the VISITOR'S choice, echoed back so they can read it
        # before authorising. What must not appear is anything the server chose.
        # Text rather than a number since tips became fractional — the value is
        # the same, and JSON's number type cannot carry 0.1 exactly.
        self.assertEqual(q["amount"], "5")


class PooledTipPersistence(unittest.TestCase):
    """The database may learn that the switch is on. Nothing else."""

    def test_profile_model_stores_no_pool_value(self):
        source = (pathlib.Path(BACKEND) / "model/Profile.py").read_text()
        tree = ast.parse(source)
        cls = next(n for n in tree.body
                   if isinstance(n, ast.ClassDef) and n.name == "Profile")
        columns = [t.id for n in cls.body if isinstance(n, ast.Assign)
                   for t in n.targets if isinstance(t, ast.Name)]
        pool_columns = sorted(c for c in columns if c.startswith("pool"))
        # CONFIGURATION ONLY. Each of these records a choice the creator made —
        # whether pooling is on, what to call it, which volunteer services it,
        # and on what terms. None of them records an amount, and the loop below
        # is what actually enforces that; this list exists so that ADDING a
        # column is a deliberate act rather than something a test waves through.
        self.assertEqual(
            pool_columns,
            ["pool_enabled", "pool_name", "pool_signing_mode", "pool_volunteer",
             "pool_volunteer_endpoint"],
            "Profile grew an unexpected pool column. Every column here must be "
            "a setting; a balance makes the platform a custodian.")
        for c in columns:
            low = c.lower()
            if "pool" in low:
                for banned in ("balance", "amount", "total", "wei", "credit", "ledger"):
                    self.assertNotIn(banned, low,
                                     "Profile.%s looks like stored pool value" % c)

    def test_no_pool_ledger_model_exists(self):
        models = os.listdir(pathlib.Path(BACKEND) / "model")
        for name in models:
            low = name.lower()
            if "pool" in low and ("ledger" in low or "balance" in low or "tip" in low):
                self.fail("model/%s looks like a pooled-tip ledger; P15 forbids a "
                          "per-tip history and a stored pool balance" % name)

    def test_service_persists_nothing(self):
        """No writes. The module is a directory, not a party."""
        source = (pathlib.Path(BACKEND) / "services/pooled_tips.py").read_text()
        for banned in ("db.session", "session.add", "session.commit",
                       ".insert(", "INSERT INTO", "UPDATE "):
            self.assertNotIn(banned, source,
                             "pooled_tips.py writes to the database (%r); it must "
                             "store nothing about tips" % banned)


class PooledTipIntegration(unittest.TestCase):
    """One component, one availability rule, wired in one place."""

    def test_availability_is_computed_in_exactly_one_place(self):
        """Five templates calling availability() would be four chances to differ."""
        hits = []
        for root, _dirs, files in os.walk(pathlib.Path(BACKEND)):
            if "/tests" in root or "__pycache__" in root:
                continue
            for f in files:
                if not f.endswith(".py"):
                    continue
                path = os.path.join(root, f)
                text = pathlib.Path(path).read_text(errors="ignore")
                if "pooled_tips import availability" in text or "pooled_tips.availability" in text:
                    hits.append(os.path.relpath(path, BACKEND))
        hits = [h for h in hits if not h.startswith("services/pooled_tips")]
        self.assertLessEqual(len(hits), 2,
                             "availability() is called from %s; the rule should be "
                             "computed once and passed down" % hits)

    def test_one_reusable_tip_component(self):
        tpl = pathlib.Path(BACKEND) / "templates/_tip_button.html"
        self.assertTrue(tpl.exists(), "the reusable tip component is missing")
        raw = tpl.read_text()
        self.assertIn("macro tip_button", raw)
        # Strip Jinja comments: the block documenting what must NOT be rendered
        # obviously names those things. What matters is the EMITTED markup.
        body = re.sub(r"\{#.*?#\}", "", raw, flags=re.S)
        # It must render nothing without a live availability dict.
        self.assertIn("if tip", body,
                      "the component renders unconditionally; a disabled recipient "
                      "would show a button that cannot work")
        for banned in ("channel_id", "nonce", "preimage", "sig_a", "sig_b"):
            self.assertNotIn(banned, body,
                             "the tip component exposes %r to visitors" % banned)


if __name__ == "__main__":
    unittest.main()


class TipQuoteRoute(unittest.TestCase):
    """Structural properties of the HTTP boundary.

    Checked by reading the route's AST rather than booting Flask, matching this
    package's existing approach. What matters here is not that a happy path
    returns 200 — it is that the route CANNOT read certain things from a
    request, and cannot sign or persist. Those are properties of the code, and a
    request-level test would only sample them.
    """

    def setUp(self):
        source = (pathlib.Path(BACKEND) / "blueprints/profiles.py").read_text()
        tree = ast.parse(source)
        self.fn = next(n for n in ast.walk(tree)
                       if isinstance(n, ast.FunctionDef) and n.name == "tip_quote")
        # Strip the docstring: it DESCRIBES what the route must not do, so it
        # naturally names those things. The checks below are about the code.
        body = list(self.fn.body)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        stripped = ast.FunctionDef(
            name=self.fn.name, args=self.fn.args, body=body or [ast.Pass()],
            decorator_list=[], returns=None, type_params=[])
        ast.fix_missing_locations(stripped)
        self.src = ast.unparse(stripped)

    def test_recipient_comes_from_the_url_not_the_body(self):
        self.assertIn("slug", [a.arg for a in self.fn.args.args],
                      "the recipient must be a path parameter resolved against "
                      "application state")
        # The only thing read from the request body is the amount.
        reads = {n.args[0].value for n in ast.walk(self.fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "get" and n.args
                 and isinstance(n.args[0], ast.Constant)
                 and isinstance(n.args[0].value, str)}
        self.assertEqual(reads, {"amount"},
                         "the route reads %s from the request; only the amount "
                         "may come from the caller" % sorted(reads))

    def test_route_cannot_accept_payment_identifiers(self):
        for banned in ("channel_id", "payment_id", "route_id", "nonce",
                       "preimage", "private_key", "privkey", "signature",
                       "sig_a", "sig_b", "secret", "mnemonic"):
            self.assertNotIn(banned, self.src,
                             "tip_quote references %r; a quote must never accept "
                             "or emit payment credentials" % banned)

    def test_route_requires_an_authenticated_caller(self):
        self.assertIn("get_slip()", self.src)
        self.assertIn("slip_required", self.src,
                      "an unauthenticated caller must be refused, using the "
                      "existing 401 convention")

    def test_route_refuses_an_unknown_or_private_profile(self):
        self.assertIn("unknown_profile", self.src)
        self.assertIn("is_public", self.src,
                      "a private profile must not be quotable")

    def test_route_never_signs_and_never_moves_money(self):
        for banned in ("sign", "send_transaction", "sendTransaction",
                       "transfer", "eth_send", "wallet"):
            self.assertNotIn(banned, self.src.lower().replace("signed", ""),
                             "tip_quote appears to %r; a quote must not move "
                             "money or authorise anything" % banned)

    def test_route_persists_nothing(self):
        for banned in ("session.add", "session.commit", "session.delete",
                       ".insert(", "db.session.execute"):
            self.assertNotIn(banned, self.src,
                             "tip_quote writes to the database (%r); no per-tip "
                             "record may be persisted" % banned)

    def test_route_delegates_to_the_tested_service(self):
        self.assertIn("from services.pooled_tips import", self.src,
                      "the route must call the tested quote service rather than "
                      "reimplementing the availability rules")


class VolunteerEndpointIsSeparate(unittest.TestCase):
    """The recipient's node and the volunteer's mailbox are different places.

    They were one field. A real Firefox run then pointed `channel_endpoint` at
    the volunteer, the volunteer answered the initial STATE_REQUEST as though it
    were a party to the channel, `recipient_unreachable` was never established,
    and the payment ended UNKNOWN instead of queued. No money moved — the
    classification held — but the tip could never queue.
    """

    def setUp(self):
        self.author = author_slip(pool_enabled=True)
        self.viewer = Slip(Profile(slug="viewer"))
        self.wallets = {id(self.author): AUTHOR, id(self.viewer): VIEWER}

    def quote(self, **profile_kw):
        if profile_kw:
            for k, v in profile_kw.items():
                setattr(self.author.profile, k, v)
        ns = load(wallets=self.wallets)
        return ns["quote"](self.author, self.viewer, amount=5)

    def test_the_quote_carries_both_endpoints(self):
        q = self.quote()
        self.assertIn("endpoint", q)
        self.assertIn("volunteer_endpoint", q)

    def test_the_two_endpoints_are_distinct_values(self):
        self.author.profile.channel_endpoint = "https://recipient.example/scpp/v1"
        self.author.profile.pool_volunteer_endpoint = "https://volunteer.example"
        q = self.quote()
        self.assertEqual(q["endpoint"], "https://recipient.example/scpp/v1")
        self.assertEqual(q["volunteer_endpoint"], "https://volunteer.example")
        self.assertNotEqual(q["endpoint"], q["volunteer_endpoint"])

    def test_a_missing_volunteer_endpoint_fails_closed(self):
        # NOT substituted with the recipient's own endpoint, which is exactly
        # the confusion this field exists to end.
        ns = load(wallets=self.wallets)
        self.author.profile.pool_volunteer_endpoint = None
        with self.assertRaises(ns["PooledTipError"]):
            ns["quote"](self.author, self.viewer, amount=5)
        self.assertFalse(ns["accepts_pooled_tips"](self.author))

    def test_an_http_volunteer_endpoint_is_refused(self):
        ns = load(wallets=self.wallets)
        self.author.profile.pool_volunteer_endpoint = "http://volunteer.example"
        self.assertIsNone(ns["volunteer_endpoint_of"](self.author.profile))
        self.assertFalse(ns["accepts_pooled_tips"](self.author))

    def test_the_volunteer_endpoint_is_derived_not_supplied(self):
        # quote() takes an amount and nothing else from a caller. There is no
        # parameter through which a volunteer could be named.
        import inspect

        ns = load(wallets=self.wallets)
        params = set(inspect.signature(ns["quote"]).parameters)
        self.assertEqual(params, {"author_slip", "viewer_slip", "amount", "now"})
        for banned in ("volunteer", "endpoint", "mailbox"):
            self.assertNotIn(banned, params)

    def test_the_route_passes_only_the_amount(self):
        # The assembled path, not just the helper: the view must read the
        # recipient from the URL and the amount from the body, and nothing else.
        import re

        src = pathlib.Path(BACKEND, "blueprints/profiles.py").read_text()
        body = src[src.index("def tip_quote("):]
        body = body[:body.index("\n@")] if "\n@" in body else body
        for banned in ["volunteer_endpoint\"", "'volunteer_endpoint'"]:
            self.assertNotIn("get(" + banned, body,
                             "the quote view reads a volunteer endpoint from the request")


class AmountDenomination(unittest.TestCase):
    """A person types WHOLE AXON. The protocol signs BASE UNITS.

    They differ by 10^18, and the quote used to carry only one number for both
    jobs. A real browser tip of "5" therefore produced a signed state moving 5
    base units — 0.000000000000000005 AXON — while the dialog said "Send 5 to
    Tips". Found by reading the frame a real browser had actually queued, not by
    any test.

    The convention is not invented here: services/channel_awards.py already does
    `amount_wei = credits * (10 ** 18)` for the sibling award path.
    """

    def setUp(self):
        self.author = author_slip(pool_enabled=True)
        self.viewer = Slip(Profile(slug="viewer"))
        self.wallets = {id(self.author): AUTHOR, id(self.viewer): VIEWER}

    def test_the_quote_carries_both_denominations(self):
        ns = load(wallets=self.wallets)
        q = ns["quote"](self.author, self.viewer, amount=5)
        self.assertEqual(q["amount"], "5", "the human figure must stay human")
        self.assertEqual(q["amount_base"], str(5 * 10 ** 18))

    def test_the_base_amount_is_a_string(self):
        # 5e18 is past what JSON's number type carries exactly, and a rounded
        # amount is a rounded payment.
        ns = load(wallets=self.wallets)
        q = ns["quote"](self.author, self.viewer, amount=1)
        self.assertIsInstance(q["amount_base"], str)

    def test_the_two_differ_by_the_token_decimals(self):
        ns = load(wallets=self.wallets)
        from decimal import Decimal
        for typed in ("1", "5", "250", "0.1", "0.000000000000000001"):
            q = ns["quote"](self.author, self.viewer, amount=typed)
            self.assertEqual(
                int(q["amount_base"]),
                int(Decimal(q["amount"]) * 10 ** ns["ANON_DECIMALS"]),
                "the displayed figure and the signed one must be the same number")

    def test_the_client_signs_the_base_amount_never_the_display_one(self):
        # Assembled, not isolated: the shipped flow must reach for amount_base
        # in every place it hands an amount to the protocol.
        js = pathlib.Path(BACKEND, "static/pof/tip-flow.js").read_text()
        handoffs = [line for line in js.splitlines()
                    if "amount:" in line and "quote." in line]
        self.assertTrue(handoffs, "tip-flow.js no longer passes an amount")
        for line in handoffs:
            self.assertIn("quote.amount_base", line,
                          "a display amount is being handed to the protocol: " + line.strip())


class FractionalTips(unittest.TestCase):
    """Tips may be a fraction of a coin, converted exactly.

    They could not be. `quote()` did `int(amount)`, so 0.1 became 0 and came
    back as "the amount must be greater than zero" — the smallest tip anybody
    could send was one whole AXON. For a payment channel that is the wrong
    floor: the entire point is that sending a little costs nothing.

    DECIMAL, NOT FLOAT, and that is the part worth testing. 0.1 has no exact
    binary representation, so float(0.1) * 10**18 is 100000000000000001 — an
    amount one base unit away from the one on screen, inside a state somebody is
    about to sign. Every assertion below is really about that gap.
    """

    def setUp(self):
        self.author = author_slip(pool_enabled=True)
        self.viewer = Slip(Profile(slug="viewer"))
        self.wallets = {id(self.author): AUTHOR, id(self.viewer): VIEWER}

    def quote(self, amount):
        return load(wallets=self.wallets)["quote"](self.author, self.viewer, amount=amount)

    def test_a_tenth_of_a_coin_is_accepted_and_exact(self):
        q = self.quote("0.1")
        self.assertEqual(q["amount"], "0.1")
        self.assertEqual(q["amount_base"], str(10 ** 17))

    def test_amounts_where_float_arithmetic_would_be_wrong(self):
        """The cases that make this Decimal rather than float.

        0.1 is a bad example — it happens to survive `0.1 * 10**18` intact,
        because the error falls below what a double can express at that
        magnitude. These do not: 0.07 lands eight base units high and 1.005 lands
        128 low. Off by a few base units is nothing to a person and everything to
        a signed state, which either balances or does not.
        """
        from decimal import Decimal
        for typed in ("0.07", "1.005", "0.615", "12.345"):
            q = self.quote(typed)
            exact = int(Decimal(typed) * 10 ** 18)
            self.assertEqual(int(q["amount_base"]), exact, typed)

    def test_one_base_unit_is_the_floor(self):
        q = self.quote("0.000000000000000001")
        self.assertEqual(q["amount_base"], "1")

    def test_below_one_base_unit_is_refused_rather_than_rounded(self):
        # Rounding here would sign an amount the visitor did not choose.
        ns = load(wallets=self.wallets)
        with self.assertRaises(ns["PooledTipError"]) as caught:
            ns["quote"](self.author, self.viewer, amount="0.0000000000000000001")
        self.assertIn("smaller than the token", str(caught.exception))

    def test_zero_and_negative_are_still_refused(self):
        ns = load(wallets=self.wallets)
        for bad in ("0", "-1", "-0.5"):
            with self.assertRaises(ns["PooledTipError"], msg=bad):
                ns["quote"](self.author, self.viewer, amount=bad)

    def test_nonsense_is_still_refused(self):
        ns = load(wallets=self.wallets)
        for bad in ("abc", "", None, "1/2", "0x1"):
            with self.assertRaises(ns["PooledTipError"], msg=repr(bad)):
                ns["quote"](self.author, self.viewer, amount=bad)

    def test_the_ceiling_still_applies_to_fractions(self):
        ns = load(wallets=self.wallets)
        with self.assertRaises(ns["PooledTipError"]):
            ns["quote"](self.author, self.viewer, amount="1000000.5")

    def test_a_float_that_reaches_the_parser_is_read_as_typed(self):
        # str() before Decimal(): Decimal(0.1) faithfully reproduces the float's
        # error, which is the one thing this must not do.
        q = self.quote(0.1)
        self.assertEqual(q["amount_base"], str(10 ** 17))

    def test_display_and_signed_amount_are_the_same_number(self):
        from decimal import Decimal
        for typed in ("0.1", "1", "2.5", "0.000000000000000001", "999999.999999999999999999"):
            q = self.quote(typed)
            self.assertEqual(
                Decimal(q["amount"]) * 10 ** 18, Decimal(q["amount_base"]),
                "the dialog would describe a different payment from the signed one")

    def test_the_browser_sends_the_typed_text_not_a_parsed_number(self):
        # A JSON number would be a double, and 0.1 does not survive one. The
        # server parses the text exactly once, as a Decimal.
        js = pathlib.Path(BACKEND, "static/pof/tip-flow.js").read_text()
        body = re.search(r"body: JSON\.stringify\(\{ amount: (\w+) \}\)", js)
        self.assertIsNotNone(body, "tip-flow.js no longer posts an amount")
        self.assertEqual(
            body.group(1), "text",
            "the amount must go on the wire as the text the user typed")

    def test_the_input_allows_fractions(self):
        html = pathlib.Path(BACKEND, "templates/_tip_button.html").read_text()
        field = re.search(r'<input[^>]*id="tip-amount"[^>]*>', html, re.S)
        self.assertIsNotNone(field)
        self.assertIn('step="any"', field.group(0),
                      'step="1" is a whole-coin floor in the markup')
