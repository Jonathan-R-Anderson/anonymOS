"""The directive that can move the whole network — and every way it must refuse.

This is the highest-consequence action in the project: one signature relocates
the origin, the domain and the signing key. So the tests are not about the happy
path, which is one line. They are about the refusals, because a refusal that
does not happen is how the network gets moved by somebody who should not be able
to move it.
"""

import ast
import json
import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
    """Exec only the named definitions, skipping module-level app imports."""
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


import re as _re  # noqa: E402  (needed by the module-level regex constants)

ND = _load_pure(
    "services/network_directive.py",
    {"SIGNED_FIELDS", "KIND_MOVE", "KIND_FREEZE", "KIND_RESUME", "KINDS",
     "DEFAULT_DELAY_SECONDS", "DirectiveError", "canonical", "parse_canonical",
     "build", "check_acceptable", "_DOMAIN", "_ADDRESS", "_HEXKEY",
     "_LOOK_IT_UP", "redirect_target", "NEVER_REDIRECT"},
    # `current()` reads a SiteSetting, which needs the app. check_acceptable
    # takes `existing` explicitly precisely so it can be reasoned about without
    # one; the stub asserts that stays true rather than papering over it.
    extra={"re": _re, "json": json,
           "current": lambda: (_ for _ in ()).throw(
               AssertionError("check_acceptable must not reach the database "
                              "when `existing` was passed"))},
)
NOW = 1_800_000_000


def move(sequence=1, now=NOW, **kwargs):
    kwargs.setdefault("origin_domain", "syndichan.net")
    return ND["build"](ND["KIND_MOVE"], sequence, now, **kwargs)


class CanonicalFormTest(unittest.TestCase):
    """The signed bytes. If two implementations disagree, the signature is
    worthless on whichever machine disagrees — during an incident."""

    def test_dict_order_cannot_change_the_message(self):
        directive = move()
        shuffled = dict(reversed(list(directive.items())))
        self.assertEqual(ND["canonical"](directive), ND["canonical"](shuffled))

    def test_every_signed_field_appears(self):
        text = ND["canonical"](move(note="hello"))
        for field in ND["SIGNED_FIELDS"]:
            with self.subTest(field=field):
                self.assertIn("%s:" % field, text)

    def test_it_is_readable_in_a_signing_prompt(self):
        """A wallet dialog showing minified JSON is a dialog nobody reads.

        The point of signing is that a person sees what they are agreeing to,
        so this asserts the shape a human can check: a header line, then one
        labelled field per line.
        """
        text = ND["canonical"](move(origin_domain="syndichan.net"))
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("syndichan network directive"))
        self.assertIn("origin_domain: syndichan.net", lines)
        self.assertEqual(len(lines), 1 + len(ND["SIGNED_FIELDS"]))

    def test_absent_values_are_explicit_not_blank(self):
        """"origin_key: " and "origin_key: -" must not be the same message.

        Otherwise an empty field can be swapped for a missing one without
        changing the signature.
        """
        text = ND["canonical"](ND["build"](ND["KIND_FREEZE"], 2, NOW))
        self.assertIn("origin_domain: -", text)

    def test_booleans_do_not_depend_on_language(self):
        """Python's True and Go's true would sign different bytes."""
        self.assertIn("emergency: yes", ND["canonical"](move(emergency=True)))
        self.assertIn("emergency: no", ND["canonical"](move(emergency=False)))

    def test_a_note_cannot_forge_a_field(self):
        """The one free-text field, checked by round-tripping rather than by
        counting substrings.

        A note reading "origin_domain: evil.example" LOOKS like a field. It must
        not become one: no extra line (newlines are stripped), and a parser
        splitting on the first ": " keeps it inside the note's value. Counting
        occurrences would fail this while the format is perfectly safe, which is
        why the assertion is on what parses back out.
        """
        directive = move(note="hi\norigin_domain: evil.example\nemergency: yes")
        parsed = ND["parse_canonical"](ND["canonical"](directive))
        self.assertEqual(parsed["origin_domain"], "syndichan.net")
        self.assertFalse(parsed["emergency"])
        self.assertIn("evil.example", parsed["note"])

    def test_every_directive_round_trips(self):
        """The Go verifier has to parse exactly this. If the format cannot
        round-trip here it will not round-trip there either, and the failure
        would land on a machine nobody can reach, during an incident.
        """
        for directive in (move(),
                          move(sequence=42, emergency=True,
                               origin_address="203.0.113.9:443",
                               origin_key="b" * 64, note="failover"),
                          ND["build"](ND["KIND_FREEZE"], 9, NOW),
                          ND["build"](ND["KIND_RESUME"], 10, NOW, note="all clear")):
            with self.subTest(kind=directive["kind"], seq=directive["sequence"]):
                parsed = ND["parse_canonical"](ND["canonical"](directive))
                self.assertEqual(parsed, directive)

    def test_a_truncated_message_is_refused(self):
        text = ND["canonical"](move())
        with self.assertRaises(ND["DirectiveError"]):
            ND["parse_canonical"]("\n".join(text.split("\n")[:-1]))
        with self.assertRaises(ND["DirectiveError"]):
            ND["parse_canonical"]("something else entirely")


class BuildTest(unittest.TestCase):
    def test_a_move_must_name_a_real_domain(self):
        for bad in ("", "not a domain", "http://x.com", "x", ".com",
                    "evil.example/../"):
            with self.subTest(domain=bad):
                with self.assertRaises(ND["DirectiveError"]):
                    move(origin_domain=bad)

    def test_a_freeze_cannot_smuggle_a_domain(self):
        """Otherwise the directive that exists to STOP moves performs one."""
        with self.assertRaises(ND["DirectiveError"]):
            ND["build"](ND["KIND_FREEZE"], 2, NOW, origin_domain="evil.example")
        with self.assertRaises(ND["DirectiveError"]):
            ND["build"](ND["KIND_RESUME"], 2, NOW, origin_key="a" * 64)

    def test_an_ordinary_move_waits(self):
        directive = move()
        self.assertEqual(directive["not_before"],
                         NOW + ND["DEFAULT_DELAY_SECONDS"])

    def test_an_emergency_move_does_not_wait(self):
        """The requirement is immediate failover. The delay is what is traded
        away, and visibility is what is paid instead."""
        directive = move(emergency=True)
        self.assertEqual(directive["not_before"], NOW)
        self.assertTrue(directive["emergency"])

    def test_sequence_must_be_a_positive_whole_number(self):
        for bad in ("", None, 0, -1, "abc", 1.5):
            with self.subTest(sequence=bad):
                with self.assertRaises(ND["DirectiveError"]):
                    move(sequence=bad)

    def test_an_origin_key_must_look_like_one(self):
        with self.assertRaises(ND["DirectiveError"]):
            move(origin_key="not-a-key")
        self.assertEqual(move(origin_key="A" * 64)["origin_key"], "a" * 64)

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(ND["DirectiveError"]):
            ND["build"]("delete-everything", 1, NOW)


class AcceptabilityTest(unittest.TestCase):
    """A valid signature is not enough. These are the rules a correctly signed
    directive still has to pass."""

    def test_nothing_in_force_accepts_anything(self):
        ND["check_acceptable"](move(sequence=1), existing=None)

    def test_a_replayed_directive_is_refused(self):
        """The reason the sequence exists. A directive captured off the wire
        today must be worthless tomorrow — its signature stays valid forever.
        """
        in_force = move(sequence=7)
        for stale in (1, 6, 7):
            with self.subTest(sequence=stale):
                with self.assertRaises(ND["DirectiveError"]):
                    ND["check_acceptable"](move(sequence=stale), existing=in_force)

    def test_moving_forward_is_allowed(self):
        ND["check_acceptable"](move(sequence=8), existing=move(sequence=7))

    def test_a_freeze_blocks_further_moves(self):
        freeze = ND["build"](ND["KIND_FREEZE"], 7, NOW)
        with self.assertRaises(ND["DirectiveError"]):
            ND["check_acceptable"](move(sequence=8), existing=freeze)

    def test_only_a_resume_lifts_a_freeze(self):
        freeze = ND["build"](ND["KIND_FREEZE"], 7, NOW)
        ND["check_acceptable"](ND["build"](ND["KIND_RESUME"], 8, NOW),
                               existing=freeze)

    def test_a_resume_still_cannot_go_backwards(self):
        """Otherwise a captured resume unfreezes a network that was frozen
        deliberately, which is the one state that exists to stop an attacker."""
        freeze = ND["build"](ND["KIND_FREEZE"], 7, NOW)
        with self.assertRaises(ND["DirectiveError"]):
            ND["check_acceptable"](ND["build"](ND["KIND_RESUME"], 5, NOW),
                                   existing=freeze)

    def test_the_refusal_says_which_rule(self):
        """An operator reading this during an incident needs to know whether the
        problem is the signature or the sequence."""
        try:
            ND["check_acceptable"](move(sequence=3), existing=move(sequence=9))
        except ND["DirectiveError"] as error:
            self.assertIn("3", str(error))
            self.assertIn("9", str(error))
        else:
            self.fail("expected a refusal")


class SignedFieldsTest(unittest.TestCase):
    def test_the_signature_covers_everything_that_matters(self):
        """A field outside SIGNED_FIELDS can be altered in transit without
        invalidating anything. Each of these decides where the network goes.
        """
        for field in ("kind", "sequence", "not_before", "emergency",
                      "origin_domain", "origin_address", "origin_key"):
            with self.subTest(field=field):
                self.assertIn(field, ND["SIGNED_FIELDS"])

    def test_the_signature_is_not_among_the_signed_fields(self):
        self.assertNotIn("signature", ND["SIGNED_FIELDS"])
        self.assertNotIn("signer", ND["SIGNED_FIELDS"])


if __name__ == "__main__":
    unittest.main()


class RedirectTest(unittest.TestCase):
    """The old domain hands people forward. What it must NOT forward matters
    more than what it does."""

    def setUp(self):
        self.in_force = None
        ND["current"] = lambda: self.in_force

    def move(self, domain="syndichan.net", not_before=0):
        self.in_force = {"kind": "move", "origin_domain": domain,
                         "sequence": 3, "not_before": not_before}

    def target(self, host="syndichan.org", path="/", **kwargs):
        return ND["redirect_target"](host, path, now=NOW, **kwargs)

    def test_nothing_in_force_redirects_nothing(self):
        self.assertIsNone(self.target())

    def test_an_old_domain_is_forwarded(self):
        self.move()
        self.assertEqual(self.target(path="/boards/g"),
                         "https://syndichan.net/boards/g")

    def test_the_query_string_survives(self):
        self.move()
        self.assertEqual(
            ND["redirect_target"]("syndichan.org", "/search", "q=hello", now=NOW),
            "https://syndichan.net/search?q=hello")

    def test_the_new_domain_does_not_redirect_to_itself(self):
        """Otherwise every request on the new domain is an infinite loop."""
        self.move()
        self.assertIsNone(self.target(host="syndichan.net"))
        self.assertIsNone(self.target(host="syndichan.net:443"))
        self.assertIsNone(self.target(host="gw3.syndichan.net"))

    def test_the_directive_document_is_never_forwarded(self):
        """It is HOW a node learns the domain changed. Forwarding it means a
        node can only discover the move by reaching the new domain — so if the
        new domain is not up yet, it learns nothing at all."""
        self.move()
        self.assertIsNone(
            self.target(path="/.well-known/syndichan/network.json"))

    def test_acme_and_health_are_never_forwarded(self):
        """The old name must be able to renew its certificate, or it stops
        serving HTTPS and stops being able to redirect at all. Health probes do
        not follow redirects and read a 302 as unhealthy."""
        self.move()
        for path in ("/.well-known/acme-challenge/abc123", "/health", "/readyz"):
            with self.subTest(path=path):
                self.assertIsNone(self.target(path=path))

    def test_a_freeze_forwards_nothing(self):
        self.in_force = {"kind": "freeze", "sequence": 4, "not_before": 0}
        self.assertIsNone(self.target())

    def test_it_waits_for_not_before(self):
        """Redirecting early would move readers ahead of the nodes, which are
        still waiting out the same delay."""
        self.move(not_before=NOW + 600)
        self.assertIsNone(self.target())
        self.move(not_before=NOW)
        self.assertIsNotNone(self.target())

    def test_a_move_with_no_domain_forwards_nothing(self):
        self.move(domain="")
        self.assertIsNone(self.target())

    def test_the_never_list_covers_the_bootstrap_path(self):
        self.assertIn("/.well-known/syndichan/network.json", ND["NEVER_REDIRECT"])
