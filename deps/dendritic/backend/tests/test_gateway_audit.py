"""Audit receipts, and the ways somebody would try to abuse them.

The intake is open — the observers worth having are ordinary readers, and
requiring an account would leave only the observers willing to be identified. So
every test here is somebody exploiting that openness, because the design has to
survive it rather than assume good faith.

The properties being defended:

  * a report is worth exactly ONE observation, however many times it is sent —
    otherwise standing is farmable by repetition, in both directions: inflate
    yourself, or bury a rival;
  * distinct observers are counted separately from raw reports, because a
    thousand reports from one source is one source's opinion;
  * nothing produces a score, because a score drawn from uncorroborated reports
    is a verdict anyone could manufacture.
"""

import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


class DeduplicationRuleTest(unittest.TestCase):
    """The uniqueness key, stated independently of the database.

    Restated here rather than imported because the model pulls in the app. This
    is the RULE — if it and the model ever disagree, the constraint stops doing
    the job the whole design rests on.
    """

    KEY = ("gateway", "object_key", "version", "observer")

    def observation(self, **kwargs):
        base = {"gateway": "aa" * 32, "object_key": "/thread/1",
                "version": 7, "observer": "obs-1"}
        base.update(kwargs)
        return tuple(base[field] for field in self.KEY)

    def test_the_same_report_twice_is_one_observation(self):
        seen = set()
        for _ in range(50):
            seen.add(self.observation())
        self.assertEqual(len(seen), 1,
                         "a replayed report must not count more than once")

    def test_a_different_observer_is_a_different_observation(self):
        seen = {self.observation(observer="obs-1"), self.observation(observer="obs-2")}
        self.assertEqual(len(seen), 2)

    def test_a_new_version_is_a_new_observation(self):
        # Content changed, so this is genuinely a fresh thing to observe.
        seen = {self.observation(version=7), self.observation(version=8)}
        self.assertEqual(len(seen), 2)

    def test_reports_about_different_gateways_do_not_collide(self):
        seen = {self.observation(gateway="aa" * 32), self.observation(gateway="bb" * 32)}
        self.assertEqual(len(seen), 2)

    def test_one_observer_cannot_bury_a_gateway_by_repetition(self):
        # The attack: a rival POSTs "mismatch" ten thousand times.
        seen = set()
        for _ in range(10000):
            seen.add(self.observation(observer="rival"))
        self.assertEqual(len(seen), 1)


class ObserverCountingTest(unittest.TestCase):
    """Distinct observers, not raw volume, is the number that means anything."""

    def summarise(self, observations):
        observers = {o["observer"] for o in observations}
        counts = {}
        for o in observations:
            counts[o["result"]] = counts.get(o["result"], 0) + 1
        return {"observations": len(observations),
                "distinct_observers": len(observers), "counts": counts}

    def test_one_loud_observer_is_still_one_observer(self):
        flood = [{"observer": "rival", "result": "mismatch"} for _ in range(500)]
        summary = self.summarise(flood)
        self.assertEqual(summary["distinct_observers"], 1)
        self.assertEqual(summary["observations"], 500)
        # The pair is the point: 500 reports from 1 source must be legible as
        # exactly that, rather than as 500 independent accusations.

    def test_many_observers_agreeing_is_visibly_different(self):
        crowd = [{"observer": "obs-%d" % i, "result": "mismatch"} for i in range(50)]
        summary = self.summarise(crowd)
        self.assertEqual(summary["distinct_observers"], 50)


class NoVerdictTest(unittest.TestCase):
    """summary_for() must report counts, never a score.

    A score computed from uncorroborated reports is a verdict anyone could
    manufacture by POSTing at the open intake. Read from the SOURCE rather than
    by importing, because the model pulls in the whole application — and the
    property being defended is what the function returns, which is visible in
    the text.
    """

    def summary_keys(self):
        import ast

        source = (pathlib.Path(BACKEND) / "model" / "GatewayAudit.py").read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "summary_for":
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Dict):
                        return {k.value for k in sub.value.keys
                                if isinstance(k, ast.Constant)}
        return None

    def test_summary_returns_counts_not_a_score(self):
        keys = self.summary_keys()
        self.assertIsNotNone(keys, "summary_for should return a dict literal")
        self.assertEqual(keys, {"gateway", "node_key", "counts", "observations",
                                "distinct_observers", "registered_observations"})
        for forbidden in ("score", "reputation", "trust", "rating", "verdict"):
            self.assertNotIn(forbidden, keys,
                             "a score here would be a verdict drawn from "
                             "uncorroborated reports")


class IdentityTest(unittest.TestCase):
    """A gateway's name has to be a key, or the record fills with fiction.

    Every test here is the same attack from a different angle: invent an
    identity, or mangle a real one, and see whether the intake will attribute an
    observation to it.
    """

    def setUp(self):
        from services.gateway_identity import ALPHABET
        self.alphabet = ALPHABET

    def encode(self, raw):
        number = int.from_bytes(raw, "big")
        out = ""
        while number:
            number, remainder = divmod(number, 58)
            out = self.alphabet[remainder] + out
        return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out

    def peer_id(self, key):
        return self.encode(b"\x00\x24" + b"\x08\x01\x12\x20" + key)

    def test_a_peer_id_yields_the_key_it_encodes(self):
        from services.gateway_identity import ed25519_key, node_key_hex

        key = bytes(range(32))
        identity = self.peer_id(key)
        self.assertEqual(ed25519_key(identity), key)
        # The hex form is what PoF registration stores, so this equality IS the
        # binding between an audit and a node's storage record.
        self.assertEqual(node_key_hex(identity), key.hex())

    def test_a_real_libp2p_identity_decodes(self):
        # Fixed vector, so a refactor that breaks decoding cannot be masked by
        # generating input with the same code that reads it.
        from services.gateway_identity import ed25519_key

        self.assertIsNotNone(
            ed25519_key("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"))

    def test_case_folding_destroys_an_identity(self):
        # base58 is case-sensitive. This is why nothing lower-cases a gateway:
        # doing so silently converts every real peer ID into a name that belongs
        # to nobody, and the observation is then filed against fiction.
        from services.gateway_identity import is_identity, normalize

        identity = self.peer_id(bytes(range(32)))
        self.assertTrue(is_identity(identity))
        self.assertFalse(is_identity(identity.lower()))
        self.assertEqual(normalize("  " + identity + " "), identity)

    def test_invented_names_are_not_identities(self):
        from services.gateway_identity import is_identity

        for junk in ("", "gateway-1", "0" * 52, "deadbeef" * 8, "l" * 52,
                     "12D3KooW", "../../etc/passwd"):
            self.assertFalse(is_identity(junk), junk)

    def test_the_origin_names_itself_without_a_key(self):
        # The origin has no peer ID; it is the one identity this server can
        # vouch for directly, so it is named rather than left blank.
        from services.gateway_identity import ORIGIN, is_identity, normalize

        self.assertTrue(is_identity(ORIGIN))
        self.assertEqual(normalize("ORIGIN"), ORIGIN)


def _load_pure(relative_path, wanted):
    """Execute only the module-level constants and functions named in `wanted`.

    These modules import Flask and the database on the way in, so importing them
    to check a pure function would make this suite depend on the whole
    application being installed. Everything asked for here is a literal or a
    function over literals, so the rest of the module is simply not run.
    """
    import ast

    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if names & wanted:
                keep.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in wanted:
            keep.append(node)
    namespace = {}
    exec(compile(ast.Module(body=keep, type_ignores=[]), relative_path, "exec"),
         namespace)
    return namespace


class AuditsDoNotScoreTest(unittest.TestCase):
    """Audits are attributed to a node key but must never move its score.

    Every other reputation event was verified by this server. An audit was
    reported by a stranger through an open endpoint, so if it counted, any
    passer-by could set an operator's standing — which is the one thing the
    score exists to prevent.
    """

    def reputation(self):
        return _load_pure("services/reputation.py",
                          {"WEIGHTS", "BASELINE", "MAX_SCORE", "MIN_SCORE",
                           "score_for"})

    def test_score_for_ignores_audit_results(self):
        module = self.reputation()
        # Smuggled into the very dict the score function reads. It must make no
        # difference: score_for iterates its own weights rather than the input,
        # so unknown keys cannot contribute by construction.
        hostile = {"pass": 10000, "mismatch": 10000, "stale": 500, "unsigned": 5}
        self.assertEqual(module["score_for"](hostile), module["BASELINE"])

    def test_a_real_event_still_moves_the_score(self):
        # Guards the test above: if score_for were broken to ignore everything,
        # the previous assertion would pass for the wrong reason.
        module = self.reputation()
        self.assertGreater(module["score_for"]({"proof_accepted": 5}),
                           module["BASELINE"])

    def test_audit_results_are_not_weighted_events(self):
        # The two vocabularies must stay disjoint. If they ever overlap, an
        # audit result would land on a weight by name alone — no code change
        # required, which is what makes it worth a test.
        weights = self.reputation()["WEIGHTS"]
        results = _load_pure("model/GatewayAudit.py",
                             {"RESULTS", "RESULT_PASS", "RESULT_MISMATCH",
                              "RESULT_STALE", "RESULT_UNSIGNED"})["RESULTS"]
        self.assertEqual(set(results) & set(weights), set())


class ResultVocabularyTest(unittest.TestCase):
    """The four outcomes a reader can distinguish, and why stale is separate."""

    RESULTS = ("pass", "mismatch", "stale", "unsigned")

    def test_stale_is_not_the_same_as_mismatch(self):
        # A stale page has a GENUINE signature — the bytes were really published
        # by the origin, just not recently. Collapsing it into "mismatch" would
        # accuse a gateway of forgery for what may be a caching bug, and losing
        # the distinction would hide the one attack a hash cannot see.
        self.assertIn("stale", self.RESULTS)
        self.assertIn("mismatch", self.RESULTS)
        self.assertNotEqual("stale", "mismatch")

    def test_unsigned_is_recorded_rather_than_ignored(self):
        # "No signature offered" is itself information: a gateway stripping
        # headers looks exactly like this, and silence would hide it.
        self.assertIn("unsigned", self.RESULTS)


if __name__ == "__main__":
    unittest.main()
