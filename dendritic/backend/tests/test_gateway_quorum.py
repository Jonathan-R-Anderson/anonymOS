"""Quorum, and the ways agreement gets faked.

The thresholds are arithmetic and would be dull to test on their own. What is
worth testing is the claim underneath them: that this cannot be made to emit a
verdict by one party running more machines. Every test here is that attack from
a different angle.

The property being defended: agreement is cheap, independence is not, and a
verdict requires the expensive one.
"""

import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services.gateway_quorum import (DEFAULTS, VERDICT_CLEAN,  # noqa: E402
                                     VERDICT_INSUFFICIENT,
                                     VERDICT_NOT_INDEPENDENT, VERDICT_TAMPERED,
                                     evaluate)


def observation(result, observer, operator, network):
    return {"result": result, "observer": observer, "kind": "validator",
            "operator": operator, "network": network}


def independent(result, count=5, prefix="v"):
    """Validators that are genuinely different parties."""
    return [observation(result, "%s%d" % (prefix, i), "operator-%d" % i,
                        "10.%d.0" % i) for i in range(count)]


class IndependenceGateTest(unittest.TestCase):

    def test_one_operator_running_five_validators_gets_no_verdict(self):
        # THE attack this whole module exists to refuse. Five machines, perfect
        # agreement, one owner. Cheap to mount and indistinguishable from real
        # corroboration if only agreement were counted.
        crowd = [observation("mismatch", "v%d" % i, "operator-1", "10.0.0")
                 for i in range(5)]
        result = evaluate(crowd)
        self.assertEqual(result["verdict"], VERDICT_NOT_INDEPENDENT)
        self.assertFalse(result["independent"])
        self.assertEqual(result["operators"], 1)

    def test_one_operator_across_many_networks_is_still_one_operator(self):
        # Renting VPS in five countries is not five opinions.
        spread = [observation("mismatch", "v%d" % i, "operator-1", "10.%d.0" % i)
                  for i in range(5)]
        self.assertEqual(evaluate(spread)["verdict"], VERDICT_NOT_INDEPENDENT)

    def test_many_operators_in_one_datacentre_is_not_enough(self):
        # The converse: distinct payout addresses are cheap to mint, so the
        # network threshold has to hold the line when the operator one is gamed.
        rack = [observation("mismatch", "v%d" % i, "operator-%d" % i, "10.0.0")
                for i in range(5)]
        result = evaluate(rack)
        self.assertEqual(result["verdict"], VERDICT_NOT_INDEPENDENT)
        self.assertEqual(result["networks"], 1)

    def test_genuinely_independent_validators_do_produce_a_verdict(self):
        # Guards the tests above: if evaluate() refused everything, they would
        # all pass for the wrong reason.
        result = evaluate(independent("mismatch"))
        self.assertEqual(result["verdict"], VERDICT_TAMPERED)
        self.assertTrue(result["independent"])

    def test_a_clean_gateway_is_also_a_verdict(self):
        self.assertEqual(evaluate(independent("pass"))["verdict"], VERDICT_CLEAN)


class AgreementTest(unittest.TestCase):

    def test_too_few_validators_is_insufficient_not_clean(self):
        # "Nobody checked" must never read as "nothing wrong".
        result = evaluate(independent("pass", count=2))
        self.assertEqual(result["verdict"], VERDICT_INSUFFICIENT)
        self.assertFalse(result["independent"])

    def test_a_split_vote_produces_no_verdict(self):
        split = (independent("pass", count=3, prefix="a")
                 + independent("mismatch", count=2, prefix="b"))
        self.assertEqual(evaluate(split)["verdict"], VERDICT_INSUFFICIENT)

    def test_one_validator_repeating_itself_counts_once(self):
        # Deduplication happens upstream too; enforced again because a verdict
        # rests on this number.
        shouting = [observation("mismatch", "same-validator", "operator-1", "10.0.0")
                    for _ in range(50)]
        self.assertEqual(evaluate(shouting)["validators"], 1)

    def test_client_reports_never_count_toward_quorum(self):
        # Anyone can POST a client report. If those counted, a verdict would be
        # purchasable with a loop.
        flood = [{"result": "mismatch", "observer": "reader-%d" % i,
                  "kind": "client", "operator": "op-%d" % i, "network": "10.%d.0" % i}
                 for i in range(100)]
        result = evaluate(flood)
        self.assertEqual(result["validators"], 0)
        self.assertEqual(result["verdict"], VERDICT_INSUFFICIENT)

    def test_the_minority_never_wins(self):
        majority = (independent("pass", count=4, prefix="a")
                    + [observation("mismatch", "liar", "operator-9", "10.9.0")])
        self.assertEqual(evaluate(majority)["verdict"], VERDICT_CLEAN)


class ResultVocabularyTest(unittest.TestCase):
    """The quorum module restates the result names; they must not drift.

    If they ever diverge, evaluate() would silently stop recognising the very
    results it is weighing — every observation would fall through to "no
    verdict", which reads as "nothing found" rather than as a bug.
    """

    def test_quorum_results_match_the_model(self):
        import ast
        import pathlib

        source = (pathlib.Path(BACKEND) / "model" / "GatewayAudit.py").read_text()
        tree = ast.parse(source)
        model_values = {
            node.targets[0].id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id.startswith("RESULT_")
            and isinstance(node.value, ast.Constant)
        }
        from services import gateway_quorum

        for name, value in model_values.items():
            self.assertEqual(getattr(gateway_quorum, name), value,
                             "%s drifted from the model" % name)


class GovernanceTest(unittest.TestCase):
    """Thresholds are parameters, so a network can raise them as it grows."""

    def test_thresholds_are_configurable_not_baked_in(self):
        strict = dict(DEFAULTS, gateway_quorum_operators=5)
        # Four operators cleared the default but not the raised bar.
        four = independent("mismatch", count=5)
        four[4]["operator"] = four[0]["operator"]
        self.assertEqual(evaluate(four, strict)["verdict"], VERDICT_NOT_INDEPENDENT)
        self.assertEqual(evaluate(four)["verdict"], VERDICT_TAMPERED)

    def test_defaults_demand_more_than_one_operator(self):
        # A default of 1 would silently disable the only real protection here.
        self.assertGreater(DEFAULTS["gateway_quorum_operators"], 1)
        self.assertGreater(DEFAULTS["gateway_quorum_networks"], 1)


class ReceiptSigningTest(unittest.TestCase):
    """A signature says who sent a report, and nothing about whether it is true."""

    def keys(self):
        from nacl.signing import SigningKey
        import base64
        key = SigningKey.generate()
        return key, base64.b64encode(bytes(key.verify_key)).decode("ascii")

    def test_a_signature_over_one_report_does_not_transfer_to_another(self):
        # Otherwise a genuine "pass" could be lifted and replayed as a forged
        # "mismatch" for a different object, in the same observer's name.
        import base64

        from services.audit_receipts import receipt_message, verify_signature

        key, public = self.keys()
        honest = receipt_message("gw", "/thread/1", 7, "abc", "pass")
        forged = receipt_message("gw", "/thread/2", 7, "abc", "mismatch")
        signature = base64.b64encode(key.sign(honest).signature).decode("ascii")

        self.assertTrue(verify_signature(public, signature, honest))
        self.assertFalse(verify_signature(public, signature, forged))

    def test_validator_standing_requires_a_registered_key(self):
        # Anyone can generate a keypair and claim to be a validator. Standing
        # comes from being a node the network registered, not from asserting it.
        import base64

        from services.audit_receipts import (KIND_CLIENT, KIND_VALIDATOR,
                                             classify, receipt_message)

        key, public = self.keys()
        message = receipt_message("gw", "/", 1, "abc", "pass")
        signature = base64.b64encode(key.sign(message).signature).decode("ascii")
        raw_hex = bytes(key.verify_key).hex()

        kind, _, verified = classify(KIND_VALIDATOR, public, signature, message, set())
        self.assertEqual(kind, KIND_CLIENT, "an unregistered key claimed validator standing")
        self.assertTrue(verified)

        kind, _, _ = classify(KIND_VALIDATOR, public, signature, message, {raw_hex})
        self.assertEqual(kind, KIND_VALIDATOR)

    def test_a_signed_observer_is_named_by_its_key(self):
        # A self-declared name beside a signature would let one key file under
        # many identities and inflate "distinct observers".
        import base64

        from services.audit_receipts import classify, observer_id, receipt_message

        key, public = self.keys()
        message = receipt_message("gw", "/", 1, "abc", "pass")
        signature = base64.b64encode(key.sign(message).signature).decode("ascii")
        _, observer, _ = classify("client", public, signature, message, set())
        self.assertEqual(observer, observer_id(public))
        self.assertTrue(observer)

    def test_an_unsigned_report_claims_no_identity(self):
        from services.audit_receipts import classify, receipt_message

        message = receipt_message("gw", "/", 1, "abc", "pass")
        kind, observer, verified = classify("validator", "", "", message, set())
        self.assertEqual(kind, "client")
        self.assertEqual(observer, "")
        self.assertFalse(verified)


if __name__ == "__main__":
    unittest.main()


class CanaryTest(unittest.TestCase):
    """Canaries only work while a gateway cannot recognise one."""

    def paths(self):
        from services import canaries
        return canaries.canary_paths()

    def test_a_canary_does_not_announce_itself(self):
        # A path containing "canary", or a bare sequential id, is one a gateway
        # can special-case -- serving those honestly and everything else
        # altered, which defeats the entire mechanism.
        for path in self.paths():
            lowered = path.lower()
            for tell in ("canary", "test", "probe", "audit", "honeypot"):
                self.assertNotIn(tell, lowered, path)

    def test_canaries_look_like_ordinary_pages(self):
        for path in self.paths():
            self.assertTrue(path.startswith("/"), path)
            self.assertRegex(path, r"^/(thread|boards|media)/[0-9a-f]{12}$", path)

    def test_the_set_is_stable_across_calls(self):
        # An unstable set could never be shown to have been altered: a validator
        # would be asking for different pages each round.
        self.assertEqual(self.paths(), self.paths())

    def test_canaries_are_distinct(self):
        self.assertEqual(len(set(self.paths())), len(self.paths()))

    def test_body_is_deterministic(self):
        # Two different responses would be indistinguishable from tampering,
        # so every audit of a varying canary would be inconclusive.
        from services.canaries import canary_body
        path = self.paths()[0]
        self.assertEqual(canary_body(path), canary_body(path))

    def test_different_canaries_have_different_bodies(self):
        from services.canaries import canary_body
        first, second = self.paths()[0], self.paths()[1]
        self.assertNotEqual(canary_body(first), canary_body(second))


class ValidatorStandingTest(unittest.TestCase):
    """Only an on-chain registration confers validator standing.

    A pending registration costs a keypair and a wallet address, both free and
    unlimited. If it counted, one person could mint as many quorum-eligible
    validators as they liked and independence would be back to counting — the
    exact failure the whole quorum design exists to prevent.
    """

    def registered_keys_source(self):
        import ast
        import pathlib

        source = (pathlib.Path(BACKEND) / "services" / "reputation.py").read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "registered_keys":
                return ast.dump(node)
        return ""

    def test_registered_keys_filters_on_submitted(self):
        dumped = self.registered_keys_source()
        self.assertIn("STATUS_SUBMITTED", dumped,
                      "validator standing must require an on-chain registration")
        self.assertNotIn("STATUS_PENDING", dumped,
                         "a self-declared registration must not confer standing")


class DecayTest(unittest.TestCase):
    """Standing fades without work — in both directions."""

    def module(self):
        return _load_reputation()

    def test_a_fresh_event_counts_fully(self):
        import datetime
        m = self.module()
        now = datetime.datetime(2026, 1, 1)
        self.assertAlmostEqual(m["_decay"](now, now), 1.0)

    def test_an_old_event_counts_for_less(self):
        import datetime
        m = self.module()
        now = datetime.datetime(2026, 1, 1)
        month = m["_decay"](now - datetime.timedelta(days=30), now)
        year = m["_decay"](now - datetime.timedelta(days=365), now)
        self.assertLess(month, 1.0)
        self.assertLess(year, month)
        self.assertGreater(year, 0.0)

    def test_penalties_decay_too(self):
        # Decaying only credit would make waiting a way to launder a bad
        # record: get caught, do nothing, come back clean. _decay is applied to
        # the event, not to its sign, which is what prevents that.
        import ast
        import pathlib
        source = (pathlib.Path(BACKEND) / "services" / "reputation.py").read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_decay":
                dumped = ast.dump(node)
                for sign_test in ("proof_accepted", "fraud", "cheating"):
                    self.assertNotIn(sign_test, dumped,
                                     "_decay must not branch on which event it is")
                return
        self.fail("_decay not found")

    def test_a_missing_timestamp_does_not_erase_a_record(self):
        # Treating "no date" as infinitely old would silently zero a node's
        # history because of a data problem.
        m = self.module()
        self.assertEqual(m["_decay"](None), 1.0)

    def test_decay_is_gradual_not_a_cliff(self):
        # A step function would make standing depend on which side of a
        # threshold a node happened to land on.
        import datetime
        m = self.module()
        now = datetime.datetime(2026, 1, 1)
        values = [m["_decay"](now - datetime.timedelta(days=d), now)
                  for d in range(0, 100, 10)]
        for earlier, later in zip(values, values[1:]):
            self.assertLess(later, earlier)
            self.assertGreater(later / earlier, 0.9)


def _load_reputation():
    return _load_pure_module("services/reputation.py",
                             {"_decay", "DAILY_DECAY", "DECAY_FLOOR"})


def _load_pure_module(relative_path, wanted):
    """Exec only the named pure definitions, skipping the app imports."""
    import ast
    import pathlib

    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, ast.FunctionDef) and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    # `datetime` is provided rather than exec'd from an Import node, which would
    # need locations of its own for no benefit.
    namespace = {"datetime": __import__("datetime")}
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace
