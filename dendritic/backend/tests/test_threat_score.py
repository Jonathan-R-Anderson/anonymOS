"""Threat scoring: mostly the ways it must NOT fire.

A scorer is judged by its false positives. The attacker is inconvenienced by a
wrong block; the reader is locked out of a site they did nothing to, with no way
to reach anyone. So most of what is worth testing is restraint.
"""

import os
import pathlib
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services.threat_score import (BAND_BLOCK, BAND_SAFE,  # noqa: E402
                                   EXEMPT_PREFIXES, band_for, is_exempt,
                                   score_request)


def features(**overrides):
    base = {"path": "/", "query": "", "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
            "headers": {"Host": "syndichan.org"}, "address": "203.0.113.9",
            "recent_requests": 3, "window_seconds": 60, "recent_404s": 0,
            "recent_failed_logins": 0}
    base.update(overrides)
    return base


class OrdinaryTrafficTest(unittest.TestCase):
    """The reader must sail through."""

    def test_a_normal_page_view_scores_nothing(self):
        result = score_request(features())
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["band"], BAND_SAFE)

    def test_reading_quickly_is_not_an_attack(self):
        # Someone opening tabs. Nothing about this should approach a block.
        result = score_request(features(recent_requests=30, window_seconds=60))
        self.assertLess(result["score"], 26, result["reasons"])

    def test_one_missing_page_is_not_scanning(self):
        result = score_request(features(path="/thread/99999", recent_404s=1))
        self.assertEqual(result["band"], BAND_SAFE)

    def test_an_unusual_user_agent_alone_never_blocks(self):
        # Feed readers, text browsers and scripts all send odd agents. Weak
        # evidence must be priced as weak evidence.
        result = score_request(features(user_agent=""))
        self.assertLess(result["score"], 51, result["reasons"])

    def test_a_search_query_mentioning_select_is_not_injection(self):
        # A person searching for "select from the menu" must not be scored as
        # SQL injection; the pattern requires the shape, not the word.
        result = score_request(features(path="/search", query="q=select from the menu"))
        self.assertEqual(result["band"], BAND_SAFE, result["reasons"])


class AttackTest(unittest.TestCase):
    """Guards the tests above: a scorer that never fires would pass them all."""

    def test_sql_injection_scores(self):
        result = score_request(features(query="id=1' OR '1'='1"))
        self.assertGreater(result["score"], 0)
        self.assertTrue(any("SQL" in r["why"] for r in result["reasons"]))

    def test_traversal_scores(self):
        result = score_request(features(path="/static/../../etc/passwd"))
        self.assertTrue(any("traversal" in r["why"] for r in result["reasons"]))

    def test_a_named_scanning_tool_scores_heavily(self):
        result = score_request(features(user_agent="sqlmap/1.7"))
        self.assertGreaterEqual(result["score"], 35)

    def test_a_flood_plus_enumeration_reaches_the_block_band(self):
        # No single signal should get here alone; the combination is the point.
        result = score_request(features(
            recent_requests=3000, window_seconds=60, recent_404s=200,
            user_agent="", path="/wp-login.php"))
        self.assertEqual(result["band"], BAND_BLOCK, result["reasons"])

    def test_no_single_signal_reaches_a_block_on_its_own(self):
        # Every signal has a benign explanation. If one could block by itself,
        # that explanation becomes somebody's lockout.
        for override in ({"query": "id=1' OR '1'='1"},
                         {"path": "/wp-admin/"},
                         {"user_agent": ""},
                         {"recent_requests": 5000, "window_seconds": 60},
                         {"recent_404s": 500},
                         {"recent_failed_logins": 100}):
            result = score_request(features(**override))
            self.assertNotEqual(result["band"], BAND_BLOCK,
                                "%s alone reached a block: %s" % (override, result["reasons"]))


class ExplanationTest(unittest.TestCase):
    """A score nobody can argue with gets defended when it is wrong."""

    def test_every_contributing_signal_is_named(self):
        result = score_request(features(query="id=1' OR '1'='1", user_agent="sqlmap/1.7"))
        self.assertGreaterEqual(len(result["reasons"]), 2)
        for reason in result["reasons"]:
            self.assertTrue(reason["why"])
            self.assertGreater(reason["points"], 0)

    def test_reasons_are_ordered_by_weight(self):
        # The top line of an incident view should be what drove the decision,
        # not whichever check happened to run first.
        result = score_request(features(query="id=1' OR '1'='1", user_agent=""))
        points = [r["points"] for r in result["reasons"]]
        self.assertEqual(points, sorted(points, reverse=True))

    def test_the_score_is_capped_so_bands_stay_meaningful(self):
        result = score_request(features(
            query="id=1' OR '1'='1", user_agent="sqlmap/1.7", path="/wp-admin/../../etc/passwd",
            recent_requests=9000, window_seconds=60, recent_404s=900,
            recent_failed_logins=900))
        self.assertLessEqual(result["score"], 100)


class ExemptionTest(unittest.TestCase):
    """A scorer that blocks the network's own traffic breaks what it protects."""

    def test_machine_endpoints_are_never_scored(self):
        for path in ("/api/v1/gateways", "/api/v1/gateway/audit",
                     "/.well-known/syndichan/snapshot.json",
                     "/snapshot/object/abc", "/api/v1/pof/candidates"):
            self.assertTrue(is_exempt(path), path)
            result = score_request(features(path=path, user_agent="",
                                            recent_requests=5000, window_seconds=60))
            self.assertTrue(result["exempt"])
            self.assertEqual(result["score"], 0)

    def test_ordinary_pages_are_not_exempt(self):
        # Guards the test above: an exemption list matching everything would
        # pass it while disabling the whole system.
        for path in ("/", "/boards/b", "/faq"):
            self.assertFalse(is_exempt(path), path)

    def test_the_exemptions_are_the_machine_paths(self):
        self.assertIn("/api/v1/gateways", EXEMPT_PREFIXES)
        self.assertIn("/.well-known/", EXEMPT_PREFIXES)


class BandTest(unittest.TestCase):

    def test_bands_match_the_specification(self):
        self.assertEqual(band_for(0), "safe")
        self.assertEqual(band_for(25), "safe")
        self.assertEqual(band_for(26), "monitor")
        self.assertEqual(band_for(50), "monitor")
        self.assertEqual(band_for(51), "challenge")
        self.assertEqual(band_for(75), "challenge")
        self.assertEqual(band_for(76), "block")
        self.assertEqual(band_for(100), "block")


class ObserveOnlyTest(unittest.TestCase):
    """Phase 1 must not enforce anything."""

    def test_the_scorer_has_no_way_to_block(self):
        # It returns a band and reasons. Nothing here calls abort, sets a
        # status, or touches a ban table — enforcement is phase 2, after real
        # traffic has shown what the thresholds should be.
        source = (pathlib.Path(BACKEND) / "services" / "threat_score.py").read_text()
        for forbidden in ("abort(", "Ban(", "add_ban", "403"):
            self.assertNotIn(forbidden, source)

    def test_the_log_records_what_would_have_happened(self):
        source = (pathlib.Path(BACKEND) / "model" / "ThreatEvent.py").read_text()
        self.assertIn("would_have", source)
        self.assertIn("RETENTION_DAYS", source)


if __name__ == "__main__":
    unittest.main()


class MaskingTest(unittest.TestCase):
    """Addresses are masked wherever anything is displayed."""

    def mask(self):
        import ast
        source = (pathlib.Path(BACKEND) / "blueprints" / "admin.py").read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_mask":
                module = ast.Module(body=[node], type_ignores=[])
                ast.fix_missing_locations(module)
                namespace = {}
                exec(compile(module, "admin.py", "exec"), namespace)
                return namespace["_mask"]
        self.fail("_mask not found")

    def test_ipv4_is_masked_to_a_network(self):
        self.assertEqual(self.mask()("203.0.113.9"), "203.0.113.0/24")

    def test_ipv6_is_masked_to_a_network(self):
        self.assertEqual(self.mask()("2001:db8:1234:5678::1"), "2001:db8::/32")

    def test_masking_happens_even_in_the_admin_view(self):
        # An interface that prints a whole address invites copying it somewhere
        # public, which is the failure the whole design is arranged to avoid.
        source = (pathlib.Path(BACKEND) / "blueprints" / "admin.py").read_text()
        body = source[source.index("def threats_overview"):]
        body = body[:body.index("\ndef _mask")]
        self.assertIn("_mask(event.address)", body)
        self.assertNotIn('"address": event.address', body)
