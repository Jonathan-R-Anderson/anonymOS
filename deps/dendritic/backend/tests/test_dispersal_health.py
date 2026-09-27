"""Making dispersal health visible without lying about what is unknown.

Phase 4.3 (roadmap/dht-storage-roadmap.md). The admin panel showed what the DHT
HOLDS and nothing about whether shards were reaching anybody, so every fault was
diagnosed by SSHing to a node and grepping its journal.

Almost every test here pins the same property from a different angle: ABSENT IS
NOT ZERO. A node that has not reported must render as "not reporting" and never
as a node with no failures. This codebase has drawn an unknown as a number
repeatedly and it has cost it weeks each time.
"""
import ast
import json
import pathlib
import socket
import unittest

from services.dispersal_health import (
    ACTIVE_WITHIN_SECONDS, NOT_REPORTING, REPORT_FRESH_SECONDS, STALE,
    Node, summarise,
)

NOW = 1_800_000_000
BACKEND = pathlib.Path(__file__).resolve().parent.parent


def healthy(**overrides):
    block = {
        "objects": 100, "under_replicated": 0, "local_only": 0,
        "fully_dispersed": 100, "placed": 6, "failed": 0, "unassignable": 0,
        "attempted": 4, "peers": 9, "age_seconds": 120,
        "recalls_outstanding": 0, "recalls_deferred": 0, "recalls_unreadable": 0,
        "refusals": [],
    }
    block.update(overrides)
    return block


def node(node_id, health=None, age=0, report_age=0):
    return Node(
        node_id, NOW - age,
        None if health is None else NOW - report_age,
        health,
    )


class AbsentIsNotZeroTest(unittest.TestCase):
    """The property the whole feature turns on."""

    def test_a_node_that_never_reported_renders_as_unknown_not_healthy(self):
        summary = summarise([node("old-build", health=None)], now=NOW)
        row = summary["nodes"][0]
        self.assertFalse(row["reporting"])
        self.assertEqual(row["why_not"], NOT_REPORTING)
        # Not one of these may be a number. A zero here IS the bug: it renders
        # identically to a node that dispersed everything successfully.
        for key in ("objects", "under_replicated", "local_only", "failed",
                    "placed", "peers", "recalls_outstanding"):
            self.assertIsNone(row[key], "%s was rendered as a number" % key)
        self.assertEqual(summary["reporting"], 0)
        self.assertEqual(summary["silent"], 1)

    def test_a_fleet_with_nobody_reporting_has_no_totals_rather_than_zero_totals(self):
        summary = summarise(
            [node("a", health=None), node("b", health=None)], now=NOW)
        for key in ("under_replicated", "local_only", "failed",
                    "recalls_outstanding", "isolated"):
            self.assertIsNone(summary[key],
                              "%s claims a fleet-wide measurement from no reports" % key)
        self.assertEqual(summary["silent"], 2)

    def test_a_measured_zero_is_a_real_answer_and_is_kept(self):
        # The mirror image, and just as important: a node that looked and found
        # nothing wrong must not be lumped in with the ones that never looked.
        summary = summarise([node("clean", healthy())], now=NOW)
        row = summary["nodes"][0]
        self.assertTrue(row["reporting"])
        self.assertEqual(row["failed"], 0)
        self.assertEqual(summary["under_replicated"], 0)
        self.assertEqual(summary["silent"], 0)

    def test_a_stale_report_is_not_shown_as_current(self):
        # The node is still heartbeating -- so it is in the active set -- but it
        # has stopped saying anything about dispersal, which is what a node whose
        # replicate loop has died looks like. Its last figures are history.
        summary = summarise(
            [node("frozen", healthy(), report_age=REPORT_FRESH_SECONDS + 60)],
            now=NOW)
        row = summary["nodes"][0]
        self.assertFalse(row["reporting"])
        self.assertEqual(row["why_not"], STALE)
        self.assertIsNone(row["under_replicated"])

    def test_a_report_that_will_not_parse_is_unknown_not_empty(self):
        from services.dispersal_health import from_storage_nodes

        class Row(object):
            node_id = "brokenrow123456"
            last_seen_at = None
            placement_reported_at = None
            placement_health = "{not json"

        class _When(object):
            @staticmethod
            def timestamp():
                return NOW

        Row.last_seen_at = _When
        Row.placement_reported_at = _When
        summary = from_storage_nodes([Row()], now=NOW)
        self.assertFalse(summary["nodes"][0]["reporting"])
        self.assertEqual(summary["reporting"], 0)

    def test_recall_counters_the_node_could_not_read_stay_absent(self):
        # The node omits them when its recall ledger will not open. Defaulting
        # to 0 would report "nothing outstanding" off an unreadable ledger --
        # the exact mistake the unreadable-row counter was added to stop.
        block = healthy()
        for key in ("recalls_outstanding", "recalls_deferred", "recalls_unreadable"):
            block.pop(key)
        summary = summarise([node("no-recall-ledger", block)], now=NOW)
        row = summary["nodes"][0]
        self.assertTrue(row["reporting"])
        self.assertIsNone(row["recalls_outstanding"])
        # And the fleet total ignores it rather than counting it as zero holders.
        self.assertEqual(summary["recalls_outstanding"], 0)


class RefusalReasonTest(unittest.TestCase):
    """'3 failures' is useless; '3 failures: storage capacity exceeded' is the point."""

    def test_a_refusal_reason_reaches_the_rendered_payload(self):
        summary = summarise([node("owner", healthy(failed=3, refusals=[
            {"peer": "12D3KooWFullDis", "count": 3,
             "reason": "storage capacity exceeded"},
        ]))], now=NOW)
        row = summary["nodes"][0]
        self.assertEqual(row["refusals"][0]["reason"], "storage capacity exceeded")
        self.assertEqual(row["refusals"][0]["peer"], "12D3KooWFullDis")
        # And it survives serialisation to the browser.
        self.assertIn("storage capacity exceeded", json.dumps(summary))

    def test_the_fleet_rolls_refusals_up_by_reason(self):
        # Three peers refusing is ambiguous. Three peers refusing for THREE
        # DIFFERENT REASONS is three separate repairs, and that is precisely the
        # week phase 4.3 was written after.
        summary = summarise([
            node("a", healthy(failed=3, refusals=[
                {"peer": "peerFull", "count": 4, "reason": "storage capacity exceeded"},
                {"peer": "peerCache", "count": 2, "reason": "node is cache-only"},
            ])),
            node("b", healthy(failed=1, refusals=[
                {"peer": "peerFull", "count": 1, "reason": "storage capacity exceeded"},
                {"peer": "peerKey", "count": 3,
                 "reason": "invalid coordinator lease signature"},
            ])),
        ], now=NOW)
        by_reason = {r["reason"]: r for r in summary["refusals"]}
        self.assertEqual(
            sorted(by_reason),
            ["invalid coordinator lease signature", "node is cache-only",
             "storage capacity exceeded"])
        self.assertEqual(by_reason["storage capacity exceeded"]["count"], 5)
        # One distinct peer, seen by two separate owners.
        self.assertEqual(by_reason["storage capacity exceeded"]["peers"], 1)
        self.assertEqual(by_reason["storage capacity exceeded"]["nodes"], 2)
        # Worst first, so truncation on the page keeps the reason that matters.
        self.assertEqual(summary["refusals"][0]["reason"], "storage capacity exceeded")

    def test_a_refusal_with_no_reason_still_says_it_was_a_refusal(self):
        summary = summarise([node("a", healthy(refusals=[
            {"peer": "peerX", "count": 2, "reason": ""},
        ]))], now=NOW)
        reason = summary["nodes"][0]["refusals"][0]["reason"]
        self.assertTrue(reason, "a blank cell reads as 'no problem'")


class FleetPictureTest(unittest.TestCase):
    def test_an_isolated_node_is_counted_separately_from_a_refused_one(self):
        # Zero placements with no peers is a dead I2P router; zero placements
        # with nine peers is a node being refused. Same number, opposite repair.
        summary = summarise([
            node("dead-router", healthy(peers=0, placed=0, failed=0)),
            node("refused", healthy(peers=9, placed=0, failed=9)),
        ], now=NOW)
        self.assertEqual(summary["isolated"], 1)
        self.assertEqual(summary["failed"], 9)

    def test_a_node_nobody_can_see_sorts_above_a_node_with_a_visible_problem(self):
        summary = summarise([
            node("has-a-problem", healthy(failed=9)),
            node("says-nothing", health=None),
        ], now=NOW)
        self.assertEqual(summary["nodes"][0]["node_id"], "says-nothing")

    def test_a_dead_row_is_not_part_of_the_picture_at_all(self):
        # Production carries roughly twice as many rows as running machines.
        summary = summarise(
            [node("gone", healthy(), age=ACTIVE_WITHIN_SECONDS + 60)], now=NOW)
        self.assertEqual(summary["nodes"], [])
        self.assertEqual(summary["reporting"], 0)
        self.assertEqual(summary["silent"], 0)


class NoNetworkInTheRequestPathTest(unittest.TestCase):
    """The admin poll runs every three seconds. It must touch no node.

    This site has already 504'd from slow work in a request handler (an inline
    news sync in GET /), and the tempting shape here is exactly that: fetch
    ?placement from each of nine nodes over I2P to draw the page. The heartbeat
    was chosen instead so the handler reads stored rows and nothing else.
    """

    def test_summarising_opens_no_socket(self):
        real_socket, real_connect = socket.socket, socket.create_connection

        def forbidden(*args, **kwargs):
            raise AssertionError(
                "the dispersal summary opened a network connection")

        socket.socket = forbidden
        socket.create_connection = forbidden
        try:
            summary = summarise([
                node("a", healthy(failed=3, refusals=[
                    {"peer": "peerFull", "count": 3,
                     "reason": "storage capacity exceeded"}])),
                node("b", health=None),
            ], now=NOW)
        finally:
            socket.socket, socket.create_connection = real_socket, real_connect
        self.assertEqual(summary["reporting"], 1)
        self.assertEqual(summary["silent"], 1)

    def _feed_source(self):
        # Unparsed rather than dumped: a failure here should print something a
        # person can read, and an ast.dump of this handler is 300 KB of noise.
        source = (BACKEND / "blueprints" / "admin.py").read_text()
        tree = ast.parse(source)
        for node_ in ast.walk(tree):
            if isinstance(node_, ast.FunctionDef) and node_.name == "live_visitors_feed":
                return ast.unparse(node_)
        raise AssertionError("live_visitors_feed is gone")

    def test_the_admin_poll_never_calls_a_node(self):
        body = self._feed_source()
        # The named ways this codebase reaches a storage node. Any of them in
        # this handler is a request-path fetch over I2P on a 3-second poll.
        for forbidden in (
            "dht_object_purge", "ledger_summary", "object_placement",
            "list_placements", "recall_shards", "requests", "urlopen",
            "urllib", "httpx", "boto3", "botocore", "socket", "gateway_probe",
        ):
            if forbidden in body:
                self.fail(
                    "live_visitors_feed reaches a node via %r; dispersal health "
                    "arrives on the heartbeat precisely so this 3-second poll "
                    "does not have to" % forbidden)

    def test_the_admin_poll_reports_dispersal_health_at_all(self):
        # Guards the other half: a handler that does no network I/O and also
        # shows nothing is not a fix. Checked structurally rather than by
        # substring, because merely importing the module would satisfy a grep.
        source = (BACKEND / "blueprints" / "admin.py").read_text()
        for node_ in ast.walk(ast.parse(source)):
            if not (isinstance(node_, ast.FunctionDef)
                    and node_.name == "live_visitors_feed"):
                continue
            assigned = {
                target.slice.value
                for inner in ast.walk(node_)
                if isinstance(inner, ast.Assign)
                for target in inner.targets
                if isinstance(target, ast.Subscript)
                and isinstance(target.slice, ast.Constant)
            }
            self.assertIn(
                "dispersal", assigned,
                "the poll no longer puts dispersal health in its response")
            return
        self.fail("live_visitors_feed is gone")


class RenderingContractTest(unittest.TestCase):
    """What the panel must draw. The template is plain inline JS, so this reads it."""

    def setUp(self):
        self.template = (
            BACKEND / "templates" / "admin-dashboard.html").read_text()

    def _requires(self, fragment, why):
        # self.fail rather than assertIn: assertIn prints both operands, and one
        # of them is a 3,000-line template.
        if fragment not in self.template:
            self.fail("admin-dashboard.html no longer has %r — %s" % (fragment, why))

    def test_the_panel_consumes_the_same_poll_as_the_map(self):
        # One endpoint, not a second one. renderDispersal is called from the
        # existing live-visitors poll.
        self._requires("renderDispersal(sum)",
                       "the panel must ride the existing live-visitors poll")
        self.assertEqual(self.template.count("function renderDispersal("), 1)

    def test_a_non_reporting_node_is_drawn_as_such_and_never_as_zero(self):
        self._requires("var DISP_UNKNOWN = 'not reporting';",
                       "a node with no report needs a word, not a number")
        self._requires("if (!n.reporting)",
                       "the non-reporting branch is what stops a row of zeros")

    def test_an_unavailable_summary_is_not_drawn_as_a_healthy_one(self):
        self._requires("This is not the same as healthy.",
                       "a failed read must say so, not render as a clean fleet")

    def test_the_refusal_reason_is_rendered(self):
        self._requires("renderDispersalRefusals",
                       "the fleet refusal roll-up is the headline finding")
        self._requires("r.reason", "a refusal count without its reason is useless")


if __name__ == "__main__":
    unittest.main()
