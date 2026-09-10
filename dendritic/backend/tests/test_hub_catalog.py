"""Publishing what our NNTP hub carries, and how to reach it.

The page this feeds is public, so the tests are about the two ways it could
mislead somebody: telling them a group exists when it does not, and telling them
a stale answer is current. Plus the one way it could take the site down, which
is talking to the hub inside a page render.
"""

import ast
import datetime
import json
import os
import pathlib
import re
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
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


HC = _load_pure(
    "services/nntpchan/hub_catalog.py",
    {"SETTING", "HOST_SETTING", "PORT_SETTING", "TLS_SETTING", "NOTICE_SETTING",
     "PROBE_HOST_SETTING", "INTERNAL_HOST", "INTERNAL_PORT",
     "STALE_AFTER_SECONDS", "_ask_hub", "_ask_one", "is_stale"},
    extra={"json": json, "_datetime": datetime},
)


class FakeClient:
    """Stands in for NNTPClient. Returns (name, high, low) like the real one."""

    def __init__(self, rows, fail=False):
        self.rows = rows
        self.fail = fail

    def __enter__(self):
        if self.fail:
            raise OSError("hub is not answering")
        return self

    def __exit__(self, *exc):
        return False

    def list_active_groups(self, wildmat="*"):
        return self.rows


class AskHubTest(unittest.TestCase):
    def test_it_reads_the_real_tuple_shape(self):
        """list_active_groups yields (name, high, low), not dicts. Getting this
        wrong publishes an empty catalogue while the hub is perfectly healthy.
        """
        groups = HC["_ask_one"](lambda: FakeClient([
            ("syndichan.random", 13, 1),
            ("overchan.maniwani.imgban", 110, 1),
        ]))
        self.assertEqual([g["name"] for g in groups],
                         ["overchan.maniwani.imgban", "syndichan.random"])

    def test_articles_are_high_minus_low_not_high(self):
        """A group whose old articles expired still reports a large high-water
        mark. Publishing that overstates what a connecting peer receives."""
        groups = HC["_ask_one"](lambda: FakeClient([("g", 5000, 4900)]))
        self.assertEqual(groups[0]["articles"], 101)

    def test_an_empty_group_reports_zero_not_negative(self):
        # NNTP signals empty as high < low, which naive subtraction turns into
        # a negative article count on a public page.
        groups = HC["_ask_one"](lambda: FakeClient([("g", 0, 1)]))
        self.assertEqual(groups[0]["articles"], 0)

    def test_junk_rows_are_skipped_not_fatal(self):
        groups = HC["_ask_one"](lambda: FakeClient([
            ("good", 5, 1), ("bad", "x", "y"), ("", 3, 1), ("also-good", 2, 1),
        ]))
        self.assertEqual([g["name"] for g in groups], ["also-good", "good"])

    def test_a_dead_hub_raises_so_refresh_can_keep_the_old_answer(self):
        with self.assertRaises(OSError):
            HC["_ask_one"](lambda: FakeClient([], fail=True))

    def test_a_supplied_factory_bypasses_target_discovery(self):
        """So a caller with its own client is never routed through settings —
        which is what makes this testable without an app at all."""
        groups = HC["_ask_hub"](lambda: FakeClient([("only", 3, 1)]))
        self.assertEqual([g["name"] for g in groups], ["only"])


class StalenessTest(unittest.TestCase):
    """A list read as live when it is a day old is worse than an admitted gap:
    somebody concludes a group exists, connects, and finds nothing."""

    def test_a_fresh_catalogue_is_not_stale(self):
        now = datetime.datetime(2026, 8, 1, 12, 0, 0)
        record = {"refreshed_at": (now - datetime.timedelta(minutes=5)).isoformat() + "Z"}
        self.assertFalse(HC["is_stale"](record, now=now))

    def test_an_old_catalogue_is_stale(self):
        now = datetime.datetime(2026, 8, 1, 12, 0, 0)
        record = {"refreshed_at": (now - datetime.timedelta(days=1)).isoformat() + "Z"}
        self.assertTrue(HC["is_stale"](record, now=now))

    def test_never_refreshed_is_stale(self):
        for record in ({}, {"refreshed_at": None}, {"refreshed_at": "nonsense"}):
            with self.subTest(record=record):
                self.assertTrue(HC["is_stale"](record))


class RenderPathTest(unittest.TestCase):
    """The page must read cache only. This site has already taken an outage
    from an inline sync inside a request."""

    def test_the_federation_route_does_not_call_refresh(self):
        """No inline sync inside the request, whatever the route does.

        TWO THINGS WERE WRONG WITH THIS TEST AND ONLY ONE WAS ITS OWN FAULT.

        The federation PAGE was removed; `def federation()` no longer exists and
        `federation_request()` is a bare redirect, so the positive half --
        "it reads the cache" -- had nothing left to be true of. But the NEGATIVE
        half is the outage guard and still matters: this site has already taken
        an outage from an inline sync inside a request, and if the page ever
        comes back it must not bring one with it.

        The other fault: `source.index("def federation()")` matched inside a
        COMMENT. The comment left by the main.federation 500 fix quotes the
        function name, and the comment sits ABOVE the real function -- so the
        test was reading a block of prose and asserting things about it. It
        would have passed or failed on the wording of a comment.
        """
        source = (pathlib.Path(BACKEND) / "blueprints" / "main.py").read_text()
        routes = [m for m in re.finditer(r"(?m)^def (federation\w*)\(", source)]
        self.assertTrue(routes, "no federation route at all; if it was removed "
                                "deliberately, delete this test with it")
        for match in routes:
            body = source[match.start():match.start() + 1400]
            with self.subTest(route=match.group(1)):
                self.assertNotIn("refresh(", body)
                self.assertNotIn("_ask_hub", body)
                # Only meaningful once something renders again: a redirect has
                # no catalogue to read. Conditional rather than deleted, so the
                # requirement returns with the page.
                if "render_template" in body:
                    self.assertIn(
                        "published()", body,
                        "%s renders again and must read the CACHE, not the hub"
                        % match.group(1))

    def test_the_sync_loop_owns_the_refresh(self):
        source = (pathlib.Path(BACKEND) / "services" / "nntpchan" / "sync.py").read_text()
        self.assertIn("refresh as refresh_catalog", source)

    def test_the_refresh_runs_even_with_no_peers_configured(self):
        """Our hub's catalogue has nothing to do with whether we pull from
        anyone. Refreshing after the peer check meant it never ran at all on a
        deployment with no peers — the early return fires first — and the page
        would have advertised an empty hub forever.
        """
        source = (pathlib.Path(BACKEND) / "services" / "nntpchan" / "sync.py").read_text()
        body = source[source.index("def _sync_once_impl"):]
        refresh_at = body.index("_refresh_hub_catalog(stats)")
        early_return = body.index("if not peers:")
        self.assertLess(refresh_at, early_return,
                        "the catalogue refresh must come BEFORE the no-peers "
                        "early return, or it never runs without peers")

    def test_published_reads_only_the_cache(self):
        source = (pathlib.Path(BACKEND) / "services" / "nntpchan"
                  / "hub_catalog.py").read_text()
        start = source.index("def published()")
        body = source[start:]
        self.assertNotIn("_ask_hub", body)
        self.assertNotIn("NNTPClient", body)


if __name__ == "__main__":
    unittest.main()


class NotCarriedClaimTest(unittest.TestCase):
    """"We do not carry this" is a claim about the hub. It must not be made
    from having no information about the hub."""

    def _published(self, groups, boards):
        source = (pathlib.Path(BACKEND) / "services" / "nntpchan"
                  / "hub_catalog.py").read_text()
        tree = ast.parse(source)
        keep = [n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "published"]
        module = ast.Module(body=keep, type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {
            "catalog": lambda: {"groups": groups, "refreshed_at": "2026-01-01T00:00:00Z"},
            "local_boards_by_group": lambda: boards,
            "connection": lambda: {"host": "h", "port": 119, "tls": False, "notice": ""},
            "is_stale": lambda record: False,
        }
        exec(compile(module, "hub_catalog.py", "exec"), namespace)
        return namespace["published"]()

    def test_an_empty_catalogue_claims_nothing(self):
        """The failure seen in production: with no catalogue yet, every mapped
        group was listed as one the hub does not carry — including one it
        demonstrably does."""
        result = self._published([], {"syndichan.random": ["random"]})
        self.assertEqual(result["mapped_elsewhere"], [])

    def test_a_real_gap_is_still_reported(self):
        result = self._published(
            [{"name": "syndichan.random", "articles": 13}],
            {"syndichan.random": ["random"], "overchan.elsewhere": ["b"]})
        self.assertEqual([g["name"] for g in result["mapped_elsewhere"]],
                         ["overchan.elsewhere"])

    def test_carried_groups_carry_their_boards(self):
        result = self._published(
            [{"name": "syndichan.random", "articles": 13}],
            {"syndichan.random": ["random"]})
        self.assertEqual(result["groups"][0]["boards"], ["random"])
