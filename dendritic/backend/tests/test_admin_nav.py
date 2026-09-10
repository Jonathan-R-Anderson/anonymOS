"""The admin site map must agree with the admin routes.

Navigation used to be a row of buttons hardcoded into one template, and it drifted
from reality the moment somebody added a screen without editing that row -- which
is how two screens ended up reachable only by typing the URL.

So the map is data now, and this asserts it still describes the site. The test
that matters is `test_every_navigable_admin_page_is_in_the_map`: it fails when a
new screen is added and not listed, which is the exact mistake being prevented.
"""

import ast
import os
import re
import sys
import types
import unittest
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _install_stubs():
    """Stub `shared` just long enough to import admin_nav, then hand back a
    function that puts sys.modules the way it was found.

    THE RESTORE IS THE POINT AND IT USED TO BE MISSING. This module installed a
    fake `shared` and left it in sys.modules for the life of the process. The
    stub carries `db` and `app` and nothing else, so every module imported
    afterwards that did `from shared import db, db_retry` -- board_access does,
    and blueprints/admin imports board_access -- failed with

        ImportError: cannot import name 'db_retry' from 'shared'

    which named neither this file nor the real cause. The symptom was that
    tests/test_slip_deletion.py could not even be COLLECTED during a full run
    while passing perfectly on its own, and that it was a whole-suite failure
    rather than a test failure, so it looked like a broken module rather than
    a polluted process.

    A test that fakes a core module globally has to unfake it, or it is not
    testing one thing, it is changing the process for everything after it.
    """
    if "shared" in sys.modules:
        return lambda: None
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    shared.db = db
    shared.app = MagicMock()
    shared.app.config = {}
    sys.modules["shared"] = shared

    def restore():
        sys.modules.pop("shared", None)
        # Drop what was imported AGAINST the stub too. This module keeps its own
        # reference to admin_nav so its own assertions still work, while a later
        # test that imports services.admin_nav gets it built against the real
        # `shared` instead of a MagicMock.
        for name in [n for n in list(sys.modules) if n == "services.admin_nav"]:
            sys.modules.pop(name, None)

    return restore


_restore_stubs = _install_stubs()

from services import admin_nav  # noqa: E402

_restore_stubs()


# Screens deliberately absent from the nav, with the reason. Anything else that
# is missing is a bug, not a decision.
EXCLUDED = {
    # Reached before you are signed in; showing the map there would advertise
    # the admin surface to anyone who finds the login page.
    "admin.login",
    "admin.logout",
    # Sub-views reached FROM a listed screen, not destinations in their own
    # right. Each one is linked from its parent.
    "admin.nsfw_selftest",
    "admin.export_scraped_sources",
    "admin.contracts_addresses",
    "admin.software_update_status",
    "report_review.detail",
    # One story's review screen, reached from the newsroom desk; it needs a story
    # to mean anything.
    "news_editor.story",
    # The per-shard view of one DHT object, reached from the purge page. Listing
    # it separately would put a screen in the nav that needs a target to mean
    # anything.
    "admin.dht_purge_object",
    # Every one of the five behaviour dashboards renders the same template and
    # is linked from the others; only the entry point is in the nav.
    "admin.analytics_product",
    "admin.analytics_recommendations",
    "admin.analytics_content_health",
    "admin.analytics_data_quality",
    # The dashboard is in the shell's Session group rather than a task group.
    "admin.dashboard",
    # CONTENT MODERATION, deliberately dropped from the nav (2026-08-16) when the
    # panel was scoped to the network and the contracts. The ROUTES still exist
    # and still work if you know the URL -- they were not deleted, because
    # deleting a working destructive tool is a bigger decision than hiding it,
    # and because a half-removed feature is worse than either.
    "admin.purge_search",
    "admin.spam_blocklist",
}


def _page_endpoints(path, prefix):
    """GET routes in a blueprint file that render a template."""
    source = open(path, encoding="utf-8").read()
    tree = ast.parse(source)
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        is_route = False
        methods = None
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if isinstance(func, ast.Attribute) and func.attr == "route":
                is_route = True
                for kw in dec.keywords or []:
                    if kw.arg == "methods":
                        methods = [getattr(e, "value", None) for e in
                                   getattr(kw.value, "elts", [])]
        if not is_route:
            continue
        if methods is not None and "GET" not in methods:
            continue
        body = ast.get_source_segment(source, node) or ""
        # A page either renders directly or delegates to a _render_* helper.
        # admin.py uses both -- dht_purge() returns _render_dht_purge(...) so
        # that its several entry points cannot drift in what they pass -- and a
        # detector that only knew the first would call a real page a non-page.
        if "render_template(" not in body and not re.search(r"_render_\w+\(", body):
            continue
        found.add("%s.%s" % (prefix, node.name))
    return found


class SiteMapTest(unittest.TestCase):

    # Blueprints that contribute admin screens. report_review and news_editor
    # were here and have been DELETED from the tree, so scanning them raised
    # FileNotFoundError and this whole class failed on a missing file rather
    # than on a missing nav entry. Missing files are skipped and the scan keeps
    # working; a blueprint that comes back is picked up again by adding it here.
    _SCAN = (("admin.py", "admin"),)

    def _all_pages(self):
        pages = set()
        for filename, prefix in self._SCAN:
            path = os.path.join(BACKEND, "blueprints", filename)
            if os.path.exists(path):
                pages |= _page_endpoints(path, prefix)
        return pages

    def test_every_navigable_admin_page_is_in_the_map(self):
        """A screen nobody can reach except by typing its URL is a dead end."""
        listed = admin_nav.all_endpoints()
        missing = sorted(self._all_pages() - listed - EXCLUDED)
        self.assertEqual(missing, [],
                         "these admin screens are not reachable from the nav: %s"
                         % missing)

    def test_the_map_names_no_route_that_does_not_exist(self):
        """A stale entry renders a link to nowhere."""
        real = self._all_pages()
        stale = sorted(endpoint for endpoint in admin_nav.all_endpoints()
                       if endpoint not in real)
        self.assertEqual(stale, [],
                         "nav points at endpoints with no page: %s" % stale)

    def test_no_endpoint_is_listed_twice(self):
        seen, duplicated = set(), []
        for group in admin_nav.SITE_MAP:
            for item in group.items:
                if item.endpoint in seen:
                    duplicated.append(item.endpoint)
                seen.add(item.endpoint)
        self.assertEqual(duplicated, [])

    def test_groups_and_items_are_labelled(self):
        for group in admin_nav.SITE_MAP:
            self.assertTrue(group.label.strip())
            self.assertTrue(group.items, "%s has no items" % group.key)
            for item in group.items:
                self.assertTrue(item.label.strip())

    def test_the_panel_is_scoped_to_the_network_and_the_contracts(self):
        """Rewritten 2026-08-16: the panel is no longer a forum admin.

        It previously asserted that Moderation came first, which was right when
        this panel moderated a board. It now manages a network and a set of
        contracts, and a moderation group would be scope creep by default.
        """
        keys = [g.key for g in admin_nav.SITE_MAP]
        self.assertEqual(keys, ["network", "contracts", "system"])
        for gone in ("moderation", "newsroom", "sources", "analytics", "arcade"):
            self.assertNotIn(gone, keys,
                             "%s is back in the admin map; this panel is for the "
                             "network and the contracts" % gone)

    def test_destructive_destinations_are_marked(self):
        """`danger` means 'deletes things', not 'seems important'. The old button
        row used one colour for both and taught operators to ignore it."""
        by_endpoint = {item.endpoint: item
                       for group in admin_nav.SITE_MAP for item in group.items}
        for endpoint in ("admin.dht_purge", "admin.network_directive_admin"):
            self.assertTrue(by_endpoint[endpoint].danger,
                            "%s is destructive and is not marked" % endpoint)
        # Publishing a binary and reading status are not destructive.
        self.assertFalse(by_endpoint["admin.node_releases_admin"].danger)
        self.assertFalse(by_endpoint["admin.status_admin"].danger)

    def test_resolve_finds_a_listed_page(self):
        key, item = admin_nav.resolve("admin.contracts_console")
        self.assertEqual(key, "contracts")
        self.assertEqual(item.label, "Contracts")

    def test_resolve_is_quiet_about_unknown_endpoints(self):
        """An unlisted page must still render, with nothing highlighted."""
        self.assertEqual(admin_nav.resolve("admin.nope"), (None, None))


class ShellTest(unittest.TestCase):
    """The shell is what makes every screen navigable."""

    def _shell(self):
        return open(os.path.join(BACKEND, "templates", "admin-shell.html"),
                    encoding="utf-8").read()

    def test_the_shell_renders_the_map_rather_than_a_hardcoded_list(self):
        shell = self._shell()
        self.assertIn("admin_site_map", shell)
        # The failure being prevented: a second hardcoded button row.
        self.assertNotIn("Behavior Dashboards", shell)

    def test_the_shell_marks_the_current_page(self):
        self.assertIn("aria-current", self._shell())

    def test_the_shell_survives_an_endpoint_that_no_longer_exists(self):
        """A renamed route should drop one nav entry, not 500 every admin page."""
        self.assertIn("admin_url(item.endpoint)", self._shell())

    def test_every_admin_screen_still_uses_the_shell(self):
        """Replaces test_the_report_screens_are_no_longer_dead_ends.

        That test named admin-reports.html and admin-report-detail.html, which
        were deleted with the report_review blueprint, so it had been failing on
        a missing file rather than on a missing shell. Checking whatever admin
        screens actually exist keeps the property and stops the test from
        pinning a specific deleted page.
        """
        import glob
        screens = [f for f in glob.glob(os.path.join(BACKEND, "templates", "admin-*.html"))
                   if not f.endswith(("admin-shell.html", "admin-login.html"))]
        self.assertTrue(screens, "no admin screens found")
        for path in screens:
            body = open(path, encoding="utf-8").read()
            if "{% extends" not in body:
                continue  # a partial, not a screen
            self.assertIn('extends "admin-shell.html"', body,
                          "%s does not use the shell and has no navigation"
                          % os.path.basename(path))

if __name__ == "__main__":
    unittest.main()
