"""The newsroom is four blueprints, and nothing else asserts they are mounted.

Every other newsroom test file drives a surface directly -- a view function, a
service, a template -- because the suite stubs `shared` and so cannot import
`app.py` at all. That leaves one whole class of failure untested: the code is
perfect and unreachable. A blueprint dropped from `app.py` in a merge, a prefix
edited to something the templates do not expect, and every test in this tree
still passes while the newsroom 404s.

So this file reads `app.py` as text and asserts the wiring, and then rebuilds a
real Werkzeug map out of the rule strings the blueprint modules declare and the
prefixes `app.py` mounts them at. That second half is the one worth having: the
vote endpoints live UNDER the reading prefix (`/news/vote/<id>` inside `/news`),
which is a genuine chance for one route to swallow another, and no amount of
reading the two files side by side settles it the way asking the matcher does.

Static rather than executed on purpose. `app.py` imports psycopg2, gevent and a
configured database; a test that needed those would be a test nobody could run,
and the wiring would go back to being unasserted.
"""

import ast
import os
import re
import unittest

from werkzeug.routing import Map, Rule

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)


# What `app.py` must mount, and where. The prefixes are not arbitrary and two of
# them are load-bearing beyond taste:
#
#   /news       is in other people's citations. It is also hardcoded as a
#               fallback in `services/news_rail.py`, for the case where the rail
#               is built with no application context -- see the test below.
#   /news/vote  is deliberately nested inside the reading prefix rather than put
#               under /api, so a reader who blocks the API surface does not get
#               a page whose vote buttons silently do nothing.
#   /newsroom   is NOT under /news, because /news is the archive a reader trusts
#               and a draft served from under it is one mistake from reading as
#               published.
#   /admin/newsroom inherits the admin path's expectations while keeping its own
#               gate: `slip_is_editor` admits editors holding no admin grant.
EXPECTED = {
    "news_blueprint": ("blueprints.news", "/news"),
    "newsroom_blueprint": ("blueprints.newsroom", "/newsroom"),
    "news_editor_blueprint": ("blueprints.news_editor", "/admin/newsroom"),
    "story_votes_blueprint": ("blueprints.story_votes", "/news/vote"),
}


def _source(relpath):
    with open(os.path.join(BACKEND, relpath), encoding="utf-8") as handle:
        return handle.read()


def _app_tree():
    return ast.parse(_source("app.py"), filename="app.py")


def _imports(tree):
    """{imported name: module it came from} for `from x import y` at any depth."""
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                found[alias.asname or alias.name] = node.module or ""
    return found


def _registrations(tree):
    """{blueprint variable: url_prefix or None} for every register_blueprint."""
    found = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "register_blueprint":
            continue
        if not node.args or not isinstance(node.args[0], ast.Name):
            continue
        prefix = None
        for keyword in node.keywords:
            if keyword.arg == "url_prefix" and isinstance(keyword.value, ast.Constant):
                prefix = keyword.value.value
        found[node.args[0].id] = prefix
    return found


def _rules_in(relpath):
    """Every (endpoint, rule, methods) a blueprint module declares, unimported.

    Reads the decorators rather than the registered map, because importing these
    modules pulls in the model layer and this file is deliberately import-free.
    """
    tree = ast.parse(_source(relpath), filename=relpath)
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if called == "Blueprint" and node.value.args:
                first = node.value.args[0]
                if isinstance(first, ast.Constant):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            names[target.id] = first.value

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            target = call.func if call else decorator
            if not isinstance(target, ast.Attribute) or target.attr != "route":
                continue
            owner = target.value
            if not isinstance(owner, ast.Name) or owner.id not in names:
                continue
            if not call or not call.args or not isinstance(call.args[0], ast.Constant):
                continue
            endpoint, methods = node.name, ["GET"]
            for keyword in call.keywords:
                if keyword.arg == "endpoint" and isinstance(keyword.value, ast.Constant):
                    endpoint = keyword.value.value
                if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    methods = [element.value for element in keyword.value.elts
                               if isinstance(element, ast.Constant)]
            found.append(("%s.%s" % (names[owner.id], endpoint),
                          call.args[0].value, methods))
    return found



# The newsroom was removed with the rest of the stripped blueprints, and the
# class(es) below read its files directly: blueprints/news.py, templates/news.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the treatment the
# civil-rights classes in test_evidence_upload.py already have. The assertions
# are still correct and still worth having; deleting them would mean rewriting
# them from scratch if the feature returns, and a skipUnless brings them back
# the moment the files exist again.
_NEWSROOM_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/news.py",
        "templates/news",
    )
)
_NEWSROOM_PRESENT_GONE = "the newsroom was removed; these classes read its files"

class WiringTest(unittest.TestCase):
    """`app.py` mounts all four, at the prefixes the rest of the tree assumes."""

    def setUp(self):
        self.tree = _app_tree()

    @unittest.skipUnless(_NEWSROOM_PRESENT, _NEWSROOM_PRESENT_GONE)
    def test_every_newsroom_blueprint_is_imported(self):
        imported = _imports(self.tree)
        for name, (module, _) in sorted(EXPECTED.items()):
            self.assertEqual(
                imported.get(name), module,
                "app.py no longer imports %s from %s" % (name, module))

    @unittest.skipUnless(_NEWSROOM_PRESENT, _NEWSROOM_PRESENT_GONE)
    def test_every_newsroom_blueprint_is_registered_at_its_prefix(self):
        registered = _registrations(self.tree)
        for name, (_, prefix) in sorted(EXPECTED.items()):
            self.assertIn(name, registered,
                          "app.py never registers %s; the newsroom is 404" % name)
            self.assertEqual(
                registered[name], prefix,
                "%s moved to %r. Every citation of a published story is a %s "
                "URL, and services/news_rail.py hardcodes that prefix as its "
                "fallback -- see the test below."
                % (name, registered[name], prefix))

    def test_each_registration_says_why_its_prefix_is_what_it_is(self):
        """A prefix with no stated reason is one the next person moves.

        Not a style rule. `/newsroom` looks like an oversight until you know it
        is deliberately not under `/news`, and an unexplained line is exactly
        the kind somebody tidies into the pattern of its neighbours.
        """
        lines = _source("app.py").splitlines()
        for index, line in enumerate(lines):
            for name in EXPECTED:
                if "register_blueprint(%s" % name not in line:
                    continue
                above = []
                cursor = index - 1
                while cursor >= 0 and lines[cursor].lstrip().startswith("#"):
                    above.append(lines[cursor].strip())
                    cursor -= 1
                self.assertTrue(
                    above, "%s is registered with no comment saying what it is "
                           "or why its prefix is what it is" % name)


@unittest.skipUnless(_NEWSROOM_PRESENT, _NEWSROOM_PRESENT_GONE)
class PrefixCollisionTest(unittest.TestCase):
    """The real map, built from the real rules, at the real prefixes.

    `/news/vote/12` has to reach the vote endpoint and not the story page, and
    `/news/2026/8/a-slug` has to reach the story page and not the vote endpoint.
    Werkzeug decides that, not the order of the lines in `app.py`, so the only
    honest way to assert it is to ask Werkzeug.
    """

    def _map(self):
        rules = []
        for name, (module, prefix) in EXPECTED.items():
            relpath = module.replace(".", "/") + ".py"
            for endpoint, rule, methods in _rules_in(relpath):
                rules.append(Rule(prefix.rstrip("/") + rule,
                                  endpoint=endpoint, methods=methods))
        self.assertTrue(rules, "no routes were found at all")
        return Map(rules).bind("example.invalid")

    def test_each_path_reaches_the_route_it_looks_like(self):
        adapter = self._map()
        for path, method, expected in (
                ("/news/", "GET", "news.front"),
                ("/news/2026/8/a-story-slug", "GET", "news.story"),
                ("/news/author/somebody", "GET", "news.author"),
                ("/news/feed.xml", "GET", "news.feed_rss"),
                ("/news/feed.json", "GET", "news.feed_json"),
                # Nested inside /news and must not be eaten by it. "vote" is not
                # an integer, so it cannot match <int:year> -- assert it rather
                # than trust it, because a future /news/<slug> route would.
                ("/news/vote/12", "POST", "story_votes.cast"),
                ("/news/vote/12/clear", "POST", "story_votes.clear"),
                ("/newsroom/", "GET", "newsroom.desk"),
                ("/newsroom/new", "GET", "newsroom.new_story"),
                ("/newsroom/7/edit", "GET", "newsroom.edit_story"),
                ("/admin/newsroom/", "GET", "news_editor.queue"),
                ("/admin/newsroom/story/7", "GET", "news_editor.story")):
            endpoint, _ = adapter.match(path, method=method)
            self.assertEqual(endpoint, expected,
                             "%s %s reaches %s" % (method, path, endpoint))

    def test_no_two_newsroom_routes_claim_the_same_endpoint_name(self):
        seen = {}
        for name, (module, _) in EXPECTED.items():
            for endpoint, rule, _methods in _rules_in(module.replace(".", "/") + ".py"):
                self.assertNotIn(
                    endpoint, seen,
                    "%s is declared twice (%s and %s); url_for() would build "
                    "one of them and nobody would know which"
                    % (endpoint, seen.get(endpoint), rule))
                seen[endpoint] = rule


class FallbackPathTest(unittest.TestCase):
    """The rail's hardcoded paths must agree with where the blueprint is mounted.

    `services/news_rail.py` builds its links with `url_for` and falls back to a
    literal path, because the rail is also built by a background pass with no
    application context. That fallback is silent: move the prefix and the front
    page keeps rendering, with every headline linking to a 404.
    """

    def test_the_rail_falls_back_to_the_prefix_the_app_actually_mounts(self):
        prefix = EXPECTED["news_blueprint"][1]
        source = _source("services/news_rail.py")
        literals = re.findall(r'"(/news[^"]*)"', source)
        self.assertTrue(literals, "the rail no longer names a fallback path")
        for literal in literals:
            self.assertTrue(
                literal == prefix or literal.startswith(prefix + "/"),
                "services/news_rail.py falls back to %r, which is not under %r"
                % (literal, prefix))


@unittest.skipUnless(_NEWSROOM_PRESENT, _NEWSROOM_PRESENT_GONE)
class NavLinkTest(unittest.TestCase):
    """base.html links to the newsroom, and only when there is something in it.

    A prominent link to "nothing has been published yet" reads as a broken site
    to somebody who came looking for reporting -- the same lesson the front-page
    report strip is gated by.
    """

    def test_the_link_exists_and_points_at_the_public_front(self):
        source = _source("templates/base.html")
        self.assertIn('url_for("news.front")', source,
                      "base.html no longer links to the newsroom")

    def test_the_link_is_gated_on_there_being_something_to_read(self):
        source = _source("templates/base.html")
        match = re.search(
            r"\{%\s*if[^%]*newsroom_has_stories[^%]*%\}(.*?)\{%\s*endif\s*%\}",
            source, re.DOTALL)
        self.assertIsNotNone(
            match, "the Newsroom nav link is no longer gated by "
                   "newsroom_has_stories(); an empty newsroom now advertises "
                   "itself on every page of the site")
        self.assertIn('url_for("news.front")', match.group(1),
                      "the gate no longer wraps the link it was added for")

    def test_the_gate_is_a_context_processor_and_is_cached(self):
        source = _source("blueprints/news.py")
        self.assertIn("newsroom_has_stories", source,
                      "nothing exports newsroom_has_stories to base.html")
        self.assertIn("context_processor", source)
        # base.html renders on nearly every page on the site. Without the cache
        # this is a database query per page view, on every page, forever.
        self.assertIn("NAV_CACHE_TTL_SECONDS", source)


@unittest.skipUnless(_NEWSROOM_PRESENT, _NEWSROOM_PRESENT_GONE)
class TemplateEndpointTest(unittest.TestCase):
    """Every url_for in a newsroom template names an endpoint that exists.

    A template is not compiled until it is rendered, so a link to an endpoint
    that was renamed is a 500 on a page nobody visits in the tests -- typically
    the editor's own review screen, found by an editor mid-retraction.
    """

    TEMPLATES = ("templates/news", "templates/newsroom")
    EXTRA = ("templates/admin-newsroom.html",
             "templates/admin-newsroom-story.html",
             "templates/includes/front-news-rail.html")

    def _universe(self):
        """Every endpoint name the tree declares, read from the decorators."""
        found = {"static"}
        tree = _app_tree()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                call = decorator if isinstance(decorator, ast.Call) else None
                target = call.func if call else decorator
                if (isinstance(target, ast.Attribute) and target.attr == "route"
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "app"):
                    found.add(node.name)
        folder = os.path.join(BACKEND, "blueprints")
        for name in sorted(os.listdir(folder)):
            if not name.endswith(".py"):
                continue
            for endpoint, _rule, _methods in _rules_in("blueprints/%s" % name):
                found.add(endpoint)
        return found

    def _templates(self):
        paths = list(self.EXTRA)
        for folder in self.TEMPLATES:
            for name in sorted(os.listdir(os.path.join(BACKEND, folder))):
                if name.endswith(".html"):
                    paths.append("%s/%s" % (folder, name))
        return paths

    def test_every_endpoint_named_in_a_newsroom_template_exists(self):
        universe = self._universe()
        self.assertIn("news.front", universe, "the endpoint scan found nothing")
        for relpath in self._templates():
            source = _source(relpath)
            for endpoint in re.findall(
                    r"""url_for\(\s*["']([A-Za-z_][\w.]*)["']""", source):
                self.assertIn(
                    endpoint, universe,
                    "%s links to url_for(%r), which no route declares"
                    % (relpath, endpoint))

    def test_the_templates_being_audited_are_the_ones_on_disk(self):
        """A template added and not audited is the leak this class cannot see."""
        for relpath in self._templates():
            self.assertTrue(os.path.exists(os.path.join(BACKEND, relpath)),
                            "%s is audited but does not exist" % relpath)


if __name__ == "__main__":
    unittest.main()
