"""Every url_for() target in a template must be a real endpoint.

The bug this pins down: two helper functions were inserted between
`@admin_blueprint.route("/scrapers")` and `def scrapers():`, so the decorator
registered the HELPER as the view. The endpoint `admin.scrapers` ceased to
exist, and all 33 `url_for('admin.scrapers')` references in the admin templates
raised BuildError -- a 500 on the entire admin dashboard.

The full 64-test suite passed throughout. Nothing exercised route registration,
and a url_for build error only surfaces when a template renders, so the failure
reached production. These tests are cheap and catch exactly that class:

  1. No route decorator sits on a private (underscore-prefixed) function. That
     is the specific shape of the mistake -- a helper accidentally wearing the
     decorator that belonged to the view below it.
  2. Every endpoint named in a template's url_for() is defined somewhere in the
     blueprints.

Both are static (ast + regex) so they need no app context, no database, and no
Flask import -- which is why they can run in this environment at all.
"""
import ast
import os
import re
import unittest


HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
BLUEPRINTS = os.path.join(BACKEND, "blueprints")
TEMPLATES = os.path.join(BACKEND, "templates")


def _blueprint_files():
    return [
        os.path.join(BLUEPRINTS, n)
        for n in sorted(os.listdir(BLUEPRINTS))
        if n.endswith(".py")
    ]


def _routed_functions(path):
    """[(function_name, lineno, [decorator_source])] for every @*.route()."""
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            decorators = [ast.unparse(d) for d in node.decorator_list]
            if any(".route(" in d for d in decorators):
                out.append((node.name, node.lineno, decorators))
    return out


class RouteDecoratorPlacementTest(unittest.TestCase):
    def test_no_route_is_registered_on_a_private_helper(self):
        offenders = []
        for path in _blueprint_files():
            for name, lineno, _decs in _routed_functions(path):
                if name.startswith("_"):
                    offenders.append("%s:%d %s" % (os.path.basename(path), lineno, name))
        self.assertEqual(
            offenders, [],
            "A @route decorator is attached to a private helper. This almost always means "
            "a function was inserted between the decorator and the view it belonged to, "
            "which silently renames the endpoint and breaks every url_for() for it:\n  "
            + "\n  ".join(offenders),
        )


class TemplateEndpointsExistTest(unittest.TestCase):
    """Every url_for('<blueprint>.<endpoint>') in a template resolves."""

    URL_FOR = re.compile(r"""url_for\(\s*['"]([a-zA-Z_][\w]*\.[\w]+)['"]""")

    def _defined_endpoints(self):
        names = set()
        for path in _blueprint_files():
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    decorators = [ast.unparse(d) for d in node.decorator_list]
                    if any(".route(" in d for d in decorators):
                        names.add(node.name)
                        # Endpoints can be renamed: @route(..., endpoint="x")
                        for dec in decorators:
                            m = re.search(r"endpoint=['\"]([\w]+)['\"]", dec)
                            if m:
                                names.add(m.group(1))
        return names

    def test_every_templated_endpoint_is_defined(self):
        defined = self._defined_endpoints()
        self.assertTrue(defined, "found no routed functions at all -- the scan is broken")

        missing = {}
        for root, _dirs, files in os.walk(TEMPLATES):
            for name in files:
                if not name.endswith(".html"):
                    continue
                path = os.path.join(root, name)
                text = open(path, encoding="utf-8", errors="replace").read()
                for ref in set(self.URL_FOR.findall(text)):
                    endpoint = ref.split(".", 1)[1]
                    if endpoint not in defined:
                        missing.setdefault(ref, set()).add(name)

        self.assertEqual(
            missing, {},
            "Templates reference endpoints that no routed view defines. Each of these "
            "raises BuildError at render time (a 500 on the page):\n  "
            + "\n  ".join(
                "%s  <- %s" % (ref, ", ".join(sorted(files)))
                for ref, files in sorted(missing.items())
            ),
        )


# Python-side url_for() targets that no routed view defines, as they stand.
#
# A RATCHET, not an allowlist. Every entry is a route that does its work and
# THEN raises BuildError -- an HTTP 500 after the destructive part has already
# happened. They are enumerated so the number cannot grow quietly while the
# question of where each should redirect instead is answered
# (OUTSTANDING.md 4.13e); the same shape as tests/test_module_stub_hygiene.py's
# baseline, and for the same reason: a ratchet on an inflated baseline is worse
# than none, so this is the measured set and not a round number.
KNOWN_DEAD_PYTHON_TARGETS = {
    # EMPTY, and that is the point: on 2026-08-20 there were 57 call sites
    # naming 8 endpoints no routed view defines, every one of which would do its
    # work and THEN raise BuildError -- a 500 after the change. All 56 real ones
    # now redirect to admin.dashboard or return None; the other 2 apparent ones
    # were mentions inside COMMENTS explaining this very bug, which is why the
    # scan strips comments before counting.
    #
    # Leave it empty. An entry here is a route that 500s, and the ratchet below
    # exists to make adding one a decision somebody takes deliberately rather
    # than a thing that happens.
}


class PythonEndpointTest(TemplateEndpointsExistTest):
    """The same rule as the template scan, applied to the BLUEPRINTS.

    THIS FILE'S OWN DOCSTRING DESCRIBES THIS BUG, and the test written for it
    could not see this half. `admin.scrapers` stopped being an endpoint and
    "all 33 url_for('admin.scrapers') references in the admin templates raised
    BuildError". The admin templates were later deleted with the panel, so the
    TEMPLATE references went away and the scan went green -- while eighteen
    references in blueprints/admin.py stayed exactly where they were.

    A url_for() in Python is invisible to a template scan and surfaces only when
    the route runs, which for an admin route may be never until the day somebody
    needs it. The earlier main.faq and main.federation 500s were both this, both
    found by hand, and both times the whole-file scan that found them was run
    once and not kept.
    """

    @staticmethod
    def _code_only(path):
        """The file with COMMENTS removed.

        Comments here legitimately quote endpoints that no longer exist -- the
        notes explaining the main.federation and admin.scrapers 500s both name
        the dead endpoint, because that is what they are about. Counting those
        as call sites made the scan report two dead targets when the real number
        was zero, which is the false positive that turns a guard into noise.

        tokenize rather than a regex: a `#` inside a string literal is not a
        comment, and a scan that cannot tell the difference would delete half a
        line of real code from its own view.
        """
        import io
        import tokenize
        text = open(path, encoding="utf-8", errors="replace").read()
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return text  # unparseable: scan it whole rather than skip it
        return "\n".join(t.string for t in tokens if t.type != tokenize.COMMENT)

    def _python_url_for_targets(self):
        """endpoint -> number of call sites, across every blueprint."""
        counts = {}
        for path in _blueprint_files():
            for ref in self.URL_FOR.findall(self._code_only(path)):
                counts[ref] = counts.get(ref, 0) + 1
        return counts

    def test_no_python_url_for_target_is_newly_dead(self):
        defined = self._defined_endpoints()
        self.assertTrue(defined, "found no routed functions at all -- the scan is broken")

        dead = {
            ref: n for ref, n in self._python_url_for_targets().items()
            if ref.split(".", 1)[1] not in defined
        }
        new = {r: n for r, n in dead.items() if r not in KNOWN_DEAD_PYTHON_TARGETS}
        self.assertEqual(
            new, {},
            "A blueprint calls url_for() on an endpoint no routed view defines. "
            "The route will do its work and THEN raise BuildError -- a 500 after "
            "the change has already been made, which is how "
            "POST /federation/request came to accept submissions and then "
            "error:\n  " + "\n  ".join("%s (%d call sites)" % kv
                                        for kv in sorted(new.items())))

        grown = {r: (KNOWN_DEAD_PYTHON_TARGETS[r], n) for r, n in dead.items()
                 if r in KNOWN_DEAD_PYTHON_TARGETS and n > KNOWN_DEAD_PYTHON_TARGETS[r]}
        self.assertEqual(
            grown, {},
            "A known-dead endpoint gained call sites:\n  "
            + "\n  ".join("%s: %d -> %d" % (r, was, now)
                           for r, (was, now) in sorted(grown.items())))

    def test_the_baseline_does_not_overstate_what_is_broken(self):
        """A ratchet on an inflated baseline leaves headroom for real breakage
        while the number still looks like progress. If a target is fixed or
        loses call sites, this fails and the baseline comes down with it."""
        defined = self._defined_endpoints()
        counts = self._python_url_for_targets()
        for ref, expected in sorted(KNOWN_DEAD_PYTHON_TARGETS.items()):
            actual = counts.get(ref, 0)
            if ref.split(".", 1)[1] in defined:
                self.fail("%s is defined now; drop it from KNOWN_DEAD_PYTHON_TARGETS"
                          % ref)
            self.assertEqual(
                actual, expected,
                "%s has %d call sites, the baseline says %d -- lower the baseline"
                % (ref, actual, expected))


if __name__ == "__main__":
    unittest.main()
