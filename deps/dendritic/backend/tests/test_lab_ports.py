"""Every port a lab box exposes, not just the one an inbound stream lands on.

The importer already computed the whole list and kept one, so a box exposing a
web app, a database and a debugger advertised a single open port. The
destination always carried all of them — one .b32.i2p, every port — so this was
the page describing the box wrongly rather than the box being wrong. Somebody
port-scanning it would find services the page said were not there, which is a
bad way to learn your tooling is fine.

The fallback matters as much as the fix: a row imported before the list was kept
has an encrypted build context the site cannot re-read, so it shows the primary
alone. That must read as "only this is on record", never as "the rest are
closed".
"""

import ast
import os
import pathlib
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


REGISTRY = _load_pure("backend/services/lab_registry.py".replace("backend/", ""),
                      {"_clean_ports"})
IMPORT = _load_pure("services/vulhub_import.py",
                    {"parse_ports", "choose_primary_port", "_AVOID_PORTS",
                     "_PREFER_PORTS", "_PORT_NUM_RE"},
                    extra={"re": __import__("re")})


def _port_list(exposed, primary):
    """Mirrors LabChallenge.port_list without importing the ORM."""
    source = (pathlib.Path(BACKEND) / "model" / "LabChallenge.py").read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "port_list":
            module = ast.Module(body=[node], type_ignores=[])
            ast.fix_missing_locations(module)
            ns = {}
            exec(compile(module, "port_list", "exec"), ns)

            class Row(object):
                exposed_ports = exposed
                primary_port = primary
            return ns["port_list"](Row())
    raise AssertionError("port_list not found")


class CleanPortsTest(unittest.TestCase):
    def test_a_list_is_stored_in_order(self):
        self.assertEqual(REGISTRY["_clean_ports"]([8080, 3306, 5005]), "8080,3306,5005")

    def test_duplicates_collapse(self):
        self.assertEqual(REGISTRY["_clean_ports"]([80, 80, 443]), "80,443")

    def test_out_of_range_and_junk_are_dropped(self):
        self.assertEqual(REGISTRY["_clean_ports"]([0, 70000, -1, "x", None, 22]), "22")

    def test_nothing_is_an_empty_string_not_a_crash(self):
        self.assertEqual(REGISTRY["_clean_ports"](None), "")
        self.assertEqual(REGISTRY["_clean_ports"]([]), "")

    def test_a_pathological_project_truncates_rather_than_failing_the_import(self):
        got = REGISTRY["_clean_ports"](list(range(1000, 1100)))
        self.assertLessEqual(len(got), 200)
        self.assertFalse(got.endswith(","), "a trailing comma would parse as a blank port")


class PortListTest(unittest.TestCase):
    def test_the_primary_comes_first_even_when_recorded_later(self):
        # It is where a portless inbound stream lands, so it is the one somebody
        # tries first.
        self.assertEqual(_port_list("3306,8080,5005", 8080), [8080, 3306, 5005])

    def test_a_primary_missing_from_the_list_is_still_shown(self):
        self.assertEqual(_port_list("3306,5005", 8080), [8080, 3306, 5005])

    def test_nothing_recorded_falls_back_to_the_primary_alone(self):
        # NOT an empty list: claiming a box exposes no ports would be worse than
        # admitting only one is known.
        self.assertEqual(_port_list("", 8161), [8161])

    def test_junk_in_the_column_does_not_break_the_page(self):
        self.assertEqual(_port_list("8080,,abc, 3306 ", 8080), [8080, 3306])


class ParsePortsTest(unittest.TestCase):
    """The importer must find every port, across compose's many spellings."""

    COMPOSE = """
version: '2'
services:
  web:
    image: example/web
    ports:
      - "8080:8080"
      - "127.0.0.1:9000:9000"
    expose:
      - "8443"
  db:
    image: mysql
    ports:
      - "3306:3306/tcp"
  debug:
    image: example/dbg
    ports:
      - target: 5005
        published: 5005
"""

    def test_every_service_contributes_its_ports(self):
        got = IMPORT["parse_ports"](self.COMPOSE)
        for expected in (8080, 9000, 3306, 5005):
            self.assertIn(expected, got, "missed %d" % expected)

    def test_the_two_parse_paths_agree(self):
        """parse_ports has a PyYAML branch and a regex branch, and PyYAML is
        declared in NEITHER requirements.txt, the Pipfile NOR the Dockerfile --
        so the regex branch is what actually runs unless yaml arrives as
        somebody else's transitive dependency.

        That made the two paths silently disagree: the regex branch missed
        long-form `- target:` ports entirely and counted `expose:` entries the
        YAML branch never reads. This asserts they agree, so a future edit to
        one has to be made to the other.

        Skipped rather than failed when PyYAML is absent, because there is then
        only one path to compare and the other tests here already cover it.
        """
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML absent: only the regex path exists to test")
        import re as _re
        import services.vulhub_import as vi
        with_yaml = vi.parse_ports(self.COMPOSE)
        real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
            else __builtins__.__import__

        def no_yaml(name, *a, **k):
            if name == "yaml":
                raise ImportError("forced for this test")
            return real_import(name, *a, **k)

        import builtins
        builtins.__import__ = no_yaml
        try:
            without_yaml = vi.parse_ports(self.COMPOSE)
        finally:
            builtins.__import__ = real_import
        self.assertEqual(with_yaml, without_yaml,
                         "the YAML and regex paths disagree; whichever is "
                         "installed then decides which ports a challenge gets")

    def test_the_primary_avoids_a_database_or_debugger(self):
        # The whole reason a single port was wrong: picking one is a guess, and
        # the guess deliberately avoids backing services.
        primary = IMPORT["choose_primary_port"](self.COMPOSE)
        self.assertNotIn(primary, (3306, 5005))


if __name__ == "__main__":
    unittest.main()
