"""Source checks for mistakes that only explode in production.

This file exists because of one specific failure that has now happened twice in
a day, both times taking the whole site down:

    @blueprint.route("/a")@blueprint.route("/a")
    def handler():

Two decorators on one physical line. On the container's **Python 3.8** that is a
SyntaxError, so uwsgi cannot import the app and every route disappears. On a
modern local Python it is not — PEP 614 (3.9+) allows any expression after `@`,
so it parses as a matmul BinOp, `ast.parse` succeeds, every local check passes,
and the broken image ships.

That gap is the whole problem: the local checks were not wrong, they were run
against a different language version than production. So the test is written to
be version-independent — it reads the text, not the grammar.
"""

import ast
import os
import pathlib
import re
import sys
import unittest

BACKEND = pathlib.Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

SKIP_DIRS = {"__pycache__", "node_modules", "migrations", ".git"}


# This file is skipped by its own scan. It quotes the offending pattern in its
# docstring as documentation, and a detector that fires on the description of
# the thing it detects is a detector nobody keeps.
SELF = pathlib.Path(__file__).resolve()


def python_files():
    for path in BACKEND.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() == SELF:
            continue
        yield path


class DecoratorHygieneTest(unittest.TestCase):
    # A second "@" that begins a new decorator on the same line. Matched on the
    # raw line rather than parsed, so it holds on any Python version.
    DOUBLE_DECORATOR = re.compile(r"^\s*@[\w.]+\([^\n]*\)\s*@[\w.]+")

    def test_no_two_decorators_share_a_line(self):
        offenders = []
        for path in python_files():
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if self.DOUBLE_DECORATOR.match(line):
                    offenders.append("%s:%d  %s" % (path.relative_to(BACKEND),
                                                    number, line.strip()[:90]))
        self.assertEqual(offenders, [],
                         "two decorators on one line is a SyntaxError on Python 3.8, "
                         "which is what the container runs:\n  " + "\n  ".join(offenders))


class RequestHookTest(unittest.TestCase):
    """A Flask hook must carry the decorator that matches its signature.

    An edit inserted a new function BETWEEN `@app.before_request` and the
    function it decorated. The new function inherited the stray decorator, so an
    after_request handler taking (response) was registered as a before_request
    handler taking nothing — TypeError on every single request, a site-wide 503 —
    and the function that had legitimately been a before_request silently stopped
    running at all. Neither shows up as a syntax error, and no unit test calls
    either one.
    """

    def _hooks(self, tree):
        found = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            names = []
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(target, ast.Attribute):
                    names.append(target.attr)
            if names:
                found[node.name] = (names, [a.arg for a in node.args.args])
        return found

    def test_hook_decorators_match_their_signatures(self):
        tree = ast.parse((BACKEND / "app.py").read_text())
        problems = []
        for name, (decorators, args) in self._hooks(tree).items():
            hooks = [d for d in decorators
                     if d in ("before_request", "after_request", "teardown_request")]
            if len(hooks) > 1:
                problems.append("%s carries %s — a function cannot be both" % (name, hooks))
                continue
            if not hooks:
                continue
            hook = hooks[0]
            if hook == "after_request" and len(args) != 1:
                problems.append("%s is an after_request but takes %d argument(s); "
                                "it must take exactly the response" % (name, len(args)))
            if hook == "before_request" and args:
                problems.append("%s is a before_request but takes %s; "
                                "it must take none" % (name, args))
        self.assertEqual(problems, [], "\n  ".join(problems))


class SyntaxTest(unittest.TestCase):
    def test_every_module_parses(self):
        # Cheap, and it catches the ordinary typo that the regex above would not.
        broken = []
        for path in python_files():
            try:
                ast.parse(path.read_text())
            except SyntaxError as exc:
                broken.append("%s:%s  %s" % (path.relative_to(BACKEND), exc.lineno, exc.msg))
        self.assertEqual(broken, [], "\n  ".join(broken))


class ModuleLevelNameTest(unittest.TestCase):
    """Names used at module scope that were never imported there.

    app.py assigned `int(time.time())` at module level without importing `time`.
    That is a NameError at import, which means the app does not start at all —
    the same blast radius as a SyntaxError, from a line that looks harmless in
    review and that no unit test reaches, because nothing imports far enough to
    hit it.
    """

    def test_app_does_not_use_unimported_names_at_module_scope(self):
        source = (BACKEND / "app.py").read_text()
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add((alias.asname or alias.name).split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(alias.asname or alias.name)

        # Module-level assignments only: anything inside a function runs later,
        # and a local import there is legitimate.
        used = set()
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                    used.add(sub.id)
                elif isinstance(sub, ast.Attribute):
                    root = sub
                    while isinstance(root, ast.Attribute):
                        root = root.value
                    if isinstance(root, ast.Name):
                        used.add(root.id)

        builtins_and_locals = set(dir(__builtins__)) | {"__name__", "__file__", "os"}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        builtins_and_locals.add(target.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                builtins_and_locals.add(node.name)

        missing = sorted(used - imported - builtins_and_locals)
        self.assertEqual(missing, [],
                         "used at module scope in app.py but never imported there: %s"
                         % missing)


if __name__ == "__main__":
    unittest.main()
