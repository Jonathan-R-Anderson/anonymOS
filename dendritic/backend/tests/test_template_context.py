"""Every variable a template uses must be one somebody actually passes it.

THE BUG THIS EXISTS FOR
-----------------------
A card was added to profile-settings.html that renders `slip.name`, and the
route rendering it never passed `slip`. Jinja does not fail at edit time or at
import time — it fails when a real person loads the page, and it fails for the
WHOLE page, because an undefined attribute access aborts the render. The account
settings page returned 500 to everyone until somebody reported it.

Nothing else catches this. The template parses, the route compiles, the test
suite passes, and the failure needs the app booted with a database to reproduce.
So this checks it statically: for every `render_template("x.html", a=..., b=...)`
in the blueprints, the names x.html actually uses must come from somewhere —
the call's own keyword arguments, a parent template's own variables, a context
processor, or a Jinja global.

WHAT IT DELIBERATELY SKIPS
--------------------------
Calls it cannot read statically: a computed template name, `**kwargs`, or a
template that inherits from one outside this repo. Skipping is right — a check
that guesses would be turned off within a week — but it does mean a green run is
not proof every page renders, only that no page is missing something obvious.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

TEMPLATES = BACKEND / "templates"

# What Jinja and Flask provide on their own. Everything else ambient is DERIVED
# from the source below rather than listed here — a hand-maintained list of the
# app's own globals goes stale, and a stale allowlist in a test like this fails
# on correct code, which is how a check gets deleted.
BUILTIN = {
    "url_for", "request", "session", "config", "g", "get_flashed_messages",
    "range", "dict", "lipsum", "cycler", "joiner", "namespace",
}

# Context processors that build their dict somewhere this cannot read (a helper
# call rather than a literal), plus template globals registered on an object
# this does not walk. Named individually so each one is a decision.
OPAQUE = {
    # app.py: share_captcha() returns captcha.get_template_context()
    "captcha", "captcha_provider", "captcha_site_key", "captcha_enabled",
    # blueprints/boards.py injects the current board into board-scoped pages
    "board",
    # cooldown.py / privacy banner
    "cooldown", "privacy",
    # macros imported by lab templates from a shared macro file
    "osicon", "diffbars",
}


def _ambient():
    """Names every template gets for free, read out of the source.

    Two sources: dict literals returned from an @app.context_processor, and
    add_app_template_global(...) calls on any blueprint.
    """
    names = set(BUILTIN) | set(OPAQUE)
    for path in BACKEND.rglob("*.py"):
        if "node_modules" in str(path) or path.parent.name == "tests":
            continue
        try:
            tree = ast.parse(path.read_text())
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and any(
                    getattr(d, "attr", "") == "context_processor"
                    for d in node.decorator_list):
                for sub in ast.walk(node):
                    if not isinstance(sub, ast.Return):
                        continue
                    value = sub.value
                    if isinstance(value, ast.Dict):
                        names |= {k.value for k in value.keys
                                  if isinstance(k, ast.Constant)}
                    elif (isinstance(value, ast.Call)
                          and getattr(value.func, "id", "") == "dict"):
                        names |= {kw.arg for kw in value.keywords if kw.arg}
            if (isinstance(node, ast.Call)
                    and getattr(node.func, "attr", "") == "add_app_template_global"):
                # Either an explicit name or the function's own __name__.
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    names.add(node.args[1].value)
                elif node.args and isinstance(node.args[0], ast.Name):
                    names.add(node.args[0].id)
    return names


def _render_calls(source, path):
    """[(template_name, {kwargs}, lineno)] for statically-readable calls."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name != "render_template" or not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue  # computed template name — not readable here
        if any(keyword.arg is None for keyword in node.keywords):
            continue  # **kwargs — the caller could be passing anything
        out.append((first.value,
                    {keyword.arg for keyword in node.keywords},
                    node.lineno))
    return out


def _locally_bound(tree):
    """Names the template binds itself, so nobody has to pass them.

    find_undeclared_variables misses all of these — a `{% with radar = ... %}`,
    a `{% macro pageurl() %}`, an `{% import "x" as form %}` — and every one of
    them would be a false report about correct code. A check that cries wolf on
    working pages gets deleted, so being exhaustive here matters more than being
    strict.
    """
    from jinja2 import nodes

    bound = set()

    def _add(target):
        if isinstance(target, nodes.Name):
            bound.add(target.name)
        elif isinstance(target, nodes.Tuple):
            for item in target.items:
                _add(item)

    for node in tree.find_all((nodes.Assign, nodes.AssignBlock, nodes.For,
                               nodes.With, nodes.Macro, nodes.Import,
                               nodes.FromImport)):
        if isinstance(node, (nodes.Assign, nodes.AssignBlock, nodes.For)):
            _add(node.target)
        elif isinstance(node, nodes.With):
            for target in getattr(node, "targets", []):
                _add(target)
        elif isinstance(node, nodes.Macro):
            bound.add(node.name)
        elif isinstance(node, nodes.Import):
            bound.add(node.target)
        elif isinstance(node, nodes.FromImport):
            for name in node.names:
                bound.add(name[1] if isinstance(name, tuple) else name)
    return bound


def _guarded(tree):
    """Names only ever read with a fallback: `{{ x or "y" }}`, `x|default(...)`.

    Jinja's default Undefined is falsy and renders empty, so these are correct
    on purpose — the template is saying the value is optional. Reporting them
    would be telling somebody to pass a variable whose absence they handled.
    """
    from jinja2 import nodes

    optional = set()
    for node in tree.find_all(nodes.Or):
        if isinstance(node.left, nodes.Name):
            optional.add(node.left.name)
    for node in tree.find_all(nodes.Filter):
        if node.name == "default" and isinstance(node.node, nodes.Name):
            optional.add(node.node.name)

    # Only if EVERY use is guarded. One bare `{{ x }}` elsewhere and the
    # fallback says nothing about that use.
    bare = set()
    for node in tree.find_all(nodes.Output):
        for child in node.nodes:
            if isinstance(child, nodes.Name):
                bare.add(child.name)
    return optional - bare


def _walk(environment, template_name, seen=None):
    """(needs, bound) across a template and everything it extends or includes."""
    from jinja2 import meta

    seen = seen if seen is not None else set()
    if template_name in seen:
        return set(), set()
    seen.add(template_name)

    path = TEMPLATES / template_name
    if not path.exists():
        return set(), set()
    tree = environment.parse(path.read_text(), filename=template_name)
    needs = set(meta.find_undeclared_variables(tree))
    bound = _locally_bound(tree) | _guarded(tree)
    for other in meta.find_referenced_templates(tree):
        if other:
            child_needs, child_bound = _walk(environment, other, seen)
            needs |= child_needs
            bound |= child_bound
    return needs, bound


def _template_needs(environment, template_name):
    """Names that must be passed in.

    Bindings are subtracted across the WHOLE graph rather than per file: an
    include gets the variables of whatever included it, so
    `{% with radar = ... %}{% include "codeplay-radar.html" %}` satisfies the
    include's use of `radar` from the parent — and treating each file alone
    reports that correct code as broken.
    """
    needs, bound = _walk(environment, template_name)
    return needs - bound


class TemplateContextTest(unittest.TestCase):
    def test_every_render_call_passes_what_its_template_uses(self):
        from jinja2 import Environment, FileSystemLoader

        environment = Environment(loader=FileSystemLoader(str(TEMPLATES)))
        ambient = _ambient()
        missing = []
        for path in sorted((BACKEND / "blueprints").glob("*.py")):
            source = path.read_text()
            for template_name, passed, lineno in _render_calls(source, path):
                needs = _template_needs(environment, template_name)
                gap = needs - passed - ambient
                if gap:
                    missing.append("%s:%d renders %s without %s"
                                   % (path.name, lineno, template_name,
                                      ", ".join(sorted(gap))))
        self.assertEqual(missing, [], "\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main()
