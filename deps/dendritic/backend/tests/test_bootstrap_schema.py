"""A fresh install must not be born missing tables (roadmap F1).

THE BUG
-------
`bootstrap.initialize_db()` calls `db.create_all()`, which creates tables for
the models that have been IMPORTED at that moment and nothing else. This module
imported 23 model modules by hand, reaching 56 tables transitively. The tree
defines 145.

`save_db()` then stamps alembic at `head`, which asserts that every migration is
already applied. On a FRESH database that is the whole failure:

    create_all()      ->  56 tables
    stamp("head")     ->  74 migrations skipped
    result            ->  89 tables that nothing will ever create

Each one then fails at first use with "relation does not exist", a long way from
its cause. An EXISTING database never hit it: ensure_runtime.py sees the `board`
table and runs `update_db()`, and the migrations do their job. It was exactly and
only a fresh install that came out permanently short.

THE FIX, AND WHY IT IS TWO THINGS
---------------------------------
`import_all_models()` makes the metadata complete by construction — a new model
file is picked up because it exists, not because somebody remembered to add an
import, and forgetting that import WAS the bug.

`verify_schema()` is the belt: it compares what the models declare against what
the database actually has and raises. A missed table becomes a loud startup
failure instead of a silent permanent one.

These tests read the source rather than standing up a database, matching the
other bootstrap-adjacent tests in this directory; the numbers above were
measured against a real sqlite database while writing them.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

SRC = (BACKEND / "bootstrap.py").read_text()
TREE = ast.parse(SRC)


def _func(name):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(SRC, node) or ""
    raise AssertionError("%s not found in bootstrap.py" % name)


class CreateAllSeesEveryModel(unittest.TestCase):
    def test_initialize_db_imports_every_model_first(self):
        body = _func("initialize_db")
        self.assertIn("import_all_models()", body,
                      "create_all() runs against whatever happens to be imported; "
                      "with the hand-written list that was 56 of 145 tables")
        # Order matters: importing after create_all() creates nothing.
        self.assertLess(body.index("import_all_models()"), body.index("db.create_all()"),
                        "models are imported AFTER create_all(), which is the same as "
                        "not importing them")

    def test_models_are_discovered_not_listed(self):
        body = _func("import_all_models")
        self.assertIn("iter_modules", body,
                      "the model set is enumerated by hand again; a list is a thing to "
                      "forget to update, and forgetting it was the bug")

    def test_an_unimportable_model_is_reported_not_swallowed(self):
        body = _func("import_all_models")
        self.assertIn("app.logger.error", body,
                      "a model that cannot be imported has no table and must be named")


class SchemaIsVerified(unittest.TestCase):
    def test_initialize_db_verifies_after_creating(self):
        body = _func("initialize_db")
        self.assertIn("verify_schema()", body)
        self.assertLess(body.index("db.create_all()"), body.index("verify_schema()"))

    def test_verify_raises_rather_than_logging(self):
        body = _func("verify_schema")
        self.assertIn("raise RuntimeError", body,
                      "a missing table must stop the installation; logging it means "
                      "serving until somebody uses the one feature that needs it")
        self.assertIn("F1", body, "the failure should name the roadmap item it is about")

    def test_verify_is_schema_aware(self):
        """The analytics models live in their own Postgres schema.

        A flat `get_table_names()` lists only the default schema, so the first
        version of this check reported 25 perfectly healthy analytics tables as
        missing. A check that cries wolf on the development backend is a check
        people learn to ignore.
        """
        body = _func("verify_schema")
        self.assertIn("get_table_names(schema=", body,
                      "the check does not look inside non-default schemas")
        self.assertIn("schema_capable", body,
                      "sqlite has no schemas; checking schema-qualified tables there "
                      "reports healthy tables as missing")

    def test_stamp_still_happens_and_is_still_the_reason(self):
        """The stamp is what makes a missed table permanent.

        It is not removed — bootstrap really has just created the schema, so the
        migrations really are already reflected. The point is that the stamp
        makes create_all()'s coverage FINAL, which is why coverage has to be
        complete and verified before it runs.
        """
        body = _func("save_db")
        self.assertIn('revision="head"', body)


if __name__ == "__main__":
    unittest.main()
