"""Deleting a slip must release every reference to it, including the ones added
after the delete path was written.

The bug this guards against: `_delete_slip` used to name twelve tables by hand
while the schema had grown to thirty-seven referencing columns. Nine of the
missing ones had a NOT NULL slip_id — post votes, media votes, arcade progress
and attempts, DAO ballots, lab instances and solves, bot tokens, user profiles —
so deleting any account that had ever voted on a post raised a foreign-key
violation, the handler caught it, and the admin saw "Could not delete slip" with
no way to find out why.

A hand-written list is out of date the moment somebody adds a table, and nothing
tells them. So the delete path is derived from the metadata, and this test
asserts that derivation stays complete.
"""

import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import json  # noqa: E402
import subprocess  # noqa: E402

# `from shared import db` used to sit here, and it is the whole reason the four
# tests below passed alone and failed in the suite. It binds at IMPORT time --
# during pytest's collection -- so whichever of the 36 stub-installing modules
# sorted earlier had already put a MagicMock in sys.modules["shared"], and this
# module bound the MOCK's db by value. A MagicMock answers every attribute, so
# `db.metadata.sorted_tables` returned a mock instead of raising and the
# derivation below silently produced NOTHING.
#
# WORSE THAN FAILING: both sides of the comparison read the same poisoned db, so
# they could agree AT EMPTY -- a test asserting that nothing references slip.id
# and passing. Two attempts to repair this in-process made exactly that happen,
# because re-importing `shared` yields a FRESH SQLAlchemy instance whose
# metadata is empty (the model modules already in sys.modules stay bound to the
# object they were imported against).
#
# So the schema is derived in a SUBPROCESS. What these tests assert is a static
# property of the model definitions; it needs an interpreter nobody has stubbed,
# and asking for one is cheaper and far more honest than trying to unpick the
# pollution from inside it. The pollution itself is item 4.12.
_DERIVE = """
import json, sys
sys.path.insert(0, %r)
from services.model_registry import import_all_models
import_all_models()
from shared import db

# Derived here, independently of the implementation, by walking foreign keys.
out = []
for table in db.metadata.sorted_tables:
    for column in table.columns:
        for fk in column.foreign_keys:
            if fk.column.table.name == "slip" and fk.column.name == "id":
                out.append([table.name, column.name, bool(column.nullable)])

# And what the IMPLEMENTATION says, from the same clean interpreter. Both sides
# have to run here: comparing a clean derivation against a poisoned
# implementation is not a comparison, and letting the implementation run against
# a MagicMock is not a test of it either. In production it runs exactly like
# this -- one process, no stubs.
from blueprints.admin import _slip_references
impl = [[t.name, c.name, bool(c.nullable)] for t, c in _slip_references()]
# Sentinel-prefixed: importing the app emits log lines to STDOUT
# before this runs, so the output is not clean JSON and parsing
# the whole stream fails.
print("SLIPREFS:" + json.dumps({"derived": sorted(out), "impl": sorted(impl)}))
"""


def _schema_references():
    """(table, column, nullable) for every column pointing at slip.id."""
    result = subprocess.run(
        [sys.executable, "-c", _DERIVE % BACKEND],
        capture_output=True, text=True, cwd=BACKEND,
    )
    if result.returncode != 0:
        raise AssertionError(
            "could not derive the schema in a clean interpreter:\n%s"
            % (result.stderr.strip()[-2000:] or result.stdout.strip()[-2000:]))
    for line in result.stdout.splitlines():
        if line.startswith("SLIPREFS:"):
            payload = json.loads(line[len("SLIPREFS:"):])
            return ({k: [tuple(r) for r in v] for k, v in payload.items()})
    raise AssertionError(
        "the schema derivation printed no result:\n%s" % result.stdout[-2000:])


def _slip_references():
    """Imported lazily, INSIDE the call, and that is not stylistic.

    `blueprints.admin` pulls in a large part of the app, and 36 test modules in
    this suite install fake `model.*` / `shared` modules into sys.modules at
    import time and never remove them. pytest imports every test module during
    COLLECTION, so whichever of those sorts earlier had already replaced
    `model.Media` and friends with stubs that satisfy their own file and not
    blueprints/admin's imports. This module then failed to IMPORT, and a
    collection error is fatal to the entire run -- so roughly 1,700 unrelated
    passing tests never executed, over an error that named neither the stub nor
    the module that installed it.

    Deferring the import to call time moves it past collection, where the
    polluting modules have at least finished installing whatever they install.
    It unblocks the suite; it does not fix the pollution, which needs those 36
    modules to put sys.modules back when they are done.
    """
    return _both()["impl"]


_CACHE = {}


def _both():
    if not _CACHE:
        _CACHE.update(_schema_references())
    return _CACHE


def _referencing_columns():
    """Independently derived, so this test does not simply agree with itself."""
    return sorted((t, c) for t, c, _nullable in _both()["derived"])


class SlipReferenceCoverageTest(unittest.TestCase):
    def test_every_reference_to_slip_is_found(self):
        derived = sorted((t, c) for t, c, _nullable in _slip_references())
        self.assertEqual(derived, _referencing_columns())

    def test_the_tables_that_used_to_break_deletion_are_covered(self):
        # Named explicitly rather than left to the general check, because these
        # are the specific ones whose absence made the feature fail outright.
        covered = {t for t, _c, _nullable in _slip_references()}
        for table in (
            "post_vote", "media_vote", "codeplay_attempt", "codeplay_progress",
            "dao_vote", "lab_instance", "lab_solve", "bot_token", "user_profile",
        ):
            self.assertIn(table, covered, "%s would break slip deletion" % table)

    def test_nullable_and_not_null_references_are_distinguished(self):
        # The distinction IS the policy: a nullable reference is a record that
        # outlives the account (a ban somebody issued, a comment they left) and
        # must survive as anonymous, because deleting an account should not
        # rewrite a board's moderation history. A NOT NULL reference cannot
        # exist without the account and goes with it.
        by_name = {(t, c): nullable for t, c, nullable in _slip_references()}
        self.assertTrue(by_name[("ban", "created_by_slip_id")])
        self.assertTrue(by_name[("video_comment", "slip_id")])
        self.assertFalse(by_name[("post_vote", "slip_id")])
        self.assertFalse(by_name[("session", "slip_id")])

    def test_the_slip_table_itself_is_not_in_the_reference_list(self):
        # It is deleted last and explicitly; including it here would have the
        # loop try to null out or delete the row it is about to remove.
        self.assertNotIn("slip", {t for t, _c, _nullable in _slip_references()})


if __name__ == "__main__":
    unittest.main()
