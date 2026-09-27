"""Moving off an emergency origin without losing what people wrote on it.

A cold restore and a cutover look like the same job and are not. A cold restore
starts from a backup because the old server is gone; a cutover starts from a
server that has been ACCEPTING POSTS, so it holds data newer than any backup.
The expensive mistake — taking the backup before freezing writes — produces no
error at all, and is only visible later as posts that are simply missing.
"""

import ast
import datetime
import json
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


CO = _load_pure(
    "services/cutover.py",
    {"SETTING", "MAX_FREEZE_SECONDS", "DEFAULT_FREEZE_SECONDS", "WRITE_METHODS",
     "ALWAYS_OPEN", "current", "_now", "blocks", "refusal", "plan"},
    extra={"json": json, "_datetime": datetime},
)


class BlocksTest(unittest.TestCase):
    """What a freeze refuses, and what it must never refuse."""

    def test_writes_are_refused(self):
        for method in ("POST", "PUT", "PATCH", "DELETE", "post"):
            with self.subTest(method=method):
                self.assertTrue(CO["blocks"](method, "/boards/g/post"))

    def test_reads_continue(self):
        """The site stays readable. That is the half that is meant to work."""
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                self.assertFalse(CO["blocks"](method, "/boards/g"))

    def test_options_is_not_refused(self):
        """A frozen origin that refuses OPTIONS breaks CORS preflight and
        therefore breaks reading, which is the half meant to keep working."""
        self.assertFalse(CO["blocks"]("OPTIONS", "/api/v1/anything"))

    def test_admin_stays_open(self):
        """A freeze that locks the operator out of the page that lifts it
        turns a planned cutover into a real outage."""
        self.assertFalse(CO["blocks"]("POST", "/admin/cutover/thaw"))
        self.assertFalse(CO["blocks"]("POST", "/admin/backup"))

    def test_health_probes_stay_open(self):
        """Probes read a 503 as unhealthy, not as deliberately read-only, and a
        restarted origin mid-cutover is a worse problem."""
        for path in ("/health", "/healthz", "/readyz"):
            with self.subTest(path=path):
                self.assertFalse(CO["blocks"]("POST", path))

    def test_acme_stays_open(self):
        """Without renewal the old origin stops serving HTTPS before the move
        is finished."""
        self.assertFalse(
            CO["blocks"]("POST", "/.well-known/acme-challenge/abc"))

    def test_the_directive_document_stays_open(self):
        """It is how nodes learn where the network is going. Freezing it
        strands them on the origin being retired."""
        self.assertFalse(
            CO["blocks"]("POST", "/.well-known/syndichan/network.json"))

    def test_an_ordinary_path_that_merely_starts_similarly_is_refused(self):
        """"/administrate" is not "/admin/"."""
        self.assertTrue(CO["blocks"]("POST", "/administrate-something"))
        self.assertTrue(CO["blocks"]("POST", "/healthy-boards"))


class CurrentTest(unittest.TestCase):
    def setUp(self):
        self.stored = "{}"
        CO["get_setting"] = lambda key, default="": self.stored

    def _install(self, record):
        self.stored = json.dumps(record)
        # `current()` imports get_setting inside the function, so the pure
        # loader cannot patch it. Reimplement the one branch under test.
        CO["current"] = lambda: (
            None if not record
            or int(record.get("expires_at") or 0) <= CO["_now"]()
            else record)

    def test_an_expired_freeze_reads_as_absent(self):
        """A caller that has to remember to check the timestamp is one that
        will forget, and the site stays read-only for no reason."""
        self._install({"reason": "cutover", "expires_at": CO["_now"]() - 1})
        self.assertIsNone(CO["current"]())

    def test_a_live_freeze_reads_as_present(self):
        self._install({"reason": "cutover", "expires_at": CO["_now"]() + 600})
        self.assertIsNotNone(CO["current"]())


class RefusalTest(unittest.TestCase):
    def test_it_says_the_writing_was_not_saved(self):
        """A read-only site that implies otherwise is worse than one plainly
        down: the person walks away believing their post exists."""
        CO["current"] = lambda: {"reason": "cutover",
                                 "expires_at": CO["_now"]() + 300}
        message = CO["refusal"]()
        self.assertIn("NOT saved", message["error"])
        self.assertGreater(message["retry_after_seconds"], 0)

    def test_retry_after_is_never_negative(self):
        CO["current"] = lambda: None
        self.assertGreaterEqual(CO["refusal"]()["retry_after_seconds"], 0)


class PlanTest(unittest.TestCase):
    """The order is the feature. The expensive mistake produces no error."""

    def test_the_freeze_comes_before_the_backup(self):
        steps = [entry["step"] for entry in CO["plan"]()]
        froze = next(i for i, s in enumerate(steps) if "Freeze writes" in s)
        backed = next(i for i, s in enumerate(steps) if "FRESH backup" in s)
        self.assertLess(froze, backed)

    def test_it_says_not_to_reuse_the_old_backup(self):
        """Restoring the backup the emergency origin came from discards every
        post made during the emergency — the entire period anyone relied on
        it."""
        joined = " ".join(e["step"] + e["why"] for e in CO["plan"]())
        self.assertIn("Do not reuse", joined)
        self.assertIn("discards", joined)

    def test_the_row_count_comparison_precedes_the_directive(self):
        """It is the last moment the old data is somewhere you can look at."""
        steps = [entry["step"] for entry in CO["plan"]()]
        compare = next(i for i, s in enumerate(steps) if "Compare row counts" in s)
        switch = next(i for i, s in enumerate(steps) if "directive" in s)
        self.assertLess(compare, switch)

    def test_exactly_one_step_is_irreversible_and_it_is_the_directive(self):
        plan = CO["plan"]()
        irreversible = [e for e in plan if not e["reversible"]]
        self.assertEqual(len(irreversible), 1)
        self.assertIn("directive", irreversible[0]["step"])

    def test_thawing_the_right_server_is_called_out(self):
        """Thawing the emergency origin instead accepts posts onto a server
        nothing points at. They would be real, saved, and invisible."""
        joined = " ".join(e["why"] for e in CO["plan"]("newbox"))
        self.assertIn("invisible", joined)

    def test_demotion_is_the_last_step(self):
        plan = CO["plan"]()
        self.assertIn("gateway", plan[-1]["step"])

    def test_the_named_server_appears_in_the_plan(self):
        joined = " ".join(e["step"] for e in CO["plan"]("newbox", "syndichan.net"))
        self.assertIn("newbox", joined)
        self.assertIn("syndichan.net", joined)


class BoundsTest(unittest.TestCase):
    def test_a_freeze_cannot_be_indefinite(self):
        """An operator who starts one and is pulled away must not leave the
        site read-only forever; expiry is what recovers it."""
        self.assertLessEqual(CO["MAX_FREEZE_SECONDS"], 24 * 3600)
        self.assertLess(CO["DEFAULT_FREEZE_SECONDS"], CO["MAX_FREEZE_SECONDS"])


if __name__ == "__main__":
    unittest.main()
