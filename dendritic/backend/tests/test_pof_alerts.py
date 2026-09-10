"""Noticing that an epoch is waiting to be settled.

Epoch 0 sat a full day past its challenge window because nothing watched for it
and the page described the call without offering it. These tests are about the
two ways a notifier fails: staying silent when it should speak, and crying wolf
when the chain simply could not be read.
"""

import ast
import os
import pathlib
import sys
import threading
import time
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


PA = _load_pure(
    "services/pof_alerts.py",
    {"REFRESH_SECONDS", "_lock", "_cached", "_compute", "finalizable", "describe"},
    # `app` is only reached on the failure path, to log that the chain could
    # not be read. Stubbed rather than skipped, because that path is exactly
    # what one of these tests exercises.
    extra={"threading": threading, "time": time,
           "app": type("App", (), {"logger": type("Log", (), {
               "debug": staticmethod(lambda *a, **k: None),
               "exception": staticmethod(lambda *a, **k: None)})()})()},
)

NOW = 1_785_600_000


def epoch(number=0, finalized=False, disputes=0, deadline=NOW - 3600, rewards=0):
    return {"epoch": number, "finalized": finalized, "open_disputes": disputes,
            "challenge_deadline": deadline, "total_rewards": rewards}


def install(rows, manager="0xEPOCHMANAGER"):
    PA["_epoch_manager"] = lambda: manager
    PA["_chain"] = rows

    def chain(_manager, limit=25):
        if rows is None:
            raise OSError("rpc unreachable")
        return rows

    PA["_epoch_chain"] = chain
    # _compute imports these lazily; patch the import surface it reaches for.
    import types
    module = types.ModuleType("services.pof_chain")
    module.pof_addresses = lambda: {"EpochManager": manager}
    module.epoch_chain = chain
    sys.modules["services.pof_chain"] = module


class ComputeTest(unittest.TestCase):
    def setUp(self):
        PA["_cached"]["at"] = 0.0
        PA["_cached"]["alerts"] = []

    def test_a_closed_undisputed_epoch_is_reported(self):
        install([epoch(0, deadline=NOW - 86400)])
        alerts = PA["_compute"](NOW)
        self.assertEqual([a["epoch"] for a in alerts], [0])
        self.assertGreater(alerts[0]["overdue_seconds"], 0)

    def test_a_finalized_epoch_is_not(self):
        install([epoch(0, finalized=True)])
        self.assertEqual(PA["_compute"](NOW), [])

    def test_a_disputed_epoch_is_not(self):
        """It cannot finalize until every dispute resolves, so telling somebody
        to try would send them to spend gas on a reverting call."""
        install([epoch(0, disputes=1)])
        self.assertEqual(PA["_compute"](NOW), [])

    def test_an_epoch_still_inside_its_window_is_not(self):
        install([epoch(0, deadline=NOW + 3600)])
        self.assertEqual(PA["_compute"](NOW), [])

    def test_an_unreachable_chain_raises_no_alarm(self):
        """"We could not look" is not "nothing needs finalizing", but inventing
        an alarm from a failed read is worse than staying quiet."""
        install(None)
        self.assertEqual(PA["_compute"](NOW), [])

    def test_no_configured_manager_reports_nothing(self):
        install([epoch(0)], manager="")
        self.assertEqual(PA["_compute"](NOW), [])

    def test_whether_it_pays_anyone_is_carried(self):
        """So an operator is not sent to sign a transaction that pays nobody
        without being told first."""
        install([epoch(0, rewards=0), epoch(1, rewards=5000)])
        alerts = {a["epoch"]: a for a in PA["_compute"](NOW)}
        self.assertFalse(alerts[0]["pays_anyone"])
        self.assertTrue(alerts[1]["pays_anyone"])

    def test_malformed_rows_do_not_break_the_rest(self):
        install([{"epoch": "nonsense", "challenge_deadline": "soon"},
                 epoch(2, deadline=NOW - 60)])
        self.assertEqual([a["epoch"] for a in PA["_compute"](NOW)], [2])


class CacheTest(unittest.TestCase):
    """The bell polls. Reading an external RPC on every poll would put a
    network round trip inside a navbar render on every page."""

    def setUp(self):
        PA["_cached"]["at"] = 0.0
        PA["_cached"]["alerts"] = []

    def test_a_second_call_does_not_hit_the_chain(self):
        calls = []
        install([epoch(0)])
        original = sys.modules["services.pof_chain"].epoch_chain

        def counting(manager, limit=25):
            calls.append(1)
            return original(manager, limit)

        sys.modules["services.pof_chain"].epoch_chain = counting
        PA["finalizable"](now=NOW)
        PA["finalizable"](now=NOW + 10)
        self.assertEqual(len(calls), 1)

    def test_it_refreshes_once_the_window_passes(self):
        calls = []
        install([epoch(0)])
        original = sys.modules["services.pof_chain"].epoch_chain

        def counting(manager, limit=25):
            calls.append(1)
            return original(manager, limit)

        sys.modules["services.pof_chain"].epoch_chain = counting
        PA["finalizable"](now=NOW)
        PA["finalizable"](now=NOW + PA["REFRESH_SECONDS"] + 1)
        self.assertEqual(len(calls), 2)


class DescribeTest(unittest.TestCase):
    def test_it_says_when_nothing_would_be_paid(self):
        text = PA["describe"]({"epoch": 0, "overdue_seconds": 90000,
                               "pays_anyone": False})
        self.assertIn("pays nobody", text)
        self.assertIn("epoch 0", text.lower())

    def test_it_says_what_is_at_stake_when_there_is_something(self):
        text = PA["describe"]({"epoch": 3, "overdue_seconds": 7200,
                               "pays_anyone": True})
        self.assertIn("claimable", text)
        self.assertIn("2 hours", text)


if __name__ == "__main__":
    unittest.main()
