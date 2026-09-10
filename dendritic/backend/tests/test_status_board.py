"""The status board, tested where it could flatter itself.

A status page is worth serving only if it is believed, and every bug that makes
one MORE optimistic is worse than the outage it hides. So these tests are almost
entirely about the page refusing to claim things:

  * a day nobody probed is grey, not green, and is excluded from the average;
  * overall status is the worst component, never the mean;
  * a timeout does not count as a slow-but-successful response;
  * an operator's open incident overrides green probes.

The one in the other direction matters too: a component failing for one monitor
out of five is degraded, not down, because calling it down would be as wrong as
calling it up.
"""

import ast
import datetime
import os
import pathlib
import sys
import types
import unittest

from tests import _stub_scope

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
    """Exec just the named definitions, without importing the module."""
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


SB = _load_pure(
    "services/status_board.py",
    {"OUTAGE_FAILURE_RATIO", "CURRENT_WINDOW_MINUTES", "OPERATIONAL", "DEGRADED",
     "OUTAGE", "UNKNOWN", "SEVERITY", "_state_from", "uptime_over", "overall_state"},
    extra={"_datetime": datetime},
)


class StateTest(unittest.TestCase):
    def test_no_probes_is_unknown_not_operational(self):
        # The rule the whole page rests on. Reporting "up" for a day nobody
        # measured makes the headline number best exactly when monitoring is
        # most broken.
        self.assertEqual(SB["_state_from"](0, 0), SB["UNKNOWN"])

    def test_all_probes_passing_is_operational(self):
        self.assertEqual(SB["_state_from"](10, 0), SB["OPERATIONAL"])

    def test_a_minority_of_failures_is_degraded_not_down(self):
        # One monitor out of five failing is a fact about that monitor's path as
        # often as about the service. Calling it an outage is as wrong as
        # calling it fine.
        self.assertEqual(SB["_state_from"](5, 1), SB["DEGRADED"])

    def test_a_majority_of_failures_is_an_outage(self):
        self.assertEqual(SB["_state_from"](5, 4), SB["OUTAGE"])

    def test_the_boundary_counts_as_an_outage(self):
        # Exactly half failing is not "mostly working".
        self.assertEqual(SB["_state_from"](4, 2), SB["OUTAGE"])

    def test_a_single_failing_probe_is_an_outage(self):
        # With one monitor there is no minority to be in.
        self.assertEqual(SB["_state_from"](1, 1), SB["OUTAGE"])


class UptimeTest(unittest.TestCase):
    def test_unmeasured_days_are_excluded_not_counted_as_perfect(self):
        bars = [{"uptime": 1.0}, {"uptime": None}, {"uptime": 0.5}]
        self.assertAlmostEqual(SB["uptime_over"](bars), 0.75)

    def test_all_days_unmeasured_is_none_not_zero(self):
        # Zero would render as "0.00% uptime", which reads as a total outage
        # rather than as an absence of monitoring.
        self.assertIsNone(SB["uptime_over"]([{"uptime": None}, {"uptime": None}]))

    def test_no_days_at_all_is_none(self):
        self.assertIsNone(SB["uptime_over"]([]))


class OverallTest(unittest.TestCase):
    def test_the_banner_takes_the_worst_component_not_the_average(self):
        # Averaging produces "94% operational" while the thing somebody came to
        # use is down.
        states = [SB["OPERATIONAL"]] * 9 + [SB["OUTAGE"]]
        self.assertEqual(SB["overall_state"](states), SB["OUTAGE"])

    def test_degraded_beats_operational(self):
        self.assertEqual(
            SB["overall_state"]([SB["OPERATIONAL"], SB["DEGRADED"]]), SB["DEGRADED"])

    def test_unknown_alone_stays_unknown(self):
        self.assertEqual(SB["overall_state"]([SB["UNKNOWN"]]), SB["UNKNOWN"])

    def test_unknown_never_outranks_a_real_measurement(self):
        # A component nobody probes must not drag a measured outage down to
        # "unknown", nor lift it.
        self.assertEqual(
            SB["overall_state"]([SB["UNKNOWN"], SB["OUTAGE"]]), SB["OUTAGE"])
        self.assertEqual(
            SB["overall_state"]([SB["UNKNOWN"], SB["OPERATIONAL"]]), SB["OPERATIONAL"])

    def test_nothing_at_all_is_unknown(self):
        self.assertEqual(SB["overall_state"]([]), SB["UNKNOWN"])


class RecordProbeTest(unittest.TestCase):
    """The rollup arithmetic, which decides what every bar shows."""

    def _harness(self):
        rows = {}
        added = []

        class Query(object):
            def __init__(self, key): self.key = key
            def filter(self, *a): return self
            def one_or_none(self): return rows.get("day")

        class Session(object):
            def add(self, obj): added.append(obj)
            def query(self, model): return Query(model)

        class StatusDay(object):
            # Class attributes so the real code's filter expression
            # (StatusDay.component_key == key) resolves against the stub.
            component_key = None
            day = None

            def __init__(self, **kw):
                for k, v in kw.items(): setattr(self, k, v)
                rows["day"] = self

        class StatusProbe(object):
            def __init__(self, **kw):
                for k, v in kw.items(): setattr(self, k, v)

        ns = _load_pure(
            "services/status_board.py", {"record_probe", "_utcnow"},
            extra={"_datetime": datetime},
        )
        module = types.ModuleType("model.Status")
        module.StatusDay = StatusDay
        module.StatusProbe = StatusProbe
        shared = types.ModuleType("shared")
        shared.db = types.SimpleNamespace(session=Session())
        _stub_scope.install(self, {"model.Status": module, "shared": shared})
        return ns["record_probe"], rows, added

    def test_a_success_counts_a_probe_and_its_latency(self):
        record, rows, _ = self._harness()
        row = record("website", "node-1", True, latency_ms=120)
        self.assertEqual(row.probes, 1)
        self.assertEqual(row.failures, 0)
        self.assertEqual(row.latency_count, 1)
        self.assertEqual(row.latency_sum_ms, 120)

    def test_a_failure_counts_but_contributes_no_latency(self):
        # A timeout produces a latency equal to the timeout. Averaging that in
        # renders an outage as a slowdown, and the two must stay distinct.
        record, rows, _ = self._harness()
        row = record("website", "node-1", False, latency_ms=8000, detail="timeout")
        self.assertEqual(row.probes, 1)
        self.assertEqual(row.failures, 1)
        self.assertEqual(row.latency_count, 0)
        self.assertEqual(row.latency_sum_ms, 0)

    def test_probes_accumulate_into_one_day(self):
        record, rows, _ = self._harness()
        record("website", "node-1", True, latency_ms=100)
        record("website", "node-2", True, latency_ms=300)
        row = record("website", "node-3", False)
        self.assertEqual(row.probes, 3)
        self.assertEqual(row.failures, 1)
        self.assertEqual(row.latency_sum_ms // row.latency_count, 200)
        self.assertEqual(row.worst_latency_ms, 300)

    def test_a_negative_latency_is_clamped_rather_than_stored(self):
        # A monitor with a skewed clock should not be able to drag a mean below
        # zero and make the page claim impossible speed.
        record, rows, _ = self._harness()
        row = record("website", "node-1", True, latency_ms=-5)
        self.assertEqual(row.latency_sum_ms, 0)

    def test_an_unparseable_latency_does_not_lose_the_probe(self):
        record, rows, _ = self._harness()
        row = record("website", "node-1", True, latency_ms="soon")
        self.assertEqual(row.probes, 1)
        self.assertEqual(row.latency_count, 0)


if __name__ == "__main__":
    unittest.main()
