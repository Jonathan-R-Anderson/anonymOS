"""Throughput history, and the one distinction the graph must not blur.

A flat line at zero because the network was idle, and a flat line at zero
because nothing was measuring, are the same picture and completely different
facts. Every point therefore carries how many nodes it covers, and the chart
draws an unmeasured stretch grey rather than as a real zero.

The sampler is also guarded rather than scheduled. This project runs no reliable
cron, and a sampler that only fires on a timer stops silently when the timer
does — leaving a gap that looks exactly like a quiet network.
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


NOW = datetime.datetime(2026, 8, 2, 12, 0, 0)


class Column(object):
    """A stand-in for a SQLAlchemy column.

    The real code writes `NetworkTrafficSample.at >= since`, which on a real
    column builds a filter expression. The fakes here ignore filters, so the
    comparison only has to not raise.
    """

    def __ge__(self, other): return True
    def __lt__(self, other): return True
    def __gt__(self, other): return True
    def desc(self): return self
    def asc(self): return self


class SamplerTest(unittest.TestCase):
    """sample_traffic must not write more often than the interval."""

    def _build(self, latest_at, metrics):
        added, deleted, committed = [], [], []

        class Query(object):
            def __init__(self, model): self.model = model
            def order_by(self, *a): return self
            def filter(self, *a): return self
            def first(self): return (latest_at,) if latest_at else None
            def delete(self, **kw): deleted.append(True); return 0

        class Session(object):
            def query(self, *a): return Query(a[0] if a else None)
            def add(self, obj): added.append(obj)
            def commit(self): committed.append(True)

        ns = _load_pure(
            "services/status_board.py",
            {"sample_traffic", "_utcnow", "_network_metrics"},
            extra={"_datetime": datetime},
        )
        ns["_network_metrics"] = lambda: metrics

        status = types.ModuleType("model.Status")
        status.TRAFFIC_SAMPLE_SECONDS = 300
        status.TRAFFIC_RETENTION_DAYS = 14

        class NetworkTrafficSample(object):
            at = Column()
            def __init__(self, **kw):
                for k, v in kw.items(): setattr(self, k, v)
        status.NetworkTrafficSample = NetworkTrafficSample

        shared = types.ModuleType("shared")
        shared.db = types.SimpleNamespace(session=Session())
        _stub_scope.install(self, {"model.Status": status, "shared": shared})
        return ns["sample_traffic"], added, deleted

    METRICS = {"bytes_per_second": 12345.0, "requests_per_second": 3.5,
               "traffic_reporting_nodes": 4, "nodes": 6}

    def test_the_first_sample_is_written(self):
        sample, added, _ = self._build(None, self.METRICS)
        self.assertIsNotNone(sample(now=NOW))
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].bytes_per_second, 12345)
        self.assertEqual(added[0].reporting_nodes, 4)

    def test_a_second_call_inside_the_interval_writes_nothing(self):
        # Several monitors post within the same minute. Each must not produce a
        # point, or the series' spacing becomes "how many nodes are running".
        recent = NOW - datetime.timedelta(seconds=60)
        sample, added, _ = self._build(recent, self.METRICS)
        self.assertIsNone(sample(now=NOW))
        self.assertEqual(added, [])

    def test_a_call_after_the_interval_writes(self):
        old = NOW - datetime.timedelta(seconds=600)
        sample, added, _ = self._build(old, self.METRICS)
        self.assertIsNotNone(sample(now=NOW))
        self.assertEqual(len(added), 1)

    def test_a_clock_that_moved_backwards_does_not_insert_out_of_order(self):
        # A point written "before" the newest one is out of order in a series
        # whose entire meaning is its order.
        future = NOW + datetime.timedelta(hours=1)
        sample, added, _ = self._build(future, self.METRICS)
        self.assertIsNone(sample(now=NOW))
        self.assertEqual(added, [])

    def test_nothing_is_recorded_when_the_metrics_are_unreadable(self):
        # _network_metrics returns None values when the database is unhappy.
        # Storing that as zero would draw a real dip that never happened.
        sample, added, _ = self._build(None, {"bytes_per_second": None})
        self.assertIsNone(sample(now=NOW))
        self.assertEqual(added, [])

    def test_writing_a_sample_also_prunes(self):
        sample, _, deleted = self._build(None, self.METRICS)
        sample(now=NOW)
        self.assertTrue(deleted, "old samples must be pruned as new ones arrive")


class HistoryShapeTest(unittest.TestCase):
    """Every point must say whether it was measured."""

    def test_measured_is_false_when_no_node_reported(self):
        rows = [
            types.SimpleNamespace(at=NOW, bytes_per_second=0,
                                  requests_per_second=0.0, reporting_nodes=0),
            types.SimpleNamespace(at=NOW, bytes_per_second=500,
                                  requests_per_second=1.0, reporting_nodes=3),
        ]

        class Query(object):
            def filter(self, *a): return self
            def order_by(self, *a): return self
            def limit(self, n): return self
            def all(self): return rows

        ns = _load_pure("services/status_board.py",
                        {"traffic_history", "_utcnow"},
                        extra={"_datetime": datetime})
        status = types.ModuleType("model.Status")
        status.NetworkTrafficSample = types.SimpleNamespace(at=Column())
        shared = types.ModuleType("shared")
        shared.db = types.SimpleNamespace(
            session=types.SimpleNamespace(query=lambda *a: Query()))
        _stub_scope.install(self, {"model.Status": status, "shared": shared})

        got = ns["traffic_history"](now=NOW)
        self.assertFalse(got[0]["measured"], "0 reporting nodes is NOT a measured zero")
        self.assertTrue(got[1]["measured"])


if __name__ == "__main__":
    unittest.main()
