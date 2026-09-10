"""Traffic a node claims to have moved, and why it is bounded rather than trusted.

The figure is published as NETWORK throughput on a public page, and it is
self-reported by volunteers. Neither of those is negotiable — this server never
sees peer-to-peer shard transfers, so anything it measured itself would describe
the website and call it the network — which makes the bounds the whole defence.

Without them one node decides what the entire network appears to be doing.

The window matters as much as the volume. A node choosing its own divisor can
turn a single request into any rate it likes by claiming a short enough window,
so windows below a few seconds are refused outright.
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


SC = _load_pure(
    "services/storage_coordination.py",
    {"MAX_TRAFFIC_BYTES", "MAX_TRAFFIC_REQUESTS", "MIN_TRAFFIC_WINDOW_SECONDS",
     "MAX_TRAFFIC_WINDOW_SECONDS", "_validate_traffic"},
)
SN = _load_pure("model/StorageNode.py", {"human_rate"})


class ValidateTrafficTest(unittest.TestCase):
    def check(self, block):
        return SC["_validate_traffic"](block)

    def test_a_missing_block_is_zero_not_a_rejection(self):
        # Older clients have never heard of this field. Refusing the heartbeat
        # would take a working node off the map over a field it cannot send.
        self.assertEqual(self.check(None),
                         {"bytes": 0, "requests": 0, "window_seconds": 0})

    def test_a_normal_report_passes_through(self):
        got = self.check({"bytes": 1024, "requests": 8, "window_seconds": 60})
        self.assertEqual(got, {"bytes": 1024, "requests": 8, "window_seconds": 60})

    def test_a_zero_window_reports_nothing_rather_than_infinity(self):
        # Dividing by it is both a crash and a claim of infinite throughput.
        self.assertEqual(self.check({"bytes": 999, "requests": 9, "window_seconds": 0}),
                         {"bytes": 0, "requests": 0, "window_seconds": 0})

    def test_an_implausibly_short_window_is_refused(self):
        # One request in a claimed 1-second window is a very different number
        # from the same request over a minute, and the node picks the divisor.
        with self.assertRaises(ValueError):
            self.check({"bytes": 1, "requests": 1, "window_seconds": 1})

    def test_an_enormous_volume_is_clamped_not_believed(self):
        got = self.check({"bytes": 10 ** 24, "requests": 5, "window_seconds": 60})
        self.assertEqual(got["bytes"], SC["MAX_TRAFFIC_BYTES"])

    def test_an_enormous_request_count_is_clamped(self):
        got = self.check({"bytes": 10, "requests": 10 ** 15, "window_seconds": 60})
        self.assertEqual(got["requests"], SC["MAX_TRAFFIC_REQUESTS"])

    def test_a_long_window_is_clamped_rather_than_refused(self):
        got = self.check({"bytes": 10, "requests": 1, "window_seconds": 10 ** 9})
        self.assertEqual(got["window_seconds"], SC["MAX_TRAFFIC_WINDOW_SECONDS"])

    def test_negative_values_are_refused(self):
        # A negative byte count would subtract from the network total, letting
        # one node hide another's traffic.
        for field in ("bytes", "requests", "window_seconds"):
            block = {"bytes": 1, "requests": 1, "window_seconds": 60}
            block[field] = -1
            with self.assertRaises(ValueError, msg=field):
                self.check(block)

    def test_booleans_are_not_numbers(self):
        # bool is an int in Python, so True would otherwise pass as 1.
        with self.assertRaises(ValueError):
            self.check({"bytes": True, "requests": 1, "window_seconds": 60})

    def test_a_non_object_block_is_refused(self):
        with self.assertRaises(ValueError):
            self.check([1, 2, 3])

    def test_missing_fields_default_to_zero(self):
        got = self.check({"window_seconds": 60})
        self.assertEqual(got, {"bytes": 0, "requests": 0, "window_seconds": 60})


class HumanRateTest(unittest.TestCase):
    def test_bytes_per_second_are_shown_as_bits(self):
        # Network speed is quoted in bits everywhere else; showing bytes would
        # make the network look eight times slower than it is.
        self.assertEqual(SN["human_rate"](125), "1.0 kbit/s")

    def test_zero_is_zero_not_blank(self):
        self.assertEqual(SN["human_rate"](0), "0.0 bit/s")

    def test_none_does_not_crash_the_page(self):
        self.assertEqual(SN["human_rate"](None), "0.0 bit/s")

    def test_it_scales_up(self):
        self.assertEqual(SN["human_rate"](125_000_000), "1.0 Gbit/s")


if __name__ == "__main__":
    unittest.main()
