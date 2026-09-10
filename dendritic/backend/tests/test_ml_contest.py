"""Competition scoring, and the split that makes a leaderboard mean anything.

The metrics have to be right because somebody's ranking depends on them, but the
load-bearing test here is the public/private split: without it, unlimited
submissions against a visible score turn the leaderboard into a gradient, and
the winner is whoever submitted most.
"""

import ast
import math
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


MODEL = _load_pure(
    "model/MlContest.py",
    {"PRIVATE_FRACTION", "METRICS", "METRIC_KEYS", "DATASET_MAX_BYTES",
     "lower_is_better", "metric_label", "is_private_row", "read_csv"},
    extra={"hashlib": __import__("hashlib"), "csv": __import__("csv"),
           "io": __import__("io")},
)

SERVICE = _load_pure(
    "services/ml_contest.py",
    {"ContestError", "score_pairs", "_as_float"},
    extra={"math": math},
)


class SplitTest(unittest.TestCase):
    """The mechanism that stops a leaderboard being a gradient to climb."""

    def test_the_split_is_stable_for_the_same_id(self):
        # A shuffle would re-roll which rows are public every time anything
        # touched the competition, and a leaderboard that silently changes
        # meaning is worse than no leaderboard.
        first = MODEL["is_private_row"]("row-42", "comp")
        for _ in range(20):
            self.assertEqual(MODEL["is_private_row"]("row-42", "comp"), first)

    def test_different_competitions_split_differently(self):
        # Otherwise a person who worked out the split on one competition knows
        # it for every competition on the site.
        a = [MODEL["is_private_row"](str(i), "comp-a") for i in range(200)]
        b = [MODEL["is_private_row"](str(i), "comp-b") for i in range(200)]
        self.assertNotEqual(a, b)

    def test_roughly_the_intended_fraction_is_held_back(self):
        held = sum(1 for i in range(4000) if MODEL["is_private_row"]("id-%d" % i, "c"))
        share = held / 4000.0
        self.assertAlmostEqual(share, MODEL["PRIVATE_FRACTION"], delta=0.05)

    def test_both_halves_are_non_empty_on_a_realistic_key(self):
        # An all-public split would mean no private score at all; an all-private
        # one would mean a blank live leaderboard.
        flags = [MODEL["is_private_row"]("id-%d" % i, "c") for i in range(100)]
        self.assertTrue(any(flags))
        self.assertFalse(all(flags))


class MetricTest(unittest.TestCase):
    def test_accuracy_counts_exact_label_matches(self):
        pairs = [("a", "a"), ("b", "b"), ("c", "x")]
        self.assertAlmostEqual(SERVICE["score_pairs"]("accuracy", pairs), 2 / 3.0)

    def test_accuracy_ignores_case_and_padding(self):
        # A scoreboard that disagrees with "Yes" vs "yes " is measuring typing.
        pairs = [("Yes", "yes "), ("NO", " no")]
        self.assertEqual(SERVICE["score_pairs"]("accuracy", pairs), 1.0)

    def test_rmse_and_mae_agree_when_every_error_is_equal(self):
        pairs = [("1", "2"), ("3", "4"), ("10", "11")]
        self.assertAlmostEqual(SERVICE["score_pairs"]("rmse", pairs), 1.0)
        self.assertAlmostEqual(SERVICE["score_pairs"]("mae", pairs), 1.0)

    def test_rmse_punishes_one_large_error_more_than_mae(self):
        pairs = [("0", "0"), ("0", "0"), ("0", "9")]
        self.assertGreater(SERVICE["score_pairs"]("rmse", pairs),
                           SERVICE["score_pairs"]("mae", pairs))

    def test_a_perfect_prediction_scores_zero_error(self):
        pairs = [("1.5", "1.5"), ("2", "2")]
        self.assertEqual(SERVICE["score_pairs"]("rmse", pairs), 0.0)
        self.assertEqual(SERVICE["score_pairs"]("mae", pairs), 0.0)

    def test_logloss_is_clipped_rather_than_infinite(self):
        # A confident wrong prediction of exactly 0 would otherwise be infinite
        # loss, and one row would decide the whole competition.
        score = SERVICE["score_pairs"]("logloss", [("1", "0")])
        self.assertTrue(math.isfinite(score))
        self.assertGreater(score, 10)

    def test_logloss_rewards_being_right_and_confident(self):
        confident = SERVICE["score_pairs"]("logloss", [("1", "0.99")])
        hedged = SERVICE["score_pairs"]("logloss", [("1", "0.55")])
        self.assertLess(confident, hedged)

    def test_an_empty_split_scores_zero_rather_than_dividing_by_zero(self):
        # Possible on a tiny key. A competition should not crash because
        # somebody uploaded eleven rows.
        for metric in ("accuracy", "rmse", "mae", "logloss"):
            self.assertEqual(SERVICE["score_pairs"](metric, []), 0.0)

    def test_text_where_a_number_is_required_is_a_readable_error(self):
        with self.assertRaises(SERVICE["ContestError"]):
            SERVICE["score_pairs"]("rmse", [("1", "banana")])

    def test_an_unknown_metric_is_refused(self):
        with self.assertRaises(SERVICE["ContestError"]):
            SERVICE["score_pairs"]("vibes", [("1", "1")])


class DirectionTest(unittest.TestCase):
    def test_error_metrics_rank_upward_and_accuracy_downward(self):
        # Getting this backwards puts the worst model at the top of the board.
        self.assertTrue(MODEL["lower_is_better"]("rmse"))
        self.assertTrue(MODEL["lower_is_better"]("mae"))
        self.assertTrue(MODEL["lower_is_better"]("logloss"))
        self.assertFalse(MODEL["lower_is_better"]("accuracy"))

    def test_every_declared_metric_is_scoreable(self):
        for key in MODEL["METRIC_KEYS"]:
            self.assertIsInstance(SERVICE["score_pairs"](key, [("1", "1")]), float)


class CsvTest(unittest.TestCase):
    def test_a_plain_file_parses(self):
        headers, rows = MODEL["read_csv"](b"id,target\n1,a\n2,b\n")
        self.assertEqual(headers, ["id", "target"])
        self.assertEqual(len(rows), 2)

    def test_a_byte_order_mark_does_not_break_the_header(self):
        # Spreadsheet exports carry one constantly, and rejecting somebody's
        # data over an invisible byte helps nobody.
        headers, _rows = MODEL["read_csv"]("﻿id,target\n1,a\n".encode("utf-8"))
        self.assertEqual(headers[0], "id")

    def test_trailing_blank_lines_are_not_rows(self):
        _headers, rows = MODEL["read_csv"](b"id,target\n1,a\n\n\n")
        self.assertEqual(len(rows), 1)

    def test_a_header_with_no_data_is_refused(self):
        with self.assertRaises(ValueError):
            MODEL["read_csv"](b"id,target\n")

    def test_an_empty_file_is_refused(self):
        with self.assertRaises(ValueError):
            MODEL["read_csv"](b"")


if __name__ == "__main__":
    unittest.main()
