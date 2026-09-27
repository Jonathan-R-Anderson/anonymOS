"""Effort weighting: what a box actually says about the person who solved it.

A solve on its own says somebody got there, not how. These pin the properties
the weighting has to have — not the exact constants, which are judgements and
are allowed to move.
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


SKILLS = _load_pure(
    "services/lab_skills.py",
    {"FAILURE_COST", "FLOOR", "SLOW_AFTER_MINUTES", "SLOW_FLOOR",
     "effort_weight", "parse_skills"},
)


class EffortWeightTest(unittest.TestCase):
    def test_a_clean_fast_solve_is_the_ceiling(self):
        # Nothing may score above a clean solve, or speed becomes farmable.
        best = SKILLS["effort_weight"](0, 0)
        self.assertEqual(best, 1.0)
        for failed in range(0, 40):
            for minutes in (0, 5, 60, 600, 10_000):
                self.assertLessEqual(SKILLS["effort_weight"](failed, minutes), 1.0)

    def test_failures_reduce_the_weight(self):
        self.assertLess(SKILLS["effort_weight"](5, 0), SKILLS["effort_weight"](0, 0))
        self.assertLess(SKILLS["effort_weight"](20, 0), SKILLS["effort_weight"](5, 0))

    def test_a_messy_solve_still_counts_for_something(self):
        # Somebody who ground through a box over three days learned it. A scheme
        # that scored them near zero would be measuring confidence.
        self.assertGreater(SKILLS["effort_weight"](500, 100_000), 0.3)

    def test_the_penalty_stops_falling_rather_than_hitting_zero(self):
        # No cliff: falling off at N attempts would make the chart a record of
        # one bad evening.
        a = SKILLS["effort_weight"](100, 0)
        b = SKILLS["effort_weight"](1000, 0)
        self.assertEqual(a, b)
        self.assertGreaterEqual(a, SKILLS["FLOOR"])

    def test_time_is_weighted_more_gently_than_attempts(self):
        # People eat, sleep, and leave boxes running. Attempts are the stronger
        # signal, and the scheme has to say so.
        many_attempts = 1.0 - SKILLS["effort_weight"](25, 0)
        very_slow = 1.0 - SKILLS["effort_weight"](0, 100_000)
        self.assertGreater(many_attempts, very_slow)

    def test_extra_time_stops_counting_after_the_cap(self):
        a = SKILLS["effort_weight"](0, SKILLS["SLOW_AFTER_MINUTES"])
        b = SKILLS["effort_weight"](0, SKILLS["SLOW_AFTER_MINUTES"] * 50)
        self.assertEqual(a, b)

    def test_the_two_signals_combine(self):
        # Thirty attempts in ten minutes is a script; ten minutes and one
        # attempt is somebody who knew the box. They must not score the same.
        script = SKILLS["effort_weight"](30, 10)
        knew_it = SKILLS["effort_weight"](0, 10)
        self.assertLess(script, knew_it)

    def test_missing_values_do_not_crash_or_punish(self):
        self.assertEqual(SKILLS["effort_weight"](None, None), 1.0)
        self.assertEqual(SKILLS["effort_weight"](-5, -5), 1.0)


class ParseSkillsTest(unittest.TestCase):
    def test_a_comma_list_becomes_axis_keys(self):
        self.assertEqual(SKILLS["parse_skills"]("web, Exploitation ,crypto"),
                         ["web", "exploitation", "crypto"])

    def test_an_unlabelled_box_contributes_to_nothing(self):
        # The honest default: guessing a box's skills from its Dockerfile would
        # put confident wrong labels on hundreds of imported challenges.
        self.assertEqual(SKILLS["parse_skills"](""), [])
        self.assertEqual(SKILLS["parse_skills"](None), [])
        self.assertEqual(SKILLS["parse_skills"](" , , "), [])


if __name__ == "__main__":
    unittest.main()
