"""The Solidity course's exercises.

An exercise has two ways to be broken and both are invisible in review:

  * a validator that its own solution does not satisfy makes the lesson
    IMPOSSIBLE — the learner writes exactly the right answer and is told no;
  * a validator set the STARTER already satisfies makes the lesson pointless —
    the tick is green before anybody types anything.

Both are checked here against every lesson, because the alternative is finding
out from somebody who gave up.
"""

import ast
import os
import pathlib
import re
import sys
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _load(relative_path, name):
    namespace = {}
    source = (BACKEND / relative_path).read_text()
    exec(compile(source, relative_path, "exec"), namespace)
    return namespace[name]


BOOK = _load("services/school_solidity.py", "BOOK")
CSA = _load("services/school_csa.py", "BOOK")
PYTHON = _load("services/school_python.py", "BOOK")
WEB = _load("services/school_webdesign.py", "BOOK")
INTRO = _load("services/school_introprog.py", "BOOK")

# Every course that carries exercises, not just this one. A guard that covers a
# single book lets the next course ship with an impossible lesson in it.
BOOKS_WITH_EXERCISES = [BOOK, CSA, PYTHON, WEB, INTRO]


def lessons():
    for book in BOOKS_WITH_EXERCISES:
        for part in book["parts"]:
            for chapter in part["chapters"]:
                if chapter.get("task"):
                    yield chapter


class ExerciseTest(unittest.TestCase):
    def test_every_exercise_is_complete(self):
        # lessons() already filters to chapters that HAVE a task, so this checks
        # that a chapter offering an exercise offers all of it — a task with no
        # solution is a dead end.
        found = list(lessons())
        self.assertGreater(len(found), 20, "exercise discovery is finding nothing")
        for chapter in found:
            for field in ("task", "starter", "solution", "validators"):
                self.assertTrue(chapter.get(field), "%s lacks %s" % (chapter["slug"], field))

    def test_every_validator_accepts_its_own_solution(self):
        # The one that makes a lesson impossible.
        for chapter in lessons():
            for rule in chapter["validators"]:
                self.assertRegex(
                    chapter["solution"], rule["pattern"],
                    "%s: the published solution fails its own check (%s)"
                    % (chapter["slug"], rule["pattern"]))

    def test_the_starter_does_not_already_pass(self):
        # The one that makes a lesson pointless.
        for chapter in lessons():
            passes = all(re.search(rule["pattern"], chapter["starter"])
                         for rule in chapter["validators"])
            self.assertFalse(passes,
                             "%s: the starter code already satisfies every check"
                             % chapter["slug"])

    def test_every_hint_says_what_to_do(self):
        # A hint that only repeats the rule leaves a stuck learner stuck.
        for chapter in lessons():
            for rule in chapter["validators"]:
                self.assertGreater(len(rule.get("hint", "")), 15, chapter["slug"])

    def test_patterns_compile(self):
        for chapter in lessons():
            for rule in chapter["validators"]:
                re.compile(rule["pattern"])

    def test_patterns_use_only_syntax_javascript_shares(self):
        # These are authored in Python and run in the BROWSER. Python-only
        # constructs compile here and throw there, where the failure is a
        # silently skipped check rather than an error anybody sees.
        forbidden = ("(?P<", "(?P=", r"\A", r"\Z", "(?#", r"\Z")
        for chapter in lessons():
            for rule in chapter["validators"]:
                for token in forbidden:
                    self.assertNotIn(token, rule["pattern"], chapter["slug"])


class CurriculumTest(unittest.TestCase):
    def _solidity_lessons(self):
        return [c for p in BOOK["parts"] for c in p["chapters"] if c.get("task")]

    def test_solutions_are_modern_solidity(self):
        # The course deliberately targets 0.8, where arithmetic reverts on
        # overflow. A SafeMath import would be teaching history as practice.
        for chapter in self._solidity_lessons():
            self.assertNotIn("SafeMath", chapter["solution"], chapter["slug"])

    def test_solutions_never_use_transfer_to_send_ether(self):
        # zksolc refuses it outright, and this site deploys to Ethereum — a course
        # here should not teach a pattern its own chain rejects.
        for chapter in self._solidity_lessons():
            self.assertNotIn(".transfer(", chapter["solution"], chapter["slug"])

    def test_the_provenance_is_stated(self):
        # This course exists because the original lessons could not be reused.
        # If that note ever disappears, so does the reason.
        self.assertIn("reference", BOOK)
        self.assertTrue(BOOK.get("provenance"))

    def test_slugs_are_unique_and_url_safe(self):
        slugs = [chapter["slug"] for chapter in lessons()]
        self.assertEqual(len(slugs), len(set(slugs)))
        for slug in slugs:
            self.assertRegex(slug, r"^[a-z0-9-]+$")


if __name__ == "__main__":
    unittest.main()
