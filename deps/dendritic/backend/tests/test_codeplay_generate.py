"""Validation of generated content, and the personalised daily.

A model produces text that looks right. These tests are about the cases where
it is not, because a malformed item is worse than a missing one:

  * an MCQ whose correctAnswer indexes past its options marks a correct answer
    WRONG, and the player has no way to tell the fault is ours;
  * two identical options make one of them a wrong answer that is textually a
    right answer, which is unfair in a way nobody can argue with;
  * a bug-hunt whose "buggy" and "fixed" code are the same is a puzzle with no
    answer, and the player hunts forever.

Dropping those is the point. A batch that yields six usable questions out of ten
is a good batch; one that stores ten and breaks four is a bad batch that looks
better on the dashboard.
"""

import ast
import datetime
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


GEN = _load_pure(
    "services/codeplay_generate.py",
    {"DIFFICULTIES", "_WORD_RE", "_fingerprint", "_identity_text", "_clean_options",
     "_index_in_range", "validate_mcq", "validate_flashcard", "validate_bughunter",
     "validate_problem", "_normalise_code", "_difficulty"},
    extra={"_re": __import__("re"), "_json": __import__("json")},
)

DAILY = _load_pure(
    "services/codeplay_daily.py",
    {"MIN_ATTEMPTS_FOR_SIGNAL", "WEAK_CATEGORIES", "STRONG_ENOUGH",
     "_difficulty_for", "_bounded_int", "_today", "_prompt"},
    extra={"_datetime": datetime},
)


def mcq(**over):
    item = {"question": "What does map return?",
            "options": ["a number", "a new array", "undefined", "the same array"],
            "correctAnswer": 1, "explanation": "map builds a new array."}
    item.update(over)
    return item


class McqTest(unittest.TestCase):
    def test_a_good_question_is_kept(self):
        self.assertIsNotNone(GEN["validate_mcq"](mcq()))

    def test_an_answer_index_past_the_options_is_refused(self):
        # The worst failure available: it marks a correct answer wrong.
        self.assertIsNone(GEN["validate_mcq"](mcq(correctAnswer=4)))
        self.assertIsNone(GEN["validate_mcq"](mcq(correctAnswer=-1)))

    def test_a_boolean_answer_index_is_refused(self):
        # bool is an int in Python, so True would otherwise pass as index 1.
        self.assertIsNone(GEN["validate_mcq"](mcq(correctAnswer=True)))

    def test_duplicate_options_are_refused(self):
        # One of them is a wrong answer that is textually a right answer.
        self.assertIsNone(GEN["validate_mcq"](
            mcq(options=["a new array", "a new array", "x", "y"])))

    def test_the_wrong_number_of_options_is_refused(self):
        self.assertIsNone(GEN["validate_mcq"](mcq(options=["a", "b", "c"])))

    def test_a_question_with_no_explanation_is_refused(self):
        # It teaches nothing at the moment it exists for: being got wrong.
        self.assertIsNone(GEN["validate_mcq"](mcq(explanation="  ")))

    def test_an_unknown_difficulty_becomes_medium_rather_than_being_kept(self):
        got = GEN["validate_mcq"](mcq(difficulty="impossible"))
        self.assertEqual(got["difficulty"], "Medium")


class BugHunterTest(unittest.TestCase):
    def base(self, **over):
        item = {"title": "Off by one", "description": "Fix the loop.",
                "buggyCode": "for (let i = 0; i <= n; i++) {}",
                "fixedCode": "for (let i = 0; i < n; i++) {}",
                "explanation": "The bound was inclusive."}
        item.update(over)
        return item

    def test_a_real_bug_is_kept(self):
        self.assertIsNotNone(GEN["validate_bughunter"](self.base()))

    def test_identical_code_is_refused(self):
        # A hunt with nothing to find. The player cannot ever finish it.
        same = "for (let i = 0; i < n; i++) {}"
        self.assertIsNone(GEN["validate_bughunter"](
            self.base(buggyCode=same, fixedCode=same)))

    def test_reindentation_alone_is_not_a_fix(self):
        # Whitespace-insensitive on purpose: a model that "fixes" a bug by
        # reformatting has produced a puzzle with no answer.
        self.assertIsNone(GEN["validate_bughunter"](self.base(
            buggyCode="for (let i=0; i<n; i++) {}",
            fixedCode="for (let i = 0;  i < n;  i++) {}")))


class ProblemTest(unittest.TestCase):
    def test_a_problem_with_no_example_is_refused(self):
        # A specification, not an exercise: nothing says what shape the answer
        # should take.
        self.assertIsNone(GEN["validate_problem"](
            {"title": "Sort it", "description": "Sort the array.", "examples": []}))

    def test_a_worked_example_is_enough(self):
        got = GEN["validate_problem"]({
            "title": "Sort it", "description": "Sort the array.",
            "examples": [{"input": "[3,1]", "output": "[1,3]"}]})
        self.assertIsNotNone(got)
        self.assertEqual(len(got["examples"]), 1)

    def test_examples_missing_input_or_output_are_dropped_individually(self):
        got = GEN["validate_problem"]({
            "title": "Sort it", "description": "Sort.",
            "examples": [{"input": "[3,1]", "output": "[1,3]"},
                         {"input": "", "output": "[]"}]})
        self.assertEqual(len(got["examples"]), 1)


class FingerprintTest(unittest.TestCase):
    def test_reordering_and_punctuation_do_not_hide_a_repeat(self):
        # Asking a model repeatedly produces near-duplicates; exact-string
        # matching would not notice these.
        a = GEN["_fingerprint"]("What does map() return?")
        b = GEN["_fingerprint"]("return   map() does what")
        self.assertEqual(a, b)

    def test_rephrasing_is_deliberately_not_caught(self):
        # A fingerprint loose enough to match synonyms would also match
        # genuinely different questions on the same topic, and dropping good
        # content silently is worse than storing an occasional near-repeat.
        a = GEN["_fingerprint"]("What does map return?")
        b = GEN["_fingerprint"]("What is returned by map?")
        self.assertNotEqual(a, b)

    def test_different_questions_do_not_collide(self):
        a = GEN["_fingerprint"]("What does map return?")
        b = GEN["_fingerprint"]("What does reduce return?")
        self.assertNotEqual(a, b)


class DailyProfileTest(unittest.TestCase):
    """Aim just above the player, and admit when there is no signal."""

    def test_no_history_gets_the_gentlest_setting(self):
        # NOT a confident diagnosis of somebody the site has never seen.
        self.assertEqual(DAILY["_difficulty_for"]({"accuracy": None, "attempts": 0}), "Easy")

    def test_a_tiny_sample_is_still_treated_as_no_signal(self):
        # Two failures in a row is a bad afternoon, not a weakness.
        self.assertEqual(
            DAILY["_difficulty_for"]({"accuracy": 0.0, "attempts": 2}), "Easy")

    def test_a_strong_player_is_stretched(self):
        self.assertEqual(
            DAILY["_difficulty_for"]({"accuracy": 0.9, "attempts": 50}), "Hard")

    def test_a_middling_player_gets_medium(self):
        self.assertEqual(
            DAILY["_difficulty_for"]({"accuracy": 0.6, "attempts": 50}), "Medium")

    def test_a_struggling_player_is_not_punished(self):
        self.assertEqual(
            DAILY["_difficulty_for"]({"accuracy": 0.2, "attempts": 50}), "Easy")

    def test_the_prompt_says_plainly_when_there_is_no_history(self):
        # Left to infer from silence, a model invents a weakness.
        text = DAILY["_prompt"]({"weak": [], "strong": []}, "Easy")
        self.assertIn("no meaningful history", text)

    def test_the_prompt_names_the_weak_areas_and_avoids_the_strong(self):
        text = DAILY["_prompt"](
            {"weak": ["Recursion"], "strong": ["Array"]}, "Medium")
        self.assertIn("Recursion", text)
        self.assertIn("Array", text)

    def test_reward_and_time_are_bounded(self):
        # Straight from the model these decide XP. Unbounded, one hallucinated
        # number inflates the whole economy.
        self.assertEqual(DAILY["_bounded_int"](999999, 5, 100, 20), 100)
        self.assertEqual(DAILY["_bounded_int"](-5, 5, 100, 20), 5)
        self.assertEqual(DAILY["_bounded_int"]("lots", 5, 100, 20), 20)
        self.assertEqual(DAILY["_bounded_int"](None, 5, 60, 15), 15)


class QuotaTest(unittest.TestCase):
    """An exhausted quota arrives as 429 and must NOT be retried."""

    def setUp(self):
        self.api = _load_pure("services/openai_api.py",
                              {"_QUOTA_HINTS", "_is_quota"})

    def test_a_credit_error_is_recognised(self):
        # Verified against the live API: this is the exact wording returned.
        self.assertTrue(self.api["_is_quota"](
            "You have no credits remaining. Add credits to continue using the API"))

    def test_the_standard_quota_wording_is_recognised(self):
        self.assertTrue(self.api["_is_quota"](
            "You exceeded your current quota, please check your plan"))

    def test_an_ordinary_rate_limit_is_still_retried(self):
        # This one DOES clear on its own, and treating it as permanent would
        # abandon a batch that would have succeeded seconds later.
        self.assertFalse(self.api["_is_quota"]("Rate limit reached for requests"))

    def test_nothing_is_not_a_quota_error(self):
        self.assertFalse(self.api["_is_quota"](""))
        self.assertFalse(self.api["_is_quota"](None))


if __name__ == "__main__":
    unittest.main()
