"""Arcade scoring, progression and the skill radar.

These exercise the pure logic (content tables, XP curve, radar geometry) without
standing up the ORM, so they run in the same stubbed environment as the other
service tests here.
"""
import json
import os
import sys
import types
import unittest
from unittest.mock import MagicMock

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _install_shared_stub():
    if "shared" in sys.modules:
        return
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    # Column/relationship calls happen at import time on the model module.
    shared.db = db
    shared.app = MagicMock()
    sys.modules["shared"] = shared


_install_shared_stub()

DATA = os.path.join(BACKEND, "data", "codeplay")


class ContentTests(unittest.TestCase):
    """The converted tables must be usable, not merely present."""

    def _load(self, name):
        with open(os.path.join(DATA, name), "r", encoding="utf-8") as handle:
            return json.load(handle)

    def test_every_table_converted(self):
        for name, minimum in (("mcq.json", 100), ("flashcards.json", 50),
                              ("bughunter.json", 30), ("problems.json", 57)):
            data = self._load(name)
            self.assertGreaterEqual(len(data), minimum, name)

    def test_mcq_answers_are_in_range(self):
        # A correctAnswer pointing outside options would make a question
        # unanswerable and silently deny XP forever.
        for question in self._load("mcq.json"):
            self.assertIn("options", question, question.get("id"))
            self.assertIsInstance(question["correctAnswer"], int)
            self.assertTrue(
                0 <= question["correctAnswer"] < len(question["options"]),
                "question %s has answer %s but %d options"
                % (question.get("id"), question["correctAnswer"], len(question["options"])),
            )

    def test_apostrophes_survived_conversion(self):
        # The first converter pass broke on "JavaScript's" inside double quotes.
        text = json.dumps(self._load("mcq.json"))
        self.assertNotIn("\\\\'", text)

    def test_daily_has_all_three_difficulties(self):
        daily = self._load("daily.json")
        for level in ("Easy", "Medium", "Hard"):
            self.assertTrue(daily.get(level), level)

    def test_no_typescript_leaked_through(self):
        for name in ("mcq.json", "problems.json", "daily.json"):
            text = json.dumps(self._load(name))
            self.assertNotIn(" as const", text)
            self.assertNotIn("export const", text)


class LevelCurveTests(unittest.TestCase):
    def setUp(self):
        from model.Codeplay import CodeplayProgress
        self.cls = CodeplayProgress

    def _progress(self, xp, level):
        row = self.cls.__new__(self.cls)
        row.xp, row.level = xp, level
        row.attempts, row.correct = 0, 0
        return row

    def test_level_progress_never_exceeds_the_bar(self):
        for level in range(1, 12):
            for xp in range(0, 3000, 137):
                row = self._progress(xp, level)
                self.assertGreaterEqual(row.level_percent, 0)
                self.assertLessEqual(row.level_percent, 100)

    def test_accuracy_handles_no_attempts(self):
        row = self._progress(0, 1)
        self.assertEqual(0, row.accuracy)
        row.attempts, row.correct = 4, 3
        self.assertEqual(75, row.accuracy)

    def test_badges_do_not_duplicate(self):
        row = self._progress(0, 1)
        row.badges = ""
        self.assertTrue(row.award_badge("welcome"))
        self.assertFalse(row.award_badge("welcome"))
        self.assertEqual(["welcome"], row.badge_list)


class RadarTests(unittest.TestCase):
    def setUp(self):
        from services import codeplay
        self.codeplay = codeplay

    def test_geometry_stays_inside_the_viewbox(self):
        scores = {key: 100 for key, _l, _c in self.codeplay.SKILL_AXES}
        radar = self.codeplay.radar_points(scores, size=220)
        for point in radar["vertices"]:
            self.assertGreaterEqual(point[0], 0)
            self.assertGreaterEqual(point[1], 0)
            self.assertLessEqual(point[0], 220)
            self.assertLessEqual(point[1], 220)

    def test_zero_scores_still_produce_a_drawable_polygon(self):
        # A degenerate polygon collapsed to a point renders as nothing at all;
        # the floor keeps an empty chart visible.
        radar = self.codeplay.radar_points({k: 0 for k, _l, _c in self.codeplay.SKILL_AXES})
        self.assertTrue(radar["polygon"].strip())
        self.assertEqual(len(self.codeplay.SKILL_AXES), len(radar["vertices"]))

    def test_one_label_per_axis_with_its_value(self):
        scores = {key: 40 for key, _l, _c in self.codeplay.SKILL_AXES}
        radar = self.codeplay.radar_points(scores)
        self.assertEqual(len(self.codeplay.SKILL_AXES), len(radar["labels"]))
        for label in radar["labels"]:
            self.assertEqual(40, label["value"])
            self.assertIn(label["anchor"], ("start", "middle", "end"))

    def _content_categories(self):
        content = set()
        for name in ("mcq", "problems", "flashcards", "bughunter"):
            path = os.path.join(DATA, "%s.json" % name)
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as handle:
                for item in json.load(handle):
                    if item.get("category"):
                        content.add(item["category"])
        return content

    def test_axis_categories_match_the_content(self):
        # An axis whose categories never appear in the content can never score,
        # leaving a permanently flat spoke on everyone's chart. The security axes
        # are fed by LAB challenges instead, which is a deliberate exception and
        # has to be declared — otherwise a typo'd category set looks identical.
        content = self._content_categories()
        for key, label, cats in self.codeplay.SKILL_AXES:
            if key in self.codeplay.LAB_FED_AXES:
                continue
            self.assertTrue(cats & content,
                            "axis %s matches no category in the content" % label)

    def test_every_lab_fed_axis_is_a_real_axis(self):
        # A stale key here would exempt nothing and silently re-hide a genuinely
        # broken axis.
        keys = {key for key, _label, _cats in self.codeplay.SKILL_AXES}
        self.assertTrue(self.codeplay.LAB_FED_AXES <= keys)

    def test_no_quiz_category_feeds_nothing(self):
        # A category answered by real questions but claimed by no axis is work
        # that scores for the player and moves no part of their chart.
        claimed = set()
        for _key, _label, cats in self.codeplay.SKILL_AXES:
            claimed |= cats
        orphans = self._content_categories() - claimed
        self.assertEqual(orphans, set(),
                         "these categories feed no axis: %s" % sorted(orphans))


class ScoringTests(unittest.TestCase):
    def test_harder_work_is_worth_more(self):
        from model.Codeplay import DIFFICULTY_MULTIPLIER, XP_BY_MODE
        easy = XP_BY_MODE["mcq"] * DIFFICULTY_MULTIPLIER["Easy"]
        hard_problem = XP_BY_MODE["problem"] * DIFFICULTY_MULTIPLIER["Hard"]
        self.assertGreater(hard_problem, easy)
        self.assertGreater(XP_BY_MODE["problem"], XP_BY_MODE["flashcard"])


class SandboxTests(unittest.TestCase):
    """The judge must contain hostile code. These run the real sandbox."""

    @classmethod
    def setUpClass(cls):
        runner_dir = os.path.join(os.path.dirname(BACKEND), "code-runner")
        if not os.path.exists(os.path.join(runner_dir, "runner.py")):
            raise unittest.SkipTest("code-runner not present")
        sys.path.insert(0, runner_dir)
        flask = types.ModuleType("flask")

        class _App:
            def __init__(self, *a, **k):
                self.logger = types.SimpleNamespace(
                    exception=lambda *a, **k: None, warning=lambda *a, **k: None,
                    critical=lambda *a, **k: None)

            def route(self, *a, **k):
                return lambda f: f

            def run(self, *a, **k):
                pass

        flask.Flask = _App
        flask.jsonify = lambda *a, **k: None
        flask.request = types.SimpleNamespace(get_json=lambda **k: {})
        sys.modules.setdefault("flask", flask)
        # Skip the startup egress assertion: this box has no NetworkPolicy.
        os.environ["RUNNER_ALLOW_EGRESS"] = "i-understand-this-is-unsafe"
        import runner
        cls.runner = runner

    def test_correct_program_runs(self):
        result = self.runner.run_once("python", "print(sum(range(101)))")
        self.assertTrue(result["ok"])
        self.assertEqual("5050", result["stdout"].strip())

    def test_infinite_loop_is_killed(self):
        result = self.runner.run_once("python", "while True: pass")
        self.assertTrue(result["ok"])
        self.assertTrue(result["timed_out"] or result["exit_code"] != 0)

    def test_memory_bomb_is_capped(self):
        result = self.runner.run_once("python", "x = bytearray(10**10)")
        self.assertTrue(result["ok"])
        self.assertNotEqual(0, result["exit_code"])

    def test_fork_bomb_is_capped(self):
        result = self.runner.run_once("python", "import os\nwhile True: os.fork()")
        self.assertTrue(result["ok"])
        self.assertTrue(result["exit_code"] != 0 or result["timed_out"])

    def test_environment_carries_no_secrets(self):
        # Submitted code must not be able to read cluster credentials that
        # happen to be in the backend's environment.
        result = self.runner.run_once(
            "python", "import os;print(sorted(os.environ))")
        self.assertTrue(result["ok"])
        for leaked in ("POSTGRES_PASSWORD", "S3_SECRET_KEY", "SECRET_KEY",
                       "KUBERNETES_SERVICE_HOST"):
            self.assertNotIn(leaked, result["stdout"])

    def test_output_is_truncated(self):
        result = self.runner.run_once("python", "print('x' * 10**7)")
        self.assertTrue(result["ok"])
        self.assertLess(len(result["stdout"]), self.runner.MAX_OUTPUT_BYTES + 200)

    def test_oversized_source_is_refused_before_running(self):
        result = self.runner.run_once("python", "#" * (self.runner.MAX_SOURCE_BYTES + 1))
        self.assertFalse(result["ok"])

    def test_unknown_language_is_refused(self):
        self.assertFalse(self.runner.run_once("ruby", "puts 1")["ok"])

    def test_egress_check_is_the_gate_not_an_afterthought(self):
        # The runner must refuse to serve when it can reach the network, so a
        # missing NetworkPolicy fails loudly instead of silently.
        os.environ.pop("RUNNER_ALLOW_EGRESS", None)
        try:
            self.runner.egress_reachable = lambda *a, **k: True
            self.assertFalse(self.runner.enforce_isolation())
        finally:
            os.environ["RUNNER_ALLOW_EGRESS"] = "i-understand-this-is-unsafe"


class BattleTests(unittest.TestCase):
    def test_a_player_never_matches_themselves(self):
        # The queue can hold a stale entry for the same slip; matching on it
        # would produce a battle against oneself.
        import importlib
        keystore = types.ModuleType("keystore")
        store = {"list": []}

        class _Redis:
            def get(self, k): return None
            def setex(self, *a): pass
            def expire(self, *a): pass
            def llen(self, k): return len(store["list"])
            def rpush(self, k, v): store["list"].append(v)
            def lpop(self, k): return store["list"].pop(0) if store["list"] else None
            def lrange(self, k, a, b): return list(store["list"])
            def lrem(self, k, n, v): store["list"] = [x for x in store["list"] if x != v]

        keystore.make_redis = lambda: _Redis()
        sys.modules["keystore"] = keystore
        from services import codeplay_battle
        importlib.reload(codeplay_battle)

        import time as _time
        store["list"] = ["7:%f" % _time.time()]          # our own stale entry
        slip = types.SimpleNamespace(id=7, name="me")
        battle_id, waiting = codeplay_battle.join_queue(slip, lambda: {"id": 1})
        self.assertIsNone(battle_id)
        self.assertTrue(waiting)


if __name__ == "__main__":
    unittest.main()
