"""Converting an Edabit export into codeplay problems.

The two things worth testing are the two a learner cannot detect for themselves:
that a problem is only marked gradeable when it really can be graded here, and
that a converted test suite is complete rather than a subset that passes bad
code.
"""

import ast
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path.insert(0, BACKEND)

from services import edabit_import as conv  # noqa: E402


def challenge(**over):
    base = {
        "challenge_id": "abc123",
        "title": "Sum Two Numbers",
        "difficulty": "1.4",
        "languages": ["javascript"],
        "subjects": ["algorithms", "math"],
        "question": "Write a function that adds two numbers.",
        "url": "https://edabit.com/challenge/abc123",
        "raw": {
            "_id": "abc123",
            "language": "javascript",
            "code": "function add(a, b) {\n\n}",
            "author": "Matt",
            "quality": 4.5,
            "lab": "Test.assertEquals(add(1, 2), 3)\nTest.assertEquals(add(-1, 1), 0)",
            "stats": {"completed": {"total": 394, "ratings": [1, 2, 3]}},
        },
    }
    base.update(over)
    return base


class DifficultyTest(unittest.TestCase):
    def test_the_six_bands_are_ordered_and_cover_everything(self):
        for score, want in [(1.0, "Very Easy"), (1.4, "Very Easy"), (2.0, "Easy"),
                            (3.0, "Medium"), (4.0, "Hard"), (5.0, "Very Hard"),
                            (6.0, "Expert"), (99, "Expert")]:
            self.assertEqual(conv.band_for(score), want, "score %s" % score)

    def test_the_string_form_the_export_actually_uses_parses(self):
        self.assertEqual(conv.band_for("1.5674157303370786"), "Easy")

    def test_an_unknown_difficulty_lands_in_the_middle(self):
        # Not at an extreme in either direction: shown as Expert it scares
        # people off, shown as Very Easy it lies.
        for bad in (None, "", "nonsense", []):
            self.assertEqual(conv.band_for(bad), "Medium")

    def test_the_old_three_labels_survive_unchanged(self):
        # Existing problems and every XP figure already awarded must keep
        # meaning what they meant.
        for label in ("Easy", "Medium", "Hard"):
            self.assertIn(label, conv.DIFFICULTY_ORDER)


class TestCaseExtractionTest(unittest.TestCase):
    def test_a_simple_suite_converts(self):
        cases = conv.test_cases("Test.assertEquals(add(1, 2), 3)")
        self.assertEqual(cases, [{"input": "add(1, 2)", "expectedOutput": "3",
                                  "isHidden": False}])

    def test_the_split_is_on_the_last_top_level_comma(self):
        # Splitting on the FIRST comma would cut `edaBit(0, 10)` in half and
        # produce a test case that tests nothing.
        cases = conv.test_cases("Test.assertSimilar(edaBit(0, 10), [1, 2, 3])")
        self.assertEqual(cases[0]["input"], "edaBit(0, 10)")
        self.assertEqual(cases[0]["expectedOutput"], "[1, 2, 3]")

    def test_commas_inside_strings_do_not_split(self):
        cases = conv.test_cases("""Test.assertEquals(join(["a, b", "c"]), "a, b|c")""")
        self.assertEqual(cases[0]["input"], 'join(["a, b", "c"])')
        self.assertEqual(cases[0]["expectedOutput"], '"a, b|c"')

    def test_a_partially_convertible_suite_converts_to_nothing(self):
        # THE important one. A subset grades a submission against fewer cases
        # than the problem has and reports a pass for code that fails the
        # dropped ones — which is the single outcome a learner cannot detect.
        lab = ("Test.assertEquals(add(1, 2), 3)\n"
               "Test.expectError(() => add())\n"
               "Test.assertEquals(add(0, 0), 0)")
        self.assertEqual(conv.test_cases(lab), [])

    def test_an_empty_suite_is_no_cases_not_a_crash(self):
        for empty in ("", None, "   \n  "):
            self.assertEqual(conv.test_cases(empty), [])

    def test_early_cases_are_visible_and_later_ones_hidden(self):
        lab = "\n".join("Test.assertEquals(f(%d), %d)" % (i, i) for i in range(8))
        cases = conv.test_cases(lab)
        self.assertFalse(cases[0]["isHidden"])
        self.assertTrue(cases[-1]["isHidden"],
                        "every case visible means the answer can be special-cased")


class ConversionTest(unittest.TestCase):
    def test_a_full_conversion(self):
        item = conv.convert(challenge())
        self.assertEqual(item["id"], "edabit_abc123")
        self.assertEqual(item["difficulty"], "Very Easy")
        self.assertEqual(item["difficulty_score"], 1.4)
        self.assertEqual(item["subjects"], ["algorithms", "math"])
        self.assertEqual(item["category"], "Algorithms")
        self.assertEqual(item["source"], "edabit")
        self.assertTrue(item["source_url"], "attribution is not optional")
        self.assertEqual(item["author"], "Matt")
        self.assertEqual(item["starterCode"], {"javascript": "function add(a, b) {\n\n}"})

    def test_the_per_user_ratings_array_is_dropped(self):
        # 8 KB per challenge of loose integers whose only use is recomputing an
        # average that is already present. 68 MB of the 270 MB export.
        item = conv.convert(challenge())
        self.assertEqual(item["completed"], 394)
        self.assertNotIn("ratings", str(item))
        self.assertNotIn("raw", item)

    def test_javascript_with_a_convertible_suite_is_gradeable(self):
        self.assertTrue(conv.convert(challenge())["judgeable"])

    def test_a_language_the_runner_cannot_execute_is_not_gradeable(self):
        # The export is javascript, ruby, cpp, java, php, swift and csharp, and
        # this site runs python and javascript. Importing a ruby problem as
        # gradeable produces a Submit button that silently never passes.
        raw = dict(challenge()["raw"], language="ruby")
        item = conv.convert(challenge(raw=raw, languages=["ruby"]))
        self.assertFalse(item["judgeable"])
        self.assertTrue(item["testCases"], "the cases are still worth keeping")

    def test_no_convertible_suite_is_not_gradeable(self):
        raw = dict(challenge()["raw"], lab="Test.expectError(() => add())")
        item = conv.convert(challenge(raw=raw))
        self.assertFalse(item["judgeable"])
        self.assertEqual(item["testCases"], [])

    def test_a_challenge_with_no_statement_is_skipped(self):
        # A problem with no statement is not a problem; importing it would put
        # a blank card in the catalogue.
        self.assertIsNone(conv.convert(challenge(question="", raw={"_id": "x"})))
        self.assertIsNone(conv.convert(challenge(challenge_id="", raw={})))

    def test_xp_rises_with_difficulty(self):
        xp = [conv.XP_BY_DIFFICULTY[b] for b in conv.DIFFICULTY_ORDER]
        self.assertEqual(xp, sorted(xp))
        # The three the site already used keep their values, so importing does
        # not silently reprice existing problems.
        self.assertEqual(conv.XP_BY_DIFFICULTY["Medium"], 15)


class LegacyUpgradeTest(unittest.TestCase):
    def test_an_old_problem_gains_the_new_fields(self):
        old = {"id": "string_1", "title": "T", "description": "d",
               "difficulty": "Medium", "category": "String", "xpReward": 15,
               "testCases": [{"input": "a", "expectedOutput": "b"}],
               "starterCode": {"python": "..."}}
        item = conv.upgrade_legacy(old)
        for field in ("subjects", "languages", "difficulty_score", "source",
                      "source_url", "author", "quality", "completed", "judgeable"):
            self.assertIn(field, item)
        self.assertEqual(item["source"], "maniwani")
        self.assertEqual(item["languages"], ["python"])
        self.assertTrue(item["judgeable"], "it has test cases")

    def test_unknown_values_stay_absent_rather_than_invented(self):
        # A fabricated difficulty_score would sort these wrongly and look
        # authoritative doing it.
        item = conv.upgrade_legacy({"id": "x", "difficulty": "Easy"})
        self.assertIsNone(item["difficulty_score"])
        self.assertIsNone(item["quality"])

    def test_a_problem_with_no_cases_is_not_gradeable(self):
        self.assertFalse(conv.upgrade_legacy({"id": "x"})["judgeable"])


class DifficultyMultiplierTest(unittest.TestCase):
    """The XP table must know every band, or imported problems pay nothing."""

    def test_every_band_has_a_multiplier(self):
        path = os.path.join(BACKEND, "model", "Codeplay.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), path)
        table = None
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "DIFFICULTY_MULTIPLIER"
                    for t in node.targets):
                table = ast.literal_eval(node.value)
        self.assertIsNotNone(table, "DIFFICULTY_MULTIPLIER not found")
        for band in conv.DIFFICULTY_ORDER:
            self.assertIn(band, table, "%s would score as a default" % band)
        # Ordered, so a harder problem never pays less than an easier one.
        values = [table[b] for b in conv.DIFFICULTY_ORDER]
        self.assertEqual(values, sorted(values))


class ShardingTest(unittest.TestCase):
    """A 14 MB single object is a bad citizen in a store other people host."""

    def setUp(self):
        path = os.path.join(BACKEND, "services", "codeplay_content.py")
        with open(path, encoding="utf-8") as handle:
            self.source = handle.read()
        # Extract _shard without importing the module (it pulls in the app).
        tree = ast.parse(self.source, path)
        module = types.ModuleType("shardonly")
        module.__dict__["json"] = __import__("json")
        for node in tree.body:
            keep = (
                isinstance(node, ast.FunctionDef) and node.name == "_shard"
            ) or (
                isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "_SHARD_BYTES"
                    for t in node.targets)
            )
            if keep:
                # Executed rather than literal_eval'd: _SHARD_BYTES is written
                # as 4 * 1024 * 1024, which is an expression and reads far
                # better than 4194304.
                exec(compile(ast.Module([node], []), path, "exec"), module.__dict__)
        self.shard = module._shard
        self.limit = module._SHARD_BYTES

    def test_a_small_collection_stays_one_shard(self):
        self.assertEqual(len(self.shard([{"a": 1}], self.limit)), 1)

    def test_an_empty_collection_yields_one_empty_shard(self):
        self.assertEqual(self.shard([], self.limit), [[]])

    def test_a_large_collection_splits(self):
        items = [{"id": i, "body": "x" * 1000} for i in range(500)]
        shards = self.shard(items, 50_000)
        self.assertGreater(len(shards), 1)
        # Nothing lost and nothing duplicated.
        self.assertEqual(sum(len(s) for s in shards), len(items))
        self.assertEqual([i["id"] for s in shards for i in s], list(range(500)))

    def test_shards_respect_the_limit(self):
        import json
        items = [{"id": i, "body": "x" * 1000} for i in range(200)]
        for chunk in self.shard(items, 20_000):
            # One oversized item is allowed to exceed on its own — splitting
            # mid-item would produce a shard that is not parseable JSON.
            if len(chunk) > 1:
                self.assertLessEqual(len(json.dumps(chunk)), 20_000 * 1.2)

    def test_the_index_is_written_after_its_shards(self):
        # Otherwise a reader can fetch an index naming a shard that does not
        # exist yet.
        body = self.source
        publish = body[body.index("def publish_to_dht"):]
        shard_put = publish.index('Key=key')
        index_put = publish.index('Key="%s.json" % collection, Body=body', shard_put)
        self.assertLess(shard_put, index_put)


if __name__ == "__main__":
    unittest.main()


class LoadFormatsTest(unittest.TestCase):
    """Either the raw export or the converted form, plain or gzipped.

    The converted form exists so the 270 MB export need not be copied to a
    server to be imported: converting first gives 14 MB, and gzipped that is
    1.8 MB. Same items either way.
    """

    def setUp(self):
        import json
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.export = os.path.join(self.dir, "export.json")
        with open(self.export, "w", encoding="utf-8") as handle:
            json.dump({"challenges": [challenge()]}, handle)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_the_raw_export_loads(self):
        items = list(conv.load_export(self.export))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "edabit_abc123")

    def test_a_round_trip_through_the_compact_form_is_identical(self):
        out = os.path.join(self.dir, "compact.json.gz")
        self.assertEqual(conv.write_converted(self.export, out), 1)
        self.assertEqual(list(conv.load_export(out)), list(conv.load_export(self.export)))

    def test_converting_twice_does_not_double_convert(self):
        # A converted item has no "raw" to convert from, so feeding one back in
        # must pass it through rather than drop it.
        out = os.path.join(self.dir, "compact.json")
        conv.write_converted(self.export, out)
        again = os.path.join(self.dir, "compact2.json")
        conv.write_converted(out, again)
        self.assertEqual(list(conv.load_export(again)), list(conv.load_export(out)))
