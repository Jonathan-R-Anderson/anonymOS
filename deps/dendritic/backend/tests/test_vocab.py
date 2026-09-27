"""The vocabulary glossary: coverage, grading, and the slugs links depend on.

The definitions themselves are prose and cannot be unit tested. What can be
tested is everything around them — that no term lost its definition, that the
difficulty grades actually partition the list, and that a slug never collides,
because a collision silently sends two terms to the same anchor.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _load(relative_path, names):
    namespace = {}
    source = (BACKEND / relative_path).read_text()
    exec(compile(source, relative_path, "exec"), namespace)
    return {name: namespace[name] for name in names}


DATA = _load("services/vocab_data.py", ["TERMS", "EASY", "MEDIUM", "HARD"])
TERMS = DATA["TERMS"]
LEVELS = {DATA["EASY"], DATA["MEDIUM"], DATA["HARD"]}


def _vocab():
    # Imported rather than ast-extracted: services/vocab.py has no Flask or db
    # import, so it loads on its own.
    from services import vocab
    return vocab


class CoverageTest(unittest.TestCase):
    def test_every_term_is_complete(self):
        for row in TERMS:
            self.assertEqual(len(row), 4, row)
            term, difficulty, category, definition = row
            self.assertTrue(term.strip(), row)
            self.assertTrue(category.strip(), term)
            self.assertTrue(definition.strip(), term)

    def test_no_duplicate_terms(self):
        # A duplicate would appear twice in the listing and twice in the drill,
        # which reads as a bug and skews the drill toward that word.
        names = [row[0].lower() for row in TERMS]
        self.assertEqual(len(names), len(set(names)),
                         sorted({n for n in names if names.count(n) > 1}))

    def test_definitions_are_written_not_stubbed(self):
        """No placeholders, and a real sentence.

        The bar is deliberately low. An earlier version of this test demanded
        eight words and failed on "Element: one item in a list, reached by its
        index" — which is complete. Padding twenty short definitions to satisfy
        an arbitrary count would have made the glossary worse, so the length
        check only catches a stub, and QUALITY is covered by the restatement
        test below.
        """
        for term, _difficulty, _category, definition in TERMS:
            self.assertGreaterEqual(len(definition.split()), 5, term)
            self.assertTrue(definition.strip().endswith((".", "!")), term)
            for placeholder in ("TODO", "TBD", "FIXME", "XXX"):
                self.assertNotIn(placeholder, definition.upper(), term)

    def test_definitions_do_not_merely_restate_the_term(self):
        # "Binary Search: a search that is binary" is not a definition. Catches
        # the laziest failure mode, not every weak entry.
        for term, _difficulty, _category, definition in TERMS:
            head = definition.split(".")[0].lower()
            self.assertNotEqual(head.strip(), term.lower(), term)


class GradingTest(unittest.TestCase):
    def test_every_term_has_a_known_difficulty(self):
        for term, difficulty, _category, _definition in TERMS:
            self.assertIn(difficulty, LEVELS, term)

    def test_all_three_grades_are_used(self):
        # A grading scheme where one bucket is empty is not a grading scheme.
        used = {row[1] for row in TERMS}
        self.assertEqual(used, LEVELS)

    def test_the_grades_partition_the_list(self):
        vocab = _vocab()
        counts = vocab.counts_by_difficulty()
        self.assertEqual(sum(counts.values()), len(TERMS))

    def test_grouped_returns_every_term_exactly_once(self):
        vocab = _vocab()
        seen = [entry["term"] for _l, _lab, _b, entries in vocab.grouped()
                for entry in entries]
        self.assertEqual(sorted(seen), sorted(row[0] for row in TERMS))

    def test_each_group_is_alphabetical(self):
        # The source order is authoring order, which is nobody's way to find a
        # word.
        vocab = _vocab()
        for _level, _label, _blurb, entries in vocab.grouped():
            names = [entry["term"].lower() for entry in entries]
            self.assertEqual(names, sorted(names))


class SlugTest(unittest.TestCase):
    def test_slugs_are_unique(self):
        # Anchors on the page. A collision sends two terms to one place.
        vocab = _vocab()
        slugs = [entry["slug"] for entry in vocab.all_terms()]
        self.assertEqual(len(slugs), len(set(slugs)),
                         sorted({s for s in slugs if slugs.count(s) > 1}))

    def test_slugs_are_url_safe(self):
        vocab = _vocab()
        for entry in vocab.all_terms():
            self.assertRegex(entry["slug"], r"^[a-z0-9-]+$", entry["term"])

    def test_punctuation_and_brackets_are_folded(self):
        vocab = _vocab()
        self.assertEqual(vocab.slug_for("API (Application Program Interface)"),
                         "api-application-program-interface")
        self.assertEqual(vocab.slug_for("Input and Output (I/O) Devices"),
                         "input-and-output-i-o-devices")

    def test_a_slug_resolves_back_to_its_term(self):
        vocab = _vocab()
        for entry in vocab.all_terms()[:20]:
            self.assertEqual(vocab.term_by_slug(entry["slug"])["term"], entry["term"])


class SearchTest(unittest.TestCase):
    def test_no_filters_returns_everything(self):
        self.assertEqual(len(_vocab().search()), len(TERMS))

    def test_filters_combine_with_and(self):
        vocab = _vocab()
        got = vocab.search(difficulty="hard", category="Algorithms and Programming")
        self.assertTrue(got)
        for entry in got:
            self.assertEqual(entry["difficulty"], "hard")
            self.assertEqual(entry["category"], "Algorithms and Programming")

    def test_search_covers_definitions_not_just_terms(self):
        # Somebody who half-remembers a concept searches for what it DOES, which
        # is exactly when a glossary is needed.
        got = _vocab().search("halting problem")
        self.assertTrue(any(entry["term"] == "Undecidable Problem" for entry in got))

    def test_search_is_case_insensitive(self):
        vocab = _vocab()
        self.assertEqual(len(vocab.search("BANDWIDTH")), len(vocab.search("bandwidth")))

    def test_an_unmatched_query_returns_nothing_rather_than_everything(self):
        self.assertEqual(_vocab().search("zzzznotaterm"), [])


if __name__ == "__main__":
    unittest.main()
