import unittest
from types import SimpleNamespace

from model.WordFilter import apply_filter_rules, normalize_word_filter


def rule(pattern, replacement, *, whole_word=True, case_sensitive=False):
    return SimpleNamespace(
        pattern=pattern,
        replacement=replacement,
        whole_word=whole_word,
        case_sensitive=case_sensitive,
    )


class WordFilterTest(unittest.TestCase):
    def test_whole_word_matching_is_case_insensitive_by_default(self):
        self.assertEqual(
            "dog catapult dog",
            apply_filter_rules("Cat catapult cat", [rule("cat", "dog")]),
        )

    def test_literal_patterns_and_replacements_are_not_regex(self):
        self.assertEqual(
            r"\literal aXb",
            apply_filter_rules(
                "a.b aXb",
                [rule("a.b", r"\literal", whole_word=False, case_sensitive=True)],
            ),
        )

    def test_rules_chain_in_creation_order(self):
        self.assertEqual(
            "third",
            apply_filter_rules(
                "first",
                [rule("first", "second"), rule("second", "third")],
            ),
        )

    def test_empty_pattern_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_word_filter("  ", "replacement")


if __name__ == "__main__":
    unittest.main()
