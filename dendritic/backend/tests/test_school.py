"""The school's renderer and navigation.

The renderer is the part with a security consequence: lesson bodies become HTML
on a page, so anything it fails to escape is stored XSS the day chapters become
editable. The navigation is the part with a correctness consequence: a book you
cannot read straight through is not a book.
"""

import ast
import os
import pathlib
import sys
import unittest

BACKEND = pathlib.Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _load_pure(relative_path, wanted, extra=None):
    source = (BACKEND / relative_path).read_text()
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


from html import escape  # noqa: E402

SCHOOL = _load_pure(
    "services/school.py",
    {"render", "_inline", "reading_order", "chapter", "total_chapters", "book"},
    extra={"escape": escape},
)

BOOK = _load_pure("services/school_crypto.py", {"BOOK", "REFERENCE"})["BOOK"]


class RenderTest(unittest.TestCase):
    def test_paragraphs_split_on_blank_lines(self):
        html = SCHOOL["render"]("one line\nsame paragraph\n\nsecond paragraph")
        self.assertEqual(html.count("<p>"), 2)
        self.assertIn("one line same paragraph", html)

    def test_bullets_become_a_list(self):
        html = SCHOOL["render"]("intro\n\n- first\n- second")
        self.assertIn("<ul>", html)
        self.assertEqual(html.count("<li>"), 2)

    def test_a_wrapped_bullet_stays_one_item(self):
        # Lesson text wraps at 79 columns, so nearly every bullet continues onto
        # the next line. Treating those as new items would shred every list.
        html = SCHOOL["render"]("- a bullet that\n  continues here\n- second")
        self.assertEqual(html.count("<li>"), 2)
        self.assertIn("a bullet that continues here", html)

    def test_indented_blocks_become_code(self):
        html = SCHOOL["render"]("text\n\n    OP_DUP OP_HASH160\n    OP_EQUAL")
        self.assertIn("<pre><code>", html)
        self.assertIn("OP_DUP OP_HASH160\nOP_EQUAL", html)

    def test_backticks_become_code_spans(self):
        self.assertIn("<code>bits</code>", SCHOOL["render"]("the `bits` field"))

    def test_an_unclosed_backtick_does_not_swallow_the_paragraph(self):
        html = SCHOOL["render"]("an `unclosed span here")
        self.assertNotIn("<code>", html)
        self.assertIn("unclosed span here", html)

    def test_html_in_a_lesson_is_escaped(self):
        # The one that matters. These authors are trusted today; a renderer that
        # is only safe because of who is writing becomes unsafe the moment
        # chapters are editable.
        html = SCHOOL["render"]("beware <script>alert(1)</script> of this")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_inside_a_code_block_is_escaped_too(self):
        html = SCHOOL["render"]("    <img onerror=alert(1)>")
        self.assertNotIn("<img", html)
        self.assertIn("&lt;img", html)

    def test_html_inside_a_bullet_is_escaped_too(self):
        html = SCHOOL["render"]("- <b>bold</b>")
        self.assertNotIn("<b>", html)

    def test_empty_input_is_empty_output_rather_than_a_crash(self):
        self.assertEqual(SCHOOL["render"](""), "")
        self.assertEqual(SCHOOL["render"](None), "")


class NavigationTest(unittest.TestCase):
    def test_reading_order_covers_every_chapter_once(self):
        order = SCHOOL["reading_order"](BOOK)
        self.assertEqual(len(order), SCHOOL["total_chapters"](BOOK))
        slugs = [entry["slug"] for entry in order]
        self.assertEqual(len(slugs), len(set(slugs)), "duplicate chapter slug")

    def test_every_chapter_carries_its_part(self):
        # The part title travels with the chapter so no page has to re-derive it
        # from the nesting and get it wrong.
        for entry in SCHOOL["reading_order"](BOOK):
            self.assertTrue(entry["part_title"])
            self.assertGreaterEqual(entry["part_number"], 1)

    def test_next_links_chain_from_first_to_last(self):
        # A book you cannot read straight through is not a book.
        order = SCHOOL["reading_order"](BOOK)
        seen, slug = 0, order[0]["slug"]
        while slug is not None:
            current, _previous, following = SCHOOL["chapter"](BOOK, slug)
            self.assertIsNotNone(current, slug)
            seen += 1
            slug = following["slug"] if following else None
        self.assertEqual(seen, len(order))

    def test_the_ends_have_no_neighbour_past_them(self):
        order = SCHOOL["reading_order"](BOOK)
        self.assertIsNone(SCHOOL["chapter"](BOOK, order[0]["slug"])[1])
        self.assertIsNone(SCHOOL["chapter"](BOOK, order[-1]["slug"])[2])

    def test_an_unknown_slug_is_three_nones(self):
        self.assertEqual(SCHOOL["chapter"](BOOK, "no-such-chapter"), (None, None, None))


class CurriculumTest(unittest.TestCase):
    def test_every_chapter_has_the_fields_a_page_renders(self):
        for entry in SCHOOL["reading_order"](BOOK):
            for field in ("slug", "title", "summary", "body"):
                self.assertTrue(str(entry.get(field, "")).strip(),
                                "%s is missing %s" % (entry.get("slug"), field))

    def test_slugs_are_url_safe(self):
        for entry in SCHOOL["reading_order"](BOOK):
            self.assertRegex(entry["slug"], r"^[a-z0-9-]+$")

    def test_chapters_are_substantial_rather_than_placeholders(self):
        # Guards against a part being stubbed out and quietly shipping as a
        # heading with nothing under it.
        for entry in SCHOOL["reading_order"](BOOK):
            self.assertGreater(len(entry["body"].split()), 80, entry["slug"])


if __name__ == "__main__":
    unittest.main()
