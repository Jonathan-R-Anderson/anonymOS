"""Article markup: pull quotes, captions and footnotes.

Every assertion runs the source through `services.story_render.render_article_body`
rather than through markdown alone, because the failure this file exists to catch
is not "did the extension emit an element" but "did the element survive bleach".

That distinction is not hypothetical. The first version of these extensions used
`<p class="...">` for captions and `id=` for footnote anchors, and both were
cleaned away: captions rendered as ordinary paragraphs and every footnote link
pointed at an anchor that did not exist. Markdown-only tests passed.
"""

import os
import sys
import types
import unittest
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _install_stubs():
    """Stub `shared` only long enough to import the module under test.

    RETURNS A RESTORE FUNCTION, and calling it is the point. A stub left in
    sys.modules replaces `shared` for every test module pytest imports
    afterwards -- and it imports them all during COLLECTION, before any test
    runs. This stub carries `db` and `app` and nothing else, so a later module
    doing `from shared import db, db_retry` gets an ImportError naming neither
    this file nor the stub, and a collection error is fatal to the whole run.
    """
    if "shared" in sys.modules:
        return lambda: None
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    shared.db = db
    shared.app = MagicMock()
    shared.app.config = {}
    sys.modules["shared"] = shared

    def restore():
        sys.modules.pop("shared", None)

    return restore


_restore_stubs = _install_stubs()

from services.story_render import render_article_body  # noqa: E402

_restore_stubs()



class PullQuoteTest(unittest.TestCase):

    def test_a_pull_quote_renders_and_survives_sanitising(self):
        out = render_article_body(">> They knew, and they did nothing.")
        self.assertIn('class="article-pullquote"', out)
        self.assertIn("They knew, and they did nothing.", out)

    def test_a_single_angle_bracket_is_still_a_blockquote(self):
        """In an article `>` means quoting a source, not greentext."""
        out = render_article_body("> A line from the report.")
        self.assertIn("<blockquote>", out)
        self.assertNotIn("article-pullquote", out)

    def test_a_thread_reference_is_not_eaten_by_the_pull_quote(self):
        """`>>1234` has no space after the brackets and must stay a reference.

        Rendered with the article markup ALONE rather than through
        render_article_body, because the full extension set resolves a thread
        reference against the database and this assertion is about the pull
        quote pattern, not about whether thread 1234 exists.
        """
        from markdown import markdown
        from model.ArticleMarkup import ArticleMarkupExtension

        out = markdown("See >>1234 for the thread.",
                       extensions=[ArticleMarkupExtension()])
        self.assertNotIn("article-pullquote", out)
        self.assertIn("1234", out)

    def test_prose_around_a_pull_quote_survives(self):
        out = render_article_body("Before.\n\n>> Lifted.\n\nAfter.")
        self.assertIn("Before.", out)
        self.assertIn("After.", out)
        self.assertIn("article-pullquote", out)


class CaptionTest(unittest.TestCase):

    def test_a_caption_keeps_its_class_through_bleach(self):
        """The original bug: <p class> is cleaned to <p>, so the caption became
        indistinguishable from body text."""
        out = render_article_body("[^ Photograph by A. Reporter]")
        self.assertIn('class="article-caption"', out)
        self.assertIn("Photograph by A. Reporter", out)

    def test_a_caption_is_not_a_paragraph_element(self):
        out = render_article_body("[^ A caption]")
        self.assertNotIn('<p class="article-caption"', out)

    def test_an_ordinary_bracket_is_left_alone(self):
        out = render_article_body("A sentence [with brackets] in it.")
        self.assertNotIn("article-caption", out)


class FootnoteTest(unittest.TestCase):

    def test_a_footnote_marker_and_its_note_both_appear(self):
        out = render_article_body("Denied it.[+ Statement of 4 March.]")
        self.assertIn('class="article-footnote-ref"', out)
        self.assertIn("Statement of 4 March.", out)
        self.assertIn('class="article-footnotes"', out)

    def test_the_link_target_survives_sanitising(self):
        """Anchors used to be `id=`, which bleach removes on every tag, so every
        footnote link pointed at nothing."""
        out = render_article_body("Denied it.[+ A note.]")
        self.assertIn('href="#note-1"', out)
        self.assertIn('data-note="1"', out)

    def test_numbering_is_assigned_at_render_time_and_in_order(self):
        out = render_article_body("One.[+ First.] Two.[+ Second.]")
        self.assertIn('href="#note-1"', out)
        self.assertIn('href="#note-2"', out)
        self.assertLess(out.index("First."), out.index("Second."))

    def test_the_body_is_not_left_in_an_attribute(self):
        """It rides there between processors; leaving it would put the note in
        the page twice, once where a reader cannot see it."""
        out = render_article_body("Denied it.[+ Secret sourcing detail.]")
        self.assertNotIn("data-footnote=", out)

    def test_no_notes_section_when_there_are_no_footnotes(self):
        out = render_article_body("Just prose.")
        self.assertNotIn("article-footnotes", out)


class NoIdAttributesTest(unittest.TestCase):
    """Ids come from the template, never from text an author controls."""

    def test_rendered_article_markup_emits_no_id(self):
        out = render_article_body(
            "A.[+ note]\n\n>> quote\n\n[^ caption]")
        self.assertNotIn(" id=", out)


class RendererIsSharedTest(unittest.TestCase):

    def test_the_preview_and_the_page_use_one_function(self):
        """A preview that differs from the published result is worse than none."""
        source = open(os.path.join(BACKEND, "services", "story_render.py"),
                      encoding="utf-8").read()
        self.assertIn("render_markdown", source)
        # One extension list, built once, used by both.
        self.assertEqual(source.count("def article_extensions"), 1)


if __name__ == "__main__":
    unittest.main()
