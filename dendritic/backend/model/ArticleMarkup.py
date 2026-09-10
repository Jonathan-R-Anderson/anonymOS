"""Markup that articles need and posts do not: pull quotes, captions, footnotes.

MARKUP, NOT FORM FIELDS
-----------------------
The alternative was a structured field per element -- a "pull quote" box, a
"caption" box beside each image. Fields validate more easily and are harder to
get wrong, and they were rejected because they put the writer in the wrong
place: a pull quote is a sentence lifted from a paragraph, and choosing it while
looking at a form field rather than at the prose is how you end up with a pull
quote that repeats the standfirst. Footnotes have the same problem twice over,
since their whole purpose is to sit at a point in a sentence.

So they are markup, written where they belong, and the live preview is what
makes that safe: a writer sees the rendered result beside the source rather than
guessing.

WHY THESE THREE AND NOTHING ELSE
--------------------------------
Each earns its place by being something reporting cannot do without.

  * A CAPTION is not decoration. An uncaptioned photograph in an investigation
    is an unsourced claim -- the reader cannot tell what they are looking at or
    who took it, and the picture does evidentiary work it has not earned.
  * A FOOTNOTE is the mechanism by which "alleged" stays credible. An article
    that names a police department and cites nothing is an assertion; the same
    article with its sources at the bottom is reporting.
  * A PULL QUOTE is the only one that is purely presentational, and it is here
    because a long investigation without one is a wall of text people abandon.

Everything else an author might want -- colours, columns, font sizes -- is
absent on purpose. This is a newsroom, not a page builder, and every additional
control is a way for one story to look like it carries more authority than
another.

THE OUTPUT MUST SURVIVE BLEACH
------------------------------
`model.Post.render_markdown` cleans the rendered HTML against ALLOWED_TAGS and
ALLOWED_ATTRIBUTES, so an extension that emits a tag on neither list produces
markup that silently disappears. Every element below is built from tags already
on that list -- div, span, a, img, p -- carrying a class rather than a novel
tag, which is also why the styling lives in the stylesheet where a theme can
reach it.
"""

import re
from xml.etree import ElementTree as etree

from markdown import Extension
from markdown.blockprocessors import BlockProcessor
from markdown.inlinepatterns import InlineProcessor
from markdown.treeprocessors import Treeprocessor


# --- pull quotes -----------------------------------------------------------

class PullQuoteProcessor(BlockProcessor):
    """A paragraph of the form:

        >> Something worth lifting out of the prose.

    Two angle brackets rather than one, so it cannot collide with the blockquote
    a single `>` already means in an article. `>>1234` stays a thread reference:
    the pattern below requires whitespace after the brackets, and a bare number
    never matches.
    """

    _RE = re.compile(r"(?:^|\n)>>[ \t]+(?P<text>.+?)(?:\n|$)")

    def test(self, parent, block):
        return bool(self._RE.search(block))

    def run(self, parent, blocks):
        block = blocks.pop(0)
        match = self._RE.search(block)
        before = block[:match.start()].strip()
        after = block[match.end():].strip()
        if before:
            self.parser.parseBlocks(parent, [before])

        quote = etree.SubElement(parent, "div")
        quote.attrib["class"] = "article-pullquote"
        quote.text = match.group("text").strip()

        if after:
            blocks.insert(0, after)


# --- captions --------------------------------------------------------------

class CaptionProcessor(BlockProcessor):
    """A caption line directly under an image, written as:

        [^ Who is in the picture, and who took it]

    Kept separate from markdown's own image alt text, which is for a reader who
    cannot see the picture and is a different sentence: alt says WHAT is there,
    a caption says what it MEANS and where it came from.
    """

    _RE = re.compile(r"(?:^|\n)\[\^[ \t]+(?P<text>.+?)\](?:\n|$)")

    def test(self, parent, block):
        return bool(self._RE.search(block))

    def run(self, parent, blocks):
        block = blocks.pop(0)
        match = self._RE.search(block)
        before = block[:match.start()].strip()
        after = block[match.end():].strip()
        if before:
            self.parser.parseBlocks(parent, [before])

        # A div, not a p. `model.Post.ALLOWED_ATTRIBUTES` permits `class` on
        # div and span and NOT on p, so a <p class="article-caption"> is cleaned
        # into an ordinary paragraph and the caption silently becomes body text.
        caption = etree.SubElement(parent, "div")
        caption.attrib["class"] = "article-caption"
        caption.text = match.group("text").strip()

        if after:
            blocks.insert(0, after)


# --- footnotes -------------------------------------------------------------

FOOTNOTE_INLINE = r"\[\+(?P<body>[^\]]+)\]"


class FootnoteProcessor(InlineProcessor):
    """An inline footnote, written where it belongs in the sentence:

        The department denied it.[+ Statement of 4 March, on file.]

    Inline rather than markdown's reference-style footnotes, which put the text
    at the bottom of the source. A citation written a hundred lines away from
    the claim it supports is a citation that drifts off the claim during an
    edit, and drift is the failure that matters here -- a footnote attached to
    the wrong sentence is worse than none.

    Numbering is assigned at render time by the tree processor below, so a
    writer never maintains it and reordering paragraphs cannot leave the numbers
    wrong.
    """

    def handleMatch(self, match, data):
        marker = etree.Element("a")
        marker.attrib["class"] = "article-footnote-ref"
        # The number and the href are filled in by CollectFootnotes, which is
        # the only thing that can see the whole document and therefore the only
        # thing that can count.
        marker.attrib["data-footnote"] = match.group("body").strip()
        marker.text = "*"
        return marker, match.start(0), match.end(0)


class CollectFootnotes(Treeprocessor):
    """Number the markers and build the list at the end of the article."""

    def run(self, root):
        markers = [element for element in root.iter("a")
                   if element.get("class") == "article-footnote-ref"]
        if not markers:
            return root

        notes = etree.SubElement(root, "div")
        notes.attrib["class"] = "article-footnotes"
        heading = etree.SubElement(notes, "div")
        heading.attrib["class"] = "article-footnotes-heading"
        heading.text = "Notes"

        for index, marker in enumerate(markers, start=1):
            body = marker.get("data-footnote") or ""
            # The attribute carried the text this far; it is removed so the
            # footnote body is not duplicated into the page as an attribute a
            # reader can pull out of the markup.
            del marker.attrib["data-footnote"]
            marker.text = str(index)
            marker.attrib["href"] = "#note-%d" % index

            # NO `id` ATTRIBUTES ANYWHERE. `model.Post.ALLOWED_ATTRIBUTES` does
            # not permit `id` on any tag, so bleach removes them and every
            # footnote link lands on an anchor that does not exist -- a feature
            # that looks finished and does nothing.
            #
            # The anchor is provided by the TEMPLATE instead, which renders
            # `<div id="note-N">` around each note from data it is given rather
            # than from sanitised markup. That keeps the id outside the text a
            # writer controls, which is where it should have been anyway: an
            # author who could emit ids could collide with the page's own.
            item = etree.SubElement(notes, "div")
            item.attrib["class"] = "article-footnote"
            item.attrib["data-note"] = str(index)
            back = etree.SubElement(item, "span")
            back.attrib["class"] = "article-footnote-number"
            back.text = "%d." % index
            back.tail = " " + body
        return root


class ArticleMarkupExtension(Extension):
    """The three together. Articles get this; posts do not."""

    def extendMarkdown(self, md):
        # Priorities sit above paragraph handling so a caption or pull quote is
        # not swallowed into the paragraph above it.
        md.parser.blockprocessors.register(
            PullQuoteProcessor(md.parser), "article-pullquote", 175)
        md.parser.blockprocessors.register(
            CaptionProcessor(md.parser), "article-caption", 174)
        md.inlinePatterns.register(
            FootnoteProcessor(FOOTNOTE_INLINE), "article-footnote", 185)
        md.treeprocessors.register(
            CollectFootnotes(md), "article-footnotes", 5)
