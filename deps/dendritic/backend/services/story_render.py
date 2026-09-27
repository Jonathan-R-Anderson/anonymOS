"""How an article's body becomes HTML, and what looks like a mistake in it.

ONE RENDERER, ASKED BY BOTH THE PREVIEW AND THE PUBLISHED PAGE
---------------------------------------------------------------
A preview that differs from the result is worse than none: it teaches a writer
to trust a picture of their article that nobody else will ever see, and the
divergence is only discovered by a reader. So there is exactly one function that
turns article source into HTML, and the contributor desk's live preview and the
published story page are both required to call it. Neither may reach for
`markdown()` itself -- the moment two call sites assemble their own extension
list, the two pipelines start drifting the day somebody adds a third extension
to one of them.

The sanitiser is shared for the same reason, by going through
`model.Post.render_markdown`: a preview cleaned against a different tag list
would show a writer an element the published page silently strips.

THE ARTICLE DIALECT IS THE POST DIALECT, WITH TWO DELIBERATE DIFFERENCES
------------------------------------------------------------------------
Articles use the markup already documented at `/formatting`, because a separate
article dialect means two help pages and two renderers. The two differences are
both about the same thing -- a board post is a remark and an article is a claim:

  * `>` is a QUOTATION, not greentext. In an article a leading `>` is almost
    always a police report, a statement or a court filing being quoted, and the
    visual language of greentext is irony and implication -- exactly the wrong
    register for reporting. The markup is unchanged (both produce a
    `<blockquote>`); what changes is that an article body must not inherit the
    site-wide `blockquote { color: var(--green) }` rule from
    `scss/base/styling.scss`. That reset lives in
    `templates/newsroom/_article-styles.html`, scoped to `ARTICLE_BODY_CLASS`,
    and is why the rendered body must be wrapped in that class on EVERY surface
    -- an article body dropped onto a page without it renders every quoted
    statement in sarcasm-green.
  * `>>1234` becomes a LABELLED link ("post #1234") rather than the bare
    chan-style `>>1234`. The reference is worth keeping -- citing the thread
    where something surfaced is real sourcing -- but an article is read by
    people who have never used an imageboard, and to them `>>1234` is not a
    link, it is a typo.

WHY THIS IS NOT IN `services/newsroom.py`
------------------------------------------
That module moves stories between statuses and must be importable by background
passes; this one imports the web tier's markdown stack and, through
`url_for_post`, the request context. Keeping them apart means a scheduled
archival pass does not depend on the renderer, and the renderer does not depend
on the state machine.

WARNINGS ARE ADVICE, AND ADVICE NEVER BLOCKS
---------------------------------------------
`body_warnings()` finds the four mistakes that are recognisable from the source
alone. Every one of them is a warning and none is a refusal: an unclosed spoiler
is a typo, and a system that refuses to file a story over a typo is a system
writers route around. They are computed here rather than in JavaScript so the
live preview, the page load and the submit-time check cannot disagree about what
counts as a mistake.
"""

import re

from markdown import Extension
from markdown.inlinepatterns import InlineProcessor
from markdown.treeprocessors import Treeprocessor
from markupsafe import Markup
from sqlalchemy.orm.exc import NoResultFound
from xml.etree import ElementTree as etree

from model.AntiAi import AntiAiExtension
from model.ArticleMarkup import ArticleMarkupExtension
from model.Post import render_markdown
from model.PostReplyPattern import url_for_post
from model.Reply import REPLY_REGEXP
from model.SpacingExtension import SpacingExtension
from model.Spoiler import SpoilerExtension


# The wrapper class every surface must put around a rendered body. See the
# module docstring: without it, quotations render as greentext.
ARTICLE_BODY_CLASS = "story-body"


class ArticleReferencePattern(InlineProcessor):
    """`>>1234` as prose a stranger can read, not as chan syntax.

    Same target as `model.PostReplyPattern` and deliberately the same
    `url_for_post()`, so the two dialects can never disagree about where a post
    lives. Only the label differs.

    A reference to a post that no longer exists renders as plain text rather
    than as a dead link. In an article that is the honest rendering: the citation
    was made, the thing cited is gone, and a link that 404s reads as sloppiness
    rather than as the deletion it actually records.
    """

    def __init__(self):
        super().__init__(REPLY_REGEXP)

    def handleMatch(self, match, data):
        post_id = int(match.group(2))
        try:
            link = etree.Element("a")
            link.attrib["href"] = url_for_post(post_id)
            link.attrib["class"] = "story-post-ref"
            link.attrib["data-post-id"] = str(post_id)
            link.attrib["title"] = "A post on the boards"
            link.text = "post #%d" % post_id
            return link, match.start(0), match.end(0)
        except NoResultFound:
            gone = etree.Element("span")
            gone.attrib["class"] = "story-post-ref story-post-ref--gone"
            gone.text = "post #%d (no longer on the boards)" % post_id
            return gone, match.start(0), match.end(0)


class ArticleReferenceExtension(Extension):
    """The reference pattern, plus the one-angle-bracket blockquote rule.

    The second half is not optional and is the reason this cannot simply be
    `PostReplyExtension` with a different label. Markdown's stock blockquote
    processor matches any leading `>`, so without this narrowing a line starting
    `>>1234` is eaten as a blockquote containing `>1234` and the citation never
    reaches the inline pattern at all. `model.PostReplyExtension` carries the
    same monkey patch for the same reason; it is repeated rather than imported
    because importing it would also register the chan-style label this dialect
    exists to replace.
    """

    def extendMarkdown(self, md):
        md.inlinePatterns.register(ArticleReferencePattern(), "story_post_ref", 181)
        md.parser.blockprocessors["quote"].RE = re.compile(
            r"(^|\n)[ ]{0,3}>(?!>)[ ]?(.*)")


class ArticleFigureProcessor(Treeprocessor):
    """A paragraph that is nothing but an image becomes a captioned figure.

    Without this, `![Council offices, 12 March. Photo: A. Reporter](...)` puts
    the caption in an `alt` attribute, where a sighted reader never sees it --
    and `body_warnings()` would then be nagging writers to type words that are
    never displayed, which is how a warning gets ignored. An uncaptioned
    photograph in an investigation is an unsourced claim: nothing on the page
    says what it shows or who took it.

    A `div`/`span` pair rather than `figure`/`figcaption` because the sanitiser
    is shared with the boards (`model.Post.ALLOWED_TAGS`), which do not allow
    those tags -- and widening the shared list to make an article look nicer
    would change what every post on the site may contain.

    The `alt` is left in place as well as being shown. It is still the right
    text for a screen reader that reaches the image before the caption.

    Only top-level paragraphs are considered. An image inside a list item or a
    blockquote belongs to that structure -- lifting it out into a figure would
    silently rearrange somebody's article, which is a worse thing to do than
    leaving one image uncaptioned.
    """

    def run(self, root):
        for index, child in enumerate(list(root)):
            if child.tag != "p" or (child.text or "").strip():
                continue
            children = list(child)
            if len(children) != 1:
                continue
            image = children[0]
            if image.tag != "img" or (image.tail or "").strip():
                continue

            figure = etree.Element("div")
            figure.attrib["class"] = "story-figure"
            figure.append(image)
            caption = (image.get("alt") or "").strip()
            if caption:
                text = etree.SubElement(figure, "span")
                text.attrib["class"] = "story-figure__caption"
                text.text = caption
            figure.tail = child.tail
            root[index] = figure


class ArticleFigureExtension(Extension):
    def extendMarkdown(self, md):
        # Below "prettify" (10) so the tree is already in its final shape, and
        # well below "inline" (20) so the image element exists to be moved.
        md.treeprocessors.register(ArticleFigureProcessor(md), "story_figure", 5)


def article_extensions():
    """The article pipeline, built fresh per render.

    A new list each call because `markdown()` mutates the extensions it is given
    (the blockquote patch above writes onto the parser it is handed), and a
    module-level list of instances shared between requests is how one render's
    state leaks into the next.

    `ThreadRootExtension` is absent on purpose: it wraps its output in the
    thread view's `<div class="col text-left mw-50">` layout column, which means
    nothing on an article page and would fight the article's own measure.
    """
    return [ArticleReferenceExtension(), ArticleFigureExtension(),
            # Pull quotes, captions and footnotes: the three things reporting
            # cannot do without and a board post never needs. See
            # model/ArticleMarkup.py for why each earns its place, and why
            # nothing else was added.
            ArticleMarkupExtension(),
            SpoilerExtension(), AntiAiExtension(), SpacingExtension()]


def render_article_body(source):
    """Article source -> sanitised HTML. The only renderer. Never raises.

    Goes through `model.Post.render_markdown` so the bleach tag and attribute
    lists are literally the same object the boards use. A body that renders
    correctly here and is stripped on the published page would be the exact
    failure this module exists to prevent, and a second `clean()` call with its
    own arguments is how that happens.
    """
    return render_markdown(source or "", article_extensions())


def article_html(source):
    """The body wrapped in the class its stylesheet is scoped to.

    Every surface should call THIS rather than `render_article_body`, because
    the wrapper is not decoration -- see the module docstring on greentext. It
    returns `Markup`, so a template renders it with `{{ ... }}` and a caller
    cannot forget `|safe` on already-sanitised HTML.
    """
    return Markup('<div class="%s">%s</div>'
                  % (ARTICLE_BODY_CLASS, render_article_body(source)))


# -- what looks like a mistake ----------------------------------------------

WARNING_UNCLOSED_SPOILER = "unclosed-spoiler"
WARNING_HEADING_JUMP = "heading-jump"
WARNING_EMPTY_LINK = "empty-link"
WARNING_UNCAPTIONED_IMAGE = "uncaptioned-image"

_HEADING = re.compile(r"^(#{1,6})\s+\S")
_EMPTY_LINK = re.compile(r"(?<!\!)\[\s*\]\(\s*\S")
_UNCAPTIONED_IMAGE = re.compile(r"!\[\s*\]\(\s*\S")


def _is_code_line(line):
    """Indented code blocks are quoted material, so their contents are not typos.

    Four spaces or a tab is the only code block this markdown build understands
    (no `extra`, so no fences). Checking it here keeps `||` inside a pasted log
    from being reported as an unclosed spoiler, which is the noise that makes
    people stop reading warnings.
    """
    return line.startswith("    ") or line.startswith("\t")


def body_warnings(body):
    """Recognisable mistakes in an article body. A list, possibly empty.

    Each entry is `{"code", "message", "line"}`. `line` is 1-based and may be
    None; it exists because "you have an unclosed spoiler somewhere in four
    thousand words" is not actionable.

    The messages say what to do, not what is wrong. A warning a writer cannot
    act on is one they learn to dismiss, and once they dismiss these they will
    dismiss the one that matters.
    """
    warnings = []
    # The headline is the page's `h1`, so the first heading in the BODY is
    # measured against it rather than being exempt. A story whose first
    # subheading is `####` has skipped two levels just as surely as one that
    # jumps mid-article, and starting the count at None would have let exactly
    # that case through.
    previous_level = 1

    for number, line in enumerate((body or "").splitlines(), 1):
        if _is_code_line(line):
            continue

        # `SpoilerPattern` matches `||...||` within one line, so an odd number of
        # markers on a line is a spoiler that never closes -- it will render as
        # literal pipes in the middle of a sentence.
        if line.count("||") % 2:
            warnings.append({
                "code": WARNING_UNCLOSED_SPOILER,
                "line": number,
                "message": "A spoiler is opened with || and never closed, so "
                           "the bars will show up as text. Close it, or delete "
                           "the stray ||.",
            })

        heading = _HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            if level > previous_level + 1:
                warnings.append({
                    "code": WARNING_HEADING_JUMP,
                    "line": number,
                    # Skipped heading levels are how a screen-reader user loses
                    # the shape of an article: the outline reports a section
                    # that belongs to a subsection that was never opened.
                    "message": "This subheading is level %d, and the heading "
                               "above it is level %d (the headline counts as "
                               "level 1). Readers using a screen reader "
                               "navigate by these, so go down one level at a "
                               "time." % (level, previous_level),
                })
            previous_level = level

        if _UNCAPTIONED_IMAGE.search(line):
            warnings.append({
                "code": WARNING_UNCAPTIONED_IMAGE,
                "line": number,
                # Not a nicety. An uncaptioned photograph in an investigation is
                # an unsourced claim: nothing on the page says what it shows,
                # when, or who took it.
                "message": "An image here has no caption. Put what it shows and "
                           "who took it in the square brackets: "
                           "![Council offices, 12 March. Photo: A. Reporter](...)",
            })

        if _EMPTY_LINK.search(line):
            warnings.append({
                "code": WARNING_EMPTY_LINK,
                "line": number,
                "message": "A link here has no text, so it renders as nothing "
                           "and cannot be clicked. Put what it points at in the "
                           "square brackets.",
            })

    return warnings
