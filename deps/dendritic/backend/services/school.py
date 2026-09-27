"""Navigating the school's books, and rendering their chapters.

Two jobs. First, turn the nested part/chapter structure in school_crypto.py into
things a page needs: a flat reading order, a previous/next pair, a lookup by
slug. Second, render `body` — which is plain text, not HTML.

WHY THE BODY IS NOT HTML, AND NOT MARKDOWN EITHER
-------------------------------------------------
Not HTML because fifty-five chapters of hand-written tags are unreadable in the
file that holds them, and the point of keeping a curriculum in source is that a
mistake in it can be found and fixed in a diff.

Not markdown because the site's markdown renderer is built for POSTS — it does
reply links, greentext, spoilers and the anti-AI span — and running lesson prose
through it would give `>` at the start of a line a meaning nobody writing a
lesson intends. This renderer handles three constructs and escapes everything
else, which is the whole surface it needs.
"""

from html import escape

from services.school_crypto import BOOK as CRYPTO_BOOK
from services.school_csa import BOOK as CSA_BOOK
from services.school_cyber import BOOK as CYBER_BOOK
from services.school_python import BOOK as PYTHON_BOOK
from services.school_foundations import BOOK as FOUNDATIONS_BOOK
from services.school_hci import BOOK as HCI_BOOK
from services.school_introprog import BOOK as INTROPROG_BOOK
from services.school_webdesign import BOOK as WEBDESIGN_BOOK
from services.school_csp import BOOK as CSP_BOOK
from services.school_solidity import BOOK as SOLIDITY_BOOK

# The subjects on offer. A list rather than a dict so the order on the page is a
# decision rather than whatever the dict iterates as.
# Reading order: foundations first, then the ideas, then a real language,
# then the AP courses, then the specialisms. Somebody arriving with no
# background should be able to start at the top and keep going.
SUBJECTS = [FOUNDATIONS_BOOK, INTROPROG_BOOK, PYTHON_BOOK, WEBDESIGN_BOOK,
            CSP_BOOK, CSA_BOOK, CYBER_BOOK, HCI_BOOK,
            CRYPTO_BOOK, SOLIDITY_BOOK]


def subjects():
    return SUBJECTS


def book(slug):
    for entry in SUBJECTS:
        if entry["slug"] == slug:
            return entry
    return None


def reading_order(subject):
    """Every chapter in the order it should be read, with its part attached.

    The part title travels WITH the chapter because every place that shows a
    chapter also wants to say which part it is from, and re-deriving that from
    the nesting at each call site is how one of them ends up wrong.
    """
    out = []
    for index, part in enumerate(subject["parts"], start=1):
        for number, chapter in enumerate(part["chapters"], start=1):
            out.append({
                "part_number": index,
                "part_title": part["title"],
                "chapter_number": number,
                **chapter,
            })
    return out


def chapter(subject, slug):
    """(chapter, previous, next) or (None, None, None).

    Previous and next cross part boundaries deliberately: it is a book, and the
    end of a part is not the end of the reading.
    """
    order = reading_order(subject)
    for position, entry in enumerate(order):
        if entry["slug"] == slug:
            return (
                entry,
                order[position - 1] if position > 0 else None,
                order[position + 1] if position + 1 < len(order) else None,
            )
    return None, None, None


def total_chapters(subject):
    return sum(len(part["chapters"]) for part in subject["parts"])


# --------------------------------------------------------------- rendering

def render(body):
    """Plain lesson text -> safe HTML.

    Three constructs, and everything else is escaped:

      blank line       paragraph break
      "- " at start    list item
      four spaces      code block, kept verbatim

    Escaping happens FIRST, on the raw text, so nothing in a lesson can inject
    markup — these are trusted authors today, but a renderer that is only safe
    because of who is writing is a renderer that becomes unsafe the moment
    chapters are editable.
    """
    lines = (body or "").strip("\n").split("\n")
    html, paragraph, bullets, code = [], [], [], []

    def flush_paragraph():
        if paragraph:
            html.append("<p>%s</p>" % _inline(" ".join(paragraph)))
            paragraph.clear()

    def flush_bullets():
        if bullets:
            html.append("<ul>%s</ul>"
                        % "".join("<li>%s</li>" % _inline(b) for b in bullets))
            bullets.clear()

    def flush_code():
        if code:
            # Trailing blank lines inside a block are dropped; a code block that
            # ends with whitespace renders as a box with a gap under it.
            while code and not code[-1].strip():
                code.pop()
            html.append("<pre><code>%s</code></pre>"
                        % escape("\n".join(code)))
            code.clear()

    for line in lines:
        if line.startswith("    "):
            flush_paragraph()
            flush_bullets()
            code.append(line[4:])
            continue
        flush_code()

        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_bullets()
            continue
        if stripped.startswith("- "):
            flush_paragraph()
            bullets.append(stripped[2:])
            continue
        # A continuation line of a bullet, indented but not by four.
        if bullets and line.startswith("  "):
            bullets[-1] += " " + stripped
            continue
        flush_bullets()
        paragraph.append(stripped)

    flush_paragraph()
    flush_bullets()
    flush_code()
    return "\n".join(html)


def _inline(text):
    """Escape, then re-allow `code` spans.

    Order matters: escaping after would turn the tags this inserts into visible
    &lt;code&gt;.
    """
    out = escape(text)
    pieces = out.split("`")
    # Odd indices are inside backticks. An unclosed backtick leaves a trailing
    # piece that is simply not marked up, rather than swallowing the rest of the
    # paragraph into a code span.
    if len(pieces) % 2 == 0 and pieces:
        return "`".join(pieces)
    return "".join(
        piece if index % 2 == 0 else "<code>%s</code>" % piece
        for index, piece in enumerate(pieces)
    )


# ---------------------------------------------------------------- progress

def completed_slugs(slip_id, subject_slug):
    """Chapters this slip has marked read. Empty set when signed out."""
    if not slip_id:
        return set()
    try:
        from model.SchoolProgress import SchoolProgress
        from shared import db

        rows = (
            db.session.query(SchoolProgress.chapter_slug)
            .filter(SchoolProgress.slip_id == slip_id,
                    SchoolProgress.subject_slug == subject_slug)
            .all()
        )
        return {row[0] for row in rows}
    except Exception:
        # Reading a book must not fail because progress tracking did.
        from shared import app, db
        db.session.rollback()
        app.logger.exception("school: could not read progress for slip %s", slip_id)
        return set()


def mark_read(slip_id, subject_slug, chapter_slug, read=True):
    """Record or clear a chapter as read. Idempotent."""
    from model.SchoolProgress import SchoolProgress
    from shared import db

    row = (
        db.session.query(SchoolProgress)
        .filter(SchoolProgress.slip_id == slip_id,
                SchoolProgress.subject_slug == subject_slug,
                SchoolProgress.chapter_slug == chapter_slug)
        .one_or_none()
    )
    if read and row is None:
        db.session.add(SchoolProgress(
            slip_id=slip_id, subject_slug=subject_slug, chapter_slug=chapter_slug))
    elif not read and row is not None:
        db.session.delete(row)
    db.session.commit()
