"""Moderator-curated links shown in a board's sidebar ("Bookmarks").

Board staff only: ordinary posters cannot add these. The equivalent of the link
list a subreddit keeps in its sidebar — related boards, wikis, off-site
resources. Managed from the board settings page (blueprints/boards.py).

Every link is rendered as an <a href>, so the URL is validated on the way IN
(http/https only). Without that check a `javascript:` URL saved by a board owner
would be stored XSS against every visitor of the board.
"""
import datetime as _datetime
from urllib.parse import urlparse

from shared import db


MAX_LABEL_LENGTH = 80
MAX_URL_LENGTH = 500
# A sidebar, not a link farm. Also bounds the per-render query.
MAX_BOOKMARKS_PER_BOARD = 25
ALLOWED_SCHEMES = ("http", "https")


class BoardBookmark(db.Model):
    __tablename__ = "board_bookmark"

    id = db.Column(db.Integer, primary_key=True)
    board_id = db.Column(
        db.Integer, db.ForeignKey("board.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label = db.Column(db.String(MAX_LABEL_LENGTH), nullable=False)
    url = db.Column(db.String(MAX_URL_LENGTH), nullable=False)
    sort_order = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)


def normalize_bookmark_url(raw):
    """Return a safe absolute URL, or raise ValueError.

    Bare hosts ("example.com/wiki") are a normal thing to paste, so they get an
    https:// prefix rather than a rejection. Anything whose scheme is not
    http/https after that is refused — notably javascript:, data: and vbscript:,
    which would otherwise execute when a visitor clicked the sidebar link.
    """
    url = (raw or "").strip()
    if not url:
        raise ValueError("Enter the link's address.")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("That address is too long (max %d characters)." % MAX_URL_LENGTH)
    parsed = urlparse(url)
    if not parsed.scheme:
        # Only treat it as a bare host if it actually looks like one; this keeps
        # "javascript:alert(1)" from being rescued into "https://javascript:...".
        if url.startswith("//") or "." not in url.split("/")[0]:
            raise ValueError("Enter a full http:// or https:// address.")
        url = "https://" + url
        parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only http:// and https:// links can be added.")
    if not parsed.netloc:
        raise ValueError("Enter a full http:// or https:// address.")
    return url


def bookmarks_for_board(board_id):
    return (
        db.session.query(BoardBookmark)
        .filter(BoardBookmark.board_id == board_id)
        .order_by(BoardBookmark.sort_order.asc(), BoardBookmark.id.asc())
        .limit(MAX_BOOKMARKS_PER_BOARD)
        .all()
    )


def create_bookmark(board_id, label, url, creator_slip_id=None):
    """Append a bookmark to a board. Raises ValueError with a flashable message."""
    label = (label or "").strip()
    if not label:
        raise ValueError("Enter a name for the link.")
    if len(label) > MAX_LABEL_LENGTH:
        label = label[:MAX_LABEL_LENGTH]
    url = normalize_bookmark_url(url)
    existing = db.session.query(BoardBookmark).filter(BoardBookmark.board_id == board_id).count()
    if existing >= MAX_BOOKMARKS_PER_BOARD:
        raise ValueError("A board can have at most %d bookmarks." % MAX_BOOKMARKS_PER_BOARD)
    highest = (
        db.session.query(db.func.max(BoardBookmark.sort_order))
        .filter(BoardBookmark.board_id == board_id)
        .scalar()
    )
    bookmark = BoardBookmark(
        board_id=board_id,
        label=label,
        url=url,
        sort_order=(highest or 0) + 1,
        created_by_slip_id=creator_slip_id,
    )
    db.session.add(bookmark)
    return bookmark
