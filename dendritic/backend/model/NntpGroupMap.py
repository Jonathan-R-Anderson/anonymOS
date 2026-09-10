"""Maps an NNTPChan newsgroup (overchan.<board>) onto a local board.

Choosing which of a peer's boards to integrate into one of your boards is
exactly a row here: newsgroup -> local board id. Articles pulled from that
newsgroup are imported as posts on that board. A newsgroup can be mapped into
more than one local board, and a board can aggregate several newsgroups.
"""
from shared import db


class NntpGroupMap(db.Model):
    __tablename__ = "nntp_group_map"

    id = db.Column(db.Integer, primary_key=True)
    newsgroup = db.Column(db.String(255), nullable=False)
    board_id = db.Column(
        db.Integer, db.ForeignKey("board.id", ondelete="CASCADE"), nullable=False
    )
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    __table_args__ = (
        db.UniqueConstraint("newsgroup", "board_id", name="uq_nntp_group_board"),
    )


def normalize_newsgroup(name):
    name = (name or "").strip().lower()
    if not name:
        raise ValueError("Newsgroup is required.")
    # Tolerate the operator pasting a bare board name; overchan.* is the content
    # hierarchy in NNTPChan.
    if "." not in name and not name.startswith("overchan"):
        name = "overchan." + name
    return name


def list_group_maps(enabled_only=False):
    query = db.session.query(NntpGroupMap)
    if enabled_only:
        query = query.filter(NntpGroupMap.enabled.is_(True))
    return query.order_by(NntpGroupMap.newsgroup.asc()).all()


def maps_for_board(board_id):
    return (
        db.session.query(NntpGroupMap)
        .filter(NntpGroupMap.board_id == board_id)
        .order_by(NntpGroupMap.newsgroup.asc())
        .all()
    )


def add_group_map(newsgroup, board_id):
    newsgroup = normalize_newsgroup(newsgroup)
    try:
        board_id = int(board_id)
    except (TypeError, ValueError):
        raise ValueError("A target board is required.")
    existing = (
        db.session.query(NntpGroupMap)
        .filter_by(newsgroup=newsgroup, board_id=board_id)
        .one_or_none()
    )
    if existing is not None:
        existing.enabled = True
        db.session.add(existing)
        return existing
    row = NntpGroupMap(newsgroup=newsgroup, board_id=board_id, enabled=True)
    db.session.add(row)
    return row


def remove_group_map(map_id):
    row = db.session.query(NntpGroupMap).get(map_id)
    if row is not None:
        db.session.delete(row)
    return row is not None
