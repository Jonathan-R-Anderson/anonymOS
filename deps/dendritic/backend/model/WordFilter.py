import datetime as _datetime
import re

from sqlalchemy import or_

from shared import db


MAX_WORD_FILTER_PATTERN_LENGTH = 128
MAX_WORD_FILTER_REPLACEMENT_LENGTH = 512


class WordFilterBoard(db.Model):
    __tablename__ = "word_filter_board"

    word_filter_id = db.Column(
        db.Integer,
        db.ForeignKey("word_filter.id", ondelete="CASCADE"),
        primary_key=True,
    )
    board_id = db.Column(
        db.Integer,
        db.ForeignKey("board.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )


class WordFilter(db.Model):
    __tablename__ = "word_filter"

    id = db.Column(db.Integer, primary_key=True)
    pattern = db.Column(db.String(MAX_WORD_FILTER_PATTERN_LENGTH), nullable=False)
    replacement = db.Column(db.String(MAX_WORD_FILTER_REPLACEMENT_LENGTH), nullable=False, default="")
    case_sensitive = db.Column(db.Boolean, nullable=False, default=False)
    whole_word = db.Column(db.Boolean, nullable=False, default=True)
    is_global = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True)
    created_by_sysop = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    board_scopes = db.relationship(
        "WordFilterBoard",
        cascade="all, delete-orphan",
        lazy="select",
        order_by="WordFilterBoard.board_id",
    )

    @property
    def board_ids(self):
        return [scope.board_id for scope in self.board_scopes]


def normalize_word_filter(pattern, replacement):
    pattern = (pattern or "").strip()
    replacement = replacement or ""
    if not pattern:
        raise ValueError("Enter a word or phrase to filter.")
    if len(pattern) > MAX_WORD_FILTER_PATTERN_LENGTH:
        raise ValueError("Wordfilter matches can be at most %d characters." % MAX_WORD_FILTER_PATTERN_LENGTH)
    if len(replacement) > MAX_WORD_FILTER_REPLACEMENT_LENGTH:
        raise ValueError(
            "Wordfilter replacements can be at most %d characters."
            % MAX_WORD_FILTER_REPLACEMENT_LENGTH
        )
    return pattern, replacement


def apply_filter_rules(text, rules):
    """Apply literal wordfilter rules in creation order.

    A callable replacement is intentional: backslashes in an administrator's
    replacement are literal text rather than regular-expression backreferences.
    """

    result = text or ""
    for rule in rules:
        escaped = re.escape(rule.pattern)
        if rule.whole_word:
            escaped = r"(?<!\w)" + escaped + r"(?!\w)"
        flags = 0 if rule.case_sensitive else re.IGNORECASE
        expression = re.compile(escaped, flags)
        replacement = rule.replacement
        result = expression.sub(lambda _match, value=replacement: value, result)
    return result


def word_filters_for_board(board_id):
    return (
        db.session.query(WordFilter)
        .outerjoin(WordFilterBoard, WordFilterBoard.word_filter_id == WordFilter.id)
        .filter(or_(WordFilter.is_global.is_(True), WordFilterBoard.board_id == board_id))
        .distinct()
        .order_by(WordFilter.id.asc())
        .all()
    )


def apply_word_filters(text, board_id):
    if not text:
        return text or ""
    return apply_filter_rules(text, word_filters_for_board(board_id))


def create_word_filter(
    *, pattern, replacement, board_ids=(), is_global=False,
    case_sensitive=False, whole_word=True, creator_slip_id=None,
    created_by_sysop=False,
):
    pattern, replacement = normalize_word_filter(pattern, replacement)
    normalized_board_ids = sorted({int(board_id) for board_id in board_ids})
    if not is_global and not normalized_board_ids:
        raise ValueError("Choose at least one board for this wordfilter.")
    word_filter = WordFilter(
        pattern=pattern,
        replacement=replacement,
        case_sensitive=bool(case_sensitive),
        whole_word=bool(whole_word),
        is_global=bool(is_global),
        created_by_slip_id=creator_slip_id,
        created_by_sysop=bool(created_by_sysop),
    )
    db.session.add(word_filter)
    db.session.flush()
    if not is_global:
        for board_id in normalized_board_ids:
            word_filter.board_scopes.append(
                WordFilterBoard(word_filter_id=word_filter.id, board_id=board_id)
            )
    return word_filter


__all__ = [
    "WordFilter",
    "WordFilterBoard",
    "apply_filter_rules",
    "apply_word_filters",
    "create_word_filter",
    "normalize_word_filter",
    "word_filters_for_board",
]
