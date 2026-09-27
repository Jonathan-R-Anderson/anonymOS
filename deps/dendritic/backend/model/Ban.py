import datetime as _datetime

from sqlalchemy import or_

from shared import db


def _utcnow():
    return _datetime.datetime.utcnow()


# Duration keys offered in the ban UI -> timedelta (None == permanent). Ordered
# for display via BAN_DURATION_CHOICES below.
_DURATIONS = {
    "permanent": None,
    "1h": _datetime.timedelta(hours=1),
    "6h": _datetime.timedelta(hours=6),
    "1d": _datetime.timedelta(days=1),
    "3d": _datetime.timedelta(days=3),
    "1w": _datetime.timedelta(weeks=1),
    "2w": _datetime.timedelta(weeks=2),
    "30d": _datetime.timedelta(days=30),
    "90d": _datetime.timedelta(days=90),
}

BAN_DURATION_CHOICES = [
    ("permanent", "Permanent"),
    ("1h", "1 hour"),
    ("6h", "6 hours"),
    ("1d", "1 day"),
    ("3d", "3 days"),
    ("1w", "1 week"),
    ("2w", "2 weeks"),
    ("30d", "30 days"),
    ("90d", "90 days"),
]


def expiry_from_duration(duration):
    """Map a duration key from the ban form to an expires_at datetime.

    Returns None for a permanent ban (or an unknown/blank key)."""
    if not duration or duration == "permanent":
        return None
    delta = _DURATIONS.get(duration)
    if delta is None:
        return None
    return _utcnow() + delta


class Ban(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(255), nullable=False, unique=True)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)
    # NULL = permanent. Otherwise the ban stops applying once utcnow() passes it.
    expires_at = db.Column(db.DateTime, nullable=True)

    @property
    def is_permanent(self):
        return self.expires_at is None

    @property
    def is_active(self):
        return self.expires_at is None or self.expires_at > _utcnow()


class BoardBan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id"), nullable=False)
    ip_address = db.Column(db.String(255), nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("board_id", "ip_address", name="uq_board_ban_board_ip"),
    )

    @property
    def is_permanent(self):
        return self.expires_at is None

    @property
    def is_active(self):
        return self.expires_at is None or self.expires_at > _utcnow()


def _ban_row(ip_address):
    """The raw Ban row for an IP regardless of expiry (used to create/update)."""
    return db.session.query(Ban).filter(Ban.ip_address == ip_address).one_or_none()


def get_ban(ip_address):
    """Active (non-expired) sitewide ban for an IP, or None. Enforcement uses this."""
    ban = _ban_row(ip_address)
    if ban is not None and ban.is_active:
        return ban
    return None


def ban_ip(ip_address, reason=None, created_by_slip_id=None, expires_at=None):
    ban = _ban_row(ip_address)
    if ban is None:
        ban = Ban(
            ip_address=ip_address,
            reason=reason,
            created_by_slip_id=created_by_slip_id,
            expires_at=expires_at,
        )
    else:
        ban.reason = reason
        ban.created_by_slip_id = created_by_slip_id
        ban.expires_at = expires_at
        ban.created_at = _utcnow()
    db.session.add(ban)
    return ban


def unban_ip(ip_address):
    ban = _ban_row(ip_address)
    if ban is not None:
        db.session.delete(ban)
    return ban


def get_board_ban(board_id, ip_address):
    ban = (
        db.session.query(BoardBan)
        .filter(BoardBan.board_id == board_id, BoardBan.ip_address == ip_address)
        .one_or_none()
    )
    if ban is not None and ban.is_active:
        return ban
    return None


def _board_ban_row(board_id, ip_address):
    return (
        db.session.query(BoardBan)
        .filter(BoardBan.board_id == board_id, BoardBan.ip_address == ip_address)
        .one_or_none()
    )


def list_board_bans(board_id):
    return (
        db.session.query(BoardBan)
        .filter(BoardBan.board_id == board_id)
        .order_by(BoardBan.created_at.desc(), BoardBan.id.desc())
        .all()
    )


def ban_ip_for_board(board_id, ip_address, reason=None, created_by_slip_id=None, expires_at=None):
    ban = _board_ban_row(board_id, ip_address)
    if ban is None:
        ban = BoardBan(
            board_id=board_id,
            ip_address=ip_address,
            reason=reason,
            created_by_slip_id=created_by_slip_id,
            expires_at=expires_at,
        )
    else:
        ban.reason = reason
        ban.created_by_slip_id = created_by_slip_id
        ban.expires_at = expires_at
        ban.created_at = _utcnow()
    db.session.add(ban)
    return ban


def purge_expired_bans():
    """Delete rows whose expiry has passed. Enforcement already ignores expired
    bans (get_ban/get_board_ban), so this is just housekeeping."""
    now = _utcnow()
    removed = (
        db.session.query(Ban)
        .filter(Ban.expires_at.isnot(None), Ban.expires_at <= now)
        .delete(synchronize_session=False)
    )
    removed += (
        db.session.query(BoardBan)
        .filter(BoardBan.expires_at.isnot(None), BoardBan.expires_at <= now)
        .delete(synchronize_session=False)
    )
    return removed
