import datetime as _datetime
import uuid

from shared import db


STATUS_READY = "ready_for_handoff"
STATUS_REMOTE_OPEN = "remote_page_open"
STATUS_WAITING = "waiting_for_user"
STATUS_SUBMITTED = "submitted_unconfirmed"
STATUS_CONFIRMED = "confirmed"
STATUS_AMBIGUOUS = "ambiguous"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"

TERMINAL_STATUSES = {STATUS_CONFIRMED, STATUS_FAILED}

_ALLOWED_TRANSITIONS = {
    STATUS_READY: {STATUS_REMOTE_OPEN, STATUS_FAILED, STATUS_EXPIRED},
    STATUS_REMOTE_OPEN: {STATUS_WAITING, STATUS_SUBMITTED, STATUS_FAILED, STATUS_EXPIRED},
    STATUS_WAITING: {STATUS_SUBMITTED, STATUS_FAILED, STATUS_EXPIRED},
    STATUS_SUBMITTED: {STATUS_CONFIRMED, STATUS_AMBIGUOUS, STATUS_FAILED},
    STATUS_AMBIGUOUS: {STATUS_READY, STATUS_CONFIRMED, STATUS_FAILED},
    STATUS_EXPIRED: {STATUS_FAILED},
}


def new_public_id():
    return uuid.uuid4().hex


class OutboundReply(db.Model):
    """A visitor-originated reply waiting to be submitted on an imported source.

    This row is deliberately not a Post. The normal scraper will eventually
    import a successfully submitted reply, avoiding a local/remote duplicate.
    """

    __tablename__ = "outbound_reply"

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(32), nullable=False, unique=True, index=True, default=new_public_id)
    thread_id = db.Column(db.Integer, db.ForeignKey("thread.id", ondelete="CASCADE"), nullable=False, index=True)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id", ondelete="CASCADE"), nullable=False, index=True)
    poster_id = db.Column(db.Integer, db.ForeignKey("poster.id", ondelete="CASCADE"), nullable=False, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id", ondelete="SET NULL"), nullable=True, index=True)

    source_type = db.Column(db.String(128), nullable=False)
    source_name = db.Column(db.String(64), nullable=True)
    source_thread_id = db.Column(db.String(128), nullable=False)
    source_url = db.Column(db.Text, nullable=False)

    body = db.Column(db.String(4096), nullable=False)
    body_digest = db.Column(db.String(64), nullable=True)
    subject = db.Column(db.String(64), nullable=True)
    author_name = db.Column(db.String(128), nullable=True)
    observed_client_ip = db.Column(db.String(255), nullable=False)

    status = db.Column(db.String(32), nullable=False, default=STATUS_READY, server_default=STATUS_READY, index=True)
    transport = db.Column(db.String(32), nullable=False, default="manual_handoff", server_default="manual_handoff")
    source_post_id = db.Column(db.String(128), nullable=True)
    source_post_url = db.Column(db.Text, nullable=True)
    last_error_code = db.Column(db.String(64), nullable=True)
    last_error_detail = db.Column(db.String(512), nullable=True)
    attempt_count = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    idempotency_key = db.Column(db.String(64), nullable=True)
    handoff_secret_hash = db.Column(db.String(64), nullable=True)
    handoff_expires_at = db.Column(db.DateTime, nullable=True)
    handoff_consumed_at = db.Column(db.DateTime, nullable=True)
    adapter_id = db.Column(db.String(64), nullable=True)
    adapter_version = db.Column(db.String(32), nullable=True)
    event_secret_hash = db.Column(db.String(64), nullable=True)
    event_sequence = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    handoff_at = db.Column(db.DateTime, nullable=True)
    claimed_submitted_at = db.Column(db.DateTime, nullable=True)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    failed_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        db.UniqueConstraint(
            "poster_id",
            "idempotency_key",
            name="uq_outbound_reply_poster_idempotency",
        ),
    )

    def transition_to(self, next_status):
        if next_status == self.status:
            return
        allowed = _ALLOWED_TRANSITIONS.get(self.status, set())
        if next_status not in allowed:
            raise ValueError("Invalid outbound reply transition: %s -> %s" % (self.status, next_status))
        now = _datetime.datetime.utcnow()
        self.status = next_status
        if next_status == STATUS_REMOTE_OPEN:
            self.handoff_at = now
            self.attempt_count = int(self.attempt_count or 0) + 1
        elif next_status == STATUS_SUBMITTED:
            self.claimed_submitted_at = now
        elif next_status == STATUS_CONFIRMED:
            self.confirmed_at = now
        elif next_status == STATUS_FAILED:
            self.failed_at = now
