import datetime as _datetime
import hashlib
import secrets
from urllib.parse import urlparse

from board_sources import canonical_thread_url
from model.OutboundReply import (
    OutboundReply,
    STATUS_READY,
    STATUS_REMOTE_OPEN,
    STATUS_SUBMITTED,
    STATUS_WAITING,
)
from model.Slip import get_slip
from model.SubmissionError import SubmissionError
from post import get_ip_address, prepare_submission
from services.outbound_quote import (
    normalized_body_digest,
    normalized_idempotency_key,
    translate_source_quotes,
)
from services.source_adapters import adapter_by_id, adapter_for_source
from shared import db
from sqlalchemy.exc import IntegrityError


OUTBOUND_DRAFT_TTL_MINUTES = 30
HANDOFF_CAPABILITY_TTL_MINUTES = 5


EXTENSION_EVENTS = {
    "form_ready",
    "challenge_present",
    "user_submitted",
    "submission_error",
    "form_not_found",
}


def issue_handoff_capability(reply):
    adapter = adapter_for_source(reply.source_type, reply.source_url)
    if adapter is None:
        raise ValueError("No browser extension adapter is enabled for this source.")
    secret = secrets.token_urlsafe(32)
    now = _datetime.datetime.utcnow()
    reply.handoff_secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    reply.handoff_expires_at = now + _datetime.timedelta(minutes=HANDOFF_CAPABILITY_TTL_MINUTES)
    reply.handoff_consumed_at = None
    reply.adapter_id = adapter.id
    reply.adapter_version = adapter.version
    reply.transport = "browser_extension"
    reply.event_secret_hash = None
    reply.event_sequence = 0
    db.session.add(reply)
    db.session.commit()
    return secret, adapter


def consume_handoff_capability(public_id, secret):
    secret_hash = hashlib.sha256(str(secret or "").encode("utf-8")).hexdigest()
    event_secret = secrets.token_urlsafe(32)
    event_secret_hash = hashlib.sha256(event_secret.encode("utf-8")).hexdigest()
    now = _datetime.datetime.utcnow()
    updated = (
        db.session.query(OutboundReply)
        .filter(
            OutboundReply.public_id == public_id,
            OutboundReply.handoff_secret_hash == secret_hash,
            OutboundReply.handoff_consumed_at.is_(None),
            OutboundReply.handoff_expires_at.isnot(None),
            OutboundReply.handoff_expires_at > now,
            OutboundReply.status.in_((STATUS_READY, STATUS_REMOTE_OPEN)),
        )
        .update(
            {
                OutboundReply.handoff_consumed_at: now,
                OutboundReply.event_secret_hash: event_secret_hash,
                OutboundReply.event_sequence: 0,
            },
            synchronize_session=False,
        )
    )
    if updated != 1:
        db.session.rollback()
        return None, None
    db.session.commit()
    reply = (
        db.session.query(OutboundReply)
        .filter(OutboundReply.public_id == public_id)
        .one_or_none()
    )
    adapter = adapter_by_id(reply.adapter_id, reply.adapter_version) if reply is not None else None
    if adapter is None or not adapter.matches(reply.source_type, reply.source_url):
        return None, None
    return reply, event_secret


def record_extension_event(public_id, event_secret, sequence, event_type, detail=None):
    if event_type not in EXTENSION_EVENTS:
        return None, "invalid_event"
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        return None, "invalid_sequence"
    event_hash = hashlib.sha256(str(event_secret or "").encode("utf-8")).hexdigest()
    reply = (
        db.session.query(OutboundReply)
        .filter(
            OutboundReply.public_id == public_id,
            OutboundReply.event_secret_hash == event_hash,
        )
        .with_for_update()
        .one_or_none()
    )
    if reply is None:
        return None, "invalid_event_token"
    if (
        reply.expires_at is not None
        and reply.expires_at <= _datetime.datetime.utcnow()
    ):
        return None, "expired_event_token"
    if sequence <= int(reply.event_sequence or 0):
        return None, "stale_event"
    adapter = adapter_by_id(reply.adapter_id, reply.adapter_version)
    if adapter is None or not adapter.matches(reply.source_type, reply.source_url):
        return None, "adapter_mismatch"

    reply.event_sequence = sequence
    if event_type in ("form_ready", "challenge_present"):
        if reply.status == STATUS_REMOTE_OPEN:
            reply.transition_to(STATUS_WAITING)
    elif event_type == "user_submitted":
        if reply.status == STATUS_REMOTE_OPEN:
            reply.transition_to(STATUS_WAITING)
        if reply.status == STATUS_WAITING:
            reply.transition_to(STATUS_SUBMITTED)
    elif event_type in ("submission_error", "form_not_found"):
        reply.last_error_code = event_type
        reply.last_error_detail = str(detail or "")[:512] or None
    db.session.add(reply)
    db.session.commit()
    return reply, None


def source_thread_url(thread):
    try:
        url = canonical_thread_url(
            thread.source_type,
            thread.source_name,
            str(thread.source_thread_id),
        )
    except ValueError:
        url = (thread.source_url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise SubmissionError("This imported thread does not have a safe source URL.", thread.board)
    if thread.source_type not in ("4chan", "8chan", "7chan", "reddit"):
        expected_host = (thread.source_type or "").strip().lower()
        actual_host = (parsed.hostname or "").strip().lower()
        if expected_host and actual_host != expected_host and not actual_host.endswith("." + expected_host):
            raise SubmissionError("The imported thread source host does not match its URL.", thread.board)
    return url


def create_outbound_reply(thread, args):
    if thread.source_type == "local" or not thread.source_thread_id:
        raise SubmissionError("Only imported threads can forward replies.", thread.board)

    args["body"] = translate_source_quotes(args.get("body") or "", args.get("source_quote_map"))
    prepared = prepare_submission(thread, args, include_media=False)
    poster_id = prepared["poster"].id
    slip = get_slip()
    now = _datetime.datetime.utcnow()
    body_digest = normalized_body_digest(args["body"])
    idempotency_key = normalized_idempotency_key(args.get("idempotency_key"))
    existing = (
        db.session.query(OutboundReply)
        .filter(
            OutboundReply.poster_id == poster_id,
            OutboundReply.idempotency_key == idempotency_key,
        )
        .one_or_none()
    )
    if existing is not None:
        if existing.thread_id != thread.id or existing.body_digest != body_digest:
            raise SubmissionError("This reply submission key was already used for different content.", thread.board)
        db.session.commit()
        return existing
    reply = OutboundReply(
        thread_id=thread.id,
        board_id=thread.board,
        poster_id=poster_id,
        slip_id=slip.id if slip is not None else None,
        source_type=thread.source_type,
        source_name=thread.source_name,
        source_thread_id=str(thread.source_thread_id),
        source_url=source_thread_url(thread),
        body=args["body"],
        body_digest=body_digest,
        subject=args.get("subject"),
        author_name=(args.get("name") or "").strip()[:128] or None,
        observed_client_ip=get_ip_address(),
        status=STATUS_READY,
        idempotency_key=idempotency_key,
        created_at=now,
        expires_at=now + _datetime.timedelta(minutes=OUTBOUND_DRAFT_TTL_MINUTES),
    )
    db.session.add(reply)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = (
            db.session.query(OutboundReply)
            .filter(
                OutboundReply.poster_id == poster_id,
                OutboundReply.idempotency_key == idempotency_key,
            )
            .one_or_none()
        )
        if existing is None or existing.thread_id != thread.id or existing.body_digest != body_digest:
            raise
        return existing
    return reply
