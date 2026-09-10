import datetime as _datetime
import uuid

from flask import has_request_context, session

from model.Analytics import AnalyticsConsent, AnalyticsDeletion
from model.Slip import get_slip
from shared import db


SUBJECT_SESSION_KEY = "analytics-subject-id"
POLICY_VERSION = "2026-07-19"


def current_consent():
    if not has_request_context():
        return None
    slip = get_slip()
    subject_id = session.get(SUBJECT_SESSION_KEY)
    query = db.session.query(AnalyticsConsent)
    consent = query.filter(AnalyticsConsent.subject_id == subject_id).one_or_none() if subject_id else None
    if slip is not None and (consent is None or consent.slip_id != slip.id):
        consent = (
            query.filter(AnalyticsConsent.slip_id == slip.id)
            .order_by(AnalyticsConsent.updated_at.desc(), AnalyticsConsent.id.desc())
            .first()
        )
        if consent is not None:
            session[SUBJECT_SESSION_KEY] = consent.subject_id
    return consent


def consent_payload(consent=None):
    consent = consent if consent is not None else current_consent()
    return {
        "analytics": bool(consent and consent.analytics),
        "personalization": bool(consent and consent.personalization),
        "policy_version": consent.policy_version if consent else POLICY_VERSION,
        "anonymous_id": consent.subject_id if consent and consent.analytics else None,
    }


def set_consent(analytics, personalization=False):
    consent = current_consent()
    slip = get_slip()
    now = _datetime.datetime.utcnow()
    if consent is None:
        consent = AnalyticsConsent(
            subject_id=str(uuid.uuid4()),
            slip_id=slip.id if slip is not None else None,
            policy_version=POLICY_VERSION,
        )
        db.session.add(consent)
    elif slip is not None and consent.slip_id is None:
        consent.slip_id = slip.id
    was_enabled = bool(consent.analytics or consent.personalization)
    consent.analytics = bool(analytics)
    consent.personalization = bool(personalization and analytics)
    consent.policy_version = POLICY_VERSION
    consent.updated_at = now
    consent.withdrawn_at = None if consent.analytics else now
    session[SUBJECT_SESSION_KEY] = consent.subject_id
    if was_enabled and not consent.analytics:
        db.session.add(AnalyticsDeletion(
            id=str(uuid.uuid4()),
            subject_id=consent.subject_id,
            slip_id=consent.slip_id,
        ))
    db.session.commit()
    return consent


def queue_deletion(consent=None):
    consent = consent or current_consent()
    if consent is None:
        return None
    pending = (
        db.session.query(AnalyticsDeletion)
        .filter(
            AnalyticsDeletion.subject_id == consent.subject_id,
            AnalyticsDeletion.status == "pending",
        )
        .first()
    )
    if pending is not None:
        return pending
    deletion = AnalyticsDeletion(
        id=str(uuid.uuid4()),
        subject_id=consent.subject_id,
        slip_id=consent.slip_id,
    )
    db.session.add(deletion)
    db.session.commit()
    return deletion
