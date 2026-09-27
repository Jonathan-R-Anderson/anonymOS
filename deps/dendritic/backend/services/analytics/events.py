import datetime as _datetime
import uuid

from flask import has_request_context, session

from model.Analytics import AnalyticsEvent, AnalyticsIngestIssue
from model.Slip import get_slip
from shared import app, db
from .consent import consent_payload, current_consent
from .spec import CONTENT_TYPES, EVENT_NAMES, ID_RE, PROPERTY_FIELDS, EventValidationError, _validate_property_value


def record_ingest_issue(category, event_name=None, count=1, commit=True):
    db.session.add(AnalyticsIngestIssue(
        category=str(category)[:32],
        event_name=str(event_name)[:64] if event_name else None,
        count=max(1, int(count)),
    ))
    if commit:
        db.session.commit()


def emit_server_event(event_name, surface, content_type=None, content_id=None, properties=None,
                      request_id=None, model_id=None, position=None, experiment_ids=None):
    """Best-effort authoritative event emission for a consented current viewer."""
    if not has_request_context():
        return None
    consent = current_consent()
    if consent is None or not consent.analytics:
        return None
    properties = properties or {}
    try:
        if event_name not in EVENT_NAMES:
            raise EventValidationError("server event name is not in taxonomy v1")
        if not isinstance(surface, str) or not ID_RE.match(surface):
            raise EventValidationError("server event surface is invalid")
        if content_type is not None and content_type not in CONTENT_TYPES:
            raise EventValidationError("server event content type is invalid")
        unknown = set(properties) - PROPERTY_FIELDS
        if unknown:
            raise EventValidationError("server event contains unknown properties")
        for key, value in properties.items():
            _validate_property_value(key, value)
    except EventValidationError as exc:
        app.logger.error("analytics: rejected invalid server event %s: %s", event_name, exc)
        return None
    slip = get_slip()
    now = _datetime.datetime.utcnow()
    event = AnalyticsEvent(
        event_id=str(uuid.uuid4()),
        event_name=event_name,
        event_version=1,
        event_time=now,
        received_time=now,
        anonymous_id=consent.subject_id,
        slip_id=slip.id if slip is not None else consent.slip_id,
        session_id="server:%s" % consent.subject_id,
        surface=str(surface)[:64],
        content_type=content_type,
        content_id=str(content_id)[:128] if content_id is not None else None,
        position=position,
        request_id=str(request_id)[:128] if request_id else None,
        model_id=str(model_id)[:64] if model_id else None,
        experiment_ids=list(experiment_ids or [])[:20],
        client={"platform": "server", "app_version": "phase5"},
        context={"authenticated": slip is not None, "trust_source": "server"},
        properties=properties,
        consent=consent_payload(consent),
    )
    try:
        db.session.add(event)
        db.session.commit()
        from .features import update_online_profile
        update_online_profile([event], consent)
        try:
            from services.recommendations.advanced import update_realtime_sequence
            update_realtime_sequence([event], consent)
        except Exception:
            db.session.rollback()
            app.logger.exception("recommendations: real-time sequence update failed")
        return event
    except Exception:
        db.session.rollback()
        app.logger.exception("analytics: failed to emit server event %s", event_name)
        return None
