import datetime as _datetime
import math
import re
import uuid


EVENT_GROUPS = {
    "page_navigation": (
        "page_view", "page_visible", "page_hidden", "page_exit", "route_change",
        "session_start", "session_end", "referrer_received", "internal_navigation",
        "external_navigation", "search_submitted", "search_result_clicked",
    ),
    "impression": (
        "thread_impression", "post_impression", "comment_impression", "video_impression",
        "image_impression", "recommendation_impression", "notification_impression",
        "profile_impression",
    ),
    "interaction": (
        "thread_opened", "post_expanded", "comment_opened", "reply_started",
        "reply_submitted", "comment_edited", "comment_deleted", "reaction_added",
        "reaction_removed", "share_clicked", "bookmark_added", "follow_added",
        "follow_removed", "report_submitted", "hide_selected", "not_interested_selected",
    ),
    "media": (
        "video_started", "video_paused", "video_resumed", "video_seeked", "video_completed",
        "video_muted", "video_unmuted", "playback_speed_changed", "image_clicked",
        "image_zoomed", "gallery_advanced", "fullscreen_entered", "fullscreen_exited",
    ),
    "attention": (
        "content_entered_viewport", "content_left_viewport", "active_dwell_started",
        "active_dwell_stopped", "tab_focused", "tab_blurred", "window_idle", "window_active",
    ),
    "recommendation": (
        "recommendation_served", "recommendation_viewed", "recommendation_clicked",
        "recommendation_dismissed", "recommendation_explained", "recommendation_feedback",
    ),
}
EVENT_NAMES = frozenset(name for group in EVENT_GROUPS.values() for name in group)
CONTENT_TYPES = frozenset(("thread", "post", "comment", "video", "image", "recommendation", "search"))
IMPRESSION_EVENTS = frozenset(EVENT_GROUPS["impression"] + ("recommendation_viewed",))
RECOMMENDATION_EVENTS = frozenset(EVENT_GROUPS["recommendation"])

ENVELOPE_FIELDS = frozenset((
    "event_id", "event_name", "event_version", "event_time", "anonymous_id", "session_id",
    "device_session_id", "page_id", "surface", "content_id", "content_type", "author_id",
    "position", "request_id", "model_id", "experiment_ids", "client", "context", "properties",
    "consent",
))
CLIENT_FIELDS = frozenset(("platform", "app_version", "browser_family", "viewport_class"))
CONTEXT_FIELDS = frozenset((
    "authenticated", "entry_source", "network_class", "trust_source", "focused", "visible", "idle",
))
PROPERTY_FIELDS = frozenset((
    "visible_ms", "active_ms", "loaded_ms", "idle_ms", "content_visible_ms", "engaged_ms",
    "visible_ratio", "scroll_ratio", "progress_ratio", "playback_seconds", "playback_rate",
    "user_initiated", "source_category", "interaction_type", "reason", "candidate_item_ids",
    "ranked_item_ids", "positions", "candidate_sources", "feature_version", "eligibility_filters",
    "exclusion_reasons", "score_components", "recommendation_surface", "exploration_propensity",
))
CONSENT_FIELDS = frozenset(("analytics", "personalization", "policy_version"))
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_CLOCK_SKEW_SECONDS = 300
MAX_EVENT_SKEW_SECONDS = 86400


class EventValidationError(ValueError):
    pass


def _bounded_string(value, field, maximum=128, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EventValidationError("%s must be a non-empty string up to %d characters" % (field, maximum))
    return value


def _bounded_identifier(value, field, maximum=128, required=False):
    value = _bounded_string(value, field, maximum, required)
    if value is not None and not ID_RE.match(value):
        raise EventValidationError("%s must be an opaque identifier" % field)
    return value


def _strict_object(value, field, allowed):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise EventValidationError("%s must be an object" % field)
    unknown = set(value) - allowed
    if unknown:
        raise EventValidationError("%s contains unknown fields: %s" % (field, ", ".join(sorted(unknown))))
    return value


def _validate_property_value(key, value):
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, (int, float)):
        if not math.isfinite(value) or abs(value) > 10 ** 12:
            raise EventValidationError("properties.%s is outside the allowed range" % key)
        return
    if isinstance(value, str):
        if len(value) > 128 or not ID_RE.match(value):
            raise EventValidationError("properties.%s must be a bounded identifier" % key)
        return
    if isinstance(value, list):
        if len(value) > 500:
            raise EventValidationError("properties.%s has too many values" % key)
        for item in value:
            if not isinstance(item, (str, int, float, bool)) or isinstance(item, str) and (len(item) > 128 or not ID_RE.match(item)) or isinstance(item, float) and not math.isfinite(item):
                raise EventValidationError("properties.%s contains an invalid value" % key)
        return
    if key == "score_components" and isinstance(value, dict):
        if len(value) > 50 or any(not ID_RE.match(str(name)) or not isinstance(score, (int, float)) for name, score in value.items()):
            raise EventValidationError("properties.score_components must contain bounded numeric scores")
        return
    raise EventValidationError("properties.%s has an invalid type" % key)


def _parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise EventValidationError("event_time must be an ISO-8601 string")
    try:
        parsed = _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EventValidationError("event_time must be a valid ISO-8601 timestamp")
    if parsed.tzinfo is None:
        raise EventValidationError("event_time must include a timezone")
    return parsed.astimezone(_datetime.timezone.utc).replace(tzinfo=None)


def validate_client_event(raw, expected_anonymous_id):
    if not isinstance(raw, dict):
        raise EventValidationError("event must be an object")
    unknown = set(raw) - ENVELOPE_FIELDS
    if unknown:
        raise EventValidationError("unknown envelope fields: %s" % ", ".join(sorted(unknown)))
    try:
        event_id = str(uuid.UUID(str(raw.get("event_id"))))
    except (ValueError, TypeError, AttributeError):
        raise EventValidationError("event_id must be a UUID")
    event_name = raw.get("event_name")
    if event_name not in EVENT_NAMES:
        raise EventValidationError("event_name is not in taxonomy v1")
    if raw.get("event_version") != 1:
        raise EventValidationError("event_version must be 1")
    anonymous_id = raw.get("anonymous_id")
    if anonymous_id != expected_anonymous_id:
        raise EventValidationError("anonymous_id does not match consent subject")
    session_id = _bounded_identifier(raw.get("session_id"), "session_id", 64, required=True)
    surface = _bounded_identifier(raw.get("surface"), "surface", 64, required=True)
    content_type = raw.get("content_type")
    if content_type is not None and content_type not in CONTENT_TYPES:
        raise EventValidationError("content_type is not allowed")
    content_id = _bounded_identifier(raw.get("content_id"), "content_id", 128)
    client = _strict_object(raw.get("client"), "client", CLIENT_FIELDS)
    context = _strict_object(raw.get("context"), "context", CONTEXT_FIELDS)
    properties = _strict_object(raw.get("properties"), "properties", PROPERTY_FIELDS)
    _strict_object(raw.get("consent"), "consent", CONSENT_FIELDS)
    for key, value in client.items():
        _bounded_identifier(value, "client.%s" % key, 64, required=True)
    for key, value in context.items():
        if key in ("authenticated", "focused", "visible", "idle"):
            if not isinstance(value, bool):
                raise EventValidationError("context.%s must be boolean" % key)
        else:
            _bounded_identifier(value, "context.%s" % key, 64, required=True)
    if event_name in IMPRESSION_EVENTS:
        visible_ratio = properties.get("visible_ratio", 0)
        visible_ms = properties.get("visible_ms", 0)
        if not isinstance(visible_ratio, (int, float)) or not isinstance(visible_ms, (int, float)) or visible_ratio < 0.5 or visible_ms < 500:
            raise EventValidationError("impressions require 50% visibility for 500ms")
    if event_name in RECOMMENDATION_EVENTS and not raw.get("request_id"):
        raise EventValidationError("recommendation events require request_id")
    if not isinstance(raw.get("experiment_ids", []), list) or len(raw.get("experiment_ids", [])) > 20:
        raise EventValidationError("experiment_ids must be an array of at most 20 ids")
    for experiment_id in raw.get("experiment_ids", []):
        _bounded_identifier(experiment_id, "experiment_id", 64, required=True)
    for key, value in properties.items():
        _validate_property_value(key, value)
    position = raw.get("position")
    if position is not None and (not isinstance(position, int) or isinstance(position, bool) or position < 0 or position > 10000):
        raise EventValidationError("position must be an integer between 0 and 10000")
    event_time = _parse_time(raw.get("event_time"))
    now = _datetime.datetime.utcnow()
    skew_seconds = abs((now - event_time).total_seconds())
    if skew_seconds > MAX_EVENT_SKEW_SECONDS:
        raise EventValidationError("event_time is outside the accepted 24-hour window")
    return {
        "event_id": event_id,
        "event_name": event_name,
        "event_version": 1,
        "event_time": event_time,
        "anonymous_id": anonymous_id,
        "session_id": session_id,
        "device_session_id": _bounded_identifier(raw.get("device_session_id"), "device_session_id", 64),
        "page_id": _bounded_identifier(raw.get("page_id"), "page_id", 64),
        "surface": surface,
        "content_type": content_type,
        "content_id": content_id,
        "author_id": _bounded_identifier(raw.get("author_id"), "author_id", 128),
        "position": position,
        "request_id": _bounded_identifier(raw.get("request_id"), "request_id", 128),
        "model_id": _bounded_identifier(raw.get("model_id"), "model_id", 64),
        "experiment_ids": raw.get("experiment_ids", []),
        "client": client,
        "context": context,
        "properties": properties,
        "clock_skew": skew_seconds > MAX_CLOCK_SKEW_SECONDS,
    }
