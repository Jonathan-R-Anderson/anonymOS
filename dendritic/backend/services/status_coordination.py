"""Verifying probe reports from monitor nodes.

Same identity as the storage heartbeat: an Ed25519 signature over the exact
request body, made by the key the node id is derived from. Reusing that scheme
rather than inventing a second one means a monitor is just a node with another
role, and there is one way to be a node rather than two.

WHY SIGNING IS NOT OPTIONAL HERE
--------------------------------
These reports drive a PUBLIC page. Anybody able to post unsigned results could
manufacture an outage on it, or — worse and quieter — flood it with successes
and bury a real one, since a component's state is a ratio over recent probes.

WHY THE BODY IS SIGNED RATHER THAN A DIGEST OF IT
-------------------------------------------------
The signature covers the bytes that arrived. Signing a digest the sender
computed would let the sender choose what the signature attests to.
"""

import json
import time

from nacl.exceptions import BadSignatureError

# Room for a monitor reporting every component in one post, with detail
# strings, and nothing like enough to be worth using as a write primitive.
MAX_BODY_BYTES = 32768

# Matches the heartbeat's tolerance. A replayed report older than this is
# refused, so a captured post cannot be used later to contradict the present.
MAX_CLOCK_SKEW_SECONDS = 300

# One post per monitor covers every component; more than this is either a bug
# or somebody trying to make the rollup say what they want.
MAX_RESULTS = 64


def validate_probe_report(raw_body, node_header, signature_header):
    """Parse and verify one report. Raises PermissionError or ValueError.

    Returns {"node_id": str, "results": [{"key", "ok", "latency_ms", "detail"}]}.
    """
    from services.storage_coordination import _decode_unpadded, peer_verify_key

    if raw_body is None or len(raw_body) > MAX_BODY_BYTES:
        raise ValueError("probe report is too large")
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("probe report is not valid JSON")
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("unsupported probe report version")

    node_id = str(payload.get("node_id") or "")
    if not node_id:
        raise ValueError("probe report has no node id")
    # The header and the body must agree. Trusting only the header would let a
    # signed body be replayed under another name; trusting only the body would
    # mean the routing layer and the signature disagree about who this is.
    if node_id != str(node_header or ""):
        raise PermissionError("probe report node identity mismatch")

    try:
        signature = _decode_unpadded(signature_header)
        peer_verify_key(node_id).verify(raw_body, signature)
    except (BadSignatureError, ValueError, TypeError):
        raise PermissionError("invalid probe report signature")

    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        raise ValueError("probe report has no timestamp")
    if abs(int(time.time()) - timestamp) > MAX_CLOCK_SKEW_SECONDS:
        raise ValueError("probe report timestamp is outside the allowed clock skew")

    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError("probe report has no results")
    if len(results) > MAX_RESULTS:
        raise ValueError("probe report has too many results")

    known = _known_component_keys()
    cleaned = []
    for entry in results:
        if not isinstance(entry, dict):
            raise ValueError("probe result is not an object")
        key = str(entry.get("key") or "")
        # Only components we asked about. Without this, a monitor could invent
        # a component and it would appear on the public page as though the
        # operator had chosen to publish it.
        if key not in known:
            continue
        ok = entry.get("ok")
        if not isinstance(ok, bool):
            raise ValueError("probe result 'ok' must be true or false")
        latency = entry.get("latency_ms")
        if latency is not None:
            if not isinstance(latency, int) or isinstance(latency, bool) or latency < 0:
                raise ValueError("probe result latency is not a whole number of ms")
            # A day is not a latency. Clamped rather than refused so one broken
            # clock does not throw away a whole report.
            latency = min(latency, 86_400_000)
        cleaned.append({
            "key": key,
            "ok": ok,
            "latency_ms": latency,
            "detail": str(entry.get("detail") or "")[:300],
        })

    if not cleaned:
        raise ValueError("probe report matched no known component")
    return {"node_id": node_id, "results": cleaned}


def _known_component_keys():
    from model.Status import StatusComponent
    from shared import db

    return {
        row.key for row in
        db.session.query(StatusComponent.key)
        .filter(StatusComponent.enabled.is_(True))
        .all()
    }
