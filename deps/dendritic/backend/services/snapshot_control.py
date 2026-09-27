"""Signed records that tell gateways to stop: revocation and defensive mode.

Two operations that look different and are the same shape — a signed statement,
carrying a sequence so it cannot be rolled back, that changes what gateways do
without needing to reach any of them.

    revocation      "snapshot 8841 must not be served"     (permanent)
    defensive mode  "stop asking the origin until 12:17"   (expiring)

WHY BOTH MUST EXPIRE OR BE MONOTONIC
------------------------------------
A control record is a lever that can be pulled and then lost. Defensive mode
carries a mandatory expiry because a lost control key would otherwise leave the
whole network permanently read-only, and "the site is down because nobody can
find a key" is a worse outage than any it prevents. Revocation is permanent by
nature — the bad snapshot really is bad forever — so it carries a monotonic
sequence instead, and a gateway refuses a revocation list older than the one it
already holds. Without that, replaying an old empty list would un-revoke
everything.

WHY REVOCATION CANNOT BE "DELETE IT"
------------------------------------
A DHT cannot guarantee deletion; peers may be offline, uncooperative, or
hostile. So "revoked" means every cooperative party stops SERVING it, and a
reader's gateway refuses to accept it even if some peer still offers the bytes.
The signature is what makes that enforceable by the reader's side rather than by
the storage's goodwill.

WHAT IS SIGNED
--------------
The publisher key, not the origin content key — same separation and the same
reason as `snapshot_key.py`. A compromised build host can already forge
snapshots; letting it also forge revocations changes nothing. Letting it forge
LIVE responses would.
"""

import datetime
import json

from shared import app

REVOCATION_PREFIX = b"syndichan-revocation:v1"
DEFENSIVE_PREFIX = b"syndichan-defensive:v1"

SETTING_REVOCATIONS = "snapshot_revocations"
SETTING_REVOCATION_SEQ = "snapshot_revocation_sequence"
SETTING_DEFENSIVE = "snapshot_defensive_mode"

# A defensive-mode record may never last longer than this, whatever is asked
# for. The lever must fall back on its own.
MAX_DEFENSIVE_SECONDS = 6 * 3600


def _b64(raw):
    import base64

    return base64.b64encode(raw).decode("ascii")


def _commit(what):
    """Make a control record durable.

    Same trap as the snapshot sequence: set_setting writes to the session, which
    a request flushes at teardown and a background caller does not. A revocation
    that is not committed is a revocation nobody honours, reported as applied.
    """
    from shared import db

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("snapshot control: could not persist %s", what)


def _sign(message):
    from services.snapshot_key import _signing_key

    signer = _signing_key()
    if signer is None:
        return None
    try:
        return _b64(signer.sign(message).signature)
    except Exception:
        app.logger.exception("snapshot control: could not sign a record")
        return None


# -- revocation ------------------------------------------------------------

def revocation_message(sequences, snapshot_ids, sequence, issued_at):
    """The exact bytes a revocation is signed over.

    Both lists are sorted, because a signature over an unordered set is a
    signature over whichever order happened to be produced — and a gateway
    rebuilding the message must get the same bytes.
    """
    return b"\n".join([
        REVOCATION_PREFIX,
        ",".join(str(int(s)) for s in sorted(sequences)).encode("ascii"),
        ",".join(sorted(str(i) for i in snapshot_ids)).encode("ascii"),
        str(int(sequence)).encode("ascii"),
        str(int(issued_at)).encode("ascii"),
    ])


def current_revocations():
    """The published revocation record, or an empty signed-nothing."""
    from model.SiteSetting import get_setting

    try:
        stored = json.loads(get_setting(SETTING_REVOCATIONS, "") or "{}")
    except ValueError:
        stored = {}
    if not stored:
        return {"schema": 1, "revoked_sequences": [], "revoked_snapshot_ids": [],
                "sequence": 0, "issued_at": 0, "signature": None}
    return stored


def revoke(sequences=(), snapshot_ids=(), reason="security"):
    """Publish a revocation covering everything revoked so far, plus these.

    CUMULATIVE, not incremental. A gateway holds one record; if each publication
    listed only the newest revocation, a gateway that missed one would serve a
    snapshot everybody else had stopped serving, and nothing would ever tell it
    otherwise.
    """
    from model.SiteSetting import get_setting, set_setting

    current = current_revocations()
    merged_sequences = sorted({int(s) for s in current.get("revoked_sequences", [])}
                              | {int(s) for s in sequences})
    merged_ids = sorted({str(i) for i in current.get("revoked_snapshot_ids", [])}
                        | {str(i) for i in snapshot_ids})

    try:
        record_sequence = int(get_setting(SETTING_REVOCATION_SEQ, 0) or 0) + 1
    except (TypeError, ValueError):
        record_sequence = 1
    issued_at = int(datetime.datetime.utcnow().timestamp())

    signature = _sign(revocation_message(merged_sequences, merged_ids,
                                         record_sequence, issued_at))
    record = {
        "schema": 1,
        "revoked_sequences": merged_sequences,
        "revoked_snapshot_ids": merged_ids,
        "reason_code": str(reason or "security")[:32],
        "sequence": record_sequence,
        "issued_at": issued_at,
        "signature": signature,
    }
    set_setting(SETTING_REVOCATION_SEQ, str(record_sequence))
    set_setting(SETTING_REVOCATIONS, json.dumps(record))
    _commit("revocation %d" % record_sequence)
    if signature is None:
        app.logger.error("snapshot control: revocation %d is UNSIGNED and no "
                         "gateway will honour it", record_sequence)
    else:
        app.logger.warning("snapshot control: revoked sequences %s (record %d)",
                           merged_sequences, record_sequence)
    return record


def is_revoked(manifest):
    """Whether a manifest is covered by the current revocation record."""
    record = current_revocations()
    if int(manifest.get("sequence") or 0) in set(record.get("revoked_sequences") or []):
        return True
    return str(manifest.get("snapshot_id") or "") in set(
        record.get("revoked_snapshot_ids") or [])


# -- defensive mode --------------------------------------------------------

def defensive_message(mode, reason, issued_at, expires_at, minimum_sequence):
    return b"\n".join([
        DEFENSIVE_PREFIX,
        str(mode or "").encode("ascii"),
        str(reason or "").encode("ascii"),
        str(int(issued_at)).encode("ascii"),
        str(int(expires_at)).encode("ascii"),
        str(int(minimum_sequence or 0)).encode("ascii"),
    ])


def current_defensive_mode():
    """The published defensive-mode record, or None when not in force.

    An expired record is returned as None rather than as an expired record: a
    gateway should not have to remember to check, because the one that forgets
    stays offline after everybody else has come back.
    """
    from model.SiteSetting import get_setting

    try:
        stored = json.loads(get_setting(SETTING_DEFENSIVE, "") or "{}")
    except ValueError:
        return None
    if not stored:
        return None
    if int(stored.get("expires_at") or 0) <= int(datetime.datetime.utcnow().timestamp()):
        return None
    return stored


def declare_defensive_mode(seconds, reason="origin_overload", minimum_sequence=0):
    """Shed traffic to gateways for a bounded time.

    The bound is enforced here rather than trusted from the caller: an operator
    typing an extra zero under pressure should not be able to take the site
    read-only for a week.
    """
    from model.SiteSetting import set_setting

    seconds = max(60, min(int(seconds or 0), MAX_DEFENSIVE_SECONDS))
    issued_at = int(datetime.datetime.utcnow().timestamp())
    expires_at = issued_at + seconds
    record = {
        "schema": 1,
        "mode": "DHT_CACHE_ONLY",
        "reason": str(reason or "")[:64],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "minimum_snapshot_sequence": int(minimum_sequence or 0),
    }
    record["signature"] = _sign(defensive_message(
        record["mode"], record["reason"], issued_at, expires_at,
        record["minimum_snapshot_sequence"]))
    set_setting(SETTING_DEFENSIVE, json.dumps(record))
    _commit("defensive mode")
    app.logger.warning("snapshot control: defensive mode until %d (%s)",
                       expires_at, record["reason"])
    return record


def clear_defensive_mode():
    """End defensive mode early. Expiry still applies if this never runs."""
    from model.SiteSetting import set_setting

    set_setting(SETTING_DEFENSIVE, "")
    _commit("defensive mode cleared")
    app.logger.warning("snapshot control: defensive mode cleared")
