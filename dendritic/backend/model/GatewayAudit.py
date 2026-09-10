"""Audit receipts: durable evidence that a gateway served authentic content.

Phase 1 lets a reader DETECT tampering. On its own that changes nothing — the
reader closes the tab and the gateway carries on. This is the record that makes
detection consequential: every verified fetch, and every failed one, becomes an
attributable fact about a specific gateway key.

WHAT A RECEIPT IS NOT
---------------------
It is not a claim about a gateway's honesty. It is one observation by one
observer, and observers lie: a competing gateway would happily report its rivals
as corrupt, and a malicious gateway would report itself as flawless. So a receipt
records WHO OBSERVED WHAT, and nothing here treats a single receipt as a verdict.
Turning receipts into reputation needs corroboration, which is phase 4 and needs
independent validators that do not exist yet.

What this phase does is make sure the evidence exists and is attributable when
that day comes — because evidence not collected today cannot be corroborated
tomorrow.

DEDUPLICATION IS THE WHOLE INTEGRITY STORY
------------------------------------------
Without a key, one honest fetch can be replayed a thousand times to farm
standing, and one failure can be replayed to destroy a competitor. The unique
constraint on (gateway, object_key, version, observer) is what makes a receipt
worth exactly one observation, which is what it is.
"""

import datetime as _datetime

from shared import db

RESULT_PASS = "pass"
RESULT_MISMATCH = "mismatch"    # served bytes did not match the origin signature
RESULT_STALE = "stale"          # authentic, but an older version than already seen
RESULT_UNSIGNED = "unsigned"    # no signature offered at all

RESULTS = (RESULT_PASS, RESULT_MISMATCH, RESULT_STALE, RESULT_UNSIGNED)


class GatewayAudit(db.Model):
    __tablename__ = "gateway_audit"

    id = db.Column(db.Integer, primary_key=True)

    # The gateway's libp2p peer ID — which IS its Ed25519 public key, in the
    # encoding the controller registers under (services/gateway_identity.py
    # reads the key back out). Reputation attaches to this and never to an IP:
    # an operator who changes ISP keeps their standing, and one who changes IP
    # to escape a bad record does not escape anything.
    #
    # Case matters. Base58 is case-sensitive, so this column stores the identity
    # verbatim; folding it would turn a real key into a string that decodes to
    # nothing.
    gateway = db.Column(db.String(64), nullable=False, index=True)

    # Was this a gateway the controller had verified when the observation was
    # made? Recorded rather than resolved on read, so that unregistering does
    # not retroactively turn a report about a real gateway into a report about
    # nobody.
    gateway_registered = db.Column(db.Boolean, nullable=False, default=False)

    # The gateway the observer arrived through, when this observation came from
    # auditing a DIFFERENT one. Two gateways disagreeing is a fact about a pair,
    # and recording only the accused half loses which comparison produced it.
    #
    # It is not an accusation against either. The origin signature says which
    # one was right; this says who was in the room.
    peer_gateway = db.Column(db.String(64), nullable=True, index=True)

    object_key = db.Column(db.String(255), nullable=False, index=True)
    version = db.Column(db.BigInteger, nullable=False, default=0)
    object_hash = db.Column(db.String(64), nullable=False, default="")

    result = db.Column(db.String(16), nullable=False, default=RESULT_PASS, index=True)
    latency_ms = db.Column(db.Integer, nullable=True)

    # Who observed it. A client audit and a validator audit are the same shape
    # but carry very different weight, and conflating them would let anyone
    # manufacture validator-grade evidence.
    observer = db.Column(db.String(64), nullable=False, default="", index=True)
    observer_kind = db.Column(db.String(16), nullable=False, default="client")
    observer_signature = db.Column(db.String(128), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)

    __table_args__ = (
        # One observation per observer per object version per gateway. Replay a
        # receipt and it is the same row, which is the point: standing must not
        # be farmable by repetition, in either direction.
        db.UniqueConstraint("gateway", "object_key", "version", "observer",
                            name="uq_gateway_audit_observation"),
    )


def record(gateway, object_key, version, object_hash, result,
           observer="", observer_kind="client", latency_ms=None,
           observer_signature=None, gateway_registered=False,
           peer_gateway=None):
    """Store one observation. Returns (row, created).

    A duplicate is not an error and not a second data point — it is the same
    observation arriving twice, which is what a retrying browser does.
    """
    if result not in RESULTS:
        result = RESULT_UNSIGNED

    existing = (
        db.session.query(GatewayAudit)
        .filter(GatewayAudit.gateway == gateway,
                GatewayAudit.object_key == object_key,
                GatewayAudit.version == version,
                GatewayAudit.observer == observer)
        .one_or_none()
    )
    if existing is not None:
        return existing, False

    row = GatewayAudit(
        gateway=gateway, object_key=object_key[:255], version=int(version or 0),
        object_hash=(object_hash or "")[:64], result=result,
        observer=observer[:64], observer_kind=observer_kind[:16],
        latency_ms=latency_ms, observer_signature=(observer_signature or "")[:128] or None,
        gateway_registered=bool(gateway_registered),
        peer_gateway=(peer_gateway or None) and str(peer_gateway)[:64],
    )
    db.session.add(row)
    try:
        db.session.commit()
    except Exception:
        # Lost a race with an identical observation; the constraint did its job.
        db.session.rollback()
        return existing, False
    return row, True


def summary_for(gateway, since=None):
    """What is known about one gateway. Counts, deliberately, not a score.

    A score here would be a verdict drawn from uncorroborated reports, and a
    single observer — a rival, or the gateway itself — must not be able to
    produce one. Scoring waits for validator quorum.
    """
    from sqlalchemy import func

    query = db.session.query(GatewayAudit.result, func.count(GatewayAudit.id))
    query = query.filter(GatewayAudit.gateway == gateway)
    if since is not None:
        query = query.filter(GatewayAudit.created_at >= since)
    counts = {result: 0 for result in RESULTS}
    for result, count in query.group_by(GatewayAudit.result).all():
        counts[result] = int(count)

    # Distinct observers matters more than the raw total: a thousand reports
    # from one source is one source's opinion.
    observers = (
        db.session.query(func.count(func.distinct(GatewayAudit.observer)))
        .filter(GatewayAudit.gateway == gateway).scalar()
    )
    # Was this ever seen as a registered gateway? An identity that has only ever
    # been reported ON, and never seen registering, is most likely one somebody
    # invented — worth showing, and not worth treating as a peer.
    registered = (
        db.session.query(func.count(GatewayAudit.id))
        .filter(GatewayAudit.gateway == gateway,
                GatewayAudit.gateway_registered.is_(True)).scalar()
    )
    from services.gateway_identity import node_key_hex

    return {
        "gateway": gateway,
        # The same key as the node's PoF identity, so an audit and a storage
        # receipt about one machine can be recognised as being about one machine.
        "node_key": node_key_hex(gateway),
        "counts": counts,
        "observations": sum(counts.values()),
        "distinct_observers": int(observers or 0),
        "registered_observations": int(registered or 0),
    }


def recent(limit=100):
    return (
        db.session.query(GatewayAudit)
        .order_by(GatewayAudit.id.desc())
        .limit(limit)
        .all()
    )


def gateways_seen(limit=100):
    from sqlalchemy import func

    from services.gateway_identity import node_key_hex

    rows = (
        db.session.query(GatewayAudit.gateway,
                         func.count(GatewayAudit.id),
                         func.count(func.distinct(GatewayAudit.observer)),
                         func.max(func.cast(GatewayAudit.gateway_registered,
                                            db.Integer)))
        .group_by(GatewayAudit.gateway)
        .order_by(func.count(GatewayAudit.id).desc())
        .limit(limit)
        .all()
    )
    return [{"gateway": g, "observations": int(n), "distinct_observers": int(o),
             "node_key": node_key_hex(g), "ever_registered": bool(r)}
            for g, n, o, r in rows]


def audits_by_node_key():
    """Observation counts keyed by the node's hex Ed25519 key.

    The join that binds this table to reputation. A node signs its PoF
    registration and its gateway registration with the same ``p2p.key``, so
    converting the peer ID gives exactly the key ``services/reputation.py``
    already scores — one operator with one record, rather than two rows that
    happen to be the same machine.

    Only observations of REGISTERED gateways are counted. An identity nobody
    ever registered is not a peer whose standing is being described; letting one
    in would mean anybody could attach counts to a key they do not own.
    """
    from sqlalchemy import func

    from services.gateway_identity import node_key_hex

    rows = (
        db.session.query(GatewayAudit.gateway, GatewayAudit.result,
                         func.count(GatewayAudit.id),
                         func.count(func.distinct(GatewayAudit.observer)))
        .filter(GatewayAudit.gateway_registered.is_(True))
        .group_by(GatewayAudit.gateway, GatewayAudit.result)
        .all()
    )
    keyed = {}
    for gateway, result, count, observers in rows:
        node_key = node_key_hex(gateway)
        if not node_key:
            continue
        entry = keyed.setdefault(node_key, {"counts": {r: 0 for r in RESULTS},
                                            "observers": 0})
        entry["counts"][result] = entry["counts"].get(result, 0) + int(count)
        entry["observers"] = max(entry["observers"], int(observers))
    return keyed
