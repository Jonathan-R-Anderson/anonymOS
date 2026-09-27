"""Node reputation, computed from what actually happened.

Roadmap §12 scores nodes on a trust graph rather than on self-description: a
storage proof accepted is worth a little, a verified challenge more, a failure
costs, and being caught cheating costs enormously. Those weights are the whole
policy, so they live here as data instead of scattered through the arithmetic.

Reputation is DERIVED, never stored as a number someone can edit. It is
recomputed from receipts and settlement rejections every time it is asked for,
which means there is no reputation field to tamper with and no migration to run
when the weights change — and it stays honest about its own inputs: a node with
no history scores neutral rather than well.

Scores are per NODE, not per person. A wallet may own several nodes and a slip
may own several wallets, so a profile shows the sum of what its nodes have
earned; the network page shows nodes individually, which is the unit that
actually did the work.
"""

import datetime
import json

from model.PofRegistration import PofPayout
from model.PofRelay import PofReceipt
from model.PofSettlement import PofSettlement
from shared import db

# §12 trust-graph weights.
WEIGHTS = {
    "proof_accepted": 1.0,      # a storage/service proof that verified
    "challenge_verified": 5.0,  # an audit this node performed and confirmed
    "proof_failed": -0.3,       # could not prove what it claimed
    "fraud": -20.0,             # a receipt rejected as fabricated
    "cheating": -100.0,         # attestations from a witness set nobody drew
}

# A new node is neither trusted nor suspect. Starting at zero would make the
# first honest node indistinguishable from one that has just been caught.
BASELINE = 50.0
MAX_SCORE = 100.0
MIN_SCORE = 0.0

# Rejection reasons that indicate dishonesty rather than bad luck. An offline
# node and a lying node must not be scored the same way.
DISHONEST_REASONS = {
    "attestations came from witnesses the protocol did not select": "cheating",
    "duplicate receipt hash": "fraud",
    "provider signature invalid": "fraud",
    "provider witnessed its own receipt": "cheating",
}
NEUTRAL_REASONS = {
    "witness pool too small to draw a valid set",   # network's fault, not the node's
    "provider has no payout address in NodeRegistry",
    "receipt belongs to a different epoch",
}


def _blank():
    return {"proof_accepted": 0, "challenge_verified": 0, "proof_failed": 0,
            "fraud": 0, "cheating": 0}


# Roadmap §17: standing fades without work. An event counts fully on the day it
# happens and is worth ~0.995x of that per day afterwards, so a node that stops
# contributing drifts back toward the baseline instead of coasting forever on a
# good week from last year.
#
# Applied to CREDIT and to PENALTIES alike. Decaying only the good half would
# turn the passage of time into a way to launder a bad record: get caught, wait,
# come back clean. A node that was caught cheating must serve the same clock as
# one that proved storage.
DAILY_DECAY = 0.995

# Below this an event is worth so little that carrying it only costs arithmetic.
# ~0.995^1500 — about four years.
DECAY_FLOOR = 0.0005


def _decay(event_time, now=None):
    """How much an event that happened at `event_time` is still worth."""
    if event_time is None:
        # No timestamp is not "infinitely old" — a missing date should not
        # silently erase a node's record. Count it at full value and let the
        # data be fixed rather than the score be quietly wrong.
        return 1.0
    reference = now or datetime.datetime.utcnow()
    days = (reference - event_time).total_seconds() / 86400.0
    if days <= 0:
        return 1.0
    weight = DAILY_DECAY ** days
    return weight if weight >= DECAY_FLOOR else 0.0


def node_events(now=None):
    """Weighted scoring events per node key, from receipts and settlements.

    Counts are FLOATS because each event is discounted by its age. A node with
    three fresh proofs and one with three from last year should not present the
    same number, and the only way to say so is to stop counting in integers.
    """
    events = {}

    def bucket(key):
        return events.setdefault(key, _blank())

    # Accepted receipts: the provider proved something, and whoever witnessed it
    # performed a verified challenge.
    for receipt in db.session.query(PofReceipt).all():
        provider = (receipt.provider_key or "").lower()
        if not provider:
            continue
        weight = _decay(receipt.created_at, now)
        if weight <= 0:
            continue
        bucket(provider)["proof_accepted"] += weight
        try:
            body = json.loads(receipt.body or "{}")
        except ValueError:
            continue
        for witness in (body.get("witnesses") or []):
            # Witness keys arrive base64-encoded in the receipt body; they are
            # counted by that form since it is what identifies them here.
            key = str(witness.get("pub") or "")
            if key:
                bucket(key)["challenge_verified"] += weight

    # Settlement rejections: why work was refused, and whether that reflects on
    # the node or on the network around it.
    for settlement in db.session.query(PofSettlement).all():
        try:
            reasons = json.loads(settlement.rejections or "[]")
        except ValueError:
            continue
        for entry in reasons:
            text = str(entry).lower()
            if any(neutral in text for neutral in NEUTRAL_REASONS):
                continue
            for reason, kind in DISHONEST_REASONS.items():
                if reason in text:
                    # Rejections are summarised per epoch rather than per node,
                    # so this cannot yet be attributed to a specific node. It is
                    # counted at the network level and shown as such rather than
                    # blamed on whoever happens to be listed.
                    bucket("__network__")[kind] += 1
                    break
    return events


def score_for(counts):
    """Turn event counts into a 0-100 score.

    Only the events in WEIGHTS count. Anything else in ``counts`` is ignored by
    construction rather than by discipline, which is what keeps gateway audits
    (below) out of the score even if somebody later merges the two dicts.
    """
    total = BASELINE
    for key, weight in WEIGHTS.items():
        total += weight * counts.get(key, 0)
    return max(MIN_SCORE, min(MAX_SCORE, total))


def gateway_audits():
    """Audit observations per node key — attributed, and deliberately unscored.

    This is the binding the gateway-validation roadmap asks for: an audit names
    a gateway by peer ID, a node registers for PoF by hex key, and both are the
    same ``p2p.key``. So an operator has ONE record covering what their machine
    stored and what it served, instead of two that nobody can connect.

    WHY THESE DO NOT MOVE THE SCORE
    -------------------------------
    Every other event here was verified by this server: a receipt it checked, a
    settlement it ran. An audit was reported by a stranger over an open endpoint.
    Anyone can claim a gateway served them a forgery, and a gateway can claim it
    served everyone perfectly, so folding audits into the score would let any
    passer-by set another operator's standing — the exact property the score
    exists to deny.

    Roadmap §16 asks for audits to be scored alongside storage receipts. They
    are — but only through ``corroborated_audit_events`` below, which requires an
    independent quorum first. Raw observations still never move a score.

    They are attributed and shown because evidence not collected today cannot be
    corroborated tomorrow. Turning corroborated audits into score needs
    independent validators to disagree with each other, which is phase 4.
    """
    try:
        from model.GatewayAudit import audits_by_node_key

        return audits_by_node_key()
    except Exception:
        # A node page must not fail because the audit table is missing or a
        # migration has not run yet. No audits is the honest default.
        return {}


def corroborated_audit_events(now=None):
    """Audit findings that survived an independent quorum, as scoring events.

    Roadmap §16: audits should count for something, or running a gateway
    honestly earns nothing and the whole layer is charity. This is the path by
    which they do — and the gate in front of it is the entire reason it is safe.

    A finding counts ONLY when ``services/gateway_quorum`` returns a verdict it
    marked independent, meaning enough distinct operators across enough distinct
    networks agreed. On a one-operator network nothing qualifies, so this
    contributes nothing today and starts contributing by itself the day other
    people run validators.

    Mapped onto the EXISTING §12 weights rather than new ones. A gateway proven
    to have served altered bytes has been caught fabricating, which the trust
    graph already prices at `fraud`; inventing a parallel penalty scale would
    mean two numbers that have to be kept in agreement about how bad lying is.
    """
    from model.GatewayAudit import gateways_seen
    from services.gateway_identity import node_key_hex
    from services.gateway_quorum import (VERDICT_CLEAN, VERDICT_STALE,
                                         VERDICT_TAMPERED, VERDICT_UNSIGNED,
                                         evaluate_gateway)

    # Serving altered bytes is fabrication. Serving stale content, or stripping
    # signatures, is a failure to prove what was claimed — bad, and not the same
    # accusation.
    outcomes = {
        VERDICT_CLEAN: "proof_accepted",
        VERDICT_TAMPERED: "fraud",
        VERDICT_STALE: "proof_failed",
        VERDICT_UNSIGNED: "proof_failed",
    }
    events = {}
    try:
        seen = gateways_seen(limit=200)
    except Exception:
        return events
    for entry in seen:
        gateway = entry.get("gateway") or ""
        node_key = node_key_hex(gateway)
        if not node_key or not entry.get("ever_registered"):
            continue
        try:
            verdict = evaluate_gateway(gateway)
        except Exception:
            continue
        if not verdict.get("independent"):
            continue
        kind = outcomes.get(verdict.get("verdict"))
        if kind:
            events.setdefault(node_key, _blank())[kind] += 1
    return events


def registered_keys():
    """Nodes on-chain, whether or not they have done anything yet.

    Included so the page reflects the NETWORK rather than only its history. A
    node that registered an hour ago and has not been audited yet is a real
    participant sitting at the baseline; showing an empty page instead reads as
    "nobody is running this", which is a different and false statement.
    """
    from model.PofRegistration import PofRegistration, STATUS_SUBMITTED

    return [
        (record.p2p_public_key or "").lower()
        for record in db.session.query(PofRegistration)
        .filter(PofRegistration.status == STATUS_SUBMITTED)
        .all()
        if record.p2p_public_key
    ]


def node_reputations():
    """Every known node, best first. Registered-but-idle nodes sit at baseline."""
    events = node_events()
    payouts = {p.p2p_public_key: p.payout for p in db.session.query(PofPayout).all()}
    audits = gateway_audits()
    # §16: corroborated findings join the same weights as storage work, so one
    # score covers everything a node did rather than two that have to be read
    # together. Uncorroborated observations still never reach here.
    for key, counts in corroborated_audit_events().items():
        target = events.setdefault(key, _blank())
        for kind, value in counts.items():
            target[kind] += value

    keys = {key for key in events if key != "__network__"}
    keys.update(registered_keys())
    # A machine that has only ever served as a gateway still belongs on this
    # list. Leaving it off would say "this node has done nothing", when what it
    # has done is the half of the work this page did not used to look at.
    keys.update(audits)

    rows = []
    for key in keys:
        counts = events.get(key, _blank())
        # Weighted, not counted: these are decayed event values, so a node
        # with old work shows less than one with the same work done today.
        total = sum(counts.values())
        observed = audits.get(key)
        rows.append({
            "key": key,
            "short": key[:16] + "…" if len(key) > 16 else key,
            "payout": payouts.get(key),
            "score": score_for(counts),
            "counts": counts,
            "events": round(total, 2),
            # Served-content observations, kept in their own field rather than
            # merged into `counts`. The separation is the safeguard: `counts`
            # is what score_for reads, and these were reported by strangers.
            "audits": observed["counts"] if observed else None,
            "audit_observers": observed["observers"] if observed else 0,
            # Distinguished from a score of 50 that was EARNED: one is "not yet
            # judged", the other is "judged, and it came out neutral".
            # Decayed-to-nothing is not the same as never-judged: a node whose
            # entire history has aged out is back to "we do not currently know",
            # which is exactly what the baseline means.
            "unjudged": total <= 0,
        })
    rows.sort(key=lambda r: (-r["score"], -r["events"], r["key"]))
    return rows


def reputation_for_wallet(wallet):
    """Combined standing of every node paying out to a wallet.

    Returns None when that wallet operates no nodes, which is different from
    scoring zero: most people run none, and showing them a bad score would be
    meaningless.
    """
    if not wallet:
        return None
    target = wallet.lower()
    mine = [r for r in node_reputations() if (r["payout"] or "").lower() == target]
    if not mine:
        return None
    return {
        "nodes": len(mine),
        "score": round(sum(r["score"] for r in mine) / len(mine), 1),
        "events": sum(r["events"] for r in mine),
        "detail": mine,
    }


def network_summary():
    rows = node_reputations()
    return {
        "nodes": len(rows),
        "average": round(sum(r["score"] for r in rows) / len(rows), 1) if rows else None,
        "events": sum(r["events"] for r in rows),
    }
