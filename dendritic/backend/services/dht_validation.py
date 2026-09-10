"""Prove offloaded media is actually retrievable BEFORE anything is deleted.

This exists because the obvious check is misleading. Reading an offloaded object
goes to the storage node's S3 gateway, and that gateway serves from its OWN
LOCAL shard store first -- `FetchShard` only reaches out to peers for a shard it
does not already hold. So a green readback mostly proves "the server node still
has the bytes", which is exactly the thing you are about to stop relying on.

Hence two tiers, and only the second one justifies deleting anything:

  TIER 1  integrity_check()   -- does every offloaded object read back, and do
                                the bytes still hash to what the database
                                recorded? Catches truncation, corruption and
                                rows marked offloaded whose object is absent.
                                Non-destructive and safe to run any time.

  TIER 2  see module note below -- do the bytes survive when the node's local
                                copy is NOT available? That is the only check
                                that proves the NETWORK holds the data.

WHY TIER 2 IS NOT A FUNCTION HERE
---------------------------------
It cannot be done from the backend. The local shard store lives in the storage
node's pod on its own PVC; this process can only talk to the S3 gateway, which
is precisely the layer that hides the distinction. Tier 2 has to quarantine
shards inside that pod and re-read, which is an operational procedure.

It also cannot be done by removing ONE shard. Objects are erasure-coded 6+3, so
any 6 of the 9 shards reconstruct the chunk locally and the read succeeds
without a single byte crossing the network -- proving nothing. Forcing a remote
fetch means making fewer than 6 shards of some chunk available locally.

And note what tier 2 can prove today: with a single volunteer connected, and
that volunteer behind NAT (dial-in only), "the network has it" is true only
while that peer happens to be connected. Treat a tier-2 pass as evidence about
one peer, not about a resilient network.
"""
import hashlib

from shared import app, db


def _offloaded_query():
    from model.Media import Media

    return db.session.query(Media).filter(Media.dht_offloaded_at.isnot(None))


def integrity_check(limit=None, offset=0, verbose=False):
    """TIER 1. Read every offloaded object back and verify its digest.

    Returns counts by outcome plus the ids that failed, so a caller can act on
    them rather than just learn that something is wrong.
    """
    import services.media_read as media_read

    from model.Media import Media

    query = _offloaded_query().order_by(Media.id.asc()).offset(offset)
    if limit:
        query = query.limit(limit)
    rows = query.all()

    result = {
        "examined": 0, "ok": 0, "unreadable": 0,
        "digest_mismatch": 0, "no_recorded_digest": 0, "error": 0,
        "failed_ids": [],
    }
    for media in rows:
        result["examined"] += 1
        try:
            data = media_read.attachment_bytes(media.id, media.ext)
        except Exception:
            result["error"] += 1
            result["failed_ids"].append(media.id)
            if verbose:
                app.logger.exception("validate: read raised for media %s", media.id)
            continue
        if not data:
            # Marked offloaded but the object is not there. This is the case
            # that would silently become permanent data loss after a purge.
            result["unreadable"] += 1
            result["failed_ids"].append(media.id)
            continue
        if not media.sha256:
            # Readable, but nothing recorded to compare against. Counted apart
            # from "ok" so a run of these cannot be mistaken for verification.
            result["no_recorded_digest"] += 1
            continue
        if hashlib.sha256(data).hexdigest() != media.sha256:
            result["digest_mismatch"] += 1
            result["failed_ids"].append(media.id)
            continue
        result["ok"] += 1
    # Keep the payload small when a whole run goes wrong.
    result["failed_ids"] = result["failed_ids"][:200]
    return result


def replication_status():
    """How many independent copies could exist right now.

    Tier 1 says the bytes are readable; this says how much of that is the
    server's own node. If peers is 0, every offloaded object exists in exactly
    one place and a purge would leave no redundancy at all.
    """
    from services.storage_offload import dht_enabled
    from services import storage_coordination

    status = {"dht_enabled": dht_enabled(), "active_nodes": None, "capacity_bytes": None}
    try:
        status["bootstrap_peers"] = len(storage_coordination.bootstrap_peers())
    except Exception:
        status["bootstrap_peers"] = None
    try:
        from model.StorageNode import StorageNode
        import datetime

        cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=900)
        status["active_nodes"] = (
            db.session.query(StorageNode)
            .filter(StorageNode.last_seen_at >= cutoff)
            .count()
        )
    except Exception:
        db.session.rollback()
    return status


def purge_readiness(sample=None, tier2_attestation=None):
    """One call that answers: is it safe to delete the local copies yet?

    Deliberately conservative -- it refuses on anything it could not verify,
    because the cost of a false 'ready' is unrecoverable and the cost of a false
    'not ready' is running it again later.
    """
    integrity = integrity_check(limit=sample)
    replication = replication_status()
    blockers = []
    if integrity["examined"] == 0:
        blockers.append("nothing offloaded to verify")
    for key in ("unreadable", "digest_mismatch", "error"):
        if integrity[key]:
            blockers.append("%s=%d" % (key, integrity[key]))
    if integrity["no_recorded_digest"]:
        blockers.append(
            "no_recorded_digest=%d (readable but unverified)"
            % integrity["no_recorded_digest"]
        )
    if not replication.get("active_nodes"):
        blockers.append("no volunteer node has reported in recently")
    # Tier 1 passing cannot make this True. Every check above is satisfied by
    # the storage node simply still holding the bytes locally, which is the
    # condition a purge removes -- so without a tier-2 result this function
    # must refuse, or its name promises more than it verified.
    if not tier2_attestation:
        blockers.append(
            "TIER 2 NOT RUN: no evidence the bytes survive without the storage "
            "node's local copy (see module docstring)"
        )
    return {
        "ready": not blockers,
        "blockers": blockers,
        "tier2_attestation": tier2_attestation,
        "integrity": integrity,
        "replication": replication,
    }
