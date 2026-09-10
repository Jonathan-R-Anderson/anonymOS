"""Why an epoch has not settled, answered without building a Go binary.

There have been receipts and no settlements for the entire life of this network,
and the reason was reachable only by compiling `pof-settle` and running it by
hand. So the visible state was "0 settlements" with no explanation, which reads
as a broken pipeline and is not one.

It is not broken. Settlement computes correctly and refuses honestly: every
receipt is rejected because the witness pool is too small to draw a valid set.
A storage claim needs 5 witnesses drawn from candidates OTHER than the provider,
so it takes six participating nodes before a single receipt can be settled, and
there are two.

WHAT THIS MODULE IS FOR
-----------------------
Turning that from a mystery into a number. It answers, per epoch, "could this
settle, and if not what is missing" — using the same thresholds the aggregator
uses, so the answer here and the answer there cannot disagree.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not settle. Settlement decides money and belongs in the audited Go
aggregator where a challenger can re-run it against the same inputs and get the
same roots. A second implementation that also computed rewards would be a second
thing to keep correct, and the two disagreeing would be worse than having only
one.
"""

# Witness thresholds from roadmap §5, restated to match
# proof-of-facilitation/aggregator/witness.go ThresholdFor(). Higher-value
# claims demand larger sets: a DHT ping is cheap to re-check, a Docker job is
# not.
THRESHOLDS = {
    "dht": (2, 3),
    "gateway": (3, 5),
    "storage": (3, 5),
    "docker_worker": (4, 7),
    "bandwidth": (2, 3),
    "load_balancer": (2, 3),
    "audit": (3, 5),
}
DEFAULT_THRESHOLD = (3, 5)


def witnesses_required(service):
    """How many witnesses one claim of this service needs."""
    return THRESHOLDS.get(str(service or "").lower(), DEFAULT_THRESHOLD)[1]


def candidate_pool():
    """Nodes eligible to witness: registered on-chain, with non-zero weight.

    Mirrors the aggregator's rule, including the bootstrap floor — a node with
    no stake still weighs something while the network is young, or a new network
    could never draw its first witness set and would deadlock at zero.
    """
    from model.PofRegistration import PofPayout, PofRegistration, STATUS_SUBMITTED
    from shared import db

    rows = (db.session.query(PofRegistration)
            .filter(PofRegistration.status == STATUS_SUBMITTED).all())
    payouts = {p.p2p_public_key: (p.payout or "").lower()
               for p in db.session.query(PofPayout).all()}
    pool = []
    for row in rows:
        key = (row.p2p_public_key or "").lower()
        if key:
            pool.append({"key": key, "owner": payouts.get(key, "")})
    return pool


def epoch_readiness(limit=10):
    """Per-epoch: how many receipts, and whether they could settle at all."""
    from sqlalchemy import func

    from model.PofRelay import PofReceipt
    from model.PofSettlement import PofSettlement
    from shared import db

    pool = candidate_pool()
    owners = {entry["owner"] for entry in pool if entry["owner"]}
    settled = {row.epoch for row in db.session.query(PofSettlement).all()}

    rows = (db.session.query(PofReceipt.epoch, func.count(PofReceipt.id))
            .group_by(PofReceipt.epoch)
            .order_by(PofReceipt.epoch.desc())
            .limit(limit).all())

    # The provider is never eligible to witness its own claim, so the usable
    # pool for any single receipt is one smaller than the pool itself.
    usable = max(len(pool) - 1, 0)
    required = witnesses_required("storage")

    epochs = []
    for epoch, count in rows:
        blocked = None
        if usable < required:
            blocked = (
                "The witness pool has %d node(s); a storage claim needs %d "
                "witnesses other than the provider, so %d participating nodes "
                "are required before any receipt in this epoch can settle."
                % (len(pool), required, required + 1))
        epochs.append({
            "epoch": int(epoch),
            "receipts": int(count),
            "settled": epoch in settled,
            "can_settle": blocked is None,
            "blocked_by": blocked,
        })
    return {
        "candidates": len(pool),
        "distinct_owners": len(owners),
        "witnesses_required": required,
        "nodes_required": required + 1,
        "epochs": epochs,
        # Independence is reported separately from size because they fail
        # differently and are fixed differently: more machines fixes one, more
        # PEOPLE fixes the other, and a pool of six owned by one operator would
        # satisfy the arithmetic while corroborating nothing.
        "independent_owners_note": (
            "All candidates share one owner." if len(owners) <= 1 else None),
    }
