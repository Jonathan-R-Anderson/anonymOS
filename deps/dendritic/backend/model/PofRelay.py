"""Relay storage for receipts and assignment advertisements.

**The site does not verify any of this, and cannot.** A receipt's identity is
keccak256 over its canonical encoding, and this runtime has no keccak
(`hashlib.sha3_256` is SHA3, a different function). Signature checking therefore
happens in the aggregator, which recomputes every hash and rejects anything that
does not verify.

So this is a spool, not an authority: it accepts blobs, caps how much any one
node can push, and hands them to the aggregator to judge. That ordering is fine
because a forged receipt is worthless — settlement re-derives the hash, checks
the provider signature, and requires attestations from the witness set the chain
randomness selected. What the caps protect is disk, not correctness.
"""

import datetime

from shared import db

# A node that floods this would cost us disk, not money. Caps are sized so an
# honest node with a large shard set fits comfortably and a bad one is bounded.
MAX_RECEIPT_BYTES = 64 * 1024
MAX_RECEIPTS_PER_NODE_PER_EPOCH = 5000

# One advertised assignment is about 170 bytes of JSON: two 32-byte hashes as
# hex plus a count and a size. The old 512 KiB cap therefore held roughly 3000
# shards, and the first real node to come along was holding 4185 — so an honest
# node was refused outright with "assignment list is too large" and advertised
# nothing at all, which means nothing to audit and nothing earned. Sized now so
# a node can say what it holds, and bounded by COUNT as well as bytes because
# the count is the number that actually matters and it is the one worth
# reporting back.
MAX_ASSIGNMENTS_PER_NODE = 2000
MAX_ASSIGNMENT_BYTES = 2 * 1024 * 1024


class PofReceipt(db.Model):
    """One signed receipt, stored opaquely for the aggregator to verify."""

    id = db.Column(db.Integer, primary_key=True)
    epoch = db.Column(db.BigInteger, nullable=False, index=True)
    # Canonical receipt hash, hex. Supplied by the node and used only for
    # dedup — the aggregator recomputes it and ignores this if they disagree.
    receipt_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    provider_key = db.Column(db.String(64), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)


class PofAssignment(db.Model):
    """What a node advertises it is holding, for challengers to draw from."""

    id = db.Column(db.Integer, primary_key=True)
    p2p_public_key = db.Column(db.String(64), nullable=False, unique=True, index=True)
    # JSON array of {assignment_id, shard_root, num_chunks, bytes}.
    body = db.Column(db.Text, nullable=False)
    count = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow,
                           onupdate=datetime.datetime.utcnow)


def receipts_for_epoch(epoch, limit=20000):
    return (
        db.session.query(PofReceipt)
        .filter(PofReceipt.epoch == epoch)
        .order_by(PofReceipt.id.asc())
        .limit(limit)
        .all()
    )


def receipt_count_for(provider_key, epoch):
    return (
        db.session.query(PofReceipt.id)
        .filter(PofReceipt.provider_key == provider_key, PofReceipt.epoch == epoch)
        .count()
    )


def receipt_exists(receipt_hash):
    return db.session.query(PofReceipt.id).filter(
        PofReceipt.receipt_hash == receipt_hash).first() is not None


def all_assignments(limit=5000):
    return db.session.query(PofAssignment).limit(limit).all()
