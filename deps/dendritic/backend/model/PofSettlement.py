"""Settled epochs and the claim proofs they produce.

The roots here are a convenience copy: the chain is the authority, and anyone
can re-derive all of this by running pof-settle over the same receipts. What the
site adds is distribution — a node needs its Merkle proof to call
RewardDistributor.claim, and asking every operator to run an aggregator just to
learn their own proof would make claiming the privilege of people who can
compile Go.

Stored before submission on purpose. Computing a settlement and posting it are
separate decisions, and an operator should be able to look at what a run
produced — including who it refused to pay and why — before spending gas on it.
"""

import datetime
import json

from shared import db


class PofSettlement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    epoch = db.Column(db.BigInteger, nullable=False, unique=True, index=True)
    receipt_root = db.Column(db.String(66), nullable=False)
    reward_root = db.Column(db.String(66), nullable=False)
    node_state_root = db.Column(db.String(66), nullable=False)
    randomness = db.Column(db.String(66), nullable=False)
    # Decimal wei as text: the amounts exceed a 64-bit column and rounding a
    # reward to fit would be a silent theft.
    total_rewards = db.Column(db.String(80), nullable=False, default="0")
    accepted = db.Column(db.Integer, nullable=False, default=0)
    rejected = db.Column(db.Integer, nullable=False, default=0)
    rejections = db.Column(db.Text, nullable=False, default="[]")
    claims = db.Column(db.Text, nullable=False, default="[]")
    submitted_tx = db.Column(db.String(80), nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def claim_rows(self):
        try:
            rows = json.loads(self.claims or "[]")
        except ValueError:
            return []
        return rows if isinstance(rows, list) else []


def settlement_for_epoch(epoch):
    return (
        db.session.query(PofSettlement)
        .filter(PofSettlement.epoch == epoch)
        .one_or_none()
    )


def latest_settlements(limit=50):
    return (
        db.session.query(PofSettlement)
        .order_by(PofSettlement.epoch.desc())
        .limit(limit)
        .all()
    )


def claim_for_node(epoch, node_id):
    """The claim row for one node, or None.

    Node ids are compared lowercase-hex with the 0x optional, because the value
    reaches us from a wallet, a CLI and a config file and they do not agree on
    formatting.
    """
    record = settlement_for_epoch(epoch)
    if record is None:
        return None, None
    wanted = (node_id or "").strip().lower()
    if wanted.startswith("0x"):
        wanted = wanted[2:]
    for row in record.claim_rows():
        candidate = str(row.get("node_id") or "").strip().lower()
        if candidate.startswith("0x"):
            candidate = candidate[2:]
        if candidate == wanted:
            return record, row
    return record, None
