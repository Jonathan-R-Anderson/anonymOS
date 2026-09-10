"""Tips: sending AXONCoins to a post, a comment, or a streamer.

ONE TABLE FOR EVERY TARGET
--------------------------
A tip to a post, a tip to a reply and a tip to a live streamer are the same
event with a different subject, so they are one table keyed by (target_type,
target_id) rather than three. Three tables would mean three balance queries,
three refund paths and three places for the arithmetic to drift apart — and the
arithmetic is the part that must not drift, because it is somebody's money.

WHY THE AMOUNT IS AN INTEGER
----------------------------
Atomic units, never a float. Binary floating point cannot represent most decimal
token amounts exactly, and a rounding error in a ledger is not a display bug —
it is value that appears or disappears.

WHY A TIP IS IMMUTABLE
----------------------
There is no edit path and no soft delete. A tip that could be altered after the
fact is not a record of anything: the recipient saw a number and acted on it.
Reversals, if they are ever needed, are a second row in the other direction, so
the history remains what actually happened rather than what somebody last
decided it should look like.
"""

import datetime

from shared import db

# Target kinds. Strings rather than an enum so a new target type does not need a
# migration — the constraint that matters is that a (type, id) pair resolves,
# and that is checked in the service where the models are known.
TARGET_POST = "post"
TARGET_STREAM = "stream"

TARGET_KINDS = (TARGET_POST, TARGET_STREAM)


class Tip(db.Model):
    __tablename__ = "tip"

    id = db.Column(db.Integer, primary_key=True)

    # Who sent it. Nullable because an anonymous tip is a legitimate thing to
    # allow later; the sender is still charged, they are simply not displayed.
    from_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True, index=True)

    # Who receives it. Recorded at tip time rather than resolved through the
    # target later: a post can be moved or a stream can change hands, and the
    # person who earned the tip is the one who held it when it was sent.
    to_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True, index=True)

    target_type = db.Column(db.String(16), nullable=False, index=True)
    target_id = db.Column(db.String(64), nullable=False, index=True)

    amount = db.Column(db.BigInteger, nullable=False)

    # A short public note. Optional, length-capped, and shown next to the tip —
    # which is exactly why it is treated as untrusted display text everywhere it
    # is rendered.
    memo = db.Column(db.String(140), nullable=True)

    # Anonymous hides the sender in the UI. It does NOT hide them from the
    # operator, and the difference is stated here so nobody builds a privacy
    # claim on it: this is a display preference, not the payment privacy the
    # channel layer will eventually provide.
    anonymous = db.Column(db.Boolean, nullable=False, default=False, server_default="false")

    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.datetime.utcnow, index=True
    )

    __table_args__ = (
        db.Index("ix_tip_target", "target_type", "target_id"),
    )

    def to_dict(self, viewer_is_recipient=False):
        """Public shape. Hides the sender when they asked to be hidden.

        `viewer_is_recipient` does NOT reveal an anonymous sender either. A
        streamer who could unmask anonymous tippers would make the option
        meaningless the first time somebody relied on it.
        """
        return {
            "id": self.id,
            "amount": int(self.amount or 0),
            "memo": self.memo or "",
            "anonymous": bool(self.anonymous),
            "from_slip_id": None if self.anonymous else self.from_slip_id,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }


def tips_for(target_type, target_id, limit=50):
    """Recent tips on one target, newest first."""
    return (
        db.session.query(Tip)
        .filter(Tip.target_type == target_type, Tip.target_id == str(target_id))
        .order_by(Tip.created_at.desc())
        .limit(limit)
        .all()
    )


def total_for(target_type, target_id):
    """Sum tipped to one target.

    Computed rather than cached on the target row. A denormalised counter would
    be faster and would eventually disagree with the tips that produced it,
    which is the one thing a money total may not do.
    """
    total = (
        db.session.query(db.func.coalesce(db.func.sum(Tip.amount), 0))
        .filter(Tip.target_type == target_type, Tip.target_id == str(target_id))
        .scalar()
    )
    return int(total or 0)


def totals_for_targets(target_type, target_ids):
    """Totals for many targets at once.

    Exists so a thread of two hundred posts is one query rather than two
    hundred — the N+1 that would otherwise appear the first time tips are shown
    on a post list.
    """
    ids = [str(i) for i in target_ids]
    if not ids:
        return {}
    rows = (
        db.session.query(Tip.target_id, db.func.coalesce(db.func.sum(Tip.amount), 0))
        .filter(Tip.target_type == target_type, Tip.target_id.in_(ids))
        .group_by(Tip.target_id)
        .all()
    )
    return {str(target): int(amount or 0) for target, amount in rows}
