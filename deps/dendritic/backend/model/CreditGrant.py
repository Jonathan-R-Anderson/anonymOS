"""Credits an operator sent by hand, and why.

Every other path that moves CREDIT is automatic and keyed to something — a
Stripe session, a subscription invoice, a node's epoch receipt. This one is a
human deciding, which makes it the path most worth writing down: an unexplained
transfer out of the treasury is indistinguishable from a theft, and the person
best placed to explain it is the one making it, at the moment they make it.

So a reason is required. Not as ceremony — as the thing that makes the ledger
readable a year later, when "why does this address have 40 credits" is a
question somebody actually has to answer.
"""

import datetime as _datetime

from shared import db


class CreditGrant(db.Model):
    __tablename__ = "credit_grant"

    id = db.Column(db.Integer, primary_key=True)
    wallet = db.Column(db.String(42), nullable=False, index=True)
    credits = db.Column(db.BigInteger, nullable=False)
    reason = db.Column(db.String(255), nullable=False, default="")
    # Which purchase this was making good, when it is making one good. Lets a
    # grant issued to fix a botched delivery be tied to the delivery it fixed
    # rather than floating free as an unexplained handout.
    purchase_id = db.Column(db.Integer, db.ForeignKey("credit_purchase.id"),
                            nullable=True, index=True)

    # Written when the operator's wallet confirms the transfer. Null means the
    # grant was recorded but the transaction never landed — visible, so it can
    # be retried rather than assumed.
    tx_hash = db.Column(db.String(80), nullable=True)
    sent_at = db.Column(db.DateTime, nullable=True)

    granted_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"),
                                   nullable=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow)

    @property
    def sent(self):
        return bool(self.tx_hash)


def recent_grants(limit=50):
    return (
        db.session.query(CreditGrant)
        .order_by(CreditGrant.id.desc())
        .limit(limit)
        .all()
    )


def open_grants():
    """Recorded but not yet sent — the operator's work list."""
    return (
        db.session.query(CreditGrant)
        .filter(CreditGrant.tx_hash.is_(None))
        .order_by(CreditGrant.id.asc())
        .limit(100)
        .all()
    )


def total_granted():
    """How much has been handed out this way, ever.

    Worth having in one number: manual grants are the one path with no automatic
    counterparty, so the only way to notice them adding up is to add them up.
    """
    from sqlalchemy import func

    value = (
        db.session.query(func.coalesce(func.sum(CreditGrant.credits), 0))
        .filter(CreditGrant.tx_hash.isnot(None))
        .scalar()
    )
    return int(value or 0)
