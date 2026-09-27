"""Credit pack purchases and their delivery.

A purchase has two independent halves and they fail in different ways, so they
are tracked separately: Stripe says the buyer PAID, and the chain says the
credits were DELIVERED. Collapsing them into one status would make "paid but
not yet sent" indistinguishable from "not paid", and that is exactly the state
an operator needs to see.

Delivery is a CREDIT transfer from the treasury to the buyer's wallet. It is
queued rather than sent automatically because sending requires a private key
that can move the treasury, and a web server holding one is the single largest
risk in this system. See the note in blueprints/credits.py about the dispenser
wallet if automatic delivery is wanted.
"""

import datetime

from shared import db

STATUS_PENDING = "pending"      # session created, not paid
STATUS_PAID = "paid"            # Stripe confirmed payment; credits owed
STATUS_DELIVERED = "delivered"  # credits are in the buyer's wallet
STATUS_REFUNDED = "refunded"
STATUS_EXPIRED = "expired"      # checkout opened and abandoned; nobody paid

# A row is written BEFORE the buyer pays, because the webhook can only find the
# purchase again by the Checkout session id, and that id does not exist until
# the session is created. That is the right shape, and it has one consequence
# nobody accounted for: clicking Buy and closing the tab leaves a `pending` row
# that never resolves. It was counted as credits-on-the-way and shown to the
# buyer as such, so an abandoned $50 click read as 200 credits pending forever.
#
# Stripe expires an unpaid Checkout session 24 hours after it is created and
# emits checkout.session.expired. This is the backstop for when that event never
# arrives — no webhook secret configured, a delivery that failed every retry —
# because a queue that only self-corrects when the network cooperates is not a
# queue that self-corrects.
STALE_PENDING_HOURS = 26

# Packs, in credits. Four is the smallest, matching the $1 pack.
PACKS = (4, 20, 60, 200)


class CreditPurchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True, index=True)
    wallet = db.Column(db.String(42), nullable=False, default="")
    credits = db.Column(db.BigInteger, nullable=False, default=0)
    amount_cents = db.Column(db.Integer, nullable=False, default=0)
    # Unique so a webhook Stripe retries — which it does, by design — cannot
    # credit the same purchase twice.
    stripe_session_id = db.Column(db.String(120), nullable=True, unique=True, index=True)
    stripe_payment_intent = db.Column(db.String(120), nullable=True)
    status = db.Column(db.String(16), nullable=False, default=STATUS_PENDING, index=True)
    # The two hashes Treasury.releaseOrder takes. Written at checkout, because
    # that is the only moment the buyer's own browser is talking to us — at
    # webhook time the request comes from Stripe and its address is Stripe's.
    # See services/purchase_identity.py.
    order_id = db.Column(db.String(66), nullable=True, index=True)
    origin_hash = db.Column(db.String(66), nullable=True, index=True)

    delivery_tx = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    paid_at = db.Column(db.DateTime, nullable=True)
    delivered_at = db.Column(db.DateTime, nullable=True)


def purchase_by_session(session_id):
    return (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.stripe_session_id == session_id)
        .one_or_none()
    )


def purchases_for_slip(slip_id, limit=50):
    """A buyer's purchase history, minus the checkouts they abandoned.

    An abandoned checkout is not something that happened to them; listing it as
    "pending" says a payment is in flight when none is.
    """
    return (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.slip_id == slip_id)
        # PENDING is excluded alongside EXPIRED: it means "a Checkout session
        # was created", which is not evidence of a payment and must not be
        # shown to the buyer as though credits were coming. See
        # services/credit_ledger.purchase_entries for the whole reasoning.
        .filter(CreditPurchase.status.notin_([STATUS_EXPIRED, STATUS_PENDING]))
        .order_by(CreditPurchase.created_at.desc())
        .limit(limit)
        .all()
    )


def owed_for_slip(slip_id):
    """Credits a slip has paid for but not yet received.

    Shown everywhere a balance is shown. A purchase that has been paid but not
    delivered is otherwise INVISIBLE — the chain says zero, correctly, and the
    buyer is left with a receipt and no explanation. Displaying the balance
    without this is how a working queue looks like a lost payment.
    """
    if slip_id is None:
        return 0
    rows = (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.slip_id == slip_id)
        .filter(CreditPurchase.status == STATUS_PAID)
        .all()
    )
    return sum(row.credits for row in rows)


def undelivered():
    """Paid purchases still owed credits — the operator's work list."""
    return (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.status == STATUS_PAID)
        .order_by(CreditPurchase.paid_at.asc())
        .limit(200)
        .all()
    )


# How many unpaid Checkout sessions one slip may have open at a time.
#
# Hiding pending rows from the buyer stops the misleading balance, but not the
# thing underneath it: every click on Buy writes a row and mints a Stripe
# session, and nothing stopped somebody doing that in a loop. That costs
# database rows and Stripe API quota, and it fills the operator's own views with
# noise — an abuse worth bounding even though no credits were ever at stake.
#
# Four rather than one: a buyer legitimately opens a second tab, or changes
# their mind about the pack size and clicks a different one. The number only has
# to be small enough that a loop hits it.
MAX_OPEN_CHECKOUTS = 4


def open_checkouts(slip_id, now=None, minutes=30):
    """This slip's recent unpaid checkouts.

    Bounded by time as well as status so an old abandoned row cannot lock
    somebody out of buying. Anything older than the window is stale by
    definition and the sweep will expire it.
    """
    if slip_id is None:
        return []
    now = now or datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(minutes=minutes)
    return (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.slip_id == slip_id)
        .filter(CreditPurchase.status == STATUS_PENDING)
        .filter(CreditPurchase.created_at >= cutoff)
        .all()
    )


def mark_expired(purchase):
    """An abandoned checkout. Reversible only by an actual payment.

    Not deleted: the row is the only record that a Checkout session with this id
    was ever ours, and deleting it would make a late payment webhook arrive for
    a session nothing recognises — which is indistinguishable from a forged one.
    """
    if purchase.status != STATUS_PENDING:
        return purchase
    purchase.status = STATUS_EXPIRED
    return purchase


def expire_stale_pending(now=None, hours=STALE_PENDING_HOURS):
    """Mark abandoned checkouts expired. Returns how many were swept.

    Deliberately conservative about the cutoff: expiring a purchase that is
    merely slow would tell somebody who paid that they did not. Being late costs
    nothing, because mark_paid overrides this the moment a payment shows up.
    """
    from shared import db

    now = now or datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(hours=hours)
    rows = (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.status == STATUS_PENDING)
        .filter(CreditPurchase.created_at < cutoff)
        .all()
    )
    for row in rows:
        row.status = STATUS_EXPIRED
    if rows:
        db.session.commit()
    return len(rows)


def mark_paid(purchase, payment_intent=None):
    """Record payment. Idempotent: Stripe retries webhooks, and a retry must
    not move an already-delivered purchase backwards.

    STATUS_EXPIRED is deliberately NOT in the guard below: a payment that lands
    after the sweep gave up must still win. Expiry is a guess about silence;
    a payment is a fact."""
    if purchase.status in (STATUS_DELIVERED, STATUS_REFUNDED):
        return purchase
    purchase.status = STATUS_PAID
    purchase.paid_at = purchase.paid_at or datetime.datetime.utcnow()
    if payment_intent:
        purchase.stripe_payment_intent = payment_intent[:120]
    return purchase


def mark_delivered(purchase, tx_hash):
    purchase.status = STATUS_DELIVERED
    purchase.delivery_tx = (tx_hash or "")[:80]
    purchase.delivered_at = datetime.datetime.utcnow()
    return purchase
