"""The credit store: items priced in dollars, paid for in CREDIT.

Two decisions shape this file.

**Dollars are the source of truth; credits are derived.** An item costs
`price_usd_cents`, and its credit price is computed at the pack rate. If credits
were priced directly, the store price and the pack price would be two
independent numbers and any gap between them is an arbitrage: a credit that buys
more than it costs drains the store, one that buys less makes node rewards
worthless. Deriving one from the other means the peg cannot drift.

**Credits paid return to the treasury.** Nothing is burned and nothing is minted
here — the same credits go back out as node rewards. The house makes its money
when someone buys a pack, not when they spend one, so the store is a recycler
rather than a sink.
"""

import datetime

from model.SiteSetting import get_setting, set_setting
from shared import db

# 4 credits to the dollar. A setting rather than a constant because it is a
# price, and prices change — but changing it re-prices every item at once, which
# is the point: the peg is one number, not per-item guesswork.
CREDITS_PER_DOLLAR_KEY = "store_credits_per_dollar"
DEFAULT_CREDITS_PER_DOLLAR = 4

TREASURY_ADDRESS_KEY = "store_treasury_address"

# Digital goods deliver themselves; physical ones need somewhere to post them.
# Kept as a property of the ITEM rather than asked per order, because whether a
# thing needs shipping is a fact about the thing.
KIND_DIGITAL = "digital"
KIND_PHYSICAL = "physical"
KINDS = (KIND_DIGITAL, KIND_PHYSICAL)
KIND_LABELS = {KIND_DIGITAL: "Digital", KIND_PHYSICAL: "Physical"}

ORDER_PENDING = "pending"
ORDER_PAID = "paid"
ORDER_CANCELLED = "cancelled"

PAID_WITH_CREDITS = "credits"
PAID_WITH_CARD = "card"


def credits_per_dollar():
    try:
        value = int(get_setting(CREDITS_PER_DOLLAR_KEY, "") or DEFAULT_CREDITS_PER_DOLLAR)
    except (TypeError, ValueError):
        return DEFAULT_CREDITS_PER_DOLLAR
    return value if value > 0 else DEFAULT_CREDITS_PER_DOLLAR


def set_credits_per_dollar(value):
    set_setting(CREDITS_PER_DOLLAR_KEY, str(int(value)))


def treasury_address():
    return (get_setting(TREASURY_ADDRESS_KEY, "") or "").strip().lower()


def set_treasury_address(value):
    set_setting(TREASURY_ADDRESS_KEY, (value or "").strip().lower())


def credits_for_cents(price_usd_cents):
    """Credit price for a dollar price.

    Rounds UP to the whole credit. Credits are indivisible in the UI, and
    rounding down would sell a $0.30 item for one credit ($0.25) — a loss on
    every unit that nobody would notice until the treasury drained.
    """
    rate = credits_per_dollar()
    cents = max(0, int(price_usd_cents or 0))
    return -(-cents * rate // 100)  # ceil division


class StoreItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    price_usd_cents = db.Column(db.Integer, nullable=False, default=0)
    # Null means unlimited (a digital good); a number decrements on purchase.
    stock = db.Column(db.Integer, nullable=True)
    image_media_id = db.Column(db.Integer, nullable=True)
    kind = db.Column(db.String(16), nullable=False, default=KIND_DIGITAL)
    # Shown to the buyer after payment for a digital good — a key, a link, a
    # download. Never rendered before the order is paid.
    fulfilment_note = db.Column(db.Text, nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    @property
    def price_credits(self):
        return credits_for_cents(self.price_usd_cents)

    @property
    def price_dollars(self):
        return "%.2f" % (self.price_usd_cents / 100.0)

    @property
    def needs_shipping(self):
        return self.kind == KIND_PHYSICAL

    @property
    def in_stock(self):
        return self.stock is None or self.stock > 0


class StoreOrder(db.Model):
    """One purchase, awaiting or carrying proof of payment.

    An order is created BEFORE payment and only marked paid once a transaction
    carrying the right amount to the treasury is seen on-chain. The alternative —
    trusting the browser's word that it paid — would hand out goods for free to
    anyone who can edit a fetch call.
    """

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("store_item.id"), nullable=False, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True, index=True)
    buyer_wallet = db.Column(db.String(42), nullable=False, default="")
    price_credits = db.Column(db.BigInteger, nullable=False, default=0)
    price_usd_cents = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(16), nullable=False, default=ORDER_PENDING, index=True)
    # Collected only for physical items. Held as one block of text rather than
    # parsed fields: addresses differ wildly by country, and a rigid schema
    # silently mangles the ones it was not designed for.
    ship_to = db.Column(db.Text, nullable=False, default="")
    shipped_at = db.Column(db.DateTime, nullable=True)
    tracking = db.Column(db.String(140), nullable=True)
    tx_hash = db.Column(db.String(80), nullable=True, unique=True)
    # Which rail paid: "credits" (an on-chain AXON transfer, verified against
    # the chain) or "card" (Stripe Checkout, believed only on a signed webhook).
    # Cards buy GOODS only — never the token itself, which is a first-party
    # token sale Stripe prohibits and which pairs a reversible payment with an
    # irreversible transfer.
    paid_with = db.Column(db.String(16), nullable=False, default=PAID_WITH_CREDITS)
    stripe_session_id = db.Column(db.String(120), nullable=True, unique=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    paid_at = db.Column(db.DateTime, nullable=True)


def active_items():
    return (
        db.session.query(StoreItem)
        .filter(StoreItem.active == True)  # noqa: E712 — SQLAlchemy needs the comparison
        .order_by(StoreItem.created_at.desc())
        .all()
    )


def all_items():
    return db.session.query(StoreItem).order_by(StoreItem.created_at.desc()).all()


def item_by_id(item_id):
    return db.session.query(StoreItem).filter(StoreItem.id == item_id).one_or_none()


def orders_for_slip(slip_id, limit=50):
    return (
        db.session.query(StoreOrder)
        .filter(StoreOrder.slip_id == slip_id)
        .order_by(StoreOrder.created_at.desc())
        .limit(limit)
        .all()
    )


def order_by_stripe_session(session_id):
    """The order a Checkout session belongs to, or None.

    Looked up by session rather than by the metadata's order id: the session id
    is what Stripe signs and sends back, so it is the one identifier a forged
    webhook body cannot choose.
    """
    if not session_id:
        return None
    return (
        db.session.query(StoreOrder)
        .filter(StoreOrder.stripe_session_id == session_id)
        .one_or_none()
    )


def unshipped_orders(limit=200):
    """Paid orders for physical items that have not been sent yet."""
    return (
        db.session.query(StoreOrder)
        .join(StoreItem, StoreItem.id == StoreOrder.item_id)
        .filter(StoreOrder.status == ORDER_PAID,
                StoreItem.kind == KIND_PHYSICAL,
                StoreOrder.shipped_at.is_(None))
        .order_by(StoreOrder.paid_at.asc())
        .limit(limit)
        .all()
    )
