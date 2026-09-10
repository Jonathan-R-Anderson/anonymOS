"""Memberships: a monthly subscription, and the free machine everyone else gets.

Two things live here because they answer the same question — what is this
account entitled to right now — and answering it in two places is how an account
ends up locked out of something it paid for.

The paid side deposits credits every month and opens the whole lab catalogue.
The free side is one randomly-chosen machine per calendar month, which exists so
that "no subscription" still means "you can try this", rather than a wall.

Stripe is the authority on whether a subscription is paid. This table is a
CACHE of what Stripe last told us, which is why every field that decides access
is written only by a verified webhook, and why `is_active` distrusts its own
period end once it has passed rather than assuming a renewal happened.
"""

import datetime as _datetime

from shared import db

STATUS_ACTIVE = "active"
STATUS_PAST_DUE = "past_due"
STATUS_CANCELED = "canceled"

# Grace after the paid period ends before access is withdrawn.
#
# Stripe retries a failed card for days, and a renewal webhook can be late for
# reasons that are entirely ours — a deploy, a queue, an outage. Cutting someone
# off the instant the clock passes would punish them for our infrastructure, and
# the cost of being wrong the other way is a few days of access.
RENEWAL_GRACE = _datetime.timedelta(days=3)


class Membership(db.Model):
    __tablename__ = "membership"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False,
                        unique=True, index=True)

    stripe_customer_id = db.Column(db.String(80), nullable=True, index=True)
    # Unique so a webhook Stripe retries — which it does, by design — cannot
    # attach one subscription to two accounts.
    stripe_subscription_id = db.Column(db.String(80), nullable=True,
                                       unique=True, index=True)

    status = db.Column(db.String(16), nullable=False, default=STATUS_CANCELED, index=True)
    credits_per_month = db.Column(db.Integer, nullable=False, default=0)
    current_period_end = db.Column(db.DateTime, nullable=True)
    # Set when the member asked to stop. They keep access to the end of the
    # period they already paid for.
    cancel_at_period_end = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    @property
    def is_active(self):
        """Whether this membership currently grants access.

        past_due counts as active inside the grace window: Stripe is still
        trying the card, and the member has not done anything wrong yet.
        """
        if self.status == STATUS_ACTIVE:
            if self.current_period_end is None:
                return True
            return _datetime.datetime.utcnow() <= self.current_period_end + RENEWAL_GRACE
        if self.status == STATUS_PAST_DUE and self.current_period_end is not None:
            return _datetime.datetime.utcnow() <= self.current_period_end + RENEWAL_GRACE
        return False

    @property
    def renews_on(self):
        return self.current_period_end


class LabFreeGrant(db.Model):
    """The one machine a non-member may run in a given month.

    The machine is recorded, not just the fact of the grant, for two reasons.
    Somebody who refreshes the page must get the same machine rather than a
    reroll — otherwise "random" means "keep spinning until you like it", and the
    free tier quietly becomes the paid one. And a grant that names its machine
    can be checked at launch time without a second source of truth.

    (slip_id, period) is UNIQUE. Counting grants and comparing to one would race
    under two simultaneous requests; a unique index cannot.
    """
    __tablename__ = "lab_free_grant"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    # "YYYY-MM". A calendar month, not a rolling 30 days: everyone's allowance
    # resets on the same day, which is the version people can predict.
    period = db.Column(db.String(7), nullable=False, index=True)
    challenge_slug = db.Column(db.String(128), nullable=False)
    granted_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("slip_id", "period", name="uq_lab_free_grant_slip_period"),
    )


def current_period(now=None):
    now = now or _datetime.datetime.utcnow()
    return "%04d-%02d" % (now.year, now.month)


def membership_for(slip_id):
    if slip_id is None:
        return None
    return (
        db.session.query(Membership)
        .filter(Membership.slip_id == slip_id)
        .one_or_none()
    )


def membership_by_subscription(subscription_id):
    if not subscription_id:
        return None
    return (
        db.session.query(Membership)
        .filter(Membership.stripe_subscription_id == subscription_id)
        .one_or_none()
    )


def is_member(slip_id):
    membership = membership_for(slip_id)
    return bool(membership and membership.is_active)


def free_grant_for(slip_id, period=None):
    if slip_id is None:
        return None
    return (
        db.session.query(LabFreeGrant)
        .filter(LabFreeGrant.slip_id == slip_id,
                LabFreeGrant.period == (period or current_period()))
        .one_or_none()
    )


def grant_free_machine(slip_id, slug, period=None):
    """Record this month's free machine. Returns the existing grant unchanged if
    there already is one, so a double-click cannot spend two months' allowance
    or hand out a second machine."""
    period = period or current_period()
    existing = free_grant_for(slip_id, period)
    if existing is not None:
        return existing
    grant = LabFreeGrant(slip_id=slip_id, period=period, challenge_slug=slug)
    db.session.add(grant)
    try:
        db.session.commit()
    except Exception:
        # Lost a race with another request; the unique index did its job. Read
        # back whatever the winner wrote rather than reporting an error for
        # something that ended correctly.
        db.session.rollback()
        return free_grant_for(slip_id, period)
    return grant


def upsert_membership(slip_id, **fields):
    membership = membership_for(slip_id)
    if membership is None:
        membership = Membership(slip_id=slip_id)
        db.session.add(membership)
    for key, value in fields.items():
        setattr(membership, key, value)
    membership.updated_at = _datetime.datetime.utcnow()
    return membership
