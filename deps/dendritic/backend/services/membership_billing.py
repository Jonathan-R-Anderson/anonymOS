"""Turning Stripe's subscription events into memberships and credits.

Every function here is reached only from the SIGNED webhook. None of it trusts
the browser: a membership is created because Stripe said an invoice was paid,
never because someone came back from a success URL.

The credits a member earns each month go through the same delivery queue as a
one-off pack, deliberately. That path is already the one an operator watches,
already refuses to double-deliver, and already keeps the treasury key off this
server — a second mechanism for putting credits in a wallet would be a second
thing to get wrong.
"""

import datetime as _datetime

from model.CreditPurchase import CreditPurchase, STATUS_PAID
from model.Membership import (
    STATUS_ACTIVE, STATUS_CANCELED, STATUS_PAST_DUE,
    Membership, membership_by_subscription, membership_for, upsert_membership,
)
from model.Slip import slip_from_id, slip_wallet_address
from shared import app, db

# Stripe's subscription statuses that mean "this account has paid".
_ACTIVE_STATES = ("active", "trialing")
_PAST_DUE_STATES = ("past_due", "unpaid", "incomplete")


def _to_datetime(unix_seconds):
    if not unix_seconds:
        return None
    try:
        return _datetime.datetime.utcfromtimestamp(int(unix_seconds))
    except (TypeError, ValueError, OSError):
        return None


def _period_end_of(subscription):
    """When the paid period ends.

    Stripe moved this. It used to sit on the subscription as
    `current_period_end`; on current API versions the subscription has no such
    field and the date lives on each subscription ITEM. Reading only the old
    place silently produced None, which showed members "renews monthly" instead
    of a date and left the past-due grace window with nothing to measure
    against — a wrong answer that looked like a missing one.

    Both places are read, newest first, so this keeps working whichever version
    an account is pinned to.
    """
    for item in ((subscription.get("items") or {}).get("data") or []):
        found = _to_datetime(item.get("current_period_end"))
        if found is not None:
            return found
        period = item.get("period") or {}
        found = _to_datetime(period.get("end"))
        if found is not None:
            return found
    return _to_datetime(subscription.get("current_period_end"))


def _slip_id_from(obj):
    """Find the account an event belongs to.

    Checked in order of trustworthiness: the metadata we put on the subscription
    ourselves, then the client_reference_id from Checkout, then an existing row
    matched on the subscription id. Guessing from the email is deliberately not
    an option — an address is not proof of an account.
    """
    metadata = obj.get("metadata") or {}
    for key in ("slip_id",):
        raw = metadata.get(key)
        if raw:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    raw = obj.get("client_reference_id")
    if raw:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    return None


def _credits_from(obj, fallback=None):
    metadata = obj.get("metadata") or {}
    try:
        value = int(metadata.get("credits_per_month"))
        if value > 0:
            return value
    except (TypeError, ValueError):
        pass
    if fallback is not None:
        return fallback
    from services.membership import credits_per_month
    return credits_per_month()


def link_checkout(session):
    """A subscription Checkout completed: bind it to the account and activate it.

    This used to record the customer, the subscription and the monthly credits
    but NOT the status, so the row kept its column default of "canceled" — a
    member who had just paid was inactive from the first second: no cancel
    button, no lab access, and no way to tell from the page that anything was
    wrong. Never leave a status to a default; a default is what you get when
    nobody decided, and here somebody had.

    The status is read back FROM STRIPE rather than assumed to be active.
    Checkout completing usually means the first payment succeeded, but "usually"
    is not a thing to grant access on, and Stripe already knows the answer.

    Credits for the first month are deposited here as well, keyed on the
    invoice, because invoice.paid may never arrive: it is a separate event an
    operator has to subscribe to, and a member who paid should not be waiting on
    our webhook configuration.
    """
    slip_id = _slip_id_from(session)
    subscription_id = session.get("subscription")
    if not slip_id or not subscription_id:
        app.logger.warning("subscription checkout with no slip (%s) or subscription (%s)",
                           slip_id, subscription_id)
        return False

    from services import stripe_api
    subscription = None
    try:
        subscription = stripe_api.retrieve_subscription(subscription_id)
    except stripe_api.StripeError as exc:
        app.logger.warning("could not read subscription %s at checkout: %s",
                           subscription_id, exc)

    if subscription is not None:
        # Carry the slip through, since a subscription fetched from Stripe only
        # knows the account if we put it in its metadata at creation.
        subscription.setdefault("metadata", {}).setdefault("slip_id", str(slip_id))
        _apply_subscription(subscription)
    else:
        # Degraded, but not inactive: Stripe took the payment, and refusing
        # access because we could not re-read our own subscription would punish
        # the member for our outage. A later subscription event corrects it.
        upsert_membership(
            slip_id,
            stripe_customer_id=session.get("customer"),
            stripe_subscription_id=subscription_id,
            status=STATUS_ACTIVE,
            credits_per_month=_credits_from(session),
        )
        db.session.commit()

    membership = membership_by_subscription(subscription_id)
    if membership is None:
        return False

    invoice_id = session.get("invoice") or (
        subscription.get("latest_invoice") if subscription else None)
    if invoice_id:
        # Same key invoice.paid would use, so whichever arrives first wins and
        # the other is a no-op rather than a second month's credits.
        _deposit_month(membership, invoice_id, membership.credits_per_month or 0)
    app.logger.info("membership linked: slip %s subscription %s status %s",
                    slip_id, subscription_id, membership.status)
    return True


def _apply_subscription(obj):
    """Mirror a subscription object onto the local row."""
    subscription_id = obj.get("id")
    membership = membership_by_subscription(subscription_id)
    slip_id = _slip_id_from(obj) or (membership.slip_id if membership else None)
    if not slip_id:
        app.logger.warning("subscription %s belongs to no known account", subscription_id)
        return False

    state = (obj.get("status") or "").lower()
    if state in _ACTIVE_STATES:
        status = STATUS_ACTIVE
    elif state in _PAST_DUE_STATES:
        status = STATUS_PAST_DUE
    else:
        status = STATUS_CANCELED

    upsert_membership(
        slip_id,
        stripe_customer_id=obj.get("customer"),
        stripe_subscription_id=subscription_id,
        status=status,
        credits_per_month=_credits_from(obj, membership.credits_per_month if membership else None),
        current_period_end=_period_end_of(obj),
        cancel_at_period_end=bool(obj.get("cancel_at_period_end")),
    )
    db.session.commit()
    return True


def _deposit_month(membership, invoice_id, credits):
    """Queue this month's credits, once per invoice.

    Keyed on the Stripe invoice id through the purchase table's unique session
    column: Stripe retries webhooks by design, and without a key a retry would
    deposit the month twice.
    """
    if credits <= 0:
        return False
    slip = slip_from_id(membership.slip_id)
    if slip is None:
        app.logger.warning("membership %s has no slip", membership.id)
        return False
    wallet = slip_wallet_address(slip)
    if not wallet:
        # Nothing to deliver to. Logged loudly rather than dropped, because the
        # member has paid and is owed these credits the moment they link one.
        app.logger.warning(
            "membership credits for slip %s have nowhere to go: no wallet linked",
            membership.slip_id)
        return False

    key = "sub_invoice:%s" % invoice_id
    existing = (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.stripe_session_id == key)
        .one_or_none()
    )
    if existing is not None:
        return False

    purchase = CreditPurchase(
        slip_id=membership.slip_id,
        wallet=wallet,
        credits=credits,
        # The dollar value of the month, so the delivery queue shows what was
        # actually paid rather than a zero.
        amount_cents=0,
        stripe_session_id=key,
        status=STATUS_PAID,
        paid_at=_datetime.datetime.utcnow(),
    )
    db.session.add(purchase)
    db.session.commit()
    app.logger.info("membership month credited: %d credits for slip %s (invoice %s)",
                    credits, membership.slip_id, invoice_id)
    return True


def handle_event(kind, obj):
    """Route one verified subscription event. Returns a short label for the log."""
    if kind in ("customer.subscription.created", "customer.subscription.updated",
                "customer.subscription.deleted"):
        if kind.endswith("deleted"):
            membership = membership_by_subscription(obj.get("id"))
            if membership is not None:
                membership.status = STATUS_CANCELED
                membership.updated_at = _datetime.datetime.utcnow()
                db.session.commit()
                return "canceled"
            return "unknown-subscription"
        return "subscription-synced" if _apply_subscription(obj) else "unknown-subscription"

    if kind == "invoice.payment_failed":
        membership = membership_by_subscription(obj.get("subscription"))
        if membership is None:
            return "unknown-subscription"
        # Not canceled: Stripe will retry the card, and the grace window in
        # Membership.is_active decides how long that is allowed to take.
        membership.status = STATUS_PAST_DUE
        membership.updated_at = _datetime.datetime.utcnow()
        db.session.commit()
        return "past-due"

    if kind == "invoice.paid":
        subscription_id = obj.get("subscription")
        membership = membership_by_subscription(subscription_id)
        if membership is None:
            # The invoice can beat checkout.session.completed. Refresh from
            # Stripe rather than dropping a payment that has already been taken.
            from services import stripe_api
            try:
                subscription = stripe_api.retrieve_subscription(subscription_id)
            except stripe_api.StripeError as exc:
                app.logger.warning("could not read subscription %s: %s", subscription_id, exc)
                return "unknown-subscription"
            if not _apply_subscription(subscription):
                return "unknown-subscription"
            membership = membership_by_subscription(subscription_id)
            if membership is None:
                return "unknown-subscription"

        membership.status = STATUS_ACTIVE
        period_end = _to_datetime((obj.get("lines") or {}).get("data", [{}])[0]
                                  .get("period", {}).get("end")) if obj.get("lines") else None
        if period_end is not None:
            membership.current_period_end = period_end
        membership.updated_at = _datetime.datetime.utcnow()
        db.session.commit()

        credited = _deposit_month(membership, obj.get("id"),
                                  membership.credits_per_month or 0)
        return "month-credited" if credited else "invoice-seen"

    return "ignored"


def resync(subscription_id):
    """Re-read one subscription from Stripe and repair the local row.

    Exists because the local row is a cache and caches go wrong — a missed
    webhook, a bug in the handler, an event nobody subscribed to. Rather than
    asking a member who has already paid to cancel and subscribe again, ask
    Stripe what is true and write that down.

    Also deposits the latest invoice's credits, keyed as always on the invoice
    id, so a month that was billed but never credited is repaid exactly once.
    """
    from services import stripe_api

    subscription = stripe_api.retrieve_subscription(subscription_id)
    membership = membership_by_subscription(subscription_id)
    if membership is not None:
        subscription.setdefault("metadata", {}).setdefault(
            "slip_id", str(membership.slip_id))
    if not _apply_subscription(subscription):
        return {"ok": False, "reason": "subscription belongs to no known account"}

    membership = membership_by_subscription(subscription_id)
    invoice_id = subscription.get("latest_invoice")
    credited = False
    if invoice_id and membership is not None:
        credited = _deposit_month(membership, invoice_id,
                                  membership.credits_per_month or 0)
    return {
        "ok": True,
        "slip_id": membership.slip_id if membership else None,
        "status": membership.status if membership else None,
        "active": membership.is_active if membership else False,
        "renews_on": membership.current_period_end.isoformat() + "Z"
                     if membership and membership.current_period_end else None,
        "credited": credited,
    }
