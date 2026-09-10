"""What an account may do, and what the plan costs.

One function answers "can this slip start this machine", because the answer has
to be identical on the page that draws the button and in the handler that acts
on it. Two implementations of an entitlement rule is how a button appears that
does nothing, or worse, a button that is missing while the endpoint still works.
"""

from model.SiteSetting import get_setting, set_setting
from services.lab_draw import free_machine_for  # noqa: F401  (re-exported)

PRICE_CENTS_KEY = "membership_price_cents"
CREDITS_PER_MONTH_KEY = "membership_credits_per_month"

DEFAULT_PRICE_CENTS = 500
DEFAULT_CREDITS_PER_MONTH = 20


def _positive_int(raw, fallback):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return fallback
    return value if value > 0 else fallback


def price_cents():
    return _positive_int(get_setting(PRICE_CENTS_KEY, ""), DEFAULT_PRICE_CENTS)


def credits_per_month():
    return _positive_int(get_setting(CREDITS_PER_MONTH_KEY, ""), DEFAULT_CREDITS_PER_MONTH)


def set_plan(price_cents_value, credits_value):
    set_setting(PRICE_CENTS_KEY, str(_positive_int(price_cents_value, DEFAULT_PRICE_CENTS)))
    set_setting(CREDITS_PER_MONTH_KEY,
                str(_positive_int(credits_value, DEFAULT_CREDITS_PER_MONTH)))


def plan():
    cents = price_cents()
    return {
        "price_cents": cents,
        "price": "%.2f" % (cents / 100.0),
        "credits_per_month": credits_per_month(),
    }


def lab_entitlement(slip):
    """What this slip may run in the lab right now.

    Returns a dict rather than a bool because the caller almost always needs the
    reason too — the page has to explain the wall, not just draw it.
    """
    from model.Membership import current_period, free_grant_for, membership_for

    if slip is None:
        return {"member": False, "allowed_slug": None, "grant": None,
                "membership": None, "period": current_period(),
                "reason": "Sign in to run a machine."}

    membership = membership_for(slip.id)
    if membership is not None and membership.is_active:
        return {"member": True, "allowed_slug": None, "grant": None,
                "membership": membership, "period": current_period(),
                "reason": None}

    period = current_period()
    grant = free_grant_for(slip.id, period)
    return {
        "member": False,
        "membership": membership,
        "period": period,
        "grant": grant,
        # None until they claim it; after that, the one machine they may run.
        "allowed_slug": grant.challenge_slug if grant else None,
        "reason": None if grant else "Claim this month's free machine, or subscribe for all of them.",
    }


def may_start(slip, slug):
    """(allowed, reason). The single source of truth for lab access."""
    state = lab_entitlement(slip)
    if state["member"]:
        return True, None
    if state["allowed_slug"] is None:
        return False, ("You have not claimed this month's free machine yet. "
                       "Claim it, or subscribe to run any machine you like.")
    if state["allowed_slug"] != slug:
        return False, ("Your free machine this month is a different one. "
                       "Subscribe to run any machine in the catalogue.")
    return True, None
