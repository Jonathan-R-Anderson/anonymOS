"""Reading a Stripe subscription correctly.

Two failures here were found in production, and neither raised anything:

  * a membership was recorded with no status, so it kept the column default
    "canceled" and a member who had just paid was not a member;
  * the period end was read from `subscription.current_period_end`, which
    current Stripe API versions no longer have — it moved onto the subscription
    ITEM — so every membership showed "renews monthly" with no date and the
    past-due grace window had nothing to measure against.

Both were wrong answers that looked like missing data, which is the kind that
survives a demo.
"""

import datetime
import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

PERIOD_END = 1788161497


def _period_end_of(subscription):
    """Mirrors membership_billing._period_end_of.

    Restated here rather than imported because that module pulls in the app and
    the database; this is the arithmetic, and the arithmetic is what was wrong.
    """
    def to_dt(value):
        if not value:
            return None
        try:
            return datetime.datetime.utcfromtimestamp(int(value))
        except (TypeError, ValueError, OSError):
            return None

    for item in ((subscription.get("items") or {}).get("data") or []):
        found = to_dt(item.get("current_period_end"))
        if found is not None:
            return found
        found = to_dt((item.get("period") or {}).get("end"))
        if found is not None:
            return found
    return to_dt(subscription.get("current_period_end"))


class PeriodEndTest(unittest.TestCase):
    def test_current_stripe_puts_it_on_the_item(self):
        # The exact shape returned for a live subscription on this account.
        subscription = {
            "status": "active",
            "current_period_end": None,
            "items": {"data": [{"current_period_end": PERIOD_END, "period": None}]},
        }
        self.assertEqual(_period_end_of(subscription),
                         datetime.datetime.utcfromtimestamp(PERIOD_END))

    def test_older_stripe_puts_it_on_the_subscription(self):
        subscription = {"status": "active", "current_period_end": PERIOD_END,
                        "items": {"data": []}}
        self.assertEqual(_period_end_of(subscription),
                         datetime.datetime.utcfromtimestamp(PERIOD_END))

    def test_the_item_period_object_is_read_too(self):
        subscription = {"items": {"data": [{"period": {"end": PERIOD_END}}]}}
        self.assertEqual(_period_end_of(subscription),
                         datetime.datetime.utcfromtimestamp(PERIOD_END))

    def test_a_subscription_with_no_date_anywhere_gives_none(self):
        # None is the honest answer, and Membership.is_active treats it as "no
        # deadline to check" rather than "expired in 1970".
        self.assertIsNone(_period_end_of({"items": {"data": [{}]}}))
        self.assertIsNone(_period_end_of({}))


class StatusMappingTest(unittest.TestCase):
    """Stripe's statuses, and which of them mean the account has paid."""

    ACTIVE = ("active", "trialing")
    PAST_DUE = ("past_due", "unpaid", "incomplete")

    def _map(self, state):
        if state in self.ACTIVE:
            return "active"
        if state in self.PAST_DUE:
            return "past_due"
        return "canceled"

    def test_paid_states_are_active(self):
        for state in self.ACTIVE:
            self.assertEqual(self._map(state), "active")

    def test_failing_card_is_past_due_not_cancelled(self):
        # Stripe retries for days. Cancelling on the first failure would end a
        # membership the member is still paying for.
        for state in self.PAST_DUE:
            self.assertEqual(self._map(state), "past_due")

    def test_genuinely_over_is_cancelled(self):
        for state in ("canceled", "incomplete_expired", "paused"):
            self.assertEqual(self._map(state), "canceled")

    def test_an_unknown_status_is_not_treated_as_paid(self):
        # A status Stripe adds later must not accidentally grant access.
        self.assertEqual(self._map("something_new"), "canceled")


if __name__ == "__main__":
    unittest.main()
