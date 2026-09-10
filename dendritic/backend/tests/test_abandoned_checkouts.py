"""Clicking Buy and closing the tab must not look like a purchase.

A CreditPurchase row is written BEFORE the buyer pays, because the webhook can
only find the purchase again by its Stripe Checkout session id and that id does
not exist until the session is created. That ordering is correct and it had one
unaccounted consequence: an abandoned checkout left a `pending` row that never
resolved, was summed as credits-on-the-way, and showed a $50 click that nobody
paid for as "200 credits pending" indefinitely.

That is the worst direction for this bug to point. Telling somebody money is
coming when nobody paid invites them to wait for it, then to ask where it went.

The opposite mistake matters more, though, which is why the cutoff is generous
and why a payment always overrides expiry: expiring a purchase that was merely
slow would tell somebody who DID pay that they did not.
"""

import ast
import datetime
import os
import pathlib
import sys
import types
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

STATUS_PENDING = "pending"
STATUS_PAID = "paid"
STATUS_DELIVERED = "delivered"
STATUS_REFUNDED = "refunded"
STATUS_EXPIRED = "expired"


def _load_pure(relative_path, wanted, extra=None):
    """Exec just the named definitions, without importing the module.

    model/CreditPurchase.py pulls in the Flask app and SQLAlchemy at import
    time; this is the state machine, and the state machine is what was wrong.
    """
    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


CP = _load_pure(
    "model/CreditPurchase.py",
    {"STATUS_PENDING", "STATUS_PAID", "STATUS_DELIVERED", "STATUS_REFUNDED",
     "STATUS_EXPIRED", "STALE_PENDING_HOURS", "mark_expired", "mark_paid"},
    extra={"datetime": datetime},
)


class Purchase(object):
    def __init__(self, status=STATUS_PENDING):
        self.status = status
        self.paid_at = None
        self.stripe_payment_intent = None


class ExpiryTest(unittest.TestCase):

    def test_an_abandoned_checkout_expires(self):
        p = Purchase()
        CP["mark_expired"](p)
        self.assertEqual(p.status, STATUS_EXPIRED)

    def test_a_paid_purchase_is_never_expired_by_the_sweep(self):
        # The sweep is a guess about silence. A payment is a fact.
        for status in (STATUS_PAID, STATUS_DELIVERED, STATUS_REFUNDED):
            p = Purchase(status=status)
            CP["mark_expired"](p)
            self.assertEqual(p.status, status)

    def test_a_late_payment_beats_an_earlier_expiry(self):
        # Stripe can deliver a payment webhook after the sweep gave up — a
        # retried delivery, or a session paid at the edge of the window. If
        # expiry won, somebody who paid would be told they had not.
        p = Purchase()
        CP["mark_expired"](p)
        self.assertEqual(p.status, STATUS_EXPIRED)
        CP["mark_paid"](p)
        self.assertEqual(p.status, STATUS_PAID)
        self.assertIsNotNone(p.paid_at)

    def test_paying_still_does_not_reopen_a_delivered_purchase(self):
        # The existing guard has to survive: Stripe retries webhooks, and a
        # retry must not move a delivered purchase backwards into "owed".
        p = Purchase(status=STATUS_DELIVERED)
        CP["mark_paid"](p)
        self.assertEqual(p.status, STATUS_DELIVERED)

    def test_the_cutoff_outlives_a_stripe_session(self):
        # Stripe expires an unpaid Checkout session 24 hours after creation.
        # Sweeping sooner than that could expire one somebody is still paying.
        self.assertGreater(CP["STALE_PENDING_HOURS"], 24)


class LedgerVisibilityTest(unittest.TestCase):
    """Abandoned rows must not be summed as credits on the way."""

    def test_the_ledger_filters_unpaid_rows_out(self):
        # Widened from "!= STATUS_EXPIRED" to exclude PENDING as well.
        #
        # Expired-only was not enough: a row does not become expired until the
        # sweep runs 26 hours later, so an abandoned checkout read as credits
        # pending for a day, and repeating the click added more. See
        # tests/test_unpaid_checkouts.py for the full case.
        source = (pathlib.Path(BACKEND) / "services" / "credit_ledger.py").read_text()
        self.assertIn("STATUS_EXPIRED", source)
        self.assertIn("notin_([STATUS_EXPIRED, STATUS_PENDING])", source)
        self.assertNotIn("CreditPurchase.status != STATUS_EXPIRED", source,
                         "the narrower filter is back; PENDING rows are visible again")

    def test_purchase_history_filters_expired_rows_out(self):
        source = (pathlib.Path(BACKEND) / "model" / "CreditPurchase.py").read_text()
        i = source.index("def purchases_for_slip")
        j = source.index("def owed_for_slip")
        self.assertIn("STATUS_EXPIRED", source[i:j])

    def test_owed_counts_only_paid(self):
        # This one was already right, and is the reason the phantom never
        # reached the operator's delivery queue — only the buyer's page.
        source = (pathlib.Path(BACKEND) / "model" / "CreditPurchase.py").read_text()
        i = source.index("def owed_for_slip")
        j = source.index("def undelivered")
        self.assertIn("CreditPurchase.status == STATUS_PAID", source[i:j])


class WebhookTest(unittest.TestCase):
    def test_the_expiry_event_is_handled(self):
        # Without this the row only clears on the lazy sweep, up to 26 hours
        # later, and only if somebody loads the credits page.
        source = (pathlib.Path(BACKEND) / "blueprints" / "credits.py").read_text()
        self.assertIn("checkout.session.expired", source)
        self.assertIn("mark_expired", source)

    def test_there_is_a_sweep_that_does_not_need_the_webhook(self):
        # A webhook secret that was never set, or a delivery that failed every
        # retry, means checkout.session.expired never arrives at all.
        source = (pathlib.Path(BACKEND) / "blueprints" / "credits.py").read_text()
        self.assertIn("expire_stale_pending()", source)


if __name__ == "__main__":
    unittest.main()
