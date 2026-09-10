"""An unpaid checkout must not read as credits.

THE BUG THIS FIXES
------------------
A CreditPurchase row is written BEFORE the buyer pays — it has to be, because
the webhook can only find the purchase again by its Checkout session id, and
that id does not exist until the session is created.

So clicking Buy and closing the tab left a `pending` row, and the buyer's ledger
counted it:

    Card purchase | 60 | pending | $15.00 AXONCoins pack

for a purchase nobody paid for. The row only became `expired` when a sweep ran
26 hours later, so for a day the page showed credits that did not exist — and
clicking Buy repeatedly filled it with more.

Nothing downstream ever spent them: owed_for_slip and undelivered both key on
STATUS_PAID, so the operator's payout list was never affected. That makes this
a display bug rather than theft, which is not a reason to leave it — a balance
that inflates on demand is the shape somebody builds an exploit around, and the
next person to read the page has no way to know it is only cosmetic.
"""

import ast
import os
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _constants(*parts):
    """Module-level literal assignments, read without importing.

    model/CreditPurchase.py imports `shared`, which pulls in the whole app and
    needs flask_migrate — absent in the local test environment. The values under
    test are plain literals, so reading them is both sufficient and faster.
    """
    path = os.path.join(BACKEND, *parts)
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)
    out = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                out[target.id] = node.value.value
    return out


class LedgerExcludesUnpaidTest(unittest.TestCase):
    """The exact symptom that was reported, at the level that produced it."""

    def setUp(self):
        c = _constants("model", "CreditPurchase.py")
        self.pending = c["STATUS_PENDING"]
        self.paid = c["STATUS_PAID"]
        self.delivered = c["STATUS_DELIVERED"]
        self.expired = c["STATUS_EXPIRED"]

    def _shown(self, statuses):
        """Which statuses survive the buyer-facing filter."""
        excluded = {self.expired, self.pending}
        return [s for s in statuses if s not in excluded]

    def test_a_pending_purchase_is_not_shown_as_credits(self):
        self.assertNotIn(self.pending, self._shown([self.pending]))

    def test_a_paid_purchase_is_shown(self):
        # The other direction matters just as much: somebody who paid and is
        # waiting for delivery must see it, or a working queue looks like a
        # lost payment.
        self.assertIn(self.paid, self._shown([self.paid]))
        self.assertIn(self.delivered, self._shown([self.delivered]))

    def test_repeated_abandoned_checkouts_add_nothing(self):
        statuses = [self.pending] * 20 + [self.paid]
        shown = self._shown(statuses)
        self.assertEqual(shown, [self.paid],
                         "twenty abandoned clicks contributed to the balance")


class FilterIsAppliedInBothPlacesTest(unittest.TestCase):
    """Static check that both buyer-facing queries exclude PENDING.

    Two separate queries feed the credits page — the ledger and the receipts
    table — and fixing one would leave the number visible in the other. Read
    from source rather than executed, so this needs no database.
    """

    def setUp(self):
        self.backend = BACKEND

    def _source(self, *parts):
        with open(os.path.join(self.backend, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_the_ledger_excludes_pending(self):
        source = self._source("services", "credit_ledger.py")
        self.assertIn("notin_([STATUS_EXPIRED, STATUS_PENDING])", source,
                      "purchase_entries must exclude unpaid checkouts")

    def test_the_receipts_list_excludes_pending(self):
        source = self._source("model", "CreditPurchase.py")
        self.assertIn("notin_([STATUS_EXPIRED, STATUS_PENDING])", source,
                      "purchases_for_slip must exclude unpaid checkouts")

    def test_owed_still_counts_only_paid(self):
        # The one number that drives an actual payout. It was already correct,
        # and this pins it: if it ever starts counting pending, an abandoned
        # click becomes a claim on the treasury rather than a cosmetic figure.
        source = self._source("model", "CreditPurchase.py")
        start = source.index("def owed_for_slip")
        body = source[start:start + 900]
        self.assertIn("CreditPurchase.status == STATUS_PAID", body)
        self.assertNotIn("STATUS_PENDING", body)

    def test_undelivered_still_counts_only_paid(self):
        source = self._source("model", "CreditPurchase.py")
        start = source.index("def undelivered")
        body = source[start:start + 500]
        self.assertIn("CreditPurchase.status == STATUS_PAID", body)


class OpenCheckoutCapTest(unittest.TestCase):
    """Hiding the rows fixes the display; capping them fixes the abuse.

    Every click on Buy writes a row and mints a Stripe session. Nothing stopped
    that in a loop, which costs database rows and Stripe API quota even though
    no credits were ever at stake.
    """

    def setUp(self):
        self.backend = BACKEND

    def test_a_cap_exists_and_is_small(self):
        MAX_OPEN_CHECKOUTS = _constants("model", "CreditPurchase.py")["MAX_OPEN_CHECKOUTS"]
        self.assertGreaterEqual(MAX_OPEN_CHECKOUTS, 2,
                                "a cap of one breaks a buyer with two tabs open")
        self.assertLessEqual(MAX_OPEN_CHECKOUTS, 10,
                             "too high to bound a loop")

    def test_checkout_enforces_it(self):
        with open(os.path.join(self.backend, "blueprints", "credits.py"),
                  encoding="utf-8") as handle:
            source = handle.read()
        start = source.index("def checkout()")
        body = source[start:start + 3000]
        self.assertIn("open_checkouts(slip.id)", body)
        self.assertIn("MAX_OPEN_CHECKOUTS", body)

    def test_expiring_early_cannot_lose_a_real_payment(self):
        # The cap expires the oldest open session, which is only safe because
        # mark_paid accepts EXPIRED -> PAID. If that guard ever gains
        # STATUS_EXPIRED, this cap starts eating payments that arrive late.
        with open(os.path.join(self.backend, "model", "CreditPurchase.py"),
                  encoding="utf-8") as handle:
            source = handle.read()
        start = source.index("def mark_paid")
        body = source[start:start + 700]
        guard = body[body.index("if purchase.status in"):]
        guard = guard[:guard.index("\n")]
        self.assertNotIn("STATUS_EXPIRED", guard,
                         "mark_paid must still accept a payment against an expired "
                         "session, or the open-checkout cap silently loses money")


if __name__ == "__main__":
    unittest.main()
