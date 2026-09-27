"""Paying for store goods with a card.

Cards buy store goods here, through create_item_session. (They also buy credit
packs, through a separate helper — that is a knowing business decision, and the
policy exposure is documented in services/stripe_api.py rather than argued
here.) These tests cover the goods path, where the two things that can go wrong
both cost real money:

  * marking an order paid when it was not, which ships goods for free;
  * marking it paid TWICE, which decrements stock twice for one sale — and
    Stripe retries webhooks, so this is a certainty rather than a risk.
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

ORDER_PENDING = "pending"
ORDER_PAID = "paid"


def _load_pure(relative_path, wanted, extra=None):
    """Exec just the named definitions, without importing the module.

    blueprints/store.py pulls in Flask, the database and the chain client at
    import time. This is the decision that hands out goods, and it is worth
    testing the real code rather than a restatement of it.
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


class FakeOrder(object):
    def __init__(self, item_id=1, status=ORDER_PENDING):
        self.item_id = item_id
        self.status = status
        self.paid_at = None
        self.ship_to = ""


class FakeItem(object):
    def __init__(self, stock=None):
        self.stock = stock


class FakeSession(object):
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


def _build(order=None, item=None):
    session = FakeSession()
    namespace = _load_pure(
        "blueprints/store.py",
        {"mark_card_order_paid"},
        extra={
            "datetime": datetime,
            "ORDER_PAID": ORDER_PAID,
            "order_by_stripe_session": lambda _id: order,
            "item_by_id": lambda _id: item,
            "db": types.SimpleNamespace(session=session),
        },
    )
    return namespace["mark_card_order_paid"], session


def checkout_session(session_id="cs_1", payment_status="paid", shipping=None):
    body = {"id": session_id, "payment_status": payment_status}
    if shipping:
        body["collected_information"] = {"shipping_details": shipping}
    return body



# The store was removed with the rest of the stripped blueprints, and the
# class(es) below read its files directly: blueprints/store.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the treatment the
# civil-rights classes in test_evidence_upload.py already have. The assertions
# are still correct and still worth having; deleting them would mean rewriting
# them from scratch if the feature returns, and a skipUnless brings them back
# the moment the files exist again.
_STORE_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/store.py",
    )
)
_STORE_PRESENT_GONE = "the store blueprint was removed; this class reads it"

@unittest.skipUnless(_STORE_PRESENT, _STORE_PRESENT_GONE)
class MarkCardOrderPaidTest(unittest.TestCase):

    def test_marks_a_paid_session_paid_and_takes_one_off_the_shelf(self):
        order, item = FakeOrder(), FakeItem(stock=3)
        mark, session = _build(order, item)

        self.assertEqual(mark(checkout_session()), "paid")
        self.assertEqual(order.status, ORDER_PAID)
        self.assertIsNotNone(order.paid_at)
        self.assertEqual(item.stock, 2)
        self.assertEqual(session.commits, 1)

    def test_a_repeated_webhook_does_not_sell_the_item_twice(self):
        # Stripe retries a webhook until it gets a 2xx, and it retries after
        # ones it already got. Decrementing stock again on the second delivery
        # loses an item per retry with nothing to show for it.
        order, item = FakeOrder(status=ORDER_PAID), FakeItem(stock=3)
        mark, session = _build(order, item)

        self.assertEqual(mark(checkout_session()), "already-paid")
        self.assertEqual(item.stock, 3)
        self.assertEqual(session.commits, 0)

    def test_an_unpaid_session_is_refused(self):
        # checkout.session.completed also fires for sessions that completed
        # WITHOUT payment succeeding — a delayed bank debit, say.
        order, item = FakeOrder(), FakeItem(stock=3)
        mark, session = _build(order, item)

        self.assertEqual(mark(checkout_session(payment_status="unpaid")), "not-paid")
        self.assertEqual(order.status, ORDER_PENDING)
        self.assertEqual(item.stock, 3)
        self.assertEqual(session.commits, 0)

    def test_an_unknown_session_is_refused_rather_than_guessed_at(self):
        mark, session = _build(order=None)
        self.assertEqual(mark(checkout_session("cs_nope")), "unknown-order")
        self.assertEqual(session.commits, 0)

    def test_unlimited_stock_is_left_alone(self):
        order, item = FakeOrder(), FakeItem(stock=None)
        mark, _ = _build(order, item)
        self.assertEqual(mark(checkout_session()), "paid")
        self.assertIsNone(item.stock)

    def test_stock_never_goes_negative(self):
        order, item = FakeOrder(), FakeItem(stock=0)
        mark, _ = _build(order, item)
        mark(checkout_session())
        self.assertEqual(item.stock, 0)

    def test_a_deleted_item_does_not_break_the_payment(self):
        # The order still has to be marked paid: the buyer's card was charged
        # whether or not the item row still exists.
        order = FakeOrder()
        mark, _ = _build(order, item=None)
        self.assertEqual(mark(checkout_session()), "paid")
        self.assertEqual(order.status, ORDER_PAID)

    def test_records_the_address_the_buyer_confirmed_while_paying(self):
        # Stripe's collected address is the one the buyer saw and approved, and
        # the one any dispute refers to — better than a free-text prompt typed
        # before checkout.
        order, item = FakeOrder(), FakeItem(stock=1)
        mark, _ = _build(order, item)
        mark(checkout_session(shipping={
            "name": "A Buyer",
            "address": {"line1": "1 Example Road", "line2": "Flat 2",
                        "city": "Leeds", "state": "", "postal_code": "LS1 1AA",
                        "country": "GB"},
        }))
        self.assertIn("A Buyer", order.ship_to)
        self.assertIn("1 Example Road", order.ship_to)
        self.assertIn("LS1 1AA", order.ship_to)
        self.assertIn("GB", order.ship_to)
        # An empty state must not leave a stray blank line or a double space.
        self.assertNotIn("  ", order.ship_to)
        self.assertNotIn("\n\n", order.ship_to)

    def test_a_digital_order_keeps_an_empty_address(self):
        order, item = FakeOrder(), FakeItem(stock=1)
        mark, _ = _build(order, item)
        mark(checkout_session())
        self.assertEqual(order.ship_to, "")

    def test_reads_the_older_shipping_details_shape_too(self):
        # Stripe moved shipping_details under collected_information; sessions
        # created before that still carry the flat key, and an order that
        # silently loses its address is one nobody can post.
        order, item = FakeOrder(), FakeItem(stock=1)
        mark, _ = _build(order, item)
        body = checkout_session()
        body["shipping_details"] = {"name": "Older Shape",
                                    "address": {"line1": "2 Legacy Way", "country": "US"}}
        mark(body)
        self.assertIn("Older Shape", order.ship_to)
        self.assertIn("2 Legacy Way", order.ship_to)


class ItemSessionTest(unittest.TestCase):
    """The Checkout session itself: price from the server, never the request."""

    def _api(self):
        posted = {}

        def fake_post(path, data):
            posted["path"] = path
            posted["data"] = data
            return {"id": "cs_test", "url": "https://checkout.stripe.test/x"}

        namespace = _load_pure(
            "services/stripe_api.py",
            {"create_item_session", "SHIPPING_COUNTRIES"},
            extra={"_post": fake_post},
        )
        return namespace, posted

    def test_price_comes_from_the_caller_not_the_buyer(self):
        api, posted = self._api()
        api["create_item_session"](
            name="A Shirt", description="Cotton", amount_cents=2500,
            success_url="https://s/ok", cancel_url="https://s/no",
            metadata={"order_id": 7, "kind": "store_order"})
        data = posted["data"]
        self.assertEqual(data["line_items[0][price_data][unit_amount]"], 2500)
        self.assertEqual(data["line_items[0][price_data][currency]"], "usd")
        self.assertEqual(data["mode"], "payment")
        self.assertEqual(data["metadata[order_id]"], "7")
        self.assertEqual(data["metadata[kind]"], "store_order")

    def test_shipping_is_collected_only_for_things_that_ship(self):
        api, posted = self._api()
        api["create_item_session"](
            name="A Download", description="", amount_cents=500,
            success_url="https://s/ok", cancel_url="https://s/no",
            metadata={}, collect_shipping=False)
        self.assertFalse([k for k in posted["data"] if "shipping_address" in k])

        api, posted = self._api()
        api["create_item_session"](
            name="A Shirt", description="", amount_cents=2500,
            success_url="https://s/ok", cancel_url="https://s/no",
            metadata={}, collect_shipping=True)
        countries = [v for k, v in posted["data"].items() if "allowed_countries" in k]
        self.assertIn("US", countries)
        self.assertIn("GB", countries)
        # Every allowed country must be listed exactly once: a repeated index
        # silently drops one, and the dropped one is a customer who cannot buy.
        self.assertEqual(len(countries), len(set(countries)))
        self.assertEqual(len(countries), len(api["SHIPPING_COUNTRIES"]))

    def test_a_long_name_is_truncated_rather_than_rejected_by_stripe(self):
        api, posted = self._api()
        api["create_item_session"](
            name="x" * 400, description="y" * 900, amount_cents=100,
            success_url="https://s/ok", cancel_url="https://s/no", metadata={})
        self.assertLessEqual(len(posted["data"]["line_items[0][price_data][product_data][name]"]), 250)
        self.assertLessEqual(
            len(posted["data"]["line_items[0][price_data][product_data][description]"]), 400)

    def test_an_empty_description_is_omitted_not_sent_blank(self):
        # Stripe rejects an empty product description outright.
        api, posted = self._api()
        api["create_item_session"](
            name="A Shirt", description="", amount_cents=100,
            success_url="https://s/ok", cancel_url="https://s/no", metadata={})
        self.assertNotIn("line_items[0][price_data][product_data][description]", posted["data"])


if __name__ == "__main__":
    unittest.main()
