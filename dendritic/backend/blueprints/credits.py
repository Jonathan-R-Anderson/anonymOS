"""Buying credits with a card, and everything else that credits arrive from.

Stripe Checkout is hosted, so no card details reach this server and there is no
PCI surface here. The flow is: pick a pack -> Stripe collects payment -> a SIGNED
webhook tells us it succeeded -> the credits are queued for delivery to the
buyer's wallet.

A NOTE ON WHAT THIS IS
----------------------
Selling our own token for card payment is, in substance, a first-party token
sale. Stripe's restricted-businesses list puts "Initial coin offerings (ICOs)"
under *prohibited* — not restricted, not approval-required — and an account
closed for it takes the store's card payments down with it and can hold the
balance for months against chargebacks. The commercial shape has the same edge:
a card payment is reversible for months and an ERC-20 transfer is not reversible
at all, so buy-move-chargeback costs the merchant the goods and the money.

This is a business decision, made knowingly, and it is recorded here rather than
argued: whoever reads this next should know the exposure exists rather than
discover it from a support email. Store goods are also sold by card (see
blueprints/store.py), which is unambiguously fine — the risk is specific to
selling the token.

**Why delivery is queued rather than instant.** Sending AXON needs a key that
can move the treasury, and a public web server holding one is the largest single
risk in this system: a compromise there drains everything, whereas a compromise
of the site alone currently costs nobody their money. If instant delivery is
wanted, the safe shape is a DISPENSER wallet holding a small float — a few
hundred credits, topped up by hand — so a break-in costs the float rather than
the treasury.
"""

import datetime

from flask import (
    Blueprint, flash, jsonify, redirect, render_template, request, url_for,
)

from model.CreditPurchase import (
    CreditPurchase, PACKS, STATUS_PENDING,
    expire_stale_pending, mark_expired, mark_paid, owed_for_slip,
    purchase_by_session, purchases_for_slip,
)
from model.Slip import get_slip, slip_wallet_address
from model.Store import credits_per_dollar
from services import stripe_api, stripe_onramp
from services.pof_chain import ChainError, credit_balance, token_address
from shared import app, db

credits_blueprint = Blueprint("credits", __name__, template_folder="template")


def _wants_json():
    """Whether the caller is a script or a browser following a form.

    Cancelling has to work with JavaScript switched off — somebody trying to
    stop being charged should never be blocked by our front end — so these
    endpoints answer both, and a plain form gets a redirect instead of a page of
    raw JSON.
    """
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept") or ""
    return "application/json" in accept and "text/html" not in accept


def pack_price_cents(credits):
    """Dollar price for a pack, from the one rate the store also uses.

    Derived, never a second price list: if packs were priced independently from
    the store's credits-per-dollar, the two would drift and the gap would be
    free money for whoever noticed first.
    """
    rate = credits_per_dollar()
    return -(-int(credits) * 100 // rate)  # ceil, so a pack never sells short


@credits_blueprint.route("/")
def index():
    # Swept here rather than only on the webhook: if the webhook secret is
    # unset or a delivery failed every retry, checkout.session.expired never
    # arrives and the phantom would outlive the session that caused it. One
    # indexed UPDATE on a page nobody loads in a hot loop.
    try:
        expire_stale_pending()
    except Exception:
        app.logger.exception("could not sweep abandoned checkouts")

    slip = get_slip()
    wallet = slip_wallet_address(slip) if slip else None
    packs = [{"credits": c, "cents": pack_price_cents(c),
              "dollars": "%.2f" % (pack_price_cents(c) / 100.0)} for c in PACKS]
    balance, owed = None, 0
    if wallet:
        try:
            balance = credit_balance(token_address(), wallet)
        except ChainError:
            balance = None  # unreachable chain shows as unknown, never as zero
    if slip is not None:
        owed = owed_for_slip(slip.id)
    from model.Membership import membership_for
    from services.credit_ledger import deposits
    from services.membership import plan as membership_plan

    # The welcome grant, and why it is not claimable yet if it is not.
    from services.signup_grants import status_for

    # The claim panel moved onto this page, so its contract addresses come from
    # here now. Read from the console's saved settings, never guessed: a page
    # that invented an address would send claims into a contract nobody
    # deployed.
    from services.pof_chain import CHAIN_EXPLORER, pof_addresses
    from services.token_supply import cached_summary as supply_summary

    addresses = pof_addresses()

    return render_template(
        "credits.html",
        # refresh=True: this page already blocks on a chain read for the
        # wallet balance, so it is the right place to pay for the figure
        # and warm the cache the front page reads.
        supply=supply_summary(refresh=True),
        reward_distributor=addresses.get("RewardDistributor") or "",
        treasury=addresses.get("Treasury") or "",
        epoch_manager=addresses.get("EpochManager") or "",
        token=addresses.get("AxonToken") or addresses.get("AnonToken")
        or addresses.get("CreditToken") or "",
        explorer=CHAIN_EXPLORER,
        signup=status_for(slip) if slip else None,
        ledger=deposits(slip, wallet),
        membership=membership_for(slip.id) if slip else None,
        membership_plan=membership_plan(),
        packs=packs,
        rate=credits_per_dollar(),
        slip=slip,
        wallet=wallet,
        configured=stripe_api.configured(),
        purchases=purchases_for_slip(slip.id) if slip else [],
        balance=balance,
        owed=owed,
    )


@credits_blueprint.route("/signup-grant", methods=["POST"])
def claim_signup():
    """Claim the welcome grant.

    Queues a CreditGrant for an operator rather than sending anything — see
    services/signup_grants.py for what has to be true first, and why free
    accounts make an unconditional faucet a bad idea.
    """
    slip = get_slip()
    if slip is None:
        flash("Sign in with your slip first.")
        return redirect(url_for("slip.landing"))
    from services.signup_grants import GrantError, claim

    try:
        claim(slip)
    except GrantError as exc:
        flash(str(exc))
    else:
        flash("Claimed. An operator sends it to your wallet.")
    return redirect(url_for("credits.index"))


@credits_blueprint.route("/checkout", methods=["POST"])
def checkout():
    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Log in to buy AXONCoins."}), 403
    wallet = slip_wallet_address(slip)
    if not wallet:
        # Without a wallet there is nowhere to deliver, and taking money for
        # something undeliverable is worse than refusing the sale.
        return jsonify({"error": "Link a wallet first — that is where the AXONCoins go."}), 400
    if not stripe_api.configured():
        return jsonify({"error": "Card payments are not configured yet."}), 503

    try:
        credits = int((request.get_json(silent=True) or {}).get("credits") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "Choose a pack."}), 400
    if credits not in PACKS:
        # Only the listed packs: an arbitrary quantity is how a client-chosen
        # price sneaks in.
        return jsonify({"error": "Choose one of the listed packs."}), 400

    # Bound how many unpaid sessions one slip can have open. Each click writes a
    # row and mints a Stripe session; without a cap that is an unbounded loop
    # against our own database and Stripe quota. Expiring the oldest rather than
    # refusing outright, because the buyer's intent — start a checkout — is
    # legitimate and a hard refusal on a paid feature is the wrong answer to
    # somebody who simply changed their mind twice.
    #
    # Safe to expire early: mark_paid deliberately accepts EXPIRED -> PAID, so a
    # payment that lands against one of these still wins.
    from model.CreditPurchase import MAX_OPEN_CHECKOUTS, open_checkouts

    stale = open_checkouts(slip.id)
    if len(stale) >= MAX_OPEN_CHECKOUTS:
        stale.sort(key=lambda row: row.created_at or datetime.datetime.min)
        for row in stale[:len(stale) - MAX_OPEN_CHECKOUTS + 1]:
            mark_expired(row)
        db.session.commit()

    amount = pack_price_cents(credits)
    purchase = CreditPurchase(
        slip_id=slip.id, wallet=wallet, credits=credits,
        amount_cents=amount, status=STATUS_PENDING)
    # The buyer's address is knowable HERE and nowhere else in this flow: the
    # webhook that confirms payment is a request from Stripe's servers, so its
    # remote address is Stripe's. Recording that would look plausible and be
    # worthless — every purchase would appear to come from the same few places.
    #
    # The order id is filled in below, once Stripe has issued a session id.
    from services import purchase_identity
    purchase.origin_hash = purchase_identity.origin_hash(purchase_identity.client_ip())
    db.session.add(purchase)
    db.session.commit()

    base = (app.config.get("BASE_URL") or request.url_root).rstrip("/")
    try:
        session = stripe_api.create_checkout_session(
            credits=credits,
            amount_cents=amount,
            success_url="%s/credits/thanks?session_id={CHECKOUT_SESSION_ID}" % base,
            cancel_url="%s/credits/" % base,
            metadata={"purchase_id": purchase.id, "wallet": wallet, "credits": credits},
        )
    except stripe_api.StripeError as exc:
        db.session.delete(purchase)
        db.session.commit()
        return jsonify({"error": str(exc)}), 502

    purchase.stripe_session_id = session.get("id")
    # The on-chain order id, now that Stripe has issued the session it hashes.
    # Stored rather than derived at delivery time so the value that goes on
    # chain is the one recorded here, even if the session id is later archived.
    purchase.order_id = purchase_identity.order_id(purchase.stripe_session_id)
    db.session.commit()
    return jsonify({"ok": True, "url": session.get("url")})


@credits_blueprint.route("/guest-checkout", methods=["POST"])
def guest_checkout():
    """Buy AXONCoins without an account, delivered to an address you type.

    The account requirement was never protecting anything — delivery goes to a
    wallet, and a wallet is what the buyer supplies either way. Requiring a slip
    first turned a card payment into a signup, which is the step most people
    leave at.

    WHAT REPLACES THE ACCOUNT AS A SAFETY NET
    -----------------------------------------
    Nothing, and that is the honest position: a guest has no purchase history,
    no support thread, and no way to prove which purchase was theirs beyond the
    Stripe receipt. So the one thing that CAN be checked is checked hard —
    services/wallet_address rejects a mistyped address on its EIP-55 checksum
    before a card is charged, because a transfer to a valid-but-wrong address is
    irreversible and there is no account to recover it through.

    Rate limiting keys on the origin hash rather than a slip, since there is no
    slip. It bounds row and Stripe-session creation; it is not a fraud control.
    """
    if not stripe_api.configured():
        return jsonify({"error": "Card payments are not configured yet."}), 503

    payload = request.get_json(silent=True) or {}
    from services import purchase_identity, wallet_address

    try:
        wallet, verified = wallet_address.validate(payload.get("wallet"))
    except wallet_address.AddressError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        credits = int(payload.get("credits") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "Choose a pack."}), 400
    if credits not in PACKS:
        return jsonify({"error": "Choose one of the listed packs."}), 400

    origin = purchase_identity.origin_hash(purchase_identity.client_ip())

    # Bound how many unpaid guest sessions one origin can open. Without a slip
    # there is no other handle, and every click writes a row and mints a Stripe
    # session. Not a fraud control — a bound on our own database and quota.
    from model.CreditPurchase import MAX_OPEN_CHECKOUTS
    if origin and origin != purchase_identity.ZERO:
        open_here = (
            db.session.query(CreditPurchase)
            .filter(CreditPurchase.slip_id.is_(None),
                    CreditPurchase.origin_hash == origin,
                    CreditPurchase.status == STATUS_PENDING)
            .count()
        )
        if open_here >= MAX_OPEN_CHECKOUTS:
            return jsonify({"error":
                "You have several unfinished checkouts open. Complete or "
                "abandon one before starting another."}), 429

    amount = pack_price_cents(credits)
    purchase = CreditPurchase(
        slip_id=None, wallet=wallet, credits=credits,
        amount_cents=amount, status=STATUS_PENDING)
    purchase.origin_hash = origin
    db.session.add(purchase)
    db.session.commit()

    base = (app.config.get("BASE_URL") or request.url_root).rstrip("/")
    try:
        session = stripe_api.create_checkout_session(
            credits=credits,
            amount_cents=amount,
            success_url="%s/credits/thanks?session_id={CHECKOUT_SESSION_ID}" % base,
            cancel_url="%s/credits/" % base,
            metadata={"purchase_id": purchase.id, "wallet": wallet,
                      "credits": credits, "guest": "1"},
        )
    except stripe_api.StripeError as exc:
        db.session.delete(purchase)
        db.session.commit()
        return jsonify({"error": str(exc)}), 502

    purchase.stripe_session_id = session.get("id")
    purchase.order_id = purchase_identity.order_id(purchase.stripe_session_id)
    db.session.commit()
    return jsonify({"ok": True, "url": session.get("url"),
                    "wallet": wallet, "checksum_verified": verified})


@credits_blueprint.route("/webhook", methods=["POST"])
def webhook():
    """Stripe's signed callback — the only thing that marks a purchase paid.

    The browser returning from Checkout is not proof: anyone can visit a success
    URL. Payment is believed only when Stripe says so with a valid signature.
    """
    event, error = stripe_api.verify_webhook(request.get_data(), request.headers.get("Stripe-Signature"))
    if error:
        app.logger.warning("Stripe webhook refused: %s", error)
        return jsonify({"error": error}), 400

    kind = event.get("type")
    obj = (event.get("data") or {}).get("object") or {}

    # Subscriptions arrive as their own events, and the one that matters most is
    # invoice.paid: it fires on the first payment AND on every renewal, which is
    # the only event that reliably marks "another month has been paid for".
    if kind in ("customer.subscription.created", "customer.subscription.updated",
                "customer.subscription.deleted", "invoice.paid",
                "invoice.payment_failed"):
        from services import membership_billing
        handled = membership_billing.handle_event(kind, obj)
        return jsonify({"ok": True, "handled": handled})

    # An unpaid Checkout session expires 24h after creation and says so. Without
    # this, the row it left behind stays `pending` forever and is counted as
    # credits on the way — an abandoned click reads as a purchase in progress.
    if kind == "checkout.session.expired":
        purchase = purchase_by_session(obj.get("id"))
        if purchase is None:
            return jsonify({"ok": True, "unknown": True})
        mark_expired(purchase)
        db.session.commit()
        return jsonify({"ok": True, "handled": "expired"})

    if kind != "checkout.session.completed":
        return jsonify({"ok": True, "ignored": kind})

    session = obj
    # A subscription checkout also completes; its credits come from the invoice,
    # not from here, so it must not be looked up as a one-off pack purchase.
    if session.get("mode") == "subscription":
        from services import membership_billing
        membership_billing.link_checkout(session)
        return jsonify({"ok": True, "handled": "subscription-checkout"})

    # Store orders are the only NEW thing cards buy. Dispatched on the session's
    # own metadata rather than by guessing from the amount, because a pack
    # purchase and a store order can be the same number of dollars.
    # The store was removed with the rest of the non-infrastructure site. A
    # webhook for one can still arrive -- Stripe retries, and an order placed
    # before the removal may settle after it -- so this is acknowledged and
    # logged rather than raising. Returning 200 stops Stripe retrying forever;
    # the log line is what tells an operator a refund is owed.
    if (session.get("metadata") or {}).get("kind") == "store_order":
        app.logger.error(
            "store card payment received for session %s but the store no longer exists; "
            "this payment was NOT fulfilled and needs a manual refund",
            session.get("id"),
        )
        return jsonify({"ok": True, "handled": "store-order-orphaned"})

    purchase = purchase_by_session(session.get("id"))
    if purchase is None:
        app.logger.warning("Stripe webhook for an unknown session %s", session.get("id"))
        return jsonify({"ok": True, "unknown": True})
    if session.get("payment_status") != "paid":
        return jsonify({"ok": True, "not_paid": session.get("payment_status")})

    mark_paid(purchase, session.get("payment_intent"))
    db.session.commit()
    app.logger.info("credits purchased: %d for wallet %s (purchase %d)",
                    purchase.credits, purchase.wallet, purchase.id)

    # Deliver from the Treasury, if automatic delivery is switched on. Off by
    # default, in which case this is a no-op and the purchase waits for an
    # operator exactly as it always did.
    #
    # AFTER the commit above, and never inside it. A delivery that succeeds
    # while the transaction later rolls back would send tokens for a purchase
    # the database does not think was paid — the one failure that cannot be
    # repaired by retrying, because the chain does not roll back with us.
    #
    # Failure here is logged and swallowed rather than returned: a non-2xx
    # tells Stripe the webhook failed and it retries the whole thing, when the
    # payment was in fact recorded correctly and only the delivery did not
    # happen. That is an operator's problem to finish, not Stripe's to repeat.
    from services import token_delivery
    if token_delivery.enabled():
        try:
            tx_hash = token_delivery.deliver(purchase)
            from model.CreditPurchase import mark_delivered
            mark_delivered(purchase, tx_hash)
            db.session.commit()
            app.logger.info("credits delivered on chain: purchase %d tx %s",
                            purchase.id, tx_hash)
        except Exception:
            db.session.rollback()
            app.logger.exception(
                "automatic delivery failed for purchase %d; it stays queued",
                purchase.id)

    return jsonify({"ok": True})


@credits_blueprint.route("/subscribe", methods=["POST"])
def subscribe():
    """Start a monthly membership: every machine, and credits each month."""
    from services import membership as plan_service

    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Log in to subscribe."}), 403
    wallet = slip_wallet_address(slip)
    if not wallet:
        # Same rule as the packs: taking money for something undeliverable is
        # worse than refusing the sale.
        return jsonify({"error": "Link a wallet first — that is where the AXONCoins go."}), 400
    if not stripe_api.configured():
        return jsonify({"error": "Card payments are not configured yet."}), 503

    from model.Membership import membership_for
    existing = membership_for(slip.id)
    if existing is not None and existing.is_active and not existing.cancel_at_period_end:
        return jsonify({"error": "You already have an active membership."}), 400

    plan = plan_service.plan()
    base = (app.config.get("BASE_URL") or request.url_root).rstrip("/")
    try:
        session = stripe_api.create_subscription_session(
            price_cents=plan["price_cents"],
            credits_per_month=plan["credits_per_month"],
            success_url="%s/credits/?subscribed=1" % base,
            cancel_url="%s/credits/" % base,
            metadata={"wallet": wallet, "slip_id": slip.id},
            client_reference_id=slip.id,
        )
    except stripe_api.StripeError as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({"ok": True, "url": session.get("url")})


def _answer(ok, message, status=200, extra=None):
    """One reply for both callers: JSON for a script, a flash and a redirect for
    a browser that just submitted a form."""
    if _wants_json():
        body = {"ok": True, "message": message} if ok else {"error": message}
        body.update(extra or {})
        return jsonify(body), (status if not ok else 200)
    flash(message)
    # Back where they were. Account settings and the credits page both carry
    # these buttons, and being bounced to the other one is disorienting.
    referrer = request.referrer or ""
    if "/profile" in referrer:
        return redirect(url_for("profiles.edit"))
    return redirect(url_for("credits.index") + "#membership")


@credits_blueprint.route("/subscription/cancel", methods=["POST"])
def cancel_subscription():
    """Stop renewing. Access continues to the end of the paid period."""
    from model.Membership import membership_for

    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Log in first."}), 403
    membership = membership_for(slip.id)
    if membership is None or not membership.stripe_subscription_id:
        return _answer(False, "You do not have a membership.", 400)
    try:
        stripe_api.cancel_subscription(membership.stripe_subscription_id)
    except stripe_api.StripeError as exc:
        return _answer(False, str(exc), 502)
    membership.cancel_at_period_end = True
    db.session.commit()
    app.logger.info("membership cancelled by slip %s (subscription %s)",
                    slip.id, membership.stripe_subscription_id)
    ends = (membership.renews_on.strftime("%d %b %Y")
            if membership.renews_on else "the end of this period")
    return _answer(True, "Membership cancelled. You keep access until %s, and nothing "
                         "further will be charged." % ends,
                   extra={"renews_on": membership.renews_on.isoformat() + "Z"
                          if membership.renews_on else None})


@credits_blueprint.route("/subscription/refresh", methods=["POST"])
def refresh_subscription():
    """Ask Stripe what this membership really is, and write that down.

    A member whose row is wrong — a webhook that never fired, a handler that had
    a bug — can repair it themselves instead of contacting somebody. Safe to
    press at any time: it only ever copies Stripe's answer, and the credit
    deposit is keyed on the invoice so pressing it twice does nothing twice.
    """
    from model.Membership import membership_for
    from services import membership_billing

    slip = get_slip()
    if slip is None:
        return _answer(False, "Log in first.", 403)
    membership = membership_for(slip.id)
    if membership is None or not membership.stripe_subscription_id:
        return _answer(False, "You do not have a membership.", 400)
    try:
        result = membership_billing.resync(membership.stripe_subscription_id)
    except stripe_api.StripeError as exc:
        return _answer(False, str(exc), 502)
    if not result.get("ok"):
        return _answer(False, result.get("reason") or "Could not refresh.", 502)
    if result.get("credited"):
        return _answer(True, "Membership refreshed, and this month's credits are queued "
                             "for delivery to your wallet.")
    return _answer(True, "Membership refreshed — it is %s."
                   % ("active" if result.get("active") else "not active"))


@credits_blueprint.route("/subscription/resume", methods=["POST"])
def resume_subscription():
    """Take back a cancellation before the paid period runs out."""
    from model.Membership import membership_for

    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Log in first."}), 403
    membership = membership_for(slip.id)
    if membership is None or not membership.stripe_subscription_id:
        return _answer(False, "You do not have a membership.", 400)
    if not membership.cancel_at_period_end:
        return _answer(False, "That membership is not cancelling.", 400)
    if not membership.is_active:
        # The period already ran out. Resuming is not a thing Stripe can do to a
        # subscription that has ended, and pretending otherwise would take a
        # click and give nothing back.
        return _answer(False, "That membership has already ended — subscribe again "
                              "to restart it.", 400)
    try:
        stripe_api.resume_subscription(membership.stripe_subscription_id)
    except stripe_api.StripeError as exc:
        return _answer(False, str(exc), 502)
    membership.cancel_at_period_end = False
    db.session.commit()
    app.logger.info("membership resumed by slip %s (subscription %s)",
                    slip.id, membership.stripe_subscription_id)
    return _answer(True, "Membership kept. It renews as usual.")


@credits_blueprint.route("/thanks")
def thanks():
    """Where Stripe returns the buyer.

    Confirms by asking Stripe rather than trusting the redirect, so the page is
    honest even if the webhook has not landed yet — but it still only records
    payment, never delivery.
    """
    slip = get_slip()
    session_id = (request.args.get("session_id") or "").strip()
    purchase = purchase_by_session(session_id) if session_id else None
    if purchase is not None and purchase.status == STATUS_PENDING:
        try:
            session = stripe_api.retrieve_session(session_id)
            if session.get("payment_status") == "paid":
                mark_paid(purchase, session.get("payment_intent"))
                db.session.commit()
        except stripe_api.StripeError:
            # The webhook is the authority anyway; this is only a courtesy so
            # the page is not stale.
            pass
    return render_template("credits-thanks.html", purchase=purchase, slip=slip)


@credits_blueprint.route("/onramp")
def onramp():
    """Buy ETH with a card, delivered to your own wallet on Ethereum mainnet.

    Deliberately its own page rather than a panel on the credits page. The two
    products look alike and are not alike: the credit packs are us selling our
    own token, the onramp is Stripe selling a mainstream cryptocurrency to a
    customer whose KYC Stripe holds. Putting them side by side invites the
    reading that a card buys AXONCoins, which is the one thing this cannot do.
    """
    slip = get_slip()
    wallet = slip_wallet_address(slip) if slip else None
    return render_template(
        "credits-onramp.html",
        slip=slip,
        wallet=wallet,
        configured=stripe_onramp.configured(),
        # The onramp's own key: it must come from the same account that
        # minted the client secret, which is not necessarily the store's.
        publishable_key=stripe_onramp.publishable_key(),
        currency=stripe_onramp.DEFAULT_CURRENCY,
        network=stripe_onramp.DEFAULT_NETWORK,
    )


@credits_blueprint.route("/onramp/session", methods=["POST"])
def onramp_session():
    """Open a Stripe onramp session and hand its client secret to the widget.

    The destination wallet is read from the SESSION, never from the request. It
    is the one field worth being strict about: a client-supplied address means
    anybody who can get a logged-in browser to POST here can have the purchase
    delivered somewhere else, and a crypto transfer has no chargeback. Stripe
    would have delivered exactly what was asked for.
    """
    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Log in first."}), 403

    wallet = slip_wallet_address(slip)
    if not wallet:
        return jsonify({
            "error": "Link a wallet to your profile first — that is where the "
                     "ETH is delivered, and there is no way to redirect it "
                     "afterwards."}), 400

    payload = request.get_json(silent=True) or {}
    amount = payload.get("amount")
    if amount is not None:
        # Passed to Stripe as a *suggested* amount; the customer confirms the
        # real one in the widget. Validated anyway so a malformed value fails
        # here with a readable message instead of inside Stripe's API.
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            return jsonify({"error": "That is not an amount."}), 400
        if not (0 < amount <= 10000):
            return jsonify({"error": "Pick an amount between 0 and 10000."}), 400

    # X-Forwarded-For is a comma-separated chain behind a proxy, and handing
    # Stripe the whole string is worse than handing it nothing — it uses this for
    # its own compliance checks. threat_watch already takes the first hop.
    from services.threat_watch import _client_address

    try:
        session = stripe_onramp.create_session(
            wallet, amount=amount, customer_ip=_client_address() or None)
    except stripe_onramp.OnrampError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(session)


@credits_blueprint.route("/mine.json")
def mine():
    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Log in."}), 403
    rows = [{
        "credits": p.credits,
        "dollars": "%.2f" % (p.amount_cents / 100.0),
        "status": p.status,
        "delivery_tx": p.delivery_tx,
        "created_at": p.created_at.isoformat() + "Z" if p.created_at else None,
    } for p in purchases_for_slip(slip.id)]
    return jsonify({"purchases": rows})
