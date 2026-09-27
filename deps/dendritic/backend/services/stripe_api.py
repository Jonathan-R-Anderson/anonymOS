"""Stripe, over plain HTTPS.

No `stripe` package: the image installs from a hash-pinned Pipfile, so adding a
dependency means regenerating the lock, and Checkout needs exactly two calls.
`requests` is already here and the REST API is stable.

Card details never touch this server. Checkout is hosted by Stripe, the browser
goes there to pay, and we learn the outcome from a signed webhook — so the site
never sees a card number and there is no PCI surface to secure.

WHAT CARDS BUY HERE
-------------------
Both store goods and credit packs.

Store goods — create_item_session — are an ordinary card sale and carry no
policy risk. Credit packs — create_checkout_session — sell the token itself,
which Stripe's restricted-businesses list treats as an ICO and puts under
*prohibited*. That is a knowing business decision, not an oversight, and the
exposure is real in two directions: the account can be closed (taking store
payments with it, since both flow through these keys) and a card payment stays
reversible for months while an ERC-20 transfer never is.

Recorded here so the next person to read this knows the risk exists rather than
learning it from a support email.

A launchpad was investigated as the alternative that carries none of this and
was dropped: Fjord Foundry supports Ethereum, Polygon, Arbitrum, Optimism,
Avalanche, BNB Chain, Base, Blast and Sonic, and this stack settles on Ethereum
Era, which is not among them. Cards are the onramp because they are the onramp
that works on this chain.
"""

import hashlib
import hmac
import json
import time

import requests

from shared import app

STRIPE_API = "https://api.stripe.com/v1"
TIMEOUT = 20


# Countries Stripe may collect a shipping address for. Deliberately short: it
# is the list of places somebody is actually willing to post a parcel to, and
# growing it is a shipping decision rather than a code change.
SHIPPING_COUNTRIES = ("US", "CA", "GB", "IE", "AU", "NZ", "DE", "FR", "NL", "SE", "NO", "DK", "FI", "ES", "IT", "PL", "PT", "JP")

# Stripe signs webhooks with a timestamp; anything older is refused so a
# captured callback cannot be replayed later to mint credits again.
WEBHOOK_TOLERANCE_SECONDS = 300


class StripeError(RuntimeError):
    pass


def secret_key():
    return (app.config.get("STRIPE_SECRET_KEY") or "").strip()


def publishable_key():
    return (app.config.get("STRIPE_PUBLISHABLE_KEY") or "").strip()


def webhook_secret():
    return (app.config.get("STRIPE_WEBHOOK_SECRET") or "").strip()


def configured():
    return bool(secret_key() and publishable_key())


def _post(path, data, headers=None, api_key=None):
    """POST to Stripe.

    `headers` exists for endpoints that are only routable on a non-default API
    version — the crypto onramp is one, and Stripe answers a version it does not
    serve with "Unrecognized request URL", which reads as a wrong path rather
    than a wrong version. Passing the header per-call rather than pinning the
    account's version globally keeps that opt-in to the one caller that needs it.

    `api_key` exists because a feature can be enabled on a DIFFERENT Stripe
    account than the one taking payments. The crypto onramp is gated per
    account, and an account that has it is not necessarily the account selling
    the store's goods. Overriding the key per call lets the onramp authenticate
    as the enrolled account while everything else keeps using the live one —
    the alternative, swapping the global key, silently moves Checkout,
    subscriptions and the store onto whichever account the onramp needed.
    """
    key = api_key or secret_key()
    if not key:
        raise StripeError("Stripe is not configured on this server.")
    try:
        response = requests.post(
            STRIPE_API + path, data=data, auth=(key, ""), timeout=TIMEOUT,
            headers=headers or None)
    except Exception as exc:
        raise StripeError("Stripe unreachable: %s" % exc) from exc
    if response.status_code >= 400:
        try:
            detail = response.json().get("error", {}).get("message", "")
        except ValueError:
            detail = response.text[:200]
        # Never echo the raw body: Stripe errors can quote request parameters,
        # and this string reaches the browser.
        raise StripeError(detail or "Stripe rejected the request (HTTP %d)" % response.status_code)
    return response.json()


def create_item_session(name, description, amount_cents, success_url, cancel_url,
                        metadata, collect_shipping=False):
    """A hosted Checkout page for one store item.

    The PRICE is built here, server-side, from the item's stored price. It is
    never taken from the request: a client-supplied amount would let anyone buy
    anything for a cent.
    """
    data = {
        "mode": "payment",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "line_items[0][quantity]": 1,
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": int(amount_cents),
        "line_items[0][price_data][product_data][name]": str(name)[:250],
    }
    if description:
        data["line_items[0][price_data][product_data][description]"] = str(description)[:400]
    if collect_shipping:
        # Let Stripe collect and validate the address for a physical good rather
        # than trusting a free-text box: a mistyped address is discovered at the
        # point of sale instead of at the point of posting.
        for index, country in enumerate(SHIPPING_COUNTRIES):
            data["shipping_address_collection[allowed_countries][%d]" % index] = country
    for key, value in (metadata or {}).items():
        data["metadata[%s]" % key] = str(value)
    return _post("/checkout/sessions", data)


def create_checkout_session(credits, amount_cents, success_url, cancel_url, metadata):
    """A hosted Checkout page for one credit pack.

    The PRICE is built here, server-side, from the pack the buyer chose. It is
    never taken from the request: a client-supplied amount would let anyone buy
    a thousand credits for a cent.
    """
    data = {
        "mode": "payment",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "line_items[0][quantity]": 1,
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": int(amount_cents),
        "line_items[0][price_data][product_data][name]": "%d credits" % int(credits),
        "line_items[0][price_data][product_data][description]":
            "Spendable in the store; funds node rewards.",
    }
    for key, value in (metadata or {}).items():
        data["metadata[%s]" % key] = str(value)
    return _post("/checkout/sessions", data)


def _get(path):
    key = secret_key()
    if not key:
        raise StripeError("Stripe is not configured on this server.")
    try:
        response = requests.get(STRIPE_API + path, auth=(key, ""), timeout=TIMEOUT)
    except Exception as exc:
        raise StripeError("Stripe unreachable: %s" % exc) from exc
    if response.status_code >= 400:
        try:
            detail = response.json().get("error", {}).get("message", "")
        except ValueError:
            detail = response.text[:200]
        raise StripeError(detail or "Stripe rejected the request (HTTP %d)" % response.status_code)
    return response.json()


def create_subscription_session(price_cents, credits_per_month, success_url,
                                cancel_url, metadata, client_reference_id=None):
    """A hosted Checkout page for a recurring monthly subscription.

    Same rule as the one-off packs: the price is built here from the site's
    configured plan and never read from the request. A client-supplied amount on
    a RECURRING charge would be worse than on a single one, because the mistake
    repeats every month until somebody notices.

    client_reference_id carries the slip through Checkout, so a renewal invoice
    months later can still be attributed to an account without trusting anything
    the browser said at the time.
    """
    data = {
        "mode": "subscription",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "line_items[0][quantity]": 1,
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": int(price_cents),
        "line_items[0][price_data][recurring][interval]": "month",
        "line_items[0][price_data][product_data][name]":
            "Syndichan membership — %d credits a month" % int(credits_per_month),
        "line_items[0][price_data][product_data][description]":
            "Every lab machine, and %d credits deposited each month."
            % int(credits_per_month),
        # Repeated onto the subscription itself: Checkout metadata does not
        # travel to the invoices, and the invoice is where renewals arrive.
        "subscription_data[metadata][credits_per_month]": int(credits_per_month),
    }
    if client_reference_id is not None:
        data["client_reference_id"] = str(client_reference_id)
        data["subscription_data[metadata][slip_id]"] = str(client_reference_id)
    for key, value in (metadata or {}).items():
        data["metadata[%s]" % key] = str(value)
    return _post("/checkout/sessions", data)


def retrieve_subscription(subscription_id):
    return _get("/subscriptions/%s" % subscription_id)


def cancel_subscription(subscription_id):
    """Cancel at the end of the paid period, not immediately.

    Somebody who cancels on day 2 has paid for the month; ending their access
    that day would be keeping the money and withdrawing the service.
    """
    return _post("/subscriptions/%s" % subscription_id,
                 {"cancel_at_period_end": "true"})


def resume_subscription(subscription_id):
    """Undo a pending cancellation, while the paid period is still running.

    Somebody who cancels by mistake would otherwise have to sit out the rest of
    the month and start a new subscription — a worse outcome for them and for
    us than letting them take it back.
    """
    return _post("/subscriptions/%s" % subscription_id,
                 {"cancel_at_period_end": "false"})


def verify_webhook(payload_bytes, signature_header):
    """Verify a webhook came from Stripe.

    Without this, the endpoint is a public URL that hands out credits to anyone
    who POSTs a plausible JSON body. If no webhook secret is configured the
    answer is "no" — refusing every delivery is the safe failure, not accepting
    unsigned ones.
    """
    secret = webhook_secret()
    if not secret:
        return None, "No STRIPE_WEBHOOK_SECRET is configured; refusing unsigned callbacks."
    if not signature_header:
        return None, "Missing Stripe-Signature header."

    timestamp, signatures = None, []
    for part in signature_header.split(","):
        piece = part.strip().split("=", 1)
        if len(piece) != 2:
            continue
        if piece[0] == "t":
            timestamp = piece[1]
        elif piece[0] == "v1":
            signatures.append(piece[1])
    if not timestamp or not signatures:
        return None, "Malformed Stripe-Signature header."
    try:
        age = abs(time.time() - int(timestamp))
    except (TypeError, ValueError):
        return None, "Malformed timestamp in Stripe-Signature."
    if age > WEBHOOK_TOLERANCE_SECONDS:
        return None, "Webhook timestamp is outside the tolerance window."

    signed = ("%s." % timestamp).encode("utf-8") + payload_bytes
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    # compare_digest, not ==: a timing-variable comparison on a signature is a
    # slow but real way to forge one.
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        return None, "Signature does not match."

    try:
        return json.loads(payload_bytes.decode("utf-8")), None
    except (ValueError, UnicodeDecodeError):
        return None, "Webhook body is not JSON."


def retrieve_session(session_id):
    """Read a Checkout session back from Stripe.

    Used to confirm a purchase when the webhook has not arrived — the browser
    returning to the success page proves nothing, so the state is fetched from
    Stripe rather than believed.
    """
    key = secret_key()
    if not key:
        raise StripeError("Stripe is not configured on this server.")
    try:
        response = requests.get(
            "%s/checkout/sessions/%s" % (STRIPE_API, session_id),
            auth=(key, ""), timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        raise StripeError("Could not read the Stripe session: %s" % exc) from exc
