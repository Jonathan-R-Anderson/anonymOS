"""Stripe's fiat-to-crypto onramp: letting somebody with no crypto get some.

WHAT THIS CAN AND CANNOT DO, STATED FIRST
-----------------------------------------
The onramp delivers only these currencies — btc, eth, sol, matic, usdc, xlm —
onto these networks: bitcoin, ethereum, solana, polygon, stellar.

AXONCoins is not on that list and never will be: it is our own ERC-20, and the
list is Stripe's. **A card cannot buy AXONCoins here.** The page has to say that
in as many words, because a "buy crypto" button on a token's own site implies
otherwise, and a customer who believed it has paid Stripe for something they did
not want.

What the onramp does solve is the blocker underneath everything else: somebody
with a card and no crypto at all cannot take a single step in this system — not
buying, not voting, not paying a bounty, not claiming a grant — because every
path starts with a wallet that can pay gas. The onramp fills that wallet.

WHAT CHANGED WHEN THE CONTRACTS MOVED TO ETHEREUM MAINNET
---------------------------------------------------------
This module was written while the token lived on another chain, and said so: the
onramp could not deliver onto it at all, so a buyer had to purchase ETH on
Ethereum and then bridge it themselves — a second unfamiliar step, on a second
site, with its own way to lose the money.

**Ethereum mainnet is on Stripe's network list.** Now that the contracts are
there, the onramp delivers ETH straight onto the chain the token lives on, and
the bridge step is gone. That is worth stating rather than quietly deleting:
the Ethereum note is the reason this module looked barely worth finishing, and it
stopped being true.

So the honest shape of the flow, which the page shows as three steps:

    card → ETH in YOUR wallet, on Ethereum      (Stripe does this)
    ETH  → AXONCoins                            (a swap, or earn them by running a node)
    AXONCoins → the store, bounties, awards     (this site)

Only the first step is Stripe's, and only the first step is what this module
does.

WHY THIS IS A DIFFERENT PRODUCT FROM THE CREDIT PACKS
-----------------------------------------------------
services/stripe_api.py sells credit packs through Checkout, and its docstring
records the exposure: Stripe's restricted-business list puts ICOs under
*prohibited*, and selling our own token for card payment is in substance a
first-party token sale.

The onramp is not that. Stripe sells the customer a mainstream cryptocurrency,
Stripe holds the compliance and KYC, and the site never sells its own token for
card money. That is why this one is approved and the other carries risk, and the
two must not be conflated in the UI: one is Stripe selling ETH to a customer, the
other is us selling AXONCoins.
"""

from shared import app
from services import stripe_api

# A local pre-check, so an unsupported value is refused here with a readable
# message rather than as an opaque API error after the customer has committed.
#
# These were copied from the documentation prose and were WRONG — too narrow.
# The values below come from a live session response's destination_currencies
# and destination_networks, which is the authoritative list and is per-account.
# Re-derive them the same way rather than from docs: create a session and read
# transaction_details. The docs page listed neither Base nor Optimism, and the
# account has had both for some time.
#
# Erring narrow is not the safe direction it looks like: it refuses purchases
# Stripe would have completed, and the refusal blames Stripe for a limit that is
# ours.
SUPPORTED_CURRENCIES = ("btc", "eth", "matic", "sol", "xlm", "avax", "wld", "usdc")
SUPPORTED_NETWORKS = ("bitcoin", "ethereum", "base", "optimism", "polygon",
                      "solana", "stellar", "avalanche", "worldchain")

# What we default to: ETH on Ethereum mainnet, the exact chain the contracts are
# deployed to. ETH rather than USDC because gas is paid in ETH — a wallet holding
# only USDC still cannot move, which is the problem this exists to solve.
DEFAULT_CURRENCY = "eth"
DEFAULT_NETWORK = "ethereum"

ONRAMP_PATH = "/crypto/onramp_sessions"


class OnrampError(RuntimeError):
    """Something the buyer can act on. The message is shown to them."""


# The onramp uses the SITE'S OWN Stripe keys, on the same account as everything
# else, on the account's default API version. No separate credential and no
# version pin.
#
# Both existed here briefly, on a wrong diagnosis. "Unrecognized request URL"
# was read as the account lacking the feature, and a second key pair was added
# so the onramp could authenticate as an enrolled account. It was not that: the
# request was sending `transaction_details[...]`, which is the shape of the
# RESPONSE, and the site's domain was not yet on the onramp's allowed list.
# Fixing those two made the live account answer HTTP 200.
#
# Recorded rather than silently deleted, because "the endpoint does not exist
# for this credential" is a plausible enough reading of that error that someone
# will reach for the same fix again.


def secret_key():
    return stripe_api.secret_key()


def publishable_key():
    return stripe_api.publishable_key()


def configured():
    """Both keys present — the publishable one is needed in the browser."""
    return stripe_api.configured()


def _explain(exc):
    """Turn Stripe's reply into something the operator can act on."""
    message = str(exc)
    if "unrecognized request url" in message.lower():
        # The most misleading error this endpoint returns. The path is correct —
        # it is straight from the API reference — so it reads as a typo and is
        # not one. It has meant two different things here, and neither is
        # visible from the message:
        return (
            "Stripe did not recognise the onramp endpoint for this request. The "
            "path is correct, so this is not a typo. It has twice meant "
            "something else instead:\n"
            "  • The request body was wrong. `transaction_details` is the shape "
            "of the RESPONSE; the request takes destination_currency, "
            "destination_network and wallet_addresses[<network>] at the top "
            "level.\n"
            "  • This site's domain was not on the onramp's allowed-domains "
            "list in the Stripe dashboard.\n"
            "Failing those, the account may not be enrolled in the crypto "
            "onramp at all — which is gated, and gates sandbox keys too.")
    return "Could not start the purchase: %s" % message


def create_session(wallet_address, amount=None, currency=DEFAULT_CURRENCY,
                   network=DEFAULT_NETWORK, customer_ip=None):
    """Open an onramp session and return its client secret.

    The destination wallet is LOCKED to the address passed in. Leaving it for the
    customer to type is how somebody pastes an address from a phishing message,
    or their own address on the wrong network, and the money is gone with no
    recourse — Stripe has delivered exactly what was asked for.
    """
    currency = (currency or DEFAULT_CURRENCY).strip().lower()
    network = (network or DEFAULT_NETWORK).strip().lower()
    if currency not in SUPPORTED_CURRENCIES:
        raise OnrampError(
            "Stripe's onramp does not deliver %s. It supports: %s."
            % (currency, ", ".join(SUPPORTED_CURRENCIES)))
    if network not in SUPPORTED_NETWORKS:
        raise OnrampError(
            "Stripe's onramp does not deliver onto %s. It supports: %s."
            % (network, ", ".join(SUPPORTED_NETWORKS)))

    wallet_address = (wallet_address or "").strip()
    if not wallet_address:
        raise OnrampError("Link a wallet to your profile first — that is where "
                          "the funds are delivered.")

    # TOP-LEVEL parameters. `transaction_details` is the shape of the RESPONSE,
    # not the request — sending the response's shape back as the request is an
    # easy mistake to make from the object reference alone, and it was made here.
    #
    # lock_wallet_address is the API's own way to say what the docstring above
    # promises: the customer cannot edit the destination in the widget. Doing it
    # by omission — passing an address and hoping — leaves an editable field.
    payload = {
        "destination_currency": currency,
        "destination_network": network,
        "wallet_addresses[%s]" % network: wallet_address,
        "lock_wallet_address": "true",
    }
    if amount:
        payload["destination_amount"] = str(amount)
    if customer_ip:
        # Stripe uses this for its own compliance checks. Sent when known and
        # omitted otherwise rather than faked, because a wrong value is worse
        # than an absent one here.
        payload["customer_ip_address"] = customer_ip

    try:
        session = stripe_api._post(ONRAMP_PATH, payload)
    except Exception as exc:
        app.logger.exception("stripe onramp: session creation failed")
        raise OnrampError(_explain(exc))

    secret = (session or {}).get("client_secret")
    if not secret:
        raise OnrampError("Stripe did not return a session to continue with.")
    return {
        "client_secret": secret,
        "id": session.get("id", ""),
        "currency": currency,
        "network": network,
        "wallet": wallet_address,
    }
