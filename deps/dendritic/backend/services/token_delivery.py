"""Deliver purchased AXON from the Treasury, on chain, when Stripe confirms.

WHAT THIS COSTS, STATED BEFORE ANYTHING ELSE
---------------------------------------------
`Treasury.releaseOrder` is `onlyOwner`, so automatic delivery means this web
server holds a key that can move the treasury. blueprints/credits.py already
called that "the largest single risk in this system: a compromise there drains
everything", and that judgement has not changed because the feature was asked
for — it is simply now a cost being paid deliberately instead of avoided.

Three things follow, and none of them are optional:

  * OFF BY DEFAULT. No key configured means delivery stays queued exactly as it
    was. Enabling this is an explicit act, not a consequence of deploying.
  * PER-DELIVERY CEILING. `MAX_AUTO_DELIVERY` bounds what one call can move.
    A bug or a compromise that can send anything can send everything; a bug
    that can send at most one pack is a bad day rather than the end.
  * The safer shape remains a DISPENSER: a wallet holding a small float, topped
    up by hand, so a break-in costs the float. It cannot be used here only
    because `releaseOrder` is owner-gated and the contracts are deployed. If
    the Treasury is ever redeployed, give it a dispenser role that may call
    `releaseOrder` and nothing else, and move this off the owner key.

IDEMPOTENCY IS NOT OPTIONAL EITHER
-----------------------------------
Stripe retries a webhook on any non-2xx or timeout, so "this purchase is paid"
WILL arrive more than once. Two guards, deliberately both:

  * `orderFilled()` is checked before sending, so the ordinary retry costs a
    read and not a transaction.
  * The contract reverts on a second fill regardless, so a race between two
    concurrent webhooks cannot double-deliver even if both pass the check.

The first is an optimisation. The second is the guarantee.
"""

import os

from services import pof_chain
from shared import app

# The most one automatic delivery may move, in whole AXON. A ceiling rather
# than a rate limit: a rate limit still eventually moves everything, and the
# thing worth bounding is the blast radius of a single bad call.
MAX_AUTO_DELIVERY = int(os.environ.get("MAX_AUTO_DELIVERY", "1000"))


class DeliveryError(RuntimeError):
    """Delivery did not happen. The purchase stays queued for an operator."""


def delivery_key():
    """The treasury owner key, or empty when automatic delivery is off.

    Read from the environment rather than app.config: that is where .env
    actually lands in this deployment, and a config file the container does not
    read is how a setting goes silently missing. (It did, for the origin
    pepper.)
    """
    return (os.environ.get("TREASURY_DELIVERY_KEY") or "").strip()


def can_sign():
    """Whether the signing library is actually present.

    Checked separately because its absence is invisible until a delivery is
    attempted, and by then a customer has paid. The deployed image reported
    `enabled: True` while `eth_account` was not installed — a key, an address,
    and no possible way to sign anything.
    """
    try:
        import eth_account  # noqa: F401
        return True
    except ImportError:
        return False


def enabled():
    """Everything needed to actually deliver, not merely to intend to.

    A key and an address are not sufficient: without the signing library no
    transaction can be built, and reporting "enabled" on that basis is a
    half-truth that only surfaces after somebody has paid.
    """
    return bool(delivery_key() and treasury_address() and can_sign())


def treasury_address():
    try:
        return (pof_chain.pof_addresses() or {}).get("Treasury") or ""
    except Exception:
        return ""


def deliver(purchase):
    """Send a paid purchase's tokens. Returns a tx hash, or raises.

    Never called for anything but a PAID purchase — the caller checks that,
    because this function's job is to move tokens and a function that also
    decides whether it should is one that can be wrong about both.
    """
    if not enabled():
        raise DeliveryError("automatic delivery is not configured")
    if not purchase.wallet:
        raise DeliveryError("purchase has no destination wallet")
    order_id = purchase.order_id
    if not order_id:
        # Subscription months are created by the membership webhook, which never
        # passes through the checkout route that sets an order id — so every
        # renewal arrived undeliverable, and the refusal below fired on rows
        # that were perfectly legitimate.
        #
        # They are not identifierless, though: the Stripe INVOICE id is unique
        # per invoice and already stored, so it makes exactly as good an
        # idempotency key as a checkout session does. Derived here and written
        # back, so the value that goes on chain is recorded rather than
        # recomputed differently later.
        from services import purchase_identity

        if purchase.stripe_session_id:
            order_id = purchase_identity.order_id(purchase.stripe_session_id)
            purchase.order_id = order_id

    if not order_id or order_id == ("0x" + "00" * 32):
        # Genuinely nothing unique to key on. Refusing is right: without a guard
        # a retry delivers twice, and an operator can still send it by hand.
        raise DeliveryError("purchase has no order id to deliver against")
    if int(purchase.credits or 0) <= 0:
        raise DeliveryError("purchase has no credits to deliver")
    if int(purchase.credits) > MAX_AUTO_DELIVERY:
        raise DeliveryError(
            "purchase of %d exceeds the automatic ceiling of %d — deliver it by hand"
            % (int(purchase.credits), MAX_AUTO_DELIVERY))

    # Cheap check first. The contract enforces this regardless; this only saves
    # the gas and the failed transaction on the ordinary retry path.
    if already_filled(order_id):
        raise DeliveryError("this order has already been delivered on chain")

    return _send_release_order(
        to=purchase.wallet,
        amount_wei=int(purchase.credits) * (10 ** 18),
        order_id=order_id,
        origin_hash=purchase.origin_hash or ("0x" + "00" * 32),
    )


def already_filled(order_id):
    """Ask the chain whether this order was delivered.

    Failing OPEN — returning False when the chain cannot be reached — would
    mean a delivery attempt that the contract then refuses, which is safe but
    wastes gas. Failing CLOSED, as here, means an unreachable chain leaves the
    purchase queued for an operator, which is the state it was in before.
    """
    treasury = treasury_address()
    if not treasury:
        return True
    try:
        # pof_chain.selector returns a HEX STRING without 0x, not bytes. Mixing
        # the two raised TypeError, which the except below swallowed into "fails
        # closed" — so this reported "already delivered" for every order while
        # the check itself was crashing, and nothing was ever sent.
        data = pof_chain.selector("orderFilled(bytes32)") + _word(order_id)
        result = pof_chain._rpc("eth_call", [
            {"to": treasury, "data": "0x" + data}, "latest"])
        return int(result or "0x0", 16) != 0
    except Exception:
        app.logger.exception("token_delivery: could not read orderFilled")
        return True


def _send_release_order(to, amount_wei, order_id, origin_hash):
    """Build, sign and broadcast Treasury.releaseOrder.

    Kept separate from `deliver` so the decision to send and the mechanics of
    sending are testable apart — the interesting failures are all in the
    decision.
    """
    try:
        from eth_account import Account
    except ImportError as exc:  # pragma: no cover - deployment dependency
        raise DeliveryError(
            "eth_account is not installed; cannot sign a delivery") from exc

    key = delivery_key()
    account = Account.from_key(key)
    treasury = treasury_address()

    # Hex strings throughout, matching what pof_chain.selector returns.
    data = (pof_chain.selector("releaseOrder(address,uint256,bytes32,bytes32)")
            + _word(to) + _word(amount_wei) + _word(order_id) + _word(origin_hash))

    nonce = int(pof_chain._rpc("eth_getTransactionCount",
                               [account.address, "pending"]), 16)
    gas_price = int(pof_chain._rpc("eth_gasPrice", []), 16)
    tx = {
        "to": treasury,
        "value": 0,
        "data": "0x" + data,
        "nonce": nonce,
        "chainId": pof_chain.CHAIN_ID,
        "maxFeePerGas": gas_price * 2,
        "maxPriorityFeePerGas": min(gas_price, 2_000_000_000),
        # Estimated rather than fixed: a hardcoded limit is either wasteful or
        # the reason a delivery fails after a gas schedule change.
        "gas": _estimate_gas(account.address, treasury, data),
    }
    signed = Account.sign_transaction(tx, key)
    # eth-account renamed this attribute in 0.13: `rawTransaction` before,
    # `raw_transaction` after. This image is pinned to 0.10 (0.11+ pulls ckzg,
    # which needs a compiler the image does not have), so it is the camelCase
    # one — but reading both means a later unpin cannot break delivery at the
    # very last line, after the transaction has been built, priced and signed.
    raw = getattr(signed, "raw_transaction", None)
    if raw is None:
        raw = getattr(signed, "rawTransaction", None)
    if raw is None:
        raise DeliveryError("eth-account returned a signature in an unrecognised shape")
    # HexBytes.hex() ALREADY includes the 0x prefix in hexbytes < 1.0, while
    # plain bytes.hex() does not. Prepending unconditionally produced "0x0x…",
    # which the RPC rejects as "Invalid params" — an error that names the
    # request rather than the doubled prefix, so it reads as a malformed
    # transaction rather than a malformed string.
    #
    # Normalised instead of assumed, because both types show up depending on
    # the eth-account version pinned.
    raw_hex = raw.hex()
    if not raw_hex.startswith("0x"):
        raw_hex = "0x" + raw_hex
    tx_hash = pof_chain._rpc("eth_sendRawTransaction", [raw_hex])
    app.logger.info("token_delivery: sent %s for order %s", tx_hash, order_id)
    return tx_hash


def _estimate_gas(sender, treasury, data):
    try:
        estimate = int(pof_chain._rpc("eth_estimateGas", [{
            "from": sender, "to": treasury, "data": "0x" + data}]), 16)
        return int(estimate * 1.25)  # headroom; estimation is a lower bound
    except Exception:
        return 150_000


def _word(value):
    """One ABI word as 64 hex characters, no 0x.

    Hex rather than bytes because pof_chain.selector returns a hex string and
    the two do not concatenate — mixing them raised TypeError inside an except
    that swallowed it, which is how a broken check reported success.
    """
    if isinstance(value, int):
        return "%064x" % value
    text = str(value)
    if text.startswith("0x"):
        text = text[2:]
    return text.rjust(64, "0")
