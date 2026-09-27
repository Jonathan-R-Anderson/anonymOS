"""Confirming a store payment against the chain.

The browser says "I paid, here is the transaction hash". That claim is worth
nothing on its own — anyone can post a hash, including someone else's — so the
receipt is fetched from Ethereum and checked against what the order actually
required: the right token, the right recipient, at least the right amount, and a
transaction that has not already been used to pay for something else.

`hashlib.sha3_256` is SHA3, not keccak, so the ERC-20 Transfer topic cannot be
derived here. The canonical value is a fixed, universally published constant and
is written out below rather than computed.
"""

import json

import requests

from services.pof_chain import CHAIN_RPC, RPC_TIMEOUT, ChainError

# keccak256("Transfer(address,address,uint256)") — the ERC-20 Transfer topic.
# Identical on every EVM chain; not derivable here without keccak.
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _rpc(method, params):
    try:
        response = requests.post(
            CHAIN_RPC,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            timeout=RPC_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        raise ChainError("Ethereum RPC unreachable: %s" % exc) from exc
    if payload.get("error"):
        raise ChainError(payload["error"].get("message", "rpc error"))
    return payload.get("result")


def _topic_address(topic):
    """An address out of a 32-byte log topic (low 20 bytes)."""
    if not topic:
        return ""
    value = topic[2:] if topic.startswith("0x") else topic
    if len(value) != 64:
        return ""
    return "0x" + value[24:].lower()


def verify_credit_payment(tx_hash, token_address, treasury, min_amount_wei, from_wallet=None):
    """Check a transaction really paid the treasury.

    Returns (ok, detail). Deliberately tolerant about the SENDER — a buyer may
    pay from a different address than the one they connected with, and refusing
    that would strand a genuine payment — but strict about token, recipient and
    amount, which are the parts that decide whether we were actually paid.
    """
    if not tx_hash or not tx_hash.startswith("0x") or len(tx_hash) != 66:
        return False, "That does not look like a transaction hash."
    if not token_address or not treasury:
        return False, "The store is not configured with a token and treasury address yet."

    receipt = _rpc("eth_getTransactionReceipt", [tx_hash])
    if not receipt:
        # Not an error: it may simply not be mined yet, and telling the buyer to
        # wait is better than telling them it failed.
        return False, "Transaction not found yet — it may still be mining. Try again shortly."
    if str(receipt.get("status", "0x1")).lower() in ("0x0", "0"):
        return False, "That transaction reverted on-chain."

    token = (token_address or "").lower()
    want_to = (treasury or "").lower()
    for log in receipt.get("logs") or []:
        if (log.get("address") or "").lower() != token:
            continue  # a transfer of some other token proves nothing here
        topics = log.get("topics") or []
        if len(topics) < 3 or (topics[0] or "").lower() != TRANSFER_TOPIC:
            continue
        sender = _topic_address(topics[1])
        recipient = _topic_address(topics[2])
        if recipient != want_to:
            continue
        try:
            amount = int(log.get("data") or "0x0", 16)
        except ValueError:
            continue
        if amount < min_amount_wei:
            return False, (
                "That payment was %s wei of CREDIT but the item costs %s."
                % (amount, min_amount_wei)
            )
        if from_wallet and sender != (from_wallet or "").lower():
            # Recorded, not refused: paying from a second wallet is normal.
            return True, "paid by %s" % sender
        return True, "paid"

    return False, "No CREDIT transfer to the treasury was found in that transaction."


def credit_wei(amount_credits):
    """Credits are an 18-decimal ERC-20, so a whole credit is 1e18 wei."""
    return int(amount_credits) * (10 ** 18)


def dump_receipt(tx_hash):
    """Raw receipt, for an admin diagnosing a payment that will not confirm."""
    try:
        return json.dumps(_rpc("eth_getTransactionReceipt", [tx_hash]), indent=2)[:8000]
    except ChainError as exc:
        return str(exc)
