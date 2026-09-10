"""The AxonChannels state encoding, for a server that must check a claim.

WHY THIS EXISTS AT ALL
----------------------
An on-chain award is easy to verify: the transfer is on the chain, and
services/store_payments.py reads it there. A channel payment is not on the
chain, and this server is not a party to it — so "the author was paid" arrives
as a *claim*, and a claim nobody checks is a decoration.

What makes it checkable is the thing that makes a channel safe in the first
place: a state carries BOTH parties' signatures over a digest that names the
chain, the contract, the channel, the nonce and the balances. Anyone holding it
can verify it. That is why a channel can be settled unilaterally, and it is why
this server can be one more holder without being a participant.

THE FOURTH IMPLEMENTATION
-------------------------
The encoding now exists in Solidity, Go, JavaScript and here. That duplication
is a real cost, and it is paid the same way every time: none of these were
computed by each other. The vectors in tests/test_channel_state.py come from the
Solidity compiler, and every implementation is checked against those.

If this file drifts, awards silently stop verifying — which is the safe
direction, but only because the digest is checked and not merely trusted.

WHAT THIS FILE DOES NOT DO
--------------------------
No signing. No keys. No balances held here. The award service says of itself
that the money never touches this server, and that stays true: this reads a
state somebody else signed and says whether it holds together.

Signature recovery is not here either — see channel_awards.py. eth-account is
NOT installed at runtime (see services/wallet_auth.py), so recovery goes to the
renderer sidecar, and mixing "what the bytes are" with "who signed them" would
hide that constraint inside a hashing module.
"""

from services.keccak import keccak256

# secp256k1n/2. The contract rejects s above this, so a signature this server
# accepted but the contract would not describes a state that settles nowhere.
HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0

ZERO32 = b"\x00" * 32


class StateError(ValueError):
    """A state that does not hold together. The message is for a log, not a user."""


def normalize_address(value):
    """Lowercase 0x-form, or None. Same rule as wallet_auth, kept local."""
    if not value:
        return None
    text = str(value).strip().lower()
    if not text.startswith("0x") or len(text) != 42:
        return None
    try:
        int(text, 16)
    except ValueError:
        return None
    return text


def _address_bytes(value):
    address = normalize_address(value)
    if address is None:
        raise StateError("not an address: %r" % (value,))
    return bytes.fromhex(address[2:])


def _bytes32(value):
    """32 bytes from hex with or without 0x, or from bytes."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value).strip()
        if text.startswith("0x") or text.startswith("0X"):
            text = text[2:]
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raise StateError("not hex: %r" % (value,))
    if len(raw) != 32:
        raise StateError("expected 32 bytes, got %d" % len(raw))
    return raw


def _word(value):
    """A uint256 as a 32-byte big-endian word.

    Refuses negatives rather than wrapping them. Every quantity in this encoding
    is a uint256 on chain, so a negative one describes a state that could never
    settle, and silently wrapping it would produce a digest for a state nobody
    meant.
    """
    number = int(value)
    if number < 0:
        raise StateError("negative value in a uint256 field: %d" % number)
    if number >= 1 << 256:
        raise StateError("value does not fit in a uint256")
    return number.to_bytes(32, "big")


def derive_channel_id(a, b):
    """channelId(a, b) = keccak256(abi.encode(lower, higher)).

    SORTED. Party A is the numerically lower address and has nothing to do with
    who is paying — a giver is party A for roughly half of all authors, and code
    that assumes otherwise is right half the time, which is the worst rate there
    is because it works in testing.
    """
    lo, hi = sort_parties(a, b)
    return keccak256(_word(int(lo, 16)) + _word(int(hi, 16)))


def sort_parties(a, b):
    """(lower, higher). The only place party order is decided."""
    x = normalize_address(a)
    y = normalize_address(b)
    if x is None or y is None:
        raise StateError("cannot order %r and %r" % (a, b))
    if x == y:
        raise StateError("a channel needs two different parties")
    return (x, y) if int(x, 16) < int(y, 16) else (y, x)


def is_party_a(self_address, other_address):
    """True when self_address is party A of the channel between the two."""
    return sort_parties(self_address, other_address)[0] == normalize_address(self_address)


def htlc_root(locks):
    """keccak256 over the packed, id-sorted locks. Empty is bytes32(0).

    Zero rather than the hash of nothing, because the contract says so and a
    channel with no locks is the ordinary case.
    """
    if not locks:
        return ZERO32
    ordered = sorted(locks, key=lambda l: _bytes32(l["id"]))
    buf = b""
    previous = None
    for lock in ordered:
        lock_id = _bytes32(lock["id"])
        if previous is not None and lock_id <= previous:
            # The contract reverts on this. Two locks sharing an id would make
            # the root ambiguous, and an ambiguous root is a state that means
            # two things.
            raise StateError("duplicate lock id")
        previous = lock_id
        buf += (
            lock_id
            + _bytes32(lock["hash"])
            + _word(lock["amount"])
            + _word(lock["expiry"])
            + (b"\x01" if lock.get("payer_is_a") else b"\x00")
        )
    return keccak256(buf)


def state_digest(chain_id, contract, channel_id, nonce,
                 balance_a, balance_b, root, withdraw_a=0, withdraw_b=0):
    """The nine words both parties sign.

    Mirrors AxonChannels.stateDigest:

        keccak256(abi.encode(block.chainid, address(this), id, nonce,
                             balanceA, balanceB, root, withdrawA, withdrawB))

    The chain id and contract are in there so a state signed for one deployment
    cannot be replayed against another — which is exactly why a caller must
    never be allowed to supply them. The root is in so a state cannot be
    separated from its locks; the withdrawals so it cannot be separated from the
    value leaving under it.
    """
    return keccak256(
        _word(chain_id)
        + _word(int(_address_bytes(contract).hex(), 16))
        + _bytes32(channel_id)
        + _word(nonce)
        + _word(balance_a)
        + _word(balance_b)
        + _bytes32(root)
        + _word(withdraw_a)
        + _word(withdraw_b)
    )


def personal_digest(raw):
    """EIP-191, which the contract applies before ecrecover.

    The step most easily forgotten: a signature over the raw digest verifies
    perfectly off chain and is rejected on it.
    """
    return keccak256(b"\x19Ethereum Signed Message:\n32" + _bytes32(raw))


def decode_state(wire):
    """A state from the protocol's wire form, with every field checked.

    The wire form is storage-client's storedState: amounts as decimal strings,
    32-byte values as bare hex, and the withdrawals present only when non-zero.
    """
    if not isinstance(wire, dict):
        raise StateError("state must be an object")

    locks = []
    for entry in wire.get("pending") or []:
        locks.append({
            "id": _bytes32(entry.get("id")).hex(),
            "hash": _bytes32(entry.get("hash")).hex(),
            "amount": _amount(entry.get("amount"), "lock amount"),
            "expiry": _amount(entry.get("expiry"), "lock expiry"),
            "payer_is_a": bool(entry.get("payer_is_a")),
        })

    return {
        "channel": _bytes32(wire.get("channel")).hex(),
        "nonce": _amount(wire.get("nonce"), "nonce"),
        "balance_a": _amount(wire.get("balance_a"), "balance_a"),
        "balance_b": _amount(wire.get("balance_b"), "balance_b"),
        # Absent is zero: only a checkpoint carries these, and every payment
        # before the first checkpoint legitimately has none.
        "withdraw_a": _amount(wire.get("withdraw_a") or 0, "withdraw_a"),
        "withdraw_b": _amount(wire.get("withdraw_b") or 0, "withdraw_b"),
        "pending": locks,
    }


def _amount(value, field):
    """A non-negative integer from a decimal string or a number.

    Strings, because 100 AXON is 1e20 and JSON numbers stop being exact well
    below that. A float is refused outright rather than truncated — rounding
    somebody's money to the nearest representable double is not a recoverable
    mistake.
    """
    if isinstance(value, bool) or isinstance(value, float):
        raise StateError("%s must be an integer or a decimal string" % field)
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise StateError("%s is not a number: %r" % (field, value))
    if number < 0:
        raise StateError("%s may not be negative" % field)
    return number


def digest_of(state, chain_id, contract):
    """The digest for a decoded state, under a known deployment."""
    return state_digest(
        chain_id, contract, state["channel"], state["nonce"],
        state["balance_a"], state["balance_b"], htlc_root(state["pending"]),
        state["withdraw_a"], state["withdraw_b"],
    )


def received_by(state, party_is_a):
    """How much value has reached a party, cumulatively.

    balance + withdrawals, and the sum is the point. A checkpoint moves value
    from the balance into the withdrawal, so a party drawing their money down
    would appear to have *lost* it if only the balance were counted — and an
    award ledger built on that would credit them all over again on the way back
    up.

    Locked value is deliberately excluded. A lock is money that may still go
    back; counting it would credit an award for a payment that has not happened.
    """
    if party_is_a:
        return state["balance_a"] + state["withdraw_a"]
    return state["balance_b"] + state["withdraw_b"]


def check_signature_shape(signature):
    """Reject a signature the contract could never accept, before recovering it.

    Cheap, and it fails for a reason a log can act on: an unreachable verifier
    and a malformed signature are different problems.
    """
    text = str(signature or "").strip()
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise StateError("signature is not hex")
    if len(raw) != 65:
        raise StateError("signature must be 65 bytes, got %d" % len(raw))
    s = int.from_bytes(raw[32:64], "big")
    if s > HALF_ORDER:
        raise StateError("signature has a high s and would be rejected on chain")
    return "0x" + raw.hex()
