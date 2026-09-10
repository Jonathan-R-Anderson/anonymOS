"""Validating a wallet address somebody typed, before money moves to it.

WHY THIS IS ITS OWN MODULE
--------------------------
A guest buying tokens has no account, no linked wallet and no support thread.
The address they paste is the only record of where their purchase should go, and
a transfer to a wrong-but-valid address is irreversible and unrecoverable — no
chargeback reaches it, no operator can claw it back, and there is nobody to ask
because they were never logged in.

So the address is checked as hard as it can be checked before a card is charged,
and the one real check available is EIP-55.

WHAT EIP-55 ACTUALLY BUYS
-------------------------
An Ethereum address is 20 arbitrary bytes: every 40-hex string is a valid
address, so a typo produces another perfectly valid address that nobody holds
the key to. There is no checksum in the address itself.

EIP-55 adds one by CASING the hex digits according to a hash of the lowercase
address. Every wallet — MetaMask included — copies addresses in that form. So a
mixed-case address can be verified, and a single mistyped character is caught
with overwhelming probability.

An all-lowercase or all-uppercase address carries no checksum at all and cannot
be verified. That is accepted, because plenty of legitimate sources produce one,
but the caller is told it is unverified so the page can say so rather than imply
a check happened that did not.
"""

import re

_HEX40 = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Addresses that are valid, reachable, and certainly wrong as a destination.
BURN = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
}


class AddressError(ValueError):
    """The message is shown to the person who typed the address."""


def _keccak(data):
    from services.keccak import keccak256

    return keccak256(data)


def checksum_ok(address):
    """Whether a mixed-case address passes EIP-55."""
    body = address[2:]
    digest = _keccak(body.lower().encode("ascii")).hex()
    for index, char in enumerate(body):
        if not char.isalpha():
            continue
        upper = int(digest[index], 16) >= 8
        if (char.isupper()) != upper:
            return False
    return True


def to_checksum(address):
    """The EIP-55 form of an address."""
    body = address[2:].lower()
    digest = _keccak(body.encode("ascii")).hex()
    out = "".join(c.upper() if (c.isalpha() and int(digest[i], 16) >= 8) else c
                  for i, c in enumerate(body))
    return "0x" + out


def validate(raw):
    """Return (checksummed_address, verified) or raise AddressError.

    `verified` is False when the input carried no checksum to verify — the
    address is usable, but nothing confirmed it was typed correctly, and a page
    taking money should say which of those two situations it is in.
    """
    text = (raw or "").strip()
    if not text:
        raise AddressError("Enter the wallet address the AXONCoins should go to.")
    # A common paste artefact: an address with whitespace or an ENS-looking
    # name. Neither is resolvable here, and guessing is not an option when the
    # result is an irreversible transfer.
    text = text.replace(" ", "")
    if text.endswith(".eth"):
        raise AddressError(
            "ENS names cannot be used here — paste the 0x… address itself, "
            "which your wallet will show you.")
    if not text.startswith("0x"):
        text = "0x" + text
    if not _HEX40.match(text):
        raise AddressError(
            "That is not an Ethereum address. It should start with 0x and have "
            "40 characters after it.")
    if text.lower() in BURN:
        raise AddressError(
            "That address is a burn address — anything sent there is destroyed "
            "and cannot be recovered.")

    body = text[2:]
    has_case = body.lower() != body and body.upper() != body
    if has_case:
        if not checksum_ok(text):
            # The strongest signal available that somebody mistyped. Refusing is
            # right: a valid-looking address nobody holds the key to takes the
            # money with it.
            raise AddressError(
                "That address looks mistyped — its checksum does not match. "
                "Copy it again from your wallet rather than typing it by hand.")
        return to_checksum(text), True
    # No case information, so no checksum to check.
    return to_checksum(text), False
