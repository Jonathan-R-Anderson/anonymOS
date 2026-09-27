"""Epoch randomness, derived.

Kept apart from pof_genesis so it depends on nothing but arithmetic: no app, no
database, no chain. The Go aggregator has to reproduce this exactly, and a
derivation tangled up with Flask is one nobody can test in isolation or check
against another implementation.

EpochManager.randomnessOf(N) is written by submitEpoch(N), which commits work
already performed. But witness selection for epoch N has to be decidable DURING
epoch N, or nobody knows who was entitled to audit whom until it is too late to
have done it. Reading it from the chain is therefore a chicken and egg: every
node asks for a value that by construction does not exist yet, gets nothing, and
does no work.

So a live epoch's randomness is derived from the genesis seed:

    randomness(N) = keccak256(seed || uint64_be(N))

The seed has exactly the properties this needs, and the ones the roadmap already
argues for: fixed before any work was challenged, chosen by nobody holding a
receipt in any epoch, and public, so every witness set can be re-derived by
anyone auditing it afterwards. The derivation inherits all three.

What it does NOT inherit is unpredictability — every future epoch's randomness
is computable today. That matters only if a participant could choose WHICH epoch
to work in, and it cannot: the epoch is the clock. It would matter a great deal
for a *rotating* seed, which is why the seed is fixed and this is a bootstrap
derivation rather than the permanent beacon.

When an epoch is settled the same derived value is submitted with it, so the two
agree and anyone can check a settled epoch against randomnessOf().
"""

from services.keccak import keccak_hex


def derive_epoch_randomness(seed_hex, epoch):
    """The derived randomness for an epoch, as 0x-prefixed hex.

    Returns None for a malformed seed rather than hashing whatever was passed:
    a seed that is not 32 bytes means the caller does not have the genesis seed,
    and a value derived from something else would put this node on a witness
    schedule nobody else shares.
    """
    raw = (seed_hex or "").strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]
    if len(raw) != 64:
        return None
    try:
        seed = bytes.fromhex(raw)
    except ValueError:
        return None
    if int(epoch) < 0:
        return None
    return keccak_hex(seed, int(epoch).to_bytes(8, "big"))
