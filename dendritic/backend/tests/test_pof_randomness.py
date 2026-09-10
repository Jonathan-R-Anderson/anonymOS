"""Epoch randomness must exist before the epoch is settled, and must be the
same value everyone else derives.

The vector below is shared with the Go aggregator
(proof-of-facilitation/aggregator/randomness_test.go). Two separate
implementations in two languages agreeing on it is the only thing that keeps a
node's witness set and the settlement's witness set from being different sets.
"""

from services.pof_randomness import derive_epoch_randomness

SEED = "0xb7aa0996eef912b1b3fed14b5edb9687ea08054d98690a2fcfbad362be8f575d"


def test_shared_golden_vector():
    # The live genesis seed and the first three epochs. Any change to these is a
    # change to who audits whom, and must be made on both sides at once.
    assert derive_epoch_randomness(SEED, 0) == (
        "0x9d4f28eecbdebf3d8ca76d60cad02e618238cd83fed29521d71d3552a05a10f3")
    assert derive_epoch_randomness(SEED, 1) == (
        "0x6e5aebe8c181aa62d40d4f096d3fccf0958a9a9f96728d61c3ffc3eea7211130")
    assert derive_epoch_randomness(SEED, 4) == (
        "0xffe297c6cbb73886b04c465578258d99193147e34ed15b4a03e55df96e090db1")


def test_derivation_changes_with_the_epoch():
    a = derive_epoch_randomness(SEED, 4)
    b = derive_epoch_randomness(SEED, 5)
    assert a and b and a != b


def test_seed_accepted_with_or_without_prefix():
    assert derive_epoch_randomness(SEED, 7) == derive_epoch_randomness(SEED[2:], 7)


def test_malformed_seed_is_refused_not_guessed():
    assert derive_epoch_randomness("0xdeadbeef", 1) is None


def test_negative_epoch_is_refused():
    assert derive_epoch_randomness(SEED, -1) is None
