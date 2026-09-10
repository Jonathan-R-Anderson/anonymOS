"""The V2 encoding, checked against the contract — roadmap P9-b.

None of the vectors here were computed by this package. They come from
`npx hardhat run scripts/v2-golden-vectors.ts` in proof-of-facilitation, where
the Solidity compiler and the EVM are the authority, and they are the same
values frozen in dendritic-node/internal/channel/state_test.go and in
proof-of-facilitation/browser-test/tip-channel.test.mjs.

Four implementations of one encoding is a real cost. It is paid because each one
is checked against the same outside authority rather than against each other —
mutual agreement between two things that are both wrong is not evidence.

The vectors carry the local chain id (31337) and the deterministic hardhat
deploy address. Both are inside the digest, deliberately.
"""

import pytest

from services.channel_state import (
    StateError,
    check_signature_shape,
    decode_state,
    derive_channel_id,
    digest_of,
    htlc_root,
    is_party_a,
    personal_digest,
    received_by,
    sort_parties,
    state_digest,
)

V2_CHAIN_ID = 31337
V2_CONTRACT = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
PARTY_1 = "0x1111111111111111111111111111111111111111"
PARTY_2 = "0x2222222222222222222222222222222222222222"

GOLDEN_CHANNEL_ID = "1bbe365357fe28ec15df954baa1b29fb309dd0e8a21208d768bce9ab1c0c4fd0"
GOLDEN_HTLC_ROOT = "e8303e521e3d9771a180e3f13b1f2d3b27ff1255adf20442232588b9528d6fa2"
GOLDEN_DIGEST_NO_LOCKS = "3f1bf2e8e5456fe31a092177c1f0bda2f95004b38bb2ea12276bb5a00c03ef01"
GOLDEN_DIGEST_LOCKED = "48c16e2554db9447dfdd38a94f0a3e58a8a53b4e381156d8e5ebf4b1feac7daa"
GOLDEN_DIGEST_DRAW = "752cea0a7f93b3057c7a10d7df154f516199a7ac53b35e930347b173c7dd7cf7"

AXON = 10 ** 18


def golden_locks():
    """The lock set from scripts/v2-golden-vectors.ts, exactly."""
    return [
        {"id": (1).to_bytes(32, "big").hex(), "hash": (9).to_bytes(32, "big").hex(),
         "amount": 5 * AXON, "expiry": 100, "payer_is_a": True},
        {"id": (2).to_bytes(32, "big").hex(), "hash": (8).to_bytes(32, "big").hex(),
         "amount": 7 * AXON, "expiry": 200, "payer_is_a": False},
    ]


def base_digest(**kw):
    args = dict(
        chain_id=V2_CHAIN_ID, contract=V2_CONTRACT, channel_id=GOLDEN_CHANNEL_ID,
        nonce=5, balance_a=340 * AXON, balance_b=160 * AXON, root=b"\x00" * 32,
    )
    args.update(kw)
    return state_digest(**args).hex()


# ---- the golden vectors -----------------------------------------------------

def test_channel_id_matches_the_contract():
    assert derive_channel_id(PARTY_1, PARTY_2).hex() == GOLDEN_CHANNEL_ID


def test_channel_id_sorts_so_argument_order_cannot_change_it():
    assert derive_channel_id(PARTY_2, PARTY_1).hex() == GOLDEN_CHANNEL_ID


def test_htlc_root_matches_the_contract():
    assert htlc_root(golden_locks()).hex() == GOLDEN_HTLC_ROOT


def test_htlc_root_sorts_by_lock_id():
    assert htlc_root(list(reversed(golden_locks()))).hex() == GOLDEN_HTLC_ROOT


def test_an_empty_lock_set_roots_to_zero():
    assert htlc_root([]) == b"\x00" * 32


def test_state_digest_matches_the_contract_with_no_locks():
    assert base_digest() == GOLDEN_DIGEST_NO_LOCKS


def test_state_digest_matches_the_contract_with_locks():
    assert base_digest(root=htlc_root(golden_locks())) == GOLDEN_DIGEST_LOCKED


def test_state_digest_matches_the_contract_for_a_checkpoint():
    assert base_digest(withdraw_b=75 * AXON) == GOLDEN_DIGEST_DRAW


def test_committing_to_locks_changes_the_digest():
    # If these matched, a party could sign a state and present it with the locks
    # stripped: the signature verifies and the locked value is simply gone.
    assert GOLDEN_DIGEST_NO_LOCKS != GOLDEN_DIGEST_LOCKED


def test_the_deployment_is_inside_the_digest():
    # A state signed for one deployment must not be replayable against another,
    # which is the reason a claimant is never allowed to supply these.
    assert base_digest(chain_id=1) != GOLDEN_DIGEST_NO_LOCKS
    assert base_digest(contract="0xae70526931FF460894133201f6C8cA91bbA0E177") \
        != GOLDEN_DIGEST_NO_LOCKS


def test_personal_digest_wraps_with_eip191():
    raw = bytes.fromhex(GOLDEN_DIGEST_NO_LOCKS)
    assert personal_digest(raw) != raw
    # Stable, and independent of how the input was spelled.
    assert personal_digest(raw) == personal_digest(GOLDEN_DIGEST_NO_LOCKS)
    assert personal_digest("0x" + GOLDEN_DIGEST_NO_LOCKS) == personal_digest(raw)


# ---- party ordering ---------------------------------------------------------

def test_party_a_is_the_lower_address():
    assert sort_parties(PARTY_2, PARTY_1) == (PARTY_1, PARTY_2)
    assert is_party_a(PARTY_1, PARTY_2) is True
    assert is_party_a(PARTY_2, PARTY_1) is False


def test_a_channel_needs_two_different_parties():
    with pytest.raises(StateError):
        sort_parties(PARTY_1, PARTY_1)


# ---- the wire form ----------------------------------------------------------

def test_decoding_a_state_reproduces_its_digest():
    wire = {
        "channel": GOLDEN_CHANNEL_ID,
        "nonce": 5,
        "balance_a": str(340 * AXON),
        "balance_b": str(160 * AXON),
        "pending": [
            {"id": l["id"], "hash": l["hash"], "amount": str(l["amount"]),
             "expiry": l["expiry"], "payer_is_a": l["payer_is_a"]}
            for l in golden_locks()
        ],
    }
    assert digest_of(decode_state(wire), V2_CHAIN_ID, V2_CONTRACT).hex() \
        == GOLDEN_DIGEST_LOCKED


def test_a_checkpoints_withdrawal_survives_decoding():
    # The field that was missing from the protocol wire until P8. It is inside
    # the digest, so a state that lost it would verify against nothing.
    wire = {
        "channel": GOLDEN_CHANNEL_ID, "nonce": 5,
        "balance_a": str(340 * AXON), "balance_b": str(160 * AXON),
        "withdraw_b": str(75 * AXON),
    }
    assert digest_of(decode_state(wire), V2_CHAIN_ID, V2_CONTRACT).hex() \
        == GOLDEN_DIGEST_DRAW


def test_amounts_are_decimal_strings_not_floats():
    # 1e20 has no exact double. Truncating somebody's money is not recoverable.
    with pytest.raises(StateError):
        decode_state({"channel": GOLDEN_CHANNEL_ID, "nonce": 1,
                      "balance_a": 1e20, "balance_b": "0"})


def test_a_large_amount_survives_exactly():
    wire = {"channel": GOLDEN_CHANNEL_ID, "nonce": 1,
            "balance_a": str(10 ** 24 + 7), "balance_b": "0"}
    assert decode_state(wire)["balance_a"] == 10 ** 24 + 7


def test_negative_amounts_are_refused():
    with pytest.raises(StateError):
        decode_state({"channel": GOLDEN_CHANNEL_ID, "nonce": 1,
                      "balance_a": "-1", "balance_b": "0"})


def test_a_duplicate_lock_id_is_refused():
    duplicated = golden_locks()
    duplicated[1]["id"] = duplicated[0]["id"]
    with pytest.raises(StateError):
        htlc_root(duplicated)


# ---- what an author has received --------------------------------------------

def test_received_counts_the_balance_and_the_withdrawals():
    # A checkpoint moves value from the balance into the withdrawal. Counting
    # only the balance would make an author who drew their money down look as
    # though they had lost it — and then credit the awards all over again as it
    # came back.
    before = decode_state({"channel": GOLDEN_CHANNEL_ID, "nonce": 5,
                           "balance_a": "0", "balance_b": str(100 * AXON)})
    after = decode_state({"channel": GOLDEN_CHANNEL_ID, "nonce": 6,
                          "balance_a": "0", "balance_b": str(40 * AXON),
                          "withdraw_b": str(60 * AXON)})
    assert received_by(before, party_is_a=False) == 100 * AXON
    assert received_by(after, party_is_a=False) == 100 * AXON


def test_received_excludes_locked_value():
    # A lock may still go back. Counting it would credit an award for a payment
    # that has not happened.
    state = decode_state({
        "channel": GOLDEN_CHANNEL_ID, "nonce": 5,
        "balance_a": "0", "balance_b": str(10 * AXON),
        "pending": [{"id": (1).to_bytes(32, "big").hex(),
                     "hash": (9).to_bytes(32, "big").hex(),
                     "amount": str(90 * AXON), "expiry": 100, "payer_is_a": True}],
    })
    assert received_by(state, party_is_a=False) == 10 * AXON


# ---- signature shape --------------------------------------------------------

def test_a_high_s_signature_is_refused():
    # The contract rejects it, so accepting it here would record an award backed
    # by a state that settles nowhere.
    high_s = (b"\x11" * 32
              + (0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1
                 ).to_bytes(32, "big")
              + b"\x1b")
    with pytest.raises(StateError):
        check_signature_shape("0x" + high_s.hex())


def test_a_low_s_signature_is_accepted_and_normalised():
    low = b"\x11" * 32 + b"\x22" * 32 + b"\x1b"
    assert check_signature_shape(low.hex()) == "0x" + low.hex()


def test_a_truncated_signature_is_refused():
    with pytest.raises(StateError):
        check_signature_shape("0x1234")
