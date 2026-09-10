"""keccak256 must be keccak, not SHA3.

Every value in this file is published: the empty-string digest is the standard
keccak-256 test vector, and the selectors are the ones every ERC-20 on every
chain answers to. If this file passes, the implementation is the same function
the contracts use; if it fails, anything derived from it — selectors, node ids,
epoch randomness — is silently wrong.
"""

import hashlib

from services.keccak import keccak256, keccak_hex, selector


def test_empty_string_matches_the_published_vector():
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


def test_it_is_not_sha3():
    # The trap this module exists to avoid: SHA3-256 is a DIFFERENT function
    # with the same output size, and using it produces digests that look right.
    assert keccak256(b"") != hashlib.sha3_256(b"").digest()


def test_known_selectors():
    assert selector("totalSupply()") == "18160ddd"
    assert selector("balanceOf(address)") == "70a08231"
    assert selector("transfer(address,uint256)") == "a9059cbb"
    assert selector("approve(address,uint256)") == "095ea7b3"


def test_contract_selectors_match_the_deployed_contracts():
    # These are the values the Go client pins and exercises against the live
    # contracts on Ethereum mainnet. pof_chain.py now derives its selectors instead of
    # hardcoding them, so this is the check that the derivation is right — a
    # broken keccak would otherwise produce a table consistent only with itself.
    published = {
        "latestEpoch()": "9cb118bf",
        "randomnessOf(uint64)": "1edb4fbc",
        "isFinalized(uint64)": "b9012d5a",
        "epochs(uint64)": "4bd2d7f9",
        "isRegistered(bytes32)": "27258b22",
        "getNode(bytes32)": "50c946fe",
        "totalStaked(address)": "9bfd8d61",
    }
    for signature, pinned in published.items():
        assert selector(signature) == pinned, signature


def test_multi_part_hashing_concatenates():
    assert keccak_hex(b"ab", b"cd") == keccak_hex(b"abcd")
