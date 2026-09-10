"""Read the Proof-of-Facilitation contracts on Ethereum Mainnet from the website.

Read-only. The site never holds a key: the one write in this system (submitting
the genesis epoch) is signed by the admin's own wallet in the browser, so a
compromise of this server cannot move funds or post an epoch.

Function selectors are DERIVED from their signatures. They used to be hardcoded
because the image has no keccak library and `hashlib.sha3_256` is SHA3, a
different function that would have produced plausible-looking selectors calling
nothing — see services/keccak.py, which supplies the real one. Deriving them
means a signature and its selector can no longer disagree.
"""

import json
import os

import requests

from services.keccak import keccak256, selector
from shared import app

# Ethereum mainnet.
#
# Two lessons from moving this stack between chains, kept because both cost real
# time and neither is obvious from the code as it now stands.
#
# One: these constants kept the OLD chain's name for a while, on the reasoning
# that the values decide which chain the site reads and names could be tidied
# later. That was wrong and expensive — CHAIN_ID sat at the previous chain's id
# underneath a comment asserting the values were correct, because a name that
# lies is a place nobody looks. A constant is named for what it is, not for what
# it used to be.
#
# Two, and the one to remember before any bulk rename: a later sweep assumed
# every occurrence of the old chain's name was a chain reference and rewrote an
# identically-named SYMBOL in the admin console, which broke it. Names that
# merely resemble a chain name are not all chain references. Check each one.
# Overridable, because a hardcoded public endpoint is a single point of failure
# this project has already hit: eth.llamarpc.com began answering 403 Forbidden
# to the server, which made every chain read fail — balances unreadable on the
# credits page, and automatic delivery refusing every purchase because its
# "has this order already been filled?" pre-check fails closed.
#
# Free public RPCs rate-limit and block datacentre ranges without notice. Set
# ETH_RPC_URL to a keyed endpoint (Alchemy, Infura, or your own node) for
# anything that matters; the default only keeps a fresh checkout working.
CHAIN_RPC = (os.environ.get("ETH_RPC_URL") or "").strip() or "https://eth.llamarpc.com"
CHAIN_EXPLORER = "https://etherscan.io"
CHAIN_ID = 1

SIGNATURES = (
    "latestEpoch()",
    # Permissionless on purpose: a settlement only its author can complete is
    # one its author can also withhold. Encoded here so the page can offer the
    # call rather than only describing it — an epoch that sits past its deadline
    # because nobody happened to press anything is a settlement that silently
    # does not happen.
    "finalize(uint64)",
    "randomnessOf(uint64)",
    "isFinalized(uint64)",
    "epochs(uint64)",
    "isRegistered(bytes32)",
    "getNode(bytes32)",
    "totalStaked(address)",
    "balanceOf(address)",
    "totalSupply()",
)

SELECTORS = {signature: selector(signature) for signature in SIGNATURES}

RPC_TIMEOUT = 12


class ChainError(RuntimeError):
    """The chain could not be read. Distinct from 'the answer is empty'."""


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


def strip0x(value):
    """Hex without the 0x prefix. The image runs Python 3.8; removeprefix is 3.9+."""
    text = (value or "").strip()
    if text.startswith("0x") or text.startswith("0X"):
        return text[2:]
    return text


def _word(value):
    """A uint as a 32-byte ABI word, hex without 0x."""
    return "%064x" % value


def _call(to_address, data_hex):
    """eth_call, returning raw hex (no 0x) or None when the call reverted.

    A revert is an ordinary answer for these views — NodeRegistry.getNode
    reverts for an id it has never seen — so it is not raised as an error.
    """
    try:
        result = _rpc("eth_call", [{"to": to_address, "data": "0x" + data_hex}, "latest"])
    except ChainError as exc:
        if "revert" in str(exc).lower():
            return None
        raise
    if not result or result == "0x":
        return None
    return result[2:] if result.startswith("0x") else result


def _read_word(raw, index):
    start = index * 64
    chunk = raw[start:start + 64]
    if len(chunk) < 64:
        return None
    return chunk


def latest_epoch(epoch_manager):
    raw = _call(epoch_manager, SELECTORS["latestEpoch()"])
    if raw is None:
        return 0
    word = _read_word(raw, 0)
    return int(word, 16) if word else 0


def epoch_at(epoch_manager, epoch):
    """Read the public epochs(uint64) mapping into a dict, or None if absent.

    Every field of the struct is static, so the return is nine flat words.
    `submittedAt == 0` is the contract's own existence test.
    """
    raw = _call(epoch_manager, SELECTORS["epochs(uint64)"] + _word(epoch))
    if raw is None:
        return None
    words = [_read_word(raw, i) for i in range(9)]
    if any(w is None for w in words):
        return None
    submitted_at = int(words[5], 16)
    if submitted_at == 0:
        return None
    return {
        "epoch": epoch,
        "receipt_root": "0x" + words[0],
        "reward_root": "0x" + words[1],
        "node_state_root": "0x" + words[2],
        "randomness": "0x" + words[3],
        "total_rewards": int(words[4], 16),
        "submitted_at": submitted_at,
        "challenge_deadline": int(words[6], 16),
        "open_disputes": int(words[7], 16),
        "finalized": int(words[8], 16) != 0,
    }


def epoch_chain(epoch_manager, limit=50):
    """Every submitted epoch, oldest first — the linked list the page draws.

    Epoch numbers are contiguous from 0, so this walks upward from 0 rather than
    scanning logs. A gap ends the walk: an epoch that was never submitted has no
    successor worth showing.
    """
    latest = latest_epoch(epoch_manager)
    out = []
    for number in range(0, min(latest, limit - 1) + 1):
        row = epoch_at(epoch_manager, number)
        if row is None:
            # Epoch 0 may legitimately be absent while later ones exist only if
            # something submitted out of order; keep walking a single gap so the
            # page shows what is really there.
            if number == 0 and latest > 0:
                continue
            break
        out.append(row)
    return out


def pof_addresses():
    """Deployed contract addresses saved by the contracts console."""
    from model.SiteSetting import get_setting

    # Same key the contracts console writes (admin.POF_CONTRACTS_SETTING).
    raw = get_setting("pof_contracts", "") or "{}"
    try:
        data = json.loads(raw)
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def explorer_address_url(address):
    return "%s/address/%s" % (CHAIN_EXPLORER, address)


def explorer_tx_url(tx_hash):
    return "%s/tx/%s" % (CHAIN_EXPLORER, tx_hash)


BALANCE_OF_SELECTOR = SELECTORS["balanceOf(address)"]

CREDIT_DECIMALS = 18

# The token is Anonymous/AXON on-chain and "credits" everywhere a person reads
# it. One balance, two names — this is the single place that knows both.
# Newest first. This is a HISTORICAL FALLBACK CHAIN, not a name: each entry is a
# generation the token has had, and an installation may still hold an address
# under any of them. Entries are ADDED here, never replaced -- replacing one
# makes every address stored under the old key unreadable, which presents as
# "everyone's balance is missing".
TOKEN_KEYS = ("AxonToken", "AnonToken", "SyndiToken", "CreditToken")


def token_address():
    """Address of the credits token, whichever generation is deployed.

    The contract has been renamed twice: CreditToken -> AnonToken -> AxonToken.
    Each rename means a NEW deployment, because `credit` is `immutable` in
    RewardDistributor, StakeVault and DisputeManager, so the token cannot be
    repointed and the whole stack is redeployed together. Between shipping a
    rename and the operator finishing that redeploy, the only token that exists
    is the previous one — so every old key stays in TOKEN_KEYS as a fallback
    rather than being removed, and the site keeps reading real balances
    throughout instead of reporting everyone's credits as missing.
    """
    addresses = pof_addresses()
    for key in TOKEN_KEYS:
        found = (addresses.get(key) or "").strip()
        if found:
            return found
    return ""


def credit_balance_wei(token_address, wallet):
    """On-chain CREDIT balance of a wallet, in wei. None if it cannot be read.

    Read from the chain every time rather than tracked in our database: the
    token is an ordinary ERC-20 and its holders can send it to each other
    without telling us, so any balance we stored would drift out of date the
    moment someone did.
    """
    if not token_address or not wallet:
        return None
    address = wallet.lower()
    if address.startswith("0x"):
        address = address[2:]
    if len(address) != 40:
        return None
    raw = _call(token_address, BALANCE_OF_SELECTOR + address.rjust(64, "0"))
    if raw is None:
        return None
    word = _read_word(raw, 0)
    if word is None:
        return None
    try:
        return int(word, 16)
    except ValueError:
        return None


def credit_balance(token_address, wallet):
    """Whole credits held, or None when the chain cannot be reached.

    Rounds DOWN: showing 5 credits to someone holding 4.9 would let them try to
    buy something they cannot afford and meet a failure they were told would not
    happen.
    """
    wei = credit_balance_wei(token_address, wallet)
    if wei is None:
        return None
    return wei // (10 ** CREDIT_DECIMALS)


# The bootstrap stake floor. MUST equal aggregator/witness.go
# BootstrapStakeFloorWei and the node's copy: all three compute witness sets
# independently, and a floor they disagree on produces three different sets and
# rejects every honest receipt as fraudulent.
BOOTSTRAP_STAKE_FLOOR_WEI = 1

# Every candidate starts at full reputation. The aggregator does the same
# (CandidatesFor sets ReputationBps: 10000) because on-chain reputation does not
# exist yet; when it does, both sides must start reading it in the same commit.
DEFAULT_REPUTATION_BPS = 10000


def node_owner(registry_address, node_id_hex):
    """The wallet that registered a node, or None if it is not registered.

    getNode reverts for an unknown id, which _call returns as None — that is an
    answer, not an error: "we have never heard of this node".
    """
    if not registry_address:
        return None
    node_id = strip0x(node_id_hex)
    if len(node_id) != 64:
        return None
    raw = _call(registry_address, SELECTORS["getNode(bytes32)"] + node_id)
    if raw is None:
        return None
    # getNode returns a struct containing a dynamic `bytes` member, so the
    # return is a head offset followed by the struct: word 0 is the offset,
    # word 1 is the owner. Reading word 0 as the owner yields 0x20, which looks
    # like a valid-if-strange address and silently misattributes every node.
    owner = _read_word(raw, 1)
    if owner is None:
        return None
    address = "0x" + owner[-40:]
    if int(owner, 16) == 0:
        return None
    return address


def total_staked(stake_vault, owner):
    """Wei staked by a wallet. 0 when nothing is staked or it cannot be read."""
    if not stake_vault or not owner:
        return 0
    address = strip0x(owner).lower()
    if len(address) != 40:
        return 0
    raw = _call(stake_vault, SELECTORS["totalStaked(address)"] + address.rjust(64, "0"))
    if raw is None:
        return 0
    word = _read_word(raw, 0)
    try:
        return int(word, 16) if word else 0
    except ValueError:
        return 0
