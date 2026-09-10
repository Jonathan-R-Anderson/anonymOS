"""Awards paid over a payment channel instead of the chain — roadmap P9.

WHAT CHANGED AND WHAT DID NOT
-----------------------------
An award used to be one ERC-20 transfer: gas, every time, to send somebody five
AXONCoins. This pays over an open channel instead, so the tenth award costs what
the second one did, which is nothing.

What did not change is the thing that made the old design trustworthy: the money
never touches this server. There is no balance here to debit and no key here to
sign with. An award is either backed by evidence that stands on its own or it
did not happen.

WHAT THE EVIDENCE IS
--------------------
A fully co-signed state. Two signatures over a digest that names the chain, the
contract, the channel, the nonce and the balances — the same object that lets a
party settle a channel unilaterally against a contract that never saw the
payment. Anyone holding it can check it, and this server is one more holder.

    giver wallet + author wallet  ->  channelId       derived here, never supplied
    chain id + manager address    ->  configuration   never from the claim
    state + both signatures       ->  the claim
            |
            v
    rebuild the digest, recover both signatures, require exactly the two parties

A claim that supplied its own contract address could present a state signed for
a contract of its own making, which is why those come from config.

WHY A HIGH-WATER MARK AND NOT A RECEIPT
---------------------------------------
The obvious design keys an award to the state that paid for it, the way the
on-chain path keys one to a transaction hash. That has a hole which only opens
once payments are free.

A giver and an author can already cycle coins between themselves to manufacture
decorated posts. On chain each cycle costs gas, and that friction is the only
thing holding it back. Off chain there is no friction at all: the same ten AXON
could go back and forth forever, each pass a fresh nonce and a fresh "award".

So an award is credited against the most the author has ever been ahead in that
channel, not against any single payment:

    received  = author balance + author withdrawals
    available = received - the high-water mark already spent on awards

The mark only rises. Sending value back lowers `received`, so re-sending it buys
nothing — awarding again requires pushing the author higher than they have ever
been, which takes value that genuinely came from somewhere else.

It also makes the ledger robust to a state this server never saw. It does not
need every payment, only a later one; the evidence is cumulative rather than a
chain of receipts with a gap in it.
"""

import datetime

import requests

from shared import app, db

from model.PostAward import PostAward, tier_credits
from services.channel_state import (
    StateError,
    check_signature_shape,
    decode_state,
    derive_channel_id,
    digest_of,
    is_party_a,
    normalize_address,
    received_by,
    sort_parties,
)


class ChannelAwardError(RuntimeError):
    """Something the giver can act on. The message is shown to them."""


class VerifierUnavailable(RuntimeError):
    """We could not check, which is our problem and not the giver's.

    Kept distinct from ChannelAwardError on purpose: "your signature is wrong"
    and "we cannot tell whether your signature is wrong" call for different
    words to the user and different alarm to an operator.
    """


def deployment():
    """The chain id and manager address a state must have been signed for.

    From configuration, never from a claim. These are inside the digest
    precisely so that a state signed for one deployment cannot be replayed
    against another, and letting a caller name them would hand that back.
    """
    chain_id = app.config.get("CHANNEL_CHAIN_ID")
    manager = normalize_address(app.config.get("CHANNEL_MANAGER_ADDRESS"))
    if not chain_id or not manager:
        return None
    return int(chain_id), manager


def recover_digest_signer(digest_hex, signature):
    """The address that signed a 32-byte digest, or None.

    Goes to the renderer sidecar, like services/wallet_auth.py and for the same
    reason: eth-account is listed in requirements.txt but the image installs
    from the Pipfile, so it is NOT present at runtime.

    A DIFFERENT endpoint from /verify/wallet. That one recovers the signer of a
    text message, and ethers treats a string as UTF-8 — so handing it the hex
    digest would recover the signer of the 66 characters rather than of the 32
    bytes they spell. It would do that consistently, against the wrong thing,
    and every signature would verify as somebody who does not exist.
    """
    verify_url = app.config["RENDERER_HOST"] + "/verify/digest"
    try:
        response = requests.post(
            verify_url,
            json={"digest": "0x" + digest_hex, "signature": signature},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        app.logger.exception("Channel state verification unavailable")
        raise VerifierUnavailable("Signature verification service unavailable") from exc
    return normalize_address(payload.get("recovered_address"))


def verify_signed_state(wire_state, sig_a, sig_b, giver_wallet, author_wallet):
    """Check a co-signed state and return it, or raise.

    Returns (state, author_is_a). Everything a caller needs to reason about who
    received what, and nothing it could use to bypass this check.
    """
    config = deployment()
    if config is None:
        raise ChannelAwardError("Channel awards are not configured on this site.")
    chain_id, manager = config

    try:
        state = decode_state(wire_state)
        expected_id = derive_channel_id(giver_wallet, author_wallet).hex()
        if state["channel"] != expected_id:
            # The state is about some other channel. Deriving the id here rather
            # than reading it from the claim is what makes this checkable at all.
            raise StateError("state is for a different channel")

        digest = digest_of(state, chain_id, manager).hex()
        sig_a = check_signature_shape(sig_a)
        sig_b = check_signature_shape(sig_b)
    except StateError as exc:
        raise ChannelAwardError("That payment proof is malformed: %s" % exc)

    party_a, party_b = sort_parties(giver_wallet, author_wallet)
    recovered_a = recover_digest_signer(digest, sig_a)
    recovered_b = recover_digest_signer(digest, sig_b)

    # BOTH, and each to the right side. One signature proves only that somebody
    # proposed a state; a channel moves value when both parties agree to it.
    if recovered_a != party_a or recovered_b != party_b:
        raise ChannelAwardError("That payment proof is not signed by both parties.")

    return state, (party_a == normalize_address(author_wallet))


def unawarded_value(state, author_is_a, already_awarded):
    """How much of this channel's inflow is not yet spent on awards.

    The whole anti-gaming rule in one line. `received` can fall — the author may
    pay value back — but `already_awarded` never does, so value that goes out and
    comes back lands below the mark and buys nothing. Clamped at zero so a
    channel whose author has spent more than they were awarded reads as "nothing
    available" rather than as a negative that some caller compares wrongly.
    """
    return max(0, received_by(state, author_is_a) - already_awarded)


def high_water(channel_id):
    """How much of this channel's inflow has already been spent on awards."""
    from model.ChannelAwardLedger import ChannelAwardLedger

    row = (db.session.query(ChannelAwardLedger)
           .filter(ChannelAwardLedger.channel_id == channel_id)
           .one_or_none())
    return int(row.awarded_wei) if row else 0


def _raise_mark(channel_id, received, author_wallet):
    """Move the mark up to `received`. Never down.

    Written as a conditional UPDATE so that two awards racing on one channel
    cannot both read the old mark and both credit themselves against it. The
    loser's update matches no row, and it re-reads and fails rather than
    crediting an award twice for the same value.
    """
    from model.ChannelAwardLedger import ChannelAwardLedger

    row = (db.session.query(ChannelAwardLedger)
           .filter(ChannelAwardLedger.channel_id == channel_id)
           .one_or_none())
    if row is None:
        db.session.add(ChannelAwardLedger(
            channel_id=channel_id,
            recipient_wallet=author_wallet,
            awarded_wei=str(received),
            updated_at=datetime.datetime.utcnow(),
        ))
        return True

    updated = (db.session.query(ChannelAwardLedger)
               .filter(ChannelAwardLedger.channel_id == channel_id)
               .filter(ChannelAwardLedger.awarded_wei == row.awarded_wei)
               .update({"awarded_wei": str(received),
                        "updated_at": datetime.datetime.utcnow()},
                       synchronize_session=False))
    return updated == 1


def record(post, giver_slip, tier, proof):
    """Verify a channel-backed award and store it. Raises ChannelAwardError.

    `proof` is {state, sig_a, sig_b} as the browser received them from the
    recipient's node. Returns the fresh per-tier counts for the post.
    """
    from model.PostAward import counts_for_posts
    from services.post_awards import author_slip, wallet_for_slip

    credits = tier_credits(tier)
    if credits is None:
        raise ChannelAwardError("That is not an award tier.")
    tier = tier.strip().lower()
    amount_wei = credits * (10 ** 18)

    author = author_slip(post)
    author_wallet = wallet_for_slip(author)
    if not author_wallet:
        raise ChannelAwardError("This post cannot receive awards.")

    giver_wallet = normalize_address(_slip_wallet(giver_slip))
    if not giver_wallet:
        raise ChannelAwardError("Connect a wallet to your profile before awarding.")

    if author is not None and giver_slip is not None and author.id == giver_slip.id:
        # Not etiquette: self-awards would let one wallet cycle its own coins to
        # manufacture a decorated post. Over a channel that would cost nothing
        # at all, so the rule matters more here than it did on chain.
        raise ChannelAwardError("You cannot award your own post.")

    if not isinstance(proof, dict):
        raise ChannelAwardError("No payment proof was given.")

    state, author_is_a = verify_signed_state(
        proof.get("state"), proof.get("sig_a"), proof.get("sig_b"),
        giver_wallet, author_wallet)

    channel_id = state["channel"]
    already = high_water(channel_id)
    available = unawarded_value(state, author_is_a, already)

    if available < amount_wei:
        # The honest message. A giver in this position has usually not paid yet,
        # or has paid less than the tier costs.
        raise ChannelAwardError(
            "That channel has only %s AXON of unawarded value; %s needs %d."
            % (_anon(available), tier, credits))

    if not _raise_mark(channel_id, already + amount_wei, author_wallet):
        # Another award for this channel committed while this one was deciding.
        raise ChannelAwardError("Another award for this channel was recorded first. Try again.")

    db.session.add(PostAward(
        post_id=post.id,
        giver_slip_id=giver_slip.id,
        recipient_wallet=author_wallet,
        tier=tier,
        credits=credits,
        # No transaction hash: nothing about this went on chain. The channel and
        # the nonce are what identify it, and they are unique together for the
        # same reason tx_hash was unique — one payment cannot buy two awards.
        tx_hash=None,
        channel_id=channel_id,
        channel_nonce=state["nonce"],
        created_at=datetime.datetime.utcnow(),
    ))
    db.session.commit()
    return counts_for_posts([post.id]).get(post.id, {})


def _slip_wallet(slip):
    """The giver's wallet, from their own profile."""
    if slip is None:
        return None
    profile = getattr(slip, "profile", None)
    if profile is None:
        return None
    return (profile.eth_address or "").strip().lower() or None


def _anon(wei):
    """Whole AXON for a message. Floor, so it never overstates what is there."""
    return wei // (10 ** 18)


def channel_quote(post, giver_slip):
    """What the browser needs to pay this award over a channel, or None.

    None means "no channel path" rather than "no awards" — the caller falls back
    to the on-chain transfer, which is the floor for the great majority of
    authors who have a wallet and nothing else.
    """
    from services.post_awards import author_slip, wallet_for_slip

    config = deployment()
    if config is None:
        return None

    author = author_slip(post)
    author_wallet = wallet_for_slip(author)
    if not author_wallet:
        return None

    endpoint = _channel_endpoint(author)
    if not endpoint:
        # The author has a wallet but no node to hold a channel with.
        return None

    giver_wallet = normalize_address(_slip_wallet(giver_slip))
    if not giver_wallet or giver_wallet == author_wallet:
        return None

    chain_id, manager = config
    return {
        "recipient": author_wallet,
        "endpoint": endpoint,
        "manager": manager,
        "chain_id": chain_id,
        "channel_id": "0x" + derive_channel_id(giver_wallet, author_wallet).hex(),
        "author_is_a": is_party_a(author_wallet, giver_wallet),
    }


def _channel_endpoint(slip):
    """The author's node, if they published one."""
    if slip is None:
        return None
    profile = getattr(slip, "profile", None)
    if profile is None or not profile.is_public:
        return None
    endpoint = (getattr(profile, "channel_endpoint", "") or "").strip()
    if not endpoint:
        return None
    # Only https. A tip flow that could be pointed at http:// would let a
    # network attacker rewrite the state the browser is about to sign against.
    if not endpoint.startswith("https://"):
        return None
    return endpoint
