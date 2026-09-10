"""Giving somebody AXONCoins for a post, and proving it happened.

The browser signs an ERC-20 transfer from the giver's wallet straight to the
author's, then tells this server the transaction hash. That claim is checked
against the chain exactly like a store order is — right token, right recipient,
at least the tier's amount, and a transaction not already spent on another award.
An unverified hash is worth nothing: anybody can post one, including somebody
else's.

The money never touches this server. There is no balance here to debit and no key
here to sign with, so an award is either on chain or it did not happen.
"""

import datetime

from shared import db

from model.PostAward import PostAward, TIERS, TIER_ORDER, tier_credits


class AwardError(RuntimeError):
    """Something the giver can act on. The message is shown to them."""


def author_slip(post):
    """The slip that wrote a post, or None.

    Scraped posts have no poster row at all, which is the first reason most posts
    cannot be awarded: there is nobody on this site to pay.
    """
    poster = getattr(post, "poster_object", None)
    if poster is None:
        poster_id = getattr(post, "poster", None)
        if not poster_id:
            return None
        from model.Poster import Poster
        poster = db.session.query(Poster).filter(Poster.id == poster_id).one_or_none()
    if poster is None or not getattr(poster, "slip", None):
        return None
    from model.Slip import Slip
    return db.session.query(Slip).filter(Slip.id == poster.slip).one_or_none()


def recipient_wallet(post):
    """Where an award for this post would be paid, or None if nowhere.

    None is the normal answer. It means one of: the post is scraped, the author
    posted without a slip, the author has no profile, the author's profile is
    private, the author did not agree to be identifiable from their posts, or
    they never added a wallet. Only the last of those is something they would
    likely want to fix, and none of them are worth reporting to a stranger — so
    the caller shows no button rather than an explanation.
    """
    return wallet_for_slip(author_slip(post))


def wallet_for_slip(slip):
    """Where this slip may be paid, honouring their own visibility choices."""
    if slip is None:
        return None
    profile = getattr(slip, "profile", None)
    if profile is None or not profile.is_public:
        return None
    # The consent that matters: this author already chose to have their posts
    # point at a profile carrying this wallet. An award publishes nothing new.
    if not getattr(profile, "link_on_comments", False):
        return None
    wallet = (profile.eth_address or "").strip().lower()
    return wallet or None


def awardable_for_thread(thread_id):
    """{post_id: author_slip_id} for posts in a thread that can be awarded.

    One query for the whole thread. Doing this per post would mean four joins per
    reply on a 300-reply thread, and the answer is the same shape as
    recipient_wallet() — a post is awardable when its author has a public profile
    they let their posts link to, carrying a wallet.
    """
    from model.Post import Post
    from model.Poster import Poster
    from model.Profile import Profile

    rows = (
        db.session.query(Post.id, Poster.slip)
        .join(Poster, Poster.id == Post.poster)
        .join(Profile, Profile.slip_id == Poster.slip)
        .filter(Post.thread == thread_id)
        .filter(Profile.is_public.is_(True))
        .filter(Profile.link_on_comments.is_(True))
        .filter(Profile.eth_address.isnot(None))
        .filter(Profile.eth_address != "")
        .all()
    )
    return {int(post_id): int(slip_id) for post_id, slip_id in rows if slip_id}


def tiers_payload():
    """The tier menu, priced, for the browser."""
    return [{
        "tier": name,
        "label": TIERS[name]["label"],
        "icon": TIERS[name]["icon"],
        "credits": TIERS[name]["credits"],
        # The exact wei the browser must transfer. Computed here rather than in
        # JS: 100 * 1e18 exceeds Number.MAX_SAFE_INTEGER, and a UI that computes
        # it with floating point sends the wrong amount.
        "wei": str(TIERS[name]["credits"] * (10 ** 18)),
    } for name in TIER_ORDER]


def quote(post):
    """What the browser needs to build the transfer, or None if it cannot."""
    wallet = recipient_wallet(post)
    if not wallet:
        return None
    from services.pof_chain import token_address

    token = (token_address() or "").strip().lower()
    if not token:
        # The site knows who to pay but not what to pay in. Refusing here is the
        # difference between "no awards yet" and somebody sending AXONCoins to a
        # contract address that is empty string.
        return None
    return {"recipient": wallet, "token": token, "tiers": tiers_payload()}


def record(post, giver_slip, tier, tx_hash):
    """Verify an award transfer on chain and store it. Raises AwardError.

    Returns the fresh per-tier counts for the post, so the caller can answer the
    request without a second query.
    """
    from model.PostAward import counts_for_posts
    from services.pof_chain import ChainError, token_address
    from services.store_payments import verify_credit_payment

    credits = tier_credits(tier)
    if credits is None:
        raise AwardError("That is not an award tier.")
    tier = tier.strip().lower()

    tx_hash = (tx_hash or "").strip()
    if not tx_hash:
        raise AwardError("No transaction was given.")

    author = author_slip(post)
    wallet = wallet_for_slip(author)
    if not wallet:
        raise AwardError("This post cannot receive awards.")

    if author is not None and giver_slip is not None and author.id == giver_slip.id:
        # Not a rule about etiquette: self-awards would let one wallet cycle its
        # own AXONCoins to manufacture a decorated post at the cost of gas alone.
        raise AwardError("You cannot award your own post.")

    # Checked before touching the chain: an RPC round trip to discover a replay
    # is wasted, and the unique index would raise something unreadable.
    if db.session.query(PostAward.id).filter(PostAward.tx_hash == tx_hash).first() is not None:
        raise AwardError("That transaction has already been used for an award.")

    try:
        ok, detail = verify_credit_payment(
            tx_hash, token_address(), wallet, credits * (10 ** 18))
    except ChainError as exc:
        raise AwardError("Could not reach the chain to check that: %s" % exc)
    if not ok:
        raise AwardError(detail)

    db.session.add(PostAward(
        post_id=post.id,
        giver_slip_id=giver_slip.id,
        recipient_wallet=wallet,
        tier=tier,
        credits=credits,
        tx_hash=tx_hash,
        created_at=datetime.datetime.utcnow(),
    ))
    db.session.commit()
    return counts_for_posts([post.id]).get(post.id, {})
