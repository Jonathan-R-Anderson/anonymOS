"""Bronze, silver and gold on a post — paid in real AXONCoins.

WHY THIS IS NOT A COUNTER
-------------------------
Reddit's gold is a number the site keeps. Here it is a transfer: the giver's
wallet sends AXONCoins to the author's wallet, and the server records the award
only after it has read the transaction back off Ethereum. Nothing is credited by
this table; the table is a record of something that already happened on chain.

That is the only shape available. This server holds no signing key — deliberately,
a hot wallet here being the largest single risk in the system — so it cannot move
anybody's AXONCoins on their behalf. An award has to be signed by the person
giving it, which is also the only version that cannot be faked by us.

WHO CAN RECEIVE ONE
-------------------
Paying somebody requires their address, and this is an imageboard: publishing the
wallet behind an anonymous post would deanonymize the author to anyone who
clicked Award. So an award is only offered on posts whose author has ALREADY
chosen to be identifiable from their posts — a public profile with
`link_on_comments` on — and who has a wallet on it.

That reuses an existing, explicit consent rather than inventing a second toggle
nobody would find, and it means the button appearing tells a visitor nothing they
could not already read off the post's profile link. Everyone else simply has no
award button, with no explanation shown, because "this author is anonymous" is
itself a fact worth not publishing.
"""

import datetime as _datetime

from shared import db

# The three tiers, and what each one actually costs the giver in whole
# AXONCoins. Round numbers a person can hold in their head, spaced widely enough
# that gold means something: a tier scheme where the top rung costs twice the
# bottom one is three names for the same gesture.
TIERS = {
    "bronze": {"credits": 5, "label": "Bronze", "icon": "\U0001F949"},
    "silver": {"credits": 25, "label": "Silver", "icon": "\U0001F948"},
    "gold": {"credits": 100, "label": "Gold", "icon": "\U0001F947"},
}

# Display order. dicts preserve insertion order in the Pythons this runs on, but
# the UI ordering is a decision rather than an implementation detail, so it is
# written down instead of inherited.
TIER_ORDER = ("bronze", "silver", "gold")


def tier_credits(tier):
    """Whole AXONCoins for a tier name, or None if it is not a tier.

    Returning None rather than a default is deliberate: an unknown tier arriving
    from a request must fail the request, not quietly bill somebody the cheapest
    amount.
    """
    row = TIERS.get((tier or "").strip().lower())
    return row["credits"] if row else None


class PostAward(db.Model):
    """One award, paid either on chain or over a channel."""

    __tablename__ = "post_award"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    giver_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    # Denormalised from the profile at the time of the award. The author may
    # change wallets later, and this row has to keep saying where the money
    # actually went — it is the receipt for a payment, not a pointer to a person.
    recipient_wallet = db.Column(db.String(42), nullable=False, default="")
    tier = db.Column(db.String(16), nullable=False, default="bronze")
    credits = db.Column(db.BigInteger, nullable=False, default=0)
    # Unique: one transaction cannot pay for two awards. Without this, a single
    # transfer could be replayed against every post on the board.
    #
    # NULLABLE since P9: a channel-backed award has no transaction, because
    # nothing about it went on chain. That is the whole point of paying over a
    # channel. Postgres treats NULLs as distinct in a unique index, so many
    # channel awards coexist while the on-chain guarantee is unchanged.
    tx_hash = db.Column(db.String(80), nullable=True, unique=True)
    # Set instead of tx_hash for a channel-backed award. Unique together for the
    # same reason tx_hash was unique on its own: one payment, one award.
    channel_id = db.Column(db.String(64), nullable=True, index=True)
    channel_nonce = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("channel_id", "channel_nonce", name="uq_post_award_channel_state"),
        # An award is paid one way or the other, and exactly one way. A row with
        # neither is an award nobody paid for; a row with both is a claim that
        # two different payments bought the same thing.
        db.CheckConstraint(
            "(tx_hash IS NOT NULL AND channel_id IS NULL)"
            " OR (tx_hash IS NULL AND channel_id IS NOT NULL)",
            name="ck_post_award_one_payment_path",
        ),
    )


def counts_for_posts(post_ids):
    """{post_id: {"bronze": n, "silver": n, "gold": n}} for posts with awards.

    Posts with none are absent rather than zero-filled: the caller renders
    nothing for them, and materialising a row per post would make this scale with
    the thread instead of with the awards in it.
    """
    ids = [int(i) for i in post_ids if i]
    if not ids:
        return {}
    rows = (
        db.session.query(PostAward.post_id, PostAward.tier, db.func.count(PostAward.id))
        .filter(PostAward.post_id.in_(ids))
        .group_by(PostAward.post_id, PostAward.tier)
        .all()
    )
    out = {}
    for post_id, tier, count in rows:
        if tier not in TIERS:
            continue  # a tier retired since the award was given
        out.setdefault(int(post_id), {})[tier] = int(count)
    return out


def totals_for_slip(slip_id):
    """What somebody has been given across all their posts: count and AXONCoins.

    Shown on a profile as recognition. Counted from awards received, never from
    a stored running total, so it cannot drift away from the rows it summarises.
    """
    from model.Post import Post
    from model.Poster import Poster

    row = (
        db.session.query(db.func.count(PostAward.id),
                         db.func.coalesce(db.func.sum(PostAward.credits), 0))
        .join(Post, Post.id == PostAward.post_id)
        .join(Poster, Poster.id == Post.poster)
        .filter(Poster.slip == slip_id)
        .one()
    )
    return {"count": int(row[0] or 0), "credits": int(row[1] or 0)}
