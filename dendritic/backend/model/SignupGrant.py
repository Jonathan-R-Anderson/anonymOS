"""20 AXONCoins for a new account, and the reason it is not simply handed over.

Accounts here are free and instant — a username and a password, no captcha, no
email. So "everyone gets 20 AXONCoins on signup" is, written literally, a faucet
that pays anybody willing to type a name a thousand times. The grant has to
survive that or it is not a welcome, it is a subsidy for whoever automates first.

WHAT ACTUALLY STOPS A FARM
--------------------------
Not one clever check. Four cheap ones that each cost the farmer a different
resource, plus a human at the end:

  wallets   one grant per wallet address, ever. Wallets are free to make, but
            every grant has to land somewhere, so a farm needs N of them and
            each is separately visible on chain.
  time      an account has to exist for a while before it can claim. A burst of
            registrations cannot be cashed the same evening, which is the
            difference between noticing a farm and reading about it afterwards.
  work      the account has to have actually done something. This is the one
            that bites: it converts "make 1000 accounts" into "make 1000
            accounts AND use each of them", and the second part does not
            automate for free.
  network   a cap per network prefix, so the laziest version — one machine, one
            connection, a hundred signups — stops at the cap.

  operator  and then a person looks. Payout is a transfer an operator makes by
            hand (this server holds no signing key), so every claim passes a
            human who can see the signals below before any money moves.

None of that is proof of personhood, and pretending otherwise would be the
mistake. What it does is make farming cost time, effort and attention, and make
a farm LOOK like a farm in the operator's queue — which is the achievable goal.

THE NETWORK PREFIX IS STORED AS A HASH
--------------------------------------
Grouping signups by network needs only equality, not the address. So what is
kept is a salted hash of the /24 (or IPv6 /48), which compares identically and
cannot be turned back into somebody's address by anyone reading the table later.
"""

import datetime as _datetime
import hashlib
import ipaddress

from shared import db

# What a new account is worth.
SIGNUP_CREDITS = 20

# How long an account must exist before it can claim. Short enough not to feel
# like a punishment, long enough that a scripted burst of registrations sits in
# the queue overnight where somebody can see all of it at once.
MIN_ACCOUNT_AGE_HOURS = 24

# Qualifying actions — posts made plus arcade challenges solved. Three is not a
# meaningful contribution and is not meant to be; it is the smallest number that
# cannot be reached by a script that only knows how to fill in the signup form.
MIN_ACTIONS = 3

# Claims allowed from one network prefix. Households, offices and universities
# really do share an address, so this is a cap rather than a ban — and one that
# an operator can see being hit.
MAX_PER_NETWORK = 3

STATUS_PENDING = "pending"      # earned, not yet claimable or not yet claimed
STATUS_CLAIMED = "claimed"      # claimed; a CreditGrant is queued for the operator
STATUS_REFUSED = "refused"      # an operator judged it a farm


class SignupGrant(db.Model):
    """One per slip, created at registration. Claimed later, or never."""

    __tablename__ = "signup_grant"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False,
                        unique=True, index=True)
    credits = db.Column(db.BigInteger, nullable=False, default=SIGNUP_CREDITS)
    status = db.Column(db.String(16), nullable=False, default=STATUS_PENDING, index=True)

    # Salted hash of the /24 the account registered from. Compared, never read.
    network_hash = db.Column(db.String(64), nullable=True, index=True)
    # And the network it was CLAIMED from, which is often a different one and is
    # worth having: signing up on a phone and claiming from a farm is a pattern.
    claim_network_hash = db.Column(db.String(64), nullable=True, index=True)

    # Where it was paid. Unique: one wallet collects one signup grant, ever,
    # enforced by the database rather than by a check somebody can forget.
    wallet = db.Column(db.String(42), nullable=True, unique=True)
    credit_grant_id = db.Column(db.Integer, db.ForeignKey("credit_grant.id"), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    claimed_at = db.Column(db.DateTime, nullable=True)
    # Why an operator refused. Same reasoning as CreditGrant.reason: a decision
    # with no recorded reason is unreadable a year later.
    note = db.Column(db.String(255), nullable=False, default="")


def network_hash(ip_address, salt):
    """Salted hash of an address's network prefix, or None if unparseable.

    /24 for IPv4 and /48 for IPv6 — the smallest blocks that are usually one
    subscriber rather than one device, so a household is one bucket and a
    datacentre range is not one bucket per VM.
    """
    try:
        address = ipaddress.ip_address((ip_address or "").strip())
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 48
    network = ipaddress.ip_network("%s/%d" % (address, prefix), strict=False)
    digest = hashlib.sha256(("%s|%s" % (salt or "", network)).encode("utf-8"))
    return digest.hexdigest()


def grant_for_slip(slip_id):
    return (
        db.session.query(SignupGrant)
        .filter(SignupGrant.slip_id == slip_id)
        .one_or_none()
    )


def claims_from_network(hashed, exclude_slip_id=None):
    """How many grants have already been CLAIMED from a network prefix.

    Counts claims, not signups: registering a hundred accounts from one address
    is rude but costs nothing, and refusing on that alone would lock out a shared
    connection where one real person is trying to claim.
    """
    if not hashed:
        return 0
    query = (
        db.session.query(db.func.count(SignupGrant.id))
        .filter(SignupGrant.status == STATUS_CLAIMED)
        .filter(db.or_(SignupGrant.network_hash == hashed,
                       SignupGrant.claim_network_hash == hashed))
    )
    if exclude_slip_id:
        query = query.filter(SignupGrant.slip_id != exclude_slip_id)
    return int(query.scalar() or 0)


def pending_claims(limit=200):
    """The operator's review queue: claimed, not yet sent."""
    return (
        db.session.query(SignupGrant)
        .filter(SignupGrant.status == STATUS_CLAIMED)
        .order_by(SignupGrant.claimed_at.desc())
        .limit(limit)
        .all()
    )
