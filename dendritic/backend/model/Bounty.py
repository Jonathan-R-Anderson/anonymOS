"""Bug bounties with escrow, and the two-sided trust that has to come with it.

THE ATTACK THIS IS SHAPED AROUND
--------------------------------
A hunter's only asset is information, and they have to hand it over to get paid.
A poster who reads the report, rejects it, and fixes the bug anyway has stolen
the work — and no amount of "confirm it's good" prevents that, because the
confirmation is theirs to withhold.

So rejection is never free:

  * a rejected submission still pays the hunter a slice (REJECT_HUNTER_BPS).
    Not compensation for a real finding — compensation for the fact that
    rejection is unverifiable, priced so that reject-and-use is worse than
    accepting;
  * every resolution rates both sides, and a poster who rejects everything
    accumulates a public record of doing so;
  * either side can raise a dispute, which freezes the funds for an operator
    rather than resolving in the stronger party's favour by default.

None of that makes rejection safe. It makes it costly and visible, which is the
most an escrow with no oracle can do.

THE ESCROW IS CUSTODIAL, AND SAYING SO IS PART OF THE DESIGN
------------------------------------------------------------
Funding is a real AXON transfer to the treasury, verified on-chain exactly like
a store order. Payout is a transfer back out, made by the operator through the
admin console — because this server holds no signing key, deliberately: a hot
wallet here is the largest single risk in the system.

That means participants trust the operator to release funds. It is written down
in the model rather than implied by the UI, because somebody deciding whether to
escrow real money deserves to know which of these is trustless (the funding, and
the record) and which is not (the release).
"""

import datetime as _datetime

from shared import db

# Posted, not yet paid for. Nothing is promised until the escrow is verified.
STATUS_DRAFT = "draft"
# Escrowed and accepting work.
STATUS_OPEN = "open"
# A hunter has submitted; the poster owes an answer.
STATUS_SUBMITTED = "submitted"
# Resolved in the hunter's favour: full reward owed to them.
STATUS_ACCEPTED = "accepted"
# Resolved in the poster's favour: most of the escrow owed back to them.
STATUS_REJECTED = "rejected"
# Neither side accepted the other's account. An operator decides.
STATUS_DISPUTED = "disputed"
# Withdrawn before any submission. Full refund owed.
STATUS_CANCELLED = "cancelled"
# Every owed transfer has been made.
STATUS_SETTLED = "settled"

OPEN_STATUSES = (STATUS_OPEN, STATUS_SUBMITTED)
RESOLVED_STATUSES = (STATUS_ACCEPTED, STATUS_REJECTED, STATUS_CANCELLED, STATUS_SETTLED)

# What a rejected submission still pays the hunter, in basis points of the
# reward. The number is a judgement, not a calculation: high enough that
# reading a report and rejecting it costs real money, low enough that spamming
# worthless submissions at open bounties is not itself a living.
REJECT_HUNTER_BPS = 1500  # 15%

# The floor on a bounty. Below this the reject slice rounds to nothing and the
# incentive it exists to create disappears.
MIN_REWARD = 20

# A poster who never answers is the commonest way an escrow rots. After this
# the hunter may escalate to a dispute; the funds are already held, so the
# poster gains nothing by stalling.
REVIEW_DAYS = 14


class Bounty(db.Model):
    __tablename__ = "bounty"

    id = db.Column(db.Integer, primary_key=True)
    poster_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    # What is in scope. Free text on purpose: "our staging API" and a git URL
    # are both legitimate, and a rigid schema would exclude one of them.
    target = db.Column(db.String(300), nullable=False, default="")
    description = db.Column(db.Text, nullable=False, default="")
    # Whole AXON. Stored as the unit a person sees, converted to wei only at
    # the chain boundary, so nothing in the UI has to reason about 1e18.
    reward = db.Column(db.BigInteger, nullable=False, default=0)
    status = db.Column(db.String(16), nullable=False, default=STATUS_DRAFT, index=True)

    # Proof the escrow was actually funded: the transaction that paid the
    # treasury. Unique, so one payment cannot fund two bounties.
    escrow_tx = db.Column(db.String(80), nullable=True, unique=True)
    funded_at = db.Column(db.DateTime, nullable=True)

    resolved_at = db.Column(db.DateTime, nullable=True)
    # What each side is owed once resolved, in whole AXON. Computed at
    # resolution and STORED rather than derived on read: the split rules can
    # change, and a bounty settled under the old ones must keep its own numbers.
    payout_hunter = db.Column(db.BigInteger, nullable=False, default=0)
    payout_poster = db.Column(db.BigInteger, nullable=False, default=0)
    # Set when the operator has actually sent both.
    settled_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    @property
    def is_open(self):
        return self.status in OPEN_STATUSES

    @property
    def review_deadline(self):
        row = self.accepted_submission_at()
        return row + _datetime.timedelta(days=REVIEW_DAYS) if row else None

    def accepted_submission_at(self):
        for submission in sorted(self.submissions, key=lambda s: s.created_at):
            if submission.status == SUBMISSION_PENDING:
                return submission.created_at
        return None


SUBMISSION_PENDING = "pending"
SUBMISSION_ACCEPTED = "accepted"
SUBMISSION_REJECTED = "rejected"
SUBMISSION_WITHDRAWN = "withdrawn"


class BountySubmission(db.Model):
    __tablename__ = "bounty_submission"

    id = db.Column(db.Integer, primary_key=True)
    bounty_id = db.Column(db.Integer, db.ForeignKey("bounty.id"), nullable=False, index=True)
    hunter_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    # The finding. Visible to the poster the moment it is submitted, which is
    # precisely why rejection has to cost something.
    body = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default=SUBMISSION_PENDING, index=True)
    # The poster's reason. Required on rejection: "no" with no argument is
    # indistinguishable from theft, and the rating system needs something to
    # attach to.
    verdict_note = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    bounty = db.relationship("Bounty", backref=db.backref("submissions", lazy="joined"))


class BountyRating(db.Model):
    """One side's verdict on the other, tied to a bounty they both took part in.

    Ratings are only writable from a RESOLVED bounty, once per rater per
    bounty. An open rating system is a review-bombing surface; one that requires
    having actually transacted with somebody is far harder to abuse and says
    something real.
    """

    __tablename__ = "bounty_rating"
    __table_args__ = (
        db.UniqueConstraint("bounty_id", "rater_slip_id", name="uq_bounty_rating_once"),
    )

    id = db.Column(db.Integer, primary_key=True)
    bounty_id = db.Column(db.Integer, db.ForeignKey("bounty.id"), nullable=False, index=True)
    rater_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    rated_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    # 1..5. Deliberately not a free-form score: a scale people already know
    # needs no explanation, and a wider one invites false precision.
    score = db.Column(db.Integer, nullable=False, default=3)
    comment = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def trust_for(slip_id):
    """Somebody's public trust record.

    Returns count and mean, and NEVER invents a score for somebody with no
    history: "no ratings yet" and "rated badly" are opposite facts, and showing
    a new user as 0 would make joining indistinguishable from being untrusted.
    """
    rows = (
        db.session.query(BountyRating.score)
        .filter(BountyRating.rated_slip_id == slip_id)
        .all()
    )
    scores = [int(row[0]) for row in rows if row[0] is not None]
    if not scores:
        return {"count": 0, "mean": None}
    return {"count": len(scores), "mean": round(sum(scores) / float(len(scores)), 2)}
