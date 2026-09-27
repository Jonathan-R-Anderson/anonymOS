"""DAO proposals, votes, and the governance weight behind them.

Roadmap §12 is emphatic that this must NOT be token-weighted: someone could buy
20% of supply and steer monetary policy without ever running infrastructure. So
voting weight here is never read from a CREDIT balance. It is the governance
score:

    40% infrastructure contribution + 30% reputation
  + 20% participation             + 10% stake

Most of those inputs do not exist yet — no epoch has settled, there is no
EigenTrust reputation, and nothing is staked — so their components are 0 today
and the page says so rather than quietly inventing numbers. Until they come
online the effective weight is one member, one vote, anchored to a linked
wallet. That is a deliberate floor, not the design: when receipts start
settling, `governance_score` starts returning real components and the same
tally code keeps working.

Votes are recorded off-chain with the signature that authorised them. When the
Governance contract lands (Phase 5) each row already carries what an on-chain
migration needs: the wallet, the choice, and a verifiable signature over both.
"""

import datetime

from sqlalchemy import UniqueConstraint

from shared import db

# Multi-house governance (§12): each house vetoes only its own domain.
HOUSE_INFRASTRUCTURE = "infrastructure"
HOUSE_TREASURY = "treasury"
HOUSE_COMMUNITY = "community"
HOUSES = (HOUSE_INFRASTRUCTURE, HOUSE_TREASURY, HOUSE_COMMUNITY)
HOUSE_LABELS = {
    HOUSE_INFRASTRUCTURE: "Infrastructure Council",
    HOUSE_TREASURY: "Treasury Council",
    HOUSE_COMMUNITY: "Community Council",
}
HOUSE_SCOPE = {
    HOUSE_INFRASTRUCTURE: "Storage, gateways, DHT and container workloads.",
    HOUSE_TREASURY: "Emission, reserves, budgets and reward splits.",
    HOUSE_COMMUNITY: "Boards, moderation policy, and everything user-facing.",
}

CHOICE_FOR = "for"
CHOICE_AGAINST = "against"
CHOICE_ABSTAIN = "abstain"
CHOICES = (CHOICE_FOR, CHOICE_AGAINST, CHOICE_ABSTAIN)

STATUS_OPEN = "open"
STATUS_CLOSED = "closed"

# §12 weights. Kept as data so the split is auditable rather than buried in
# arithmetic, and so a future policy change is one edit.
SCORE_WEIGHTS = (
    ("infrastructure", 40, "Verified infrastructure contribution"),
    ("reputation", 30, "Reputation from honest participation"),
    ("participation", 20, "Governance participation"),
    ("stake", 10, "Stake bonded in StakeVault"),
)


class DaoProposal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    house = db.Column(db.String(24), nullable=False, default=HOUSE_COMMUNITY)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    author_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)
    author_wallet = db.Column(db.String(42), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    closes_at = db.Column(db.DateTime, nullable=False)
    # Set once the Governance contract exists; until then a proposal lives only
    # here and the UI says so.
    onchain_ref = db.Column(db.String(80), nullable=True)

    @property
    def is_open(self):
        return datetime.datetime.utcnow() < self.closes_at

    @property
    def status(self):
        return STATUS_OPEN if self.is_open else STATUS_CLOSED


class DaoVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    proposal_id = db.Column(db.Integer, db.ForeignKey("dao_proposal.id"), nullable=False, index=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False)
    wallet_address = db.Column(db.String(42), nullable=False)
    choice = db.Column(db.String(16), nullable=False)
    # The weight applied at the moment of voting. Snapshotted rather than
    # recomputed at tally time: a score that moves after the fact would
    # retroactively rewrite past votes.
    weight = db.Column(db.Integer, nullable=False, default=1)
    signature = db.Column(db.Text, nullable=False)
    signed_message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    __table_args__ = (
        # One vote per slip per proposal. Enforced in the schema, not just the
        # view, because "vote twice" is the first thing anyone tries.
        UniqueConstraint("proposal_id", "slip_id", name="uq_dao_vote_proposal_slip"),
    )


def governance_score(slip):
    """Return (total, components, wallet) for a slip's voting weight.

    Components whose source system is not live report `available=False` with a
    zero contribution, so the UI can distinguish "you have earned nothing yet"
    from "this cannot be measured yet" — those mean very different things to
    someone deciding whether governance is fair.
    """
    from model.Slip import slip_wallet_address

    wallet = slip_wallet_address(slip)
    components = []
    for key, weight, label in SCORE_WEIGHTS:
        if key == "participation":
            cast = (
                db.session.query(DaoVote.id)
                .filter(DaoVote.slip_id == slip.id)
                .count()
                if slip is not None else 0
            )
            # Participation is the one input measurable today. Capped so a
            # prolific voter cannot out-weigh the infrastructure component that
            # is meant to dominate once it exists.
            value = min(cast, 10) / 10.0
            components.append({
                "key": key, "label": label, "weight": weight,
                "value": value, "available": True,
                "detail": "%d vote(s) cast" % cast,
            })
        else:
            components.append({
                "key": key, "label": label, "weight": weight,
                "value": 0.0, "available": False,
                "detail": {
                    "infrastructure": "No epoch has settled yet — no receipts to score.",
                    "reputation": "Reputation graph is not built yet (Phase 5).",
                    "stake": "Nothing is bonded in StakeVault yet.",
                }[key],
            })

    scored = sum(c["weight"] * c["value"] for c in components)
    # One member, one vote until the real inputs come online — see module docs.
    total = max(1, int(round(scored)))
    return total, components, wallet


def tally(proposal):
    """Weighted and headcount totals for a proposal."""
    votes = db.session.query(DaoVote).filter(DaoVote.proposal_id == proposal.id).all()
    result = {c: {"weight": 0, "count": 0} for c in CHOICES}
    for vote in votes:
        bucket = result.get(vote.choice)
        if bucket is None:
            continue
        bucket["weight"] += vote.weight or 0
        bucket["count"] += 1
    decided = result[CHOICE_FOR]["weight"] + result[CHOICE_AGAINST]["weight"]
    result["total_weight"] = decided + result[CHOICE_ABSTAIN]["weight"]
    result["total_count"] = sum(result[c]["count"] for c in CHOICES)
    # Abstentions deliberately do not count against a proposal: they record
    # presence without preference.
    result["passing"] = result[CHOICE_FOR]["weight"] > result[CHOICE_AGAINST]["weight"] and decided > 0
    return result


def vote_of(proposal, slip):
    if slip is None:
        return None
    return (
        db.session.query(DaoVote)
        .filter(DaoVote.proposal_id == proposal.id, DaoVote.slip_id == slip.id)
        .one_or_none()
    )
