"""The escrow state machine, and the arithmetic that decides who gets what.

Read model/Bounty.py first: it explains why rejection costs the poster money.
This module is the part that has to be correct rather than the part that has to
be argued for.

THE TWO WAYS TO SAY NO, AND WHY THERE ARE TWO
---------------------------------------------
REJECT is fast, unilateral, and costs the poster REJECT_HUNTER_BPS of the reward.
It exists because rejection is unverifiable — a poster who reads a real report,
says no, and fixes the bug anyway has stolen the work, and pricing that is the
only lever an escrow with no oracle has.

DISPUTE is slow, freezes the escrow, and hands the split to an operator. It
exists because the reject slice, on its own, would be farmable: submit noise at
every open bounty and collect 15% each time. A poster facing junk disputes it
instead of rejecting, and pays nothing if an operator agrees it is junk.

So the fast path costs money and the free path costs time. Neither side gets a
way to say no that is both cheap and immediate, which is the property that makes
the whole thing survivable.

ONE SUBMISSION RESOLVES A BOUNTY
--------------------------------
Accepting or rejecting ends it. That is forced by the escrow holding exactly one
reward: if a rejection paid a slice and left the bounty open, the remaining funds
would no longer cover the reward still being advertised, and the site would be
promising money it is not holding.
"""

import datetime

from shared import db

from model.Bounty import (
    Bounty,
    BountyRating,
    BountySubmission,
    MIN_REWARD,
    REJECT_HUNTER_BPS,
    REVIEW_DAYS,
    STATUS_ACCEPTED,
    STATUS_CANCELLED,
    STATUS_DISPUTED,
    STATUS_DRAFT,
    STATUS_OPEN,
    STATUS_REJECTED,
    STATUS_SETTLED,
    STATUS_SUBMITTED,
    SUBMISSION_ACCEPTED,
    SUBMISSION_PENDING,
    SUBMISSION_REJECTED,
)

# What a bounty may still receive submissions in.
ACCEPTING = (STATUS_OPEN,)


class BountyError(RuntimeError):
    """Something the user can act on. The message is shown to them."""


def reject_split(reward):
    """(hunter, poster) for a rejected submission, in whole AXONCoins.

    Integer division, and the remainder goes to the POSTER: the escrow must
    divide exactly, and rounding a fraction of a coin toward the person being
    told no would be inventing money the escrow does not hold.

    This is also why MIN_REWARD exists — below it the hunter's slice rounds to
    zero and the disincentive this whole mechanism is built around disappears.
    """
    reward = int(reward or 0)
    hunter = (reward * REJECT_HUNTER_BPS) // 10000
    return hunter, reward - hunter


def validate_reward(value):
    """A reward as a whole number of AXONCoins. Raises BountyError."""
    try:
        reward = int(str(value).strip())
    except (TypeError, ValueError):
        raise BountyError("The reward has to be a whole number of AXONCoins.")
    if reward < MIN_REWARD:
        raise BountyError(
            "The smallest bounty is %d AXONCoins. Below that the rejection slice "
            "rounds to nothing, and the protection it provides disappears."
            % MIN_REWARD)
    return reward


def review_deadline(submission):
    """When a pending submission may be escalated by the hunter, or None."""
    if submission is None or submission.status != SUBMISSION_PENDING:
        return None
    return submission.created_at + datetime.timedelta(days=REVIEW_DAYS)


def review_overdue(submission, now=None):
    """Has the poster run out of time to answer?

    A poster who never answers is the commonest way an escrow rots, and the funds
    are already held — so stalling costs them nothing unless this exists.
    """
    deadline = review_deadline(submission)
    if deadline is None:
        return False
    return (now or datetime.datetime.utcnow()) >= deadline


def pending_submission(bounty):
    """The submission awaiting a verdict, or None."""
    for submission in sorted(bounty.submissions, key=lambda s: s.created_at):
        if submission.status == SUBMISSION_PENDING:
            return submission
    return None


# ---------------------------------------------------------------- lifecycle

def create(poster_slip, title, target, description, reward):
    """A draft. Nothing is promised until the escrow is funded."""
    title = (title or "").strip()
    if not title:
        raise BountyError("Give the bounty a title.")
    bounty = Bounty(
        poster_slip_id=poster_slip.id,
        title=title[:160],
        target=(target or "").strip()[:300],
        description=(description or "").strip(),
        reward=validate_reward(reward),
        status=STATUS_DRAFT,
        created_at=datetime.datetime.utcnow(),
    )
    db.session.add(bounty)
    db.session.commit()
    return bounty


def fund(bounty, tx_hash):
    """Open a bounty once its escrow transfer is confirmed on chain.

    The poster's claim that they paid is checked, never taken — same as a store
    order. Until this succeeds the bounty is a draft and nobody has been invited
    to do work for it.
    """
    if bounty.status != STATUS_DRAFT:
        raise BountyError("This bounty is already funded.")
    tx_hash = (tx_hash or "").strip()
    if not tx_hash:
        raise BountyError("No transaction was given.")
    if db.session.query(Bounty.id).filter(
            Bounty.escrow_tx == tx_hash, Bounty.id != bounty.id).first() is not None:
        raise BountyError("That transaction has already funded another bounty.")

    from model.Store import treasury_address
    from services.pof_chain import ChainError, token_address
    from services.store_payments import verify_credit_payment

    treasury = treasury_address()
    if not treasury:
        raise BountyError("This server has no treasury address configured yet.")
    try:
        ok, detail = verify_credit_payment(
            tx_hash, token_address(), treasury, int(bounty.reward) * (10 ** 18))
    except ChainError as exc:
        raise BountyError("Could not reach the chain to check that: %s" % exc)
    if not ok:
        raise BountyError(detail)

    bounty.escrow_tx = tx_hash
    bounty.funded_at = datetime.datetime.utcnow()
    bounty.status = STATUS_OPEN
    db.session.commit()
    return bounty


def submit(bounty, hunter_slip, body):
    """File a finding. The poster can read it immediately, which is the whole
    reason rejection has to cost them something."""
    if bounty.status not in ACCEPTING:
        raise BountyError("This bounty is not accepting submissions.")
    if bounty.poster_slip_id == hunter_slip.id:
        raise BountyError("You cannot submit to your own bounty.")
    body = (body or "").strip()
    if len(body) < 20:
        raise BountyError("Describe the finding — a few words is not a report.")

    submission = BountySubmission(
        bounty_id=bounty.id,
        hunter_slip_id=hunter_slip.id,
        body=body,
        status=SUBMISSION_PENDING,
        created_at=datetime.datetime.utcnow(),
    )
    db.session.add(submission)
    bounty.status = STATUS_SUBMITTED
    db.session.commit()
    return submission


def accept(bounty, submission):
    """Resolve in the hunter's favour. The whole reward is theirs."""
    _require_pending(bounty, submission)
    submission.status = SUBMISSION_ACCEPTED
    submission.resolved_at = datetime.datetime.utcnow()
    bounty.status = STATUS_ACCEPTED
    bounty.payout_hunter = int(bounty.reward)
    bounty.payout_poster = 0
    bounty.resolved_at = submission.resolved_at
    db.session.commit()
    return bounty


def reject(bounty, submission, note):
    """Resolve in the poster's favour, minus the slice the hunter still gets.

    A reason is required. "No" with no argument is indistinguishable from theft,
    and the rating this leaves behind needs something to attach to.
    """
    _require_pending(bounty, submission)
    note = (note or "").strip()
    if len(note) < 10:
        raise BountyError("Say why you are rejecting it. A bare no is not a verdict.")

    hunter, poster = reject_split(bounty.reward)
    submission.status = SUBMISSION_REJECTED
    submission.verdict_note = note
    submission.resolved_at = datetime.datetime.utcnow()
    bounty.status = STATUS_REJECTED
    bounty.payout_hunter = hunter
    bounty.payout_poster = poster
    bounty.resolved_at = submission.resolved_at
    db.session.commit()
    return bounty


def dispute(bounty, by_slip):
    """Freeze the escrow for an operator instead of resolving it.

    Open to both sides, for opposite reasons: a poster uses it against a junk
    submission (so the reject slice cannot be farmed), a hunter uses it against a
    poster who is stalling or who rejected a real finding.
    """
    if bounty.status not in (STATUS_SUBMITTED, STATUS_REJECTED):
        raise BountyError("There is nothing to dispute on this bounty.")
    submission = pending_submission(bounty)
    hunter_ids = {s.hunter_slip_id for s in bounty.submissions}
    if by_slip.id != bounty.poster_slip_id and by_slip.id not in hunter_ids:
        raise BountyError("Only the people involved can dispute this.")
    bounty.status = STATUS_DISPUTED
    # Any split computed by a rejection is withdrawn: an operator decides now,
    # and leaving the old numbers in place would look like a decision.
    bounty.payout_hunter = 0
    bounty.payout_poster = 0
    bounty.resolved_at = None
    db.session.commit()
    return submission


def resolve_dispute(bounty, hunter_share):
    """An operator's split, in whole AXONCoins to the hunter.

    Stored rather than derived, like every other resolution: the rules can change
    and a bounty settled under the old ones keeps its own numbers.
    """
    if bounty.status != STATUS_DISPUTED:
        raise BountyError("That bounty is not disputed.")
    try:
        hunter = int(hunter_share)
    except (TypeError, ValueError):
        raise BountyError("The hunter's share has to be a whole number.")
    if hunter < 0 or hunter > int(bounty.reward):
        raise BountyError("The split has to be between 0 and the reward.")

    bounty.payout_hunter = hunter
    bounty.payout_poster = int(bounty.reward) - hunter
    # Named by who won, so the public record and the ratings agree with what
    # actually happened rather than all disputes looking alike.
    bounty.status = STATUS_ACCEPTED if hunter > bounty.payout_poster else STATUS_REJECTED
    bounty.resolved_at = datetime.datetime.utcnow()
    for submission in bounty.submissions:
        if submission.status == SUBMISSION_PENDING:
            submission.status = (SUBMISSION_ACCEPTED if hunter > 0 else SUBMISSION_REJECTED)
            submission.resolved_at = bounty.resolved_at
    db.session.commit()
    return bounty


def cancel(bounty):
    """Withdraw a bounty nobody has worked on yet. Full refund owed."""
    if bounty.status == STATUS_DRAFT:
        # Never funded, so there is nothing to refund and nothing to record.
        db.session.delete(bounty)
        db.session.commit()
        return None
    if bounty.status != STATUS_OPEN:
        raise BountyError("Somebody has already submitted to this bounty.")
    bounty.status = STATUS_CANCELLED
    bounty.payout_hunter = 0
    bounty.payout_poster = int(bounty.reward)
    bounty.resolved_at = datetime.datetime.utcnow()
    db.session.commit()
    return bounty


def mark_settled(bounty):
    """An operator has sent both owed transfers."""
    if bounty.status not in (STATUS_ACCEPTED, STATUS_REJECTED, STATUS_CANCELLED):
        raise BountyError("That bounty has nothing owed on it.")
    bounty.status = STATUS_SETTLED
    bounty.settled_at = datetime.datetime.utcnow()
    db.session.commit()
    return bounty


def owed(bounty):
    """[(slip_id, amount)] an operator still has to send for this bounty."""
    if bounty.status not in (STATUS_ACCEPTED, STATUS_REJECTED, STATUS_CANCELLED):
        return []
    rows = []
    if bounty.payout_hunter:
        hunter = _resolved_hunter_id(bounty)
        if hunter:
            rows.append((hunter, int(bounty.payout_hunter)))
    if bounty.payout_poster:
        rows.append((bounty.poster_slip_id, int(bounty.payout_poster)))
    return rows


def _resolved_hunter_id(bounty):
    for submission in bounty.submissions:
        if submission.status in (SUBMISSION_ACCEPTED, SUBMISSION_REJECTED):
            return submission.hunter_slip_id
    return None


def _require_pending(bounty, submission):
    if submission is None or submission.bounty_id != bounty.id:
        raise BountyError("That submission is not on this bounty.")
    if submission.status != SUBMISSION_PENDING:
        raise BountyError("That submission has already been answered.")
    if bounty.status != STATUS_SUBMITTED:
        raise BountyError("This bounty is not awaiting a verdict.")


# ------------------------------------------------------------------ ratings

def rate(bounty, rater_slip, score, comment):
    """Rate the other side of a bounty you took part in.

    Only from a RESOLVED bounty, once per rater. An open rating system is a
    review-bombing surface; requiring that the two people actually transacted is
    far harder to abuse and means something.
    """
    if bounty.status not in (STATUS_ACCEPTED, STATUS_REJECTED,
                             STATUS_CANCELLED, STATUS_SETTLED):
        raise BountyError("You can rate somebody once the bounty is resolved.")
    try:
        score = int(score)
    except (TypeError, ValueError):
        raise BountyError("Pick a score from 1 to 5.")
    if score < 1 or score > 5:
        raise BountyError("Pick a score from 1 to 5.")

    hunter_id = _resolved_hunter_id(bounty)
    if rater_slip.id == bounty.poster_slip_id:
        rated = hunter_id
    elif rater_slip.id == hunter_id:
        rated = bounty.poster_slip_id
    else:
        raise BountyError("Only the people involved can rate this.")
    if not rated:
        raise BountyError("There is nobody to rate on this bounty.")

    existing = (
        db.session.query(BountyRating)
        .filter(BountyRating.bounty_id == bounty.id,
                BountyRating.rater_slip_id == rater_slip.id)
        .one_or_none()
    )
    if existing is not None:
        raise BountyError("You have already rated this bounty.")

    db.session.add(BountyRating(
        bounty_id=bounty.id,
        rater_slip_id=rater_slip.id,
        rated_slip_id=rated,
        score=score,
        comment=(comment or "").strip()[:500],
        created_at=datetime.datetime.utcnow(),
    ))
    db.session.commit()
