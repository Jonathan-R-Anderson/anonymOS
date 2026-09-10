"""Paying the node that ran the work.

THE LOOP THIS CLOSES
--------------------
A submitter is charged at queue time. Until now nothing credited the machine
that actually did the work — so the site collected credits for compute and the
volunteer who provided it received nothing. That is not an incomplete feature,
it is the network taking payment for somebody else's electricity.

WHY THE PROVIDER IS PAID ON COMPLETION, NOT ON DISPATCH
-------------------------------------------------------
Paying at dispatch would pay for accepting work rather than doing it, and the
cheapest way to earn would be to accept jobs and drop them. Paying on completion
means the node carried it to an answer.

A FAILED job still pays, at a reduced rate. That is deliberate: a node that
honestly runs a program which crashes has spent the same electricity as one
whose program succeeded, and refusing to pay would make running risky-looking
work irrational — so nodes would cherry-pick, and the jobs nobody would take are
exactly the ones that most need running. What is NOT paid is a job the node
never returned at all.

WHY THE SITE KEEPS A MARGIN
---------------------------
The submitter's charge covers the provider's share plus a margin that funds the
Treasury. Stated as an explicit constant rather than emerging from arithmetic
nobody can point at, because the one question a provider will ask is what
fraction they get, and it should have an answer.
"""

import datetime

# What fraction of the work charge reaches the node that ran it.
#
# 0.8 rather than 1.0 because the network does real work around the job —
# queueing, placement, verification, dispute handling — and rather than 0.5
# because the provider supplies the thing actually being bought. A provider who
# feels the split is unfair stops providing, and the network has no compute.
PROVIDER_SHARE = 0.8

# A failed job earns less: the electricity was spent, the answer was not
# produced. High enough that running is still worth it, low enough that failing
# is not a strategy.
FAILED_SHARE = 0.3


class EarningsError(RuntimeError):
    pass


def provider_share(credits_paid, priority_cost=0, succeeded=True):
    """What the node earns from one job.

    The priority tier is excluded: it buys queue POSITION, which the network
    provides, not compute, which the node provides. Paying the provider for it
    would mean a submitter who jumped the queue paid the node more for identical
    work.
    """
    work = max(0, int(credits_paid or 0) - int(priority_cost or 0))
    share = PROVIDER_SHARE if succeeded else FAILED_SHARE
    return int(work * share)


# A node whose result was contradicted by an independent replica is not paid.
#
# Not a punishment — a refusal to buy something the network could not confirm.
# Paying anyway would make verification decorative: the cheapest strategy would
# still be to return garbage instantly, and the replica would just be a second
# node's electricity spent to learn nothing.
#
# A DISPUTED result does not say WHICH node was wrong, so neither is paid. That
# is harsh on the honest one, and the alternative — paying both — pays the liar
# every time. The honest node loses one job's earnings; the liar loses the
# strategy.
def payable(verdict):
    from services.compute_verify import VERDICT_DISAGREED

    return verdict != VERDICT_DISAGREED


def credit_provider(job, node_id, succeeded=True, now=None):
    """Record what a node earned for one job.

    Idempotent on (job, node): a completion reported twice must not pay twice,
    and a retried callback is an ordinary event rather than an exception.
    """
    from model.ComputeEarning import ComputeEarning
    from shared import db

    if not node_id:
        raise EarningsError("cannot credit an unnamed node")

    # A contradicted result is not bought. Checked here rather than at the call
    # site so no future dispatch path can skip it by forgetting.
    if not payable(getattr(job, "verdict", None)):
        return None

    existing = (db.session.query(ComputeEarning)
                .filter(ComputeEarning.rental_id == job.id,
                        ComputeEarning.node_id == node_id)
                .one_or_none())
    if existing is not None:
        return existing

    amount = provider_share(job.credits_paid, succeeded=succeeded)
    earning = ComputeEarning(
        rental_id=job.id, node_id=node_id, amount=amount,
        device=job.device, succeeded=bool(succeeded),
        created_at=now or datetime.datetime.utcnow(),
    )
    db.session.add(earning)
    return earning


def earnings_for(node_id, limit=100):
    """A node's recent earnings, newest first."""
    from model.ComputeEarning import ComputeEarning
    from shared import db

    return (db.session.query(ComputeEarning)
            .filter(ComputeEarning.node_id == node_id)
            .order_by(ComputeEarning.created_at.desc())
            .limit(limit).all())


def total_earned(node_id):
    """What a node has earned in total.

    Computed rather than cached on the node row. A denormalised counter would be
    faster and would eventually disagree with the earnings behind it, which is
    the one thing a payment total may not do.
    """
    from model.ComputeEarning import ComputeEarning
    from shared import db

    total = (db.session.query(db.func.coalesce(db.func.sum(ComputeEarning.amount), 0))
             .filter(ComputeEarning.node_id == node_id).scalar())
    return int(total or 0)
