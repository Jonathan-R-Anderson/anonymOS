"""Everything that has ever credited an account, in one list.

The credits page showed purchases only, which meant it answered "what did you
buy" while the question people actually have is "where did my credits come
from". Those are different, and the gap is where trust goes: a member whose
subscription credited a month, an operator who was granted credits by hand, and
a node operator whose machine earned receipts all saw nothing at all, and
concluded the money had gone missing.

Four sources, deliberately kept distinct rather than merged into one number:

  purchase    a credit pack bought with a card
  membership  a month of a subscription
  grant       an operator sending credits by hand
  node        work a node did, which is the one that is NOT money yet

That last distinction is the important one. A receipt is proof of work
performed, not credit in a wallet: it becomes credit only after an epoch
settles, and until then showing it as a balance would be promising something
that has not happened. So node work appears as PENDING with what it is waiting
on written next to it, and the page says so rather than leaving somebody to
conclude they were paid and robbed.
"""

import json


def _iso(value):
    return value.isoformat() + "Z" if value else None


def purchase_entries(slip_id):
    """Card purchases and membership months. Both are CreditPurchase rows; the
    key tells them apart, because a subscription month is keyed on its Stripe
    invoice and a pack on its checkout session.

    UNPAID checkouts are excluded, and "unpaid" means anything Stripe has not
    confirmed — pending as well as expired.

    A row is written BEFORE the buyer pays, because the webhook can only find
    the purchase again by its Checkout session id and that id does not exist
    until the session is created. So clicking Buy and closing the tab leaves a
    `pending` row behind. This function used to exclude only EXPIRED, which made
    its own docstring wrong: a row is not expired until the sweep runs 26 hours
    later, so for a day an abandoned click read as "60 AXONCoins pending" —
    the site telling somebody credits were on their way when nobody had paid.

    Repeat the click and the page fills with credits nobody bought. Nothing
    downstream ever spent them (owed_for_slip and undelivered both key on PAID,
    so the operator's payout list was never affected), but a balance that
    inflates on demand is not something to leave standing on the argument that
    it is only cosmetic.

    The cost of this is one real case: somebody who has genuinely paid but whose
    webhook has not landed yet sees nothing here for a few seconds. That is
    covered — /credits/thanks asks Stripe directly and marks the purchase paid
    rather than waiting — and it is the right way round. Briefly under-reporting
    a real payment is recoverable; over-reporting one that never happened is
    what somebody builds an exploit on.
    """
    from model.CreditPurchase import (
        CreditPurchase, STATUS_DELIVERED, STATUS_EXPIRED, STATUS_PENDING,
    )
    from shared import db

    rows = (
        db.session.query(CreditPurchase)
        .filter(CreditPurchase.slip_id == slip_id)
        .filter(CreditPurchase.status.notin_([STATUS_EXPIRED, STATUS_PENDING]))
        .order_by(CreditPurchase.created_at.desc())
        .limit(200)
        .all()
    )
    out = []
    for row in rows:
        membership = (row.stripe_session_id or "").startswith("sub_invoice:")
        out.append({
            "kind": "membership" if membership else "purchase",
            "credits": int(row.credits or 0),
            "status": row.status,
            "settled": row.status == STATUS_DELIVERED,
            "detail": ("A month of membership" if membership
                       else "$%.2f AXONCoins pack" % ((row.amount_cents or 0) / 100.0)),
            "reference": row.delivery_tx,
            "at": _iso(row.created_at),
        })
    return out


def grant_entries(wallet):
    """Credits an operator sent by hand to this wallet."""
    if not wallet:
        return []
    from model.CreditGrant import CreditGrant
    from shared import db

    rows = (
        db.session.query(CreditGrant)
        .filter(CreditGrant.wallet == wallet.lower())
        .order_by(CreditGrant.created_at.desc())
        .limit(100)
        .all()
    )
    return [{
        "kind": "grant",
        "credits": int(row.credits or 0),
        "status": "delivered" if row.tx_hash else "pending",
        "settled": bool(row.tx_hash),
        "detail": row.reason or "Sent by an operator",
        "reference": row.tx_hash,
        "at": _iso(row.created_at),
    } for row in rows]


def node_entries(wallet):
    """Work this wallet's nodes have done, and where it has got to.

    Receipts are grouped by epoch because an epoch is the unit that settles: a
    hundred receipts in one epoch become one payment, and listing them
    individually would suggest a hundred payments are coming.

    A receipt is NOT credit. It is evidence accepted into an epoch that has not
    been scored yet, and saying so plainly is the whole point of this function —
    the alternative is somebody seeing work recorded, no credits arriving, and
    reasonably concluding the site lost their money.
    """
    if not wallet:
        return []
    from model.PofRegistration import all_payouts
    from model.PofRelay import PofReceipt
    from model.PofSettlement import PofSettlement
    from shared import db

    mine = {p.p2p_public_key for p in all_payouts()
            if (p.payout or "").lower() == wallet.lower()}
    if not mine:
        return []

    counts = {}
    for receipt in (db.session.query(PofReceipt)
                    .filter(PofReceipt.provider_key.in_(mine)).all()):
        counts[receipt.epoch] = counts.get(receipt.epoch, 0) + 1
    if not counts:
        return []

    settled = {
        row.epoch: row for row in
        db.session.query(PofSettlement)
        .filter(PofSettlement.epoch.in_(list(counts))).all()
    }

    # WHY nothing has settled, not just that nothing has. The old wording said
    # "it becomes credits when the epoch is scored and finalized", which reads
    # as "wait" — and somebody reasonably concluded that finalizing the epoch on
    # chain would release their money. It does not: an epoch whose receipts
    # could not be witnessed carries no rewards, so finalizing it changes a flag
    # and pays nobody.
    #
    # The real blocker is the size of the witness pool, and that is a fact about
    # the NETWORK rather than about this person's work. Saying so is the
    # difference between "your credits are coming" and "your credits cannot come
    # until N more nodes join", and only one of those is true.
    shortfall = None
    try:
        from services.settlement_readiness import candidate_pool, witnesses_required

        pool = len(candidate_pool())
        required = witnesses_required("storage")
        if max(pool - 1, 0) < required:
            shortfall = (required + 1) - pool
    except Exception:
        pass

    out = []
    for epoch in sorted(counts, reverse=True):
        settlement = settled.get(epoch)
        if shortfall:
            detail = (
                "%d receipt(s) accepted and held. This is not waiting on time or "
                "on anything you can do: a claim has to be witnessed by other "
                "nodes, and the network is %d node(s) short of being able to "
                "witness one. Finalizing the epoch will not release it — an "
                "epoch with no witnessable receipts carries no rewards. The work "
                "is recorded and settles once enough nodes are running."
                % (counts[epoch], shortfall))
        else:
            detail = (
                "%d receipt(s) accepted. Epoch %d has not been settled yet, so "
                "this is proven work rather than AXONCoins — it becomes AXONCoins "
                "when the epoch is scored and finalized."
                % (counts[epoch], epoch))
        credits, status = 0, "pending"

        if settlement is not None:
            # Only what was actually awarded to THIS wallet, read from the
            # settlement's own claim rows rather than inferred from the total.
            for claim in settlement.claim_rows():
                if str(claim.get("recipient", "")).lower() == wallet.lower():
                    try:
                        credits += int(claim.get("amount") or 0) // (10 ** 18)
                    except (TypeError, ValueError):
                        pass
            status = "delivered" if settlement.submitted_tx else "settled"
            detail = ("%d receipt(s), settled in epoch %d%s"
                      % (counts[epoch], epoch,
                         "" if settlement.submitted_tx else " (not yet on-chain)"))

        out.append({
            "kind": "node",
            "credits": credits,
            "status": status,
            "settled": status == "delivered",
            "detail": detail,
            "reference": settlement.submitted_tx if settlement else None,
            "at": None,
            "epoch": epoch,
            "receipts": counts[epoch],
        })
    return out


def deposits(slip, wallet):
    """Every credit this account has been given or earned, newest first."""
    entries = []
    if slip is not None:
        entries.extend(purchase_entries(slip.id))
    entries.extend(grant_entries(wallet))
    entries.extend(node_entries(wallet))

    # Node rows carry no timestamp (an epoch is a period, not an instant), so
    # they sort last within the list rather than being given a fake one.
    entries.sort(key=lambda e: (e.get("at") or ""), reverse=True)

    return {
        "entries": entries,
        # Counted separately from the on-chain balance on purpose: this is what
        # the site believes it owes, and the balance is what the chain says it
        # holds. When those disagree, the difference is the interesting number.
        "credited": sum(e["credits"] for e in entries if e["settled"]),
        "pending": sum(e["credits"] for e in entries if not e["settled"]),
        "pending_work": sum(e.get("receipts", 0) for e in entries
                            if e["kind"] == "node" and not e["settled"]),
    }
