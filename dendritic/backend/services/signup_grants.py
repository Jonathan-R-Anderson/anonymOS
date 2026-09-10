"""Deciding whether a signup grant may be claimed, and queueing the payout.

model/SignupGrant.py argues for the rules. This is the part that applies them,
and its one real job is to report WHY a claim is not ready rather than returning
a bare no — somebody 8 hours into a 24-hour wait and somebody who needs to make
a post are in completely different situations, and a single "not eligible" tells
neither of them what to do.
"""

import datetime

from shared import app, db

from model.SignupGrant import (
    MAX_PER_NETWORK,
    MIN_ACCOUNT_AGE_HOURS,
    MIN_ACTIONS,
    SIGNUP_CREDITS,
    STATUS_CLAIMED,
    STATUS_PENDING,
    SignupGrant,
    claims_from_network,
    grant_for_slip,
    network_hash,
)


class GrantError(RuntimeError):
    """Something the user can act on. The message is shown to them."""


def _salt():
    """Salt for network hashing.

    Falls back to the Flask secret key so this works on a server that never set
    a dedicated one — an unsalted hash of a /24 is trivially reversible, there
    being only a few billion of them.
    """
    return (app.config.get("SIGNUP_GRANT_SALT")
            or app.config.get("SECRET_KEY") or "signup-grant")


def _client_network():
    try:
        from services.client_ip import get_client_ip
        return network_hash(get_client_ip(), _salt())
    except Exception:
        # Never block registration or a claim on geolocation plumbing.
        return None


def record_signup(slip):
    """Create the grant row for a new account. Never raises.

    Called from registration, so a failure here must not cost somebody their
    account: a missing grant row can be created later, a failed signup cannot be
    undone.
    """
    try:
        if grant_for_slip(slip.id) is not None:
            return None
        grant = SignupGrant(
            slip_id=slip.id,
            credits=SIGNUP_CREDITS,
            status=STATUS_PENDING,
            network_hash=_client_network(),
            created_at=datetime.datetime.utcnow(),
        )
        db.session.add(grant)
        return grant
    except Exception:
        app.logger.exception("Could not record the signup grant for slip %s", slip.id)
        return None


def _qualifying_actions(slip_id):
    """Posts made plus arcade challenges solved.

    Two different kinds of effort on purpose: somebody who came to read and post
    and somebody who came for the arcade are both real, and requiring the wrong
    one of the two would gate the grant on taste rather than on effort.
    """
    total = 0
    try:
        from model.Post import Post
        from model.Poster import Poster
        total += int(
            db.session.query(db.func.count(Post.id))
            .join(Poster, Poster.id == Post.poster)
            .filter(Poster.slip == slip_id)
            .scalar() or 0
        )
    except Exception:
        app.logger.exception("Could not count posts for slip %s", slip_id)
    try:
        from model.Codeplay import CodeplayAttempt
        total += int(
            db.session.query(db.func.count(CodeplayAttempt.id))
            .filter(CodeplayAttempt.slip_id == slip_id,
                    CodeplayAttempt.was_correct.is_(True))
            .scalar() or 0
        )
    except Exception:
        app.logger.exception("Could not count arcade solves for slip %s", slip_id)
    return total


def status_for(slip):
    """Everything the claim page needs, including why it is not ready yet."""
    grant = grant_for_slip(slip.id)
    if grant is None:
        return {"exists": False}

    profile = getattr(slip, "profile", None)
    wallet = ((getattr(profile, "eth_address", "") or "").strip().lower() or None)

    age = datetime.datetime.utcnow() - (grant.created_at or datetime.datetime.utcnow())
    hours_left = MIN_ACCOUNT_AGE_HOURS - (age.total_seconds() / 3600.0)
    actions = _qualifying_actions(slip.id)

    blockers = []
    if not wallet:
        blockers.append("Add a wallet to your profile — the grant is paid to it.")
    if hours_left > 0:
        blockers.append("Accounts can claim after %d hours. About %d to go."
                        % (MIN_ACCOUNT_AGE_HOURS, max(1, round(hours_left))))
    if actions < MIN_ACTIONS:
        blockers.append("Do %d more thing%s first — a post, or an arcade challenge."
                        % (MIN_ACTIONS - actions, "" if MIN_ACTIONS - actions == 1 else "s"))

    return {
        "exists": True,
        "grant": grant,
        "credits": int(grant.credits or SIGNUP_CREDITS),
        "status": grant.status,
        "wallet": wallet,
        "actions": actions,
        "actions_needed": MIN_ACTIONS,
        "hours_left": max(0, int(round(hours_left))),
        "blockers": blockers,
        "claimable": grant.status == STATUS_PENDING and not blockers,
    }


def claim(slip):
    """Claim a signup grant. Raises GrantError with something actionable.

    Queues a CreditGrant for the operator rather than sending anything: this
    server holds no signing key, and saying so is better than a page that looks
    like it paid somebody when nothing moved.
    """
    grant = grant_for_slip(slip.id)
    if grant is None:
        raise GrantError("This account has no signup grant.")
    if grant.status == STATUS_CLAIMED:
        raise GrantError("You have already claimed this.")
    if grant.status != STATUS_PENDING:
        raise GrantError("An operator has already reviewed this grant.")

    state = status_for(slip)
    if state["blockers"]:
        raise GrantError(state["blockers"][0])

    wallet = state["wallet"]
    # One wallet, one signup grant, ever. Checked here for a readable message;
    # the unique index is what actually enforces it under a race.
    existing = (
        db.session.query(SignupGrant.id)
        .filter(SignupGrant.wallet == wallet, SignupGrant.slip_id != slip.id)
        .first()
    )
    if existing is not None:
        raise GrantError("That wallet has already claimed a signup grant.")

    claim_network = _client_network()
    if claims_from_network(claim_network, exclude_slip_id=slip.id) >= MAX_PER_NETWORK:
        raise GrantError(
            "Too many accounts have claimed from this network. If several people "
            "here are genuinely signing up, ask an operator to release it.")

    from model.CreditGrant import CreditGrant

    payout = CreditGrant(
        wallet=wallet,
        credits=int(grant.credits or SIGNUP_CREDITS),
        reason="Signup grant for slip %s" % slip.name,
        created_at=datetime.datetime.utcnow(),
    )
    db.session.add(payout)
    db.session.flush()

    grant.status = STATUS_CLAIMED
    grant.wallet = wallet
    grant.claim_network_hash = claim_network
    grant.claimed_at = datetime.datetime.utcnow()
    grant.credit_grant_id = payout.id
    db.session.commit()
    return grant
