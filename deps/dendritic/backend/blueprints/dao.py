"""DAO pages: proposals, weighted voting, and the governance-score breakdown.

Voting requires a linked wallet and a signature over the exact choice. That is
not ceremony: it makes each vote independently verifiable by anyone holding the
record, and it is the same evidence the Governance contract will want when
voting moves on-chain (roadmap §12, Phase 5). A vote cast from a session cookie
alone would have to be taken on trust from this server.
"""

import datetime

from flask import (
    Blueprint, flash, jsonify, redirect, render_template, request, url_for,
)

from model.Dao import (
    CHOICES,
    DaoProposal,
    DaoVote,
    HOUSE_LABELS,
    HOUSE_SCOPE,
    HOUSES,
    governance_score,
    tally,
    vote_of,
)
from model.Slip import get_slip, slip_wallet_address
from services.wallet_auth import build_message, issue_challenge, recover_signer, take_challenge
from shared import db

dao_blueprint = Blueprint("dao", __name__, template_folder="template")

MIN_DURATION_DAYS = 1
MAX_DURATION_DAYS = 30


def _vote_statement(proposal_id, choice):
    return "vote %s on DAO proposal #%d" % (choice, proposal_id)


@dao_blueprint.route("/")
def index():
    proposals = (
        db.session.query(DaoProposal)
        .order_by(DaoProposal.closes_at.desc(), DaoProposal.id.desc())
        .limit(100)
        .all()
    )
    slip = get_slip()
    weight, components, wallet = (None, None, None)
    if slip is not None:
        weight, components, wallet = governance_score(slip)
    return render_template(
        "dao-list.html",
        proposals=proposals,
        tallies={p.id: tally(p) for p in proposals},
        house_labels=HOUSE_LABELS,
        house_scope=HOUSE_SCOPE,
        houses=HOUSES,
        weight=weight,
        components=components,
        wallet=wallet,
        slip=slip,
    )


@dao_blueprint.route("/proposal/<int:proposal_id>")
def proposal(proposal_id):
    row = db.session.query(DaoProposal).filter(DaoProposal.id == proposal_id).one_or_none()
    if row is None:
        return render_template("not-found.html"), 404
    slip = get_slip()
    weight, components, wallet = (None, None, None)
    if slip is not None:
        weight, components, wallet = governance_score(slip)
    votes = (
        db.session.query(DaoVote)
        .filter(DaoVote.proposal_id == row.id)
        .order_by(DaoVote.created_at.desc())
        .limit(200)
        .all()
    )
    return render_template(
        "dao-proposal.html",
        proposal=row,
        result=tally(row),
        votes=votes,
        my_vote=vote_of(row, slip),
        house_labels=HOUSE_LABELS,
        weight=weight,
        components=components,
        wallet=wallet,
        slip=slip,
    )


@dao_blueprint.route("/new", methods=["POST"])
def create():
    slip = get_slip()
    if slip is None:
        flash("Log in to open a proposal.")
        return redirect(url_for("slip.landing"))
    wallet = slip_wallet_address(slip)
    if not wallet:
        flash("Link a MetaMask wallet before opening a proposal.")
        return redirect(url_for("profiles.edit"))

    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()
    house = (request.form.get("house") or "").strip()
    if not title or house not in HOUSES:
        flash("A proposal needs a title and a council.")
        return redirect(url_for("dao.index"))
    if len(title) > 200:
        flash("Titles must be 200 characters or fewer.")
        return redirect(url_for("dao.index"))
    try:
        days = int(request.form.get("days") or 7)
    except (TypeError, ValueError):
        days = 7
    days = max(MIN_DURATION_DAYS, min(MAX_DURATION_DAYS, days))

    row = DaoProposal(
        house=house, title=title, body=body,
        author_slip_id=slip.id, author_wallet=wallet,
        closes_at=datetime.datetime.utcnow() + datetime.timedelta(days=days),
    )
    db.session.add(row)
    db.session.commit()
    flash("Proposal opened. It closes in %d day(s)." % days)
    return redirect(url_for("dao.proposal", proposal_id=row.id))


@dao_blueprint.route("/proposal/<int:proposal_id>/challenge", methods=["POST"])
def vote_challenge(proposal_id):
    """Mint the message a voter signs. The choice is inside the signed text, so
    a signature for "against" cannot be submitted as a "for"."""
    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Not logged in"}), 403
    choice = (request.get_json(silent=True) or {}).get("choice")
    if choice not in CHOICES:
        return jsonify({"error": "Unknown choice"}), 400
    _nonce, message = issue_challenge(
        "dao-vote-%d" % proposal_id, _vote_statement(proposal_id, choice)
    )
    return jsonify({"message": message})


@dao_blueprint.route("/proposal/<int:proposal_id>/vote", methods=["POST"])
def vote(proposal_id):
    slip = get_slip()
    if slip is None:
        return jsonify({"error": "Log in to vote."}), 403
    row = db.session.query(DaoProposal).filter(DaoProposal.id == proposal_id).one_or_none()
    if row is None:
        return jsonify({"error": "No such proposal."}), 404
    if not row.is_open:
        return jsonify({"error": "Voting on this proposal has closed."}), 409

    wallet = slip_wallet_address(slip)
    if not wallet:
        return jsonify({"error": "Link a MetaMask wallet before voting."}), 403

    payload = request.get_json(silent=True) or {}
    choice = payload.get("choice")
    signature = payload.get("signature")
    if choice not in CHOICES:
        return jsonify({"error": "Unknown choice."}), 400

    taken, error = take_challenge("dao-vote-%d" % proposal_id)
    if error:
        return jsonify({"error": error}), 400
    nonce, issued_at = taken
    message = build_message(_vote_statement(proposal_id, choice), nonce, issued_at)

    try:
        recovered = recover_signer(message, signature, wallet)
    except RuntimeError:
        return jsonify({"error": "Wallet verification is unavailable right now."}), 502
    if recovered is None:
        return jsonify({"error": "That signature did not verify."}), 403
    if recovered != wallet:
        # Signed by a different wallet than the one linked to this slip: the
        # vote would be attributable to the wrong member.
        return jsonify({
            "error": "That signature came from %s, but this slip is linked to %s." % (recovered, wallet),
        }), 403

    if vote_of(row, slip) is not None:
        return jsonify({"error": "You have already voted on this proposal."}), 409

    weight, _components, _wallet = governance_score(slip)
    db.session.add(DaoVote(
        proposal_id=row.id, slip_id=slip.id, wallet_address=wallet,
        choice=choice, weight=weight, signature=signature, signed_message=message,
    ))
    try:
        db.session.commit()
    except Exception:
        # The unique constraint is the real guard against a double-submit race;
        # the check above only saves a round trip.
        db.session.rollback()
        return jsonify({"error": "You have already voted on this proposal."}), 409
    return jsonify({"ok": True, "redirect": url_for("dao.proposal", proposal_id=row.id)})
