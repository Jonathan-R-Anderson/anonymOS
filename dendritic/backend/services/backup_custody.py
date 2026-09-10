"""Choosing which gateways hold a copy of the backup.

Item 12 of roadmap/domain-and-origin-succession.md. The artifact is opaque
ciphertext (see services/backup.py), so a custodian learns nothing by holding
it. What they DO get is the ability to withhold it — and the whole point of
spreading copies is that the site can be rebuilt when this server is gone, which
is precisely when somebody unhelpful gets to decide whether to hand theirs back.

SO THE SELECTION IS ABOUT INDEPENDENCE, NOT SCORE
--------------------------------------------------
Picking the five highest-reputation gateways is the obvious approach and the
wrong one: on a young network the top five are frequently one person with five
machines, and that person can then withhold every copy at once. Reputation says
who is reliable; it says nothing about who is a different somebody.

This is the same rule `services/gateway_quorum.py` already applies to audit
findings, for the same reason — one operator's five signatures are one opinion,
and one operator's five copies are one copy.

MORE COPIES IS NOT OBVIOUSLY BETTER
-----------------------------------
Each copy is an offline target: a holder can attack the passphrase for as long
as they like, with no rate limit and nothing to notice it. Availability wants
many copies and confidentiality wants few, and the honest resolution is that the
passphrase carries that weight (which is why services/backup.py refuses a short
one) while the replica count is chosen for survival rather than maximised.
"""

from shared import app

# How many custodians to place a backup with, and across how many distinct
# operators. Governance parameters rather than constants: a network with twenty
# operators should be able to demand more spread than one with three.
DEFAULTS = {
    "backup_replicas": 5,
    "backup_distinct_operators": 3,
    # Below this, a gateway is not a custodian. Not a judgement about the
    # person — a node that keeps disappearing cannot be relied on to still have
    # the file on the day it is needed.
    "backup_minimum_reputation": 0.4,
    # A custodian must be able to hold the artifact with room to spare.
    "backup_capacity_headroom": 2.0,
}


def settings():
    from model.SiteSetting import get_setting

    resolved = {}
    for key, fallback in DEFAULTS.items():
        raw = get_setting(key, "")
        try:
            resolved[key] = type(fallback)(raw) if raw not in ("", None) else fallback
        except (TypeError, ValueError):
            resolved[key] = fallback
    return resolved


def choose(candidates, artifact_bytes, limits=None):
    """Pick custodians. Returns {"chosen": [...], "skipped": [...], ...}.

    ``candidates`` are dicts with ``id``, ``operator``, ``reputation`` and
    ``free_bytes``. Never raises: this runs on a schedule, and a selection that
    threw would stop backups being placed at all rather than placing fewer.
    """
    limits = limits or settings()
    replicas = max(1, int(limits.get("backup_replicas") or 1))
    want_operators = max(1, int(limits.get("backup_distinct_operators") or 1))
    floor = float(limits.get("backup_minimum_reputation") or 0)
    headroom = float(limits.get("backup_capacity_headroom") or 1)
    needed = int(artifact_bytes) * headroom

    eligible, skipped = [], []
    for candidate in candidates or []:
        identifier = candidate.get("id")
        if identifier is None:
            continue
        reputation = float(candidate.get("reputation") or 0)
        free = float(candidate.get("free_bytes") or 0)
        if reputation < floor:
            skipped.append({"id": identifier, "why": "reputation %.2f below %.2f"
                            % (reputation, floor)})
            continue
        if free < needed:
            skipped.append({"id": identifier,
                            "why": "%.1f MB free, needs %.1f MB with headroom"
                                   % (free / 1048576, needed / 1048576)})
            continue
        eligible.append(candidate)

    # Best first, then a stable tiebreak. Without the tiebreak the chosen set
    # churns between runs for no reason, and a custodian list that changes every
    # cycle means copies are constantly being moved rather than held.
    eligible.sort(key=lambda item: (-float(item.get("reputation") or 0),
                                    str(item.get("id"))))

    chosen = []
    operators = set()
    # First pass takes at most one per operator, so the spread is achieved
    # before the count is. Filling by score first and hoping for variety is how
    # five slots go to one person's five machines.
    for candidate in eligible:
        if len(chosen) >= replicas:
            break
        operator = _operator_of(candidate)
        if operator in operators:
            continue
        operators.add(operator)
        chosen.append(candidate)

    # Second pass fills any remaining slots, now that spread is secured.
    if len(chosen) < replicas:
        taken = {candidate.get("id") for candidate in chosen}
        for candidate in eligible:
            if len(chosen) >= replicas:
                break
            if candidate.get("id") in taken:
                continue
            chosen.append(candidate)

    distinct = len({_operator_of(candidate) for candidate in chosen})
    warnings = []
    if distinct < want_operators:
        # Reported, not refused. Refusing would mean a young network keeps NO
        # copies at all, which is worse than copies with too few operators —
        # the artifact is opaque either way, and the risk being described is
        # availability, not disclosure.
        warnings.append(
            "These %d copies span %d operator(s), not %d. Whoever controls "
            "them can withhold every copy at once; more independent gateways "
            "are the only fix." % (len(chosen), distinct, want_operators))
    if len(chosen) < replicas:
        warnings.append(
            "Placed %d of %d copies — no other gateway met the reputation and "
            "capacity bar." % (len(chosen), replicas))
    if not chosen:
        warnings.append(
            "No gateway is holding a backup. This server is the only copy.")

    return {"chosen": chosen, "skipped": skipped,
            "distinct_operators": distinct, "warnings": warnings,
            "replicas_wanted": replicas}


def _operator_of(candidate):
    """Who this gateway belongs to, for independence purposes.

    Falls back to the gateway's own id when no operator is known, which counts
    it as its OWN operator. That is the safe direction: treating unknowns as one
    shared operator would collapse them into a single slot and place fewer
    copies than intended, while this errs toward placing more.
    """
    operator = (candidate.get("operator") or "").strip().lower()
    return operator or ("gateway:%s" % candidate.get("id"))


def challenge(custodian_digest, expected_digest):
    """Is this custodian still holding the right bytes?

    The whole question, and it is answerable by a holder who cannot decrypt a
    single byte — which is what makes an untrusted volunteer a useful custodian
    at all. See services/backup.verify: the digest is in the plaintext header
    precisely so this can be asked without a key.

    It does NOT establish that the plaintext is genuine. Whoever rewrote the
    ciphertext could rewrite the digest beside it, and only the passphrase
    holder can settle that, at restore time, from the AEAD tags.
    """
    custodian_digest = (custodian_digest or "").strip().lower()
    expected_digest = (expected_digest or "").strip().lower()
    if not custodian_digest or not expected_digest:
        return False
    return custodian_digest == expected_digest
