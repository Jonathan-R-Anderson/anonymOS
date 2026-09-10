"""Several publishers signing one snapshot, so one stolen key cannot forge one.

A snapshot today rests on a single key. Steal it and you can publish anything —
revocation and the root keyring bound the damage afterwards, but nothing stops
the forgery being served in the meantime. Quorum removes that: a manifest needs
M signatures from distinct operators, so an attacker needs M compromises rather
than one.

THE THING THAT MAKES THIS HARD, MEASURED
----------------------------------------
Quorum is worthless unless a co-publisher can INDEPENDENTLY check what it is
signing. The obvious method is to rebuild the snapshot and compare — and on this
site, measured, that reproduces 5 of 7 routes:

    SAME  /            SAME  /economy   SAME  /faq
    SAME  /formatting  SAME  /snapshot/search-index.json
    DIFF  /boards/b    DIFF  /boards/mark

The two that differ are live boards. That is not a defect to engineer around: a
snapshot of a changing site, taken at two different instants, legitimately
differs. **Two publishers reading a live site cannot reproduce each other's
work, and no amount of determinism fixes it.**

SO A SIGNATURE SAYS WHAT WAS CHECKED, NOT THAT EVERYTHING IS RIGHT
------------------------------------------------------------------
Each signature carries its COVERAGE — how many routes that publisher verified
against its own rebuild, out of how many the manifest names — and the coverage
is inside the signed message. A publisher that checked nothing therefore cannot
look like one that checked everything, which it could if coverage were a field
beside the signature rather than under it.

That makes the guarantee legible rather than absolute: "three operators agree,
each having independently confirmed the five stable routes" is a true and useful
statement. "Three operators certify this snapshot" would not be.

WHY DISTINCT OPERATORS AND NOT DISTINCT KEYS
--------------------------------------------
Keys are free. One person with three keys is one person, and a quorum counting
keys would be satisfied by a single compromised machine generating as many as it
liked. Operators come from the ROOT-SIGNED keyring, so who counts as separate is
decided by the offline key rather than by whoever is signing.
"""

import datetime
import json

from shared import app

QUORUM_PREFIX = b"syndichan-quorum:v1"

# SGVS-style defaults, as governance parameters rather than constants.
DEFAULTS = {
    # Signatures required.
    "snapshot_quorum_signatures": 2,
    # ...from this many distinct operators. This is the threshold that means
    # anything; the one above is satisfiable by one machine with two keys.
    "snapshot_quorum_operators": 2,
    # A signature covering fewer than this fraction of routes is recorded but
    # does not count toward quorum: a publisher that verified one page in fifty
    # has not meaningfully checked the snapshot.
    "snapshot_quorum_min_coverage_pct": 50,
}


def thresholds():
    try:
        from model.SiteSetting import get_setting
    except Exception:
        return dict(DEFAULTS)
    values = {}
    for name, fallback in DEFAULTS.items():
        try:
            values[name] = int(get_setting(name, fallback) or fallback)
        except Exception:
            values[name] = fallback
    return values


def attestation_message(snapshot_id, sequence, source_root, verified, total):
    """The exact bytes a co-publisher signs.

    Coverage is INSIDE the message. If it sat beside the signature instead, a
    publisher could sign once and then claim any coverage it liked — and the
    number that makes this honest would be the one thing not protected.
    """
    return b"\n".join([
        QUORUM_PREFIX,
        str(snapshot_id or "").encode("ascii"),
        str(int(sequence or 0)).encode("ascii"),
        str(source_root or "").encode("ascii"),
        str(int(verified)).encode("ascii"),
        str(int(total)).encode("ascii"),
    ])


def source_root(manifest):
    """A Merkle root over (path, source_hash) — the REPRODUCIBLE commitment.

    Distinct from `root_hash`, which covers the served objects. Those carry a
    build-time banner and legitimately differ between publishers, so they cannot
    be what independent parties attest to. Source hashes are what the site
    produced, and are the same for anybody who asked at the same moment.
    """
    from services.content_signing import merkle_root
    from services.snapshot import sha256_hex

    leaves = []
    for path, entry in sorted((manifest.get("routes") or {}).items()):
        leaves.append(sha256_hex(
            ("%s\n%s" % (path, entry.get("source_hash") or "")).encode("utf-8")))
    return merkle_root(leaves) if leaves else ""


def check_against_rebuild(manifest):
    """Rebuild the snapshot and report which routes match. ``(verified, total,
    unmatched)``.

    Run by a co-publisher before signing. Rebuilt at the manifest's own
    timestamp and sequence, so anything that legitimately depends on those is
    held constant and only real disagreement shows up.
    """
    from services.snapshot import build

    when = datetime.datetime.utcfromtimestamp(int(manifest.get("created_at") or 0))
    rebuilt, _objects = build(sequence=int(manifest.get("sequence") or 0), now=when)
    theirs = manifest.get("routes") or {}
    mine = rebuilt["routes"]

    verified, unmatched = 0, []
    for path, entry in theirs.items():
        claimed = entry.get("source_hash")
        observed = mine.get(path, {}).get("source_hash")
        if claimed and observed and claimed == observed:
            verified += 1
        else:
            unmatched.append(path)
    return verified, len(theirs), unmatched


def sign_attestation(manifest, verified, total):
    """Sign what this publisher actually confirmed."""
    from services.snapshot_key import _signing_key, public_key_b64

    signer = _signing_key()
    if signer is None:
        return None
    import base64

    message = attestation_message(manifest.get("snapshot_id"),
                                  manifest.get("sequence"),
                                  manifest.get("source_root"), verified, total)
    try:
        return {
            "public_key": public_key_b64(),
            "verified_routes": int(verified),
            "total_routes": int(total),
            "signed_at": int(datetime.datetime.utcnow().timestamp()),
            "signature": base64.b64encode(signer.sign(message).signature).decode("ascii"),
        }
    except Exception:
        app.logger.exception("snapshot quorum: could not sign an attestation")
        return None


def _operator_for(public_key_b64):
    """Which operator a publisher key belongs to, per the root-signed keyring.

    Falls back to the key itself when no keyring is installed, which makes every
    key its own operator — permissive, and visible in the independence count
    rather than hidden. Once a keyring exists, the OFFLINE key decides who is
    separate, not whoever is signing.
    """
    from services.snapshot_keyring import current_keyring, verify_keyring

    record = current_keyring()
    if not record or not verify_keyring(record):
        return public_key_b64
    for entry in record.get("publisher_keys") or []:
        if entry.get("public_key") == public_key_b64:
            return entry.get("operator") or entry.get("public_key")
    return None   # not delegated at all


def verify_quorum(manifest, limits=None):
    """Weigh a manifest's signatures. Returns a verdict dict, never raises."""
    import base64

    limits = limits or thresholds()
    signatures = manifest.get("signatures") or []
    root = manifest.get("source_root") or ""
    total_routes = len(manifest.get("routes") or {})

    accepted, operators, rejected = [], set(), []
    for entry in signatures:
        public = entry.get("public_key")
        operator = _operator_for(public) if public else None
        if not operator:
            rejected.append("key not delegated by the root keyring")
            continue
        verified = int(entry.get("verified_routes") or 0)
        total = int(entry.get("total_routes") or 0)
        message = attestation_message(manifest.get("snapshot_id"),
                                      manifest.get("sequence"), root, verified, total)
        try:
            from nacl.signing import VerifyKey

            VerifyKey(base64.b64decode(public + "===")).verify(
                message, base64.b64decode(entry.get("signature", "") + "==="))
        except Exception:
            rejected.append("signature did not verify")
            continue
        # Coverage floor: a publisher that verified one page in fifty has not
        # meaningfully checked anything, and counting it would let a lazy or
        # captured co-signer supply quorum for free.
        pct = (100 * verified // total) if total else 0
        if pct < limits["snapshot_quorum_min_coverage_pct"]:
            rejected.append("coverage %d%% below the floor" % pct)
            continue
        accepted.append({"operator": operator, "coverage_pct": pct,
                         "verified_routes": verified})
        operators.add(operator)

    enough_signatures = len(accepted) >= limits["snapshot_quorum_signatures"]
    enough_operators = len(operators) >= limits["snapshot_quorum_operators"]
    return {
        "signatures": len(accepted),
        "operators": len(operators),
        "rejected": rejected,
        "total_routes": total_routes,
        "thresholds": limits,
        # True only when BOTH gates clear. Anything reading this must branch on
        # it rather than on the signature count: signatures are cheap, distinct
        # operators are not, and only the pair is evidence.
        "quorum": bool(enough_signatures and enough_operators),
        "why": _why(accepted, operators, limits, enough_signatures, enough_operators),
        "attestations": accepted,
    }


def _why(accepted, operators, limits, enough_signatures, enough_operators):
    if enough_signatures and enough_operators:
        return ("%d attestation(s) across %d operator(s); each independently "
                "confirmed the routes it could reproduce"
                % (len(accepted), len(operators)))
    if not enough_signatures:
        return ("%d valid attestation(s); %d required"
                % (len(accepted), limits["snapshot_quorum_signatures"]))
    return ("%d attestation(s) but only %d distinct operator(s); %d required. "
            "Signatures from one operator are one party's claim repeated, "
            "however many keys it holds."
            % (len(accepted), len(operators), limits["snapshot_quorum_operators"]))


def record_attestation(sequence, attestation):
    """Store a co-publisher's signature against a snapshot."""
    from model.SiteSetting import get_setting, set_setting
    from shared import db

    key = "snapshot_attestations_%d" % int(sequence)
    try:
        existing = json.loads(get_setting(key, "") or "[]")
    except ValueError:
        existing = []
    # One attestation per key. A publisher signing repeatedly must not be able
    # to look like several — the same reason audit receipts deduplicate.
    existing = [entry for entry in existing
                if entry.get("public_key") != attestation.get("public_key")]
    existing.append(attestation)
    set_setting(key, json.dumps(existing))
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("snapshot quorum: could not persist an attestation")
        return []
    return existing


def attestations_for(sequence):
    from model.SiteSetting import get_setting

    try:
        return json.loads(get_setting("snapshot_attestations_%d" % int(sequence), "") or "[]")
    except ValueError:
        return []
