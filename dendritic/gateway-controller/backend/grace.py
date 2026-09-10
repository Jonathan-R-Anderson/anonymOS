"""Letting a reliable gateway drop out briefly without losing its name.

Phase 5 of roadmap/domain-and-origin-succession.md.

Today a gateway that misses a few health checks has its DNS record deleted. When
it comes back it needs a new record, and — because its certificate was issued for
a name that stopped resolving — potentially a new certificate too. A thirty
second network blip therefore costs a volunteer an hour, which is a bad deal for
somebody donating bandwidth.

WHY GRACE HAS TO BE CAPPED BY SHARE, NOT ONLY BY TIME
-----------------------------------------------------
A graced record points DNS at a machine that is not answering. One of those
among nine healthy ones costs a few readers one retry. Nine of them among one
healthy one is a site that appears broken to almost everybody, and browsers move
between A records slowly enough that people leave first.

So there are two independent bounds and both matter: how LONG a record may
survive being unhealthy, and what SHARE of the published answers may be graced
at once. A time bound alone is not enough, because a correlated outage — one
datacentre, one country, one bad release — takes out many gateways at the same
moment, and that is exactly when the time bound is least protective.

WHAT "RELIABLE" MEANS HERE
--------------------------
The controller's own observations, not the backend's reputation score. It
already knows who has been registered a long time and failed rarely, and that is
precisely the question being asked — "has this one earned the benefit of the
doubt from ME". Reaching across to another service for a number would add a
dependency to the one component whose job is to keep DNS correct when things are
going wrong.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DEFAULTS = {
    # How long a record may outlive its gateway's health.
    "grace_seconds": 1800,
    # What share of published answers may be graced at once, 0..1.
    "grace_max_share": 0.34,
    # Below this standing, no grace at all.
    "grace_minimum_standing": 0.6,
    # A gateway must have been around long enough to have a record worth
    # trusting. Without this, one registered five minutes ago and immediately
    # unhealthy would qualify on a spotless failure count.
    "grace_minimum_age_seconds": 86400,
}


@dataclass(frozen=True)
class Candidate:
    """One gateway being considered for grace."""

    hostname: str
    healthy: bool
    standing: float
    unhealthy_seconds: float
    age_seconds: float


def standing(failure_count: int, age_seconds: float,
             minimum_age_seconds: float) -> float:
    """How much benefit of the doubt this gateway has earned, 0..1.

    Deliberately simple and local. Failures dominate, and age is a gate rather
    than a multiplier — a gateway that has been up for a year and fails
    constantly has not earned anything, and treating longevity as credit would
    say otherwise.
    """
    if age_seconds < max(0.0, minimum_age_seconds):
        return 0.0
    failures = max(0, int(failure_count or 0))
    # 0 failures -> 1.0, 1 -> 0.5, 3 -> 0.25, 7 -> 0.125. A gateway that has
    # failed a handful of times is not disqualified, it is just behind one that
    # has not.
    return 1.0 / (1.0 + failures)


def decide(candidates: list[Candidate], limits: dict | None = None) -> dict:
    """Which unhealthy gateways keep their DNS record.

    Returns {"keep": [hostname], "drop": [{hostname, why}], "warnings": [...]}.
    Never raises: this runs inside the DNS reconcile, and an exception here
    would stop records being maintained for everyone.
    """
    limits = {**DEFAULTS, **(limits or {})}
    window = float(limits["grace_seconds"])
    max_share = float(limits["grace_max_share"])
    floor = float(limits["grace_minimum_standing"])
    minimum_age = float(limits["grace_minimum_age_seconds"])

    healthy = [item for item in candidates if item.healthy]
    unhealthy = [item for item in candidates if not item.healthy]

    eligible, drop = [], []
    for item in unhealthy:
        if item.age_seconds < minimum_age:
            drop.append({"hostname": item.hostname,
                         "why": "registered %.0fh ago; grace needs %.0fh"
                                % (item.age_seconds / 3600, minimum_age / 3600)})
            continue
        if item.standing < floor:
            drop.append({"hostname": item.hostname,
                         "why": "standing %.2f below %.2f" % (item.standing, floor)})
            continue
        if item.unhealthy_seconds > window:
            # The bound that stops a graced record becoming a permanent one
            # pointing at a machine that is never coming back.
            drop.append({"hostname": item.hostname,
                         "why": "down %.0fm; grace lasts %.0fm"
                                % (item.unhealthy_seconds / 60, window / 60)})
            continue
        eligible.append(item)

    # Best standing first, then longest-established, then a stable name tiebreak
    # so the same input never produces a different answer between runs.
    eligible.sort(key=lambda item: (-item.standing, -item.age_seconds, item.hostname))

    total_if_all_kept = len(healthy) + len(eligible)
    allowed = _share_allowance(len(healthy), len(eligible), max_share)

    keep = [item.hostname for item in eligible[:allowed]]
    warnings = []
    for item in eligible[allowed:]:
        drop.append({
            "hostname": item.hostname,
            "why": "share cap reached — at most %.0f%% of published answers may "
                   "be graced, and %d healthy gateway(s) cannot carry more"
                   % (max_share * 100, len(healthy)),
        })

    if not healthy and unhealthy:
        # Every gateway is down. Keeping records here would publish only
        # addresses that do not answer, and browsers move between A records
        # slowly enough that readers give up first. Nothing is gained either:
        # there is no healthy gateway to fail over TO.
        #
        # Checked against `unhealthy` rather than `keep`, because the share cap
        # usually zeroes `keep` before this point — and then the one situation
        # an operator most needs to be told about would pass in silence.
        if keep:
            for hostname in keep:
                drop.append({"hostname": hostname,
                             "why": "no healthy gateway remains to fail over to"})
            keep = []
        warnings.append(
            "No gateway is healthy. %d record(s) are being withdrawn rather "
            "than graced: keeping them would publish only unreachable "
            "addresses." % len(unhealthy))

    if len(keep) < len(eligible):
        warnings.append(
            "%d of %d eligible gateway(s) kept their record; the rest exceeded "
            "the %.0f%% share cap or the %.0f-minute window."
            % (len(keep), len(eligible), max_share * 100, window / 60))

    return {"keep": keep, "drop": drop, "warnings": warnings,
            "healthy": len(healthy), "graced": len(keep),
            "would_publish": len(healthy) + len(keep),
            "total_if_uncapped": total_if_all_kept}


def _share_allowance(healthy_count: int, eligible_count: int,
                     max_share: float) -> int:
    """How many graced records fit under the share cap.

    Solved against the FINAL published set rather than the healthy set, because
    each graced record enlarges the very total it is being measured against —
    computing it the other way lets the real share drift above the cap exactly
    when there are fewest healthy gateways to absorb it.
    """
    if eligible_count <= 0:
        return 0
    if max_share <= 0:
        return 0
    if max_share >= 1:
        return eligible_count
    # keep <= max_share * (healthy + keep)  =>  keep <= healthy * s / (1 - s)
    allowance = int(healthy_count * max_share / (1.0 - max_share))
    return max(0, min(eligible_count, allowance))


def certificate_note(kept: list[str]) -> str | None:
    """What grace does and does not do for a gateway's certificate.

    Worth saying plainly, because the obvious assumption is wrong: keeping the
    DNS record does NOT renew anything. Gateways obtain certificates themselves
    over HTTP-01, which requires them to be reachable — so a gateway that is
    down cannot renew no matter what DNS says.

    What grace buys is that the NAME still resolves, so the moment it returns it
    can renew against the record it already had instead of negotiating a new
    hostname first. Renewing on behalf of a gateway that is offline needs DNS-01
    performed centrally, which would put certificate keys for gateway
    subdomains in this service — a real concentration of trust in a design that
    otherwise keeps gateways unprivileged. Not done here by default.
    """
    if not kept:
        return None
    return (
        "%d record(s) are being held through an outage. This keeps the name "
        "resolving; it does not renew any certificate. A gateway that is down "
        "cannot complete an HTTP-01 challenge, so it renews when it returns."
        % len(kept))
