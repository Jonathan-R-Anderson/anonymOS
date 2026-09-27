"""Publishing where a joining node can find the network.

A node that is not yet in the DHT has to learn about it from somewhere, and that
somewhere used to be one hardcoded hostname. One name is one thing that can be
offline, seized, or blocked. These SRV records let a node discover several
gateways instead and try the next when one does not answer.

WHY SRV AND NOT A RECORDS ON A SHARED NAME
SRV returns HOSTNAMES. A gateway holds a certificate for gw-<id>.<domain>, so a
node connecting to a bare address could not complete TLS — and the only ways
around that are skipping verification, which hands the bootstrap document to
anyone on the path, or maintaining a certificate for a shared name that every
gateway would need the key to. Neither is acceptable for the document that tells
a node which coordinator key to trust.

WHY THIS IS A SEPARATE MAINTAINER
DNSSynchronizer filters everything it sees to A and AAAA records, so SRV records
are invisible to it and can never be caught by its deletion planner. Keeping
this apart means a bug here cannot remove a single gateway address record, which
is the failure that would take the site off the internet. The two never touch
the same rows.

DRY RUN BY DEFAULT
This writes to a live zone. Every call reports the plan and changes nothing
unless explicitly told to apply, because the first run of DNS code is exactly
where you want to read what it intends before it does it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# The service name a node resolves. Underscore-prefixed labels are what SRV
# requires and are what keeps this from colliding with any real hostname.
SERVICE_LABEL = "_syndichan-bootstrap._tcp"

DEFAULTS = {
    # Every healthy gateway is equal: a joining node should spread its trust
    # rather than always ask the same one first, and equal weight is what makes
    # a resolver shuffle them.
    "srv_priority": 10,
    "srv_weight": 10,
    "srv_port": 443,
    # Short. These point at volunteer machines whose health changes, and a long
    # TTL means a node keeps trying one that left an hour ago.
    "srv_ttl": 300,
    # Enough that one being offline is unremarkable, few enough that a joining
    # node is not fanning out across the whole network on every refresh.
    "srv_maximum": 5,
}


@dataclass(frozen=True)
class Desired:
    target: str
    priority: int
    weight: int
    port: int


def desired_records(hostnames, limits: dict | None = None) -> list[Desired]:
    """The SRV set that should exist, given the healthy gateways.

    Sorted, so the same input always produces the same plan and a reconcile does
    not churn records for no reason.
    """
    limits = {**DEFAULTS, **(limits or {})}
    # `if name` BEFORE str(): str(None) is "none", which is truthy and would be
    # published as an SRV record pointing at a host called "none". A joining
    # node would then resolve it, fail, and be one source down for no reason.
    unique = sorted({str(name).strip().rstrip(".").lower()
                     for name in hostnames or [] if name and str(name).strip()})
    return [
        Desired(target=name, priority=int(limits["srv_priority"]),
                weight=int(limits["srv_weight"]), port=int(limits["srv_port"]))
        for name in unique[: int(limits["srv_maximum"])]
    ]


def target_of(answer: str) -> str:
    """The hostname inside a Name.com SRV answer.

    Name.com packs an SRV as "{weight} {port} {target}" in one string rather
    than as separate fields. Comparing that whole string against a bare hostname
    never matches, so every reconcile would delete each record and recreate it —
    churning the zone forever and leaving a window on each pass where a joining
    node finds fewer sources than exist.
    """
    parts = str(answer or "").strip().split()
    if not parts:
        return ""
    return parts[-1].rstrip(".").lower()


def plan(existing, desired: list[Desired]) -> dict:
    """What to create and what to remove. Pure, so it can be read before it runs.

    `existing` is Name.com's raw SRV dicts.
    """
    have = {}
    for record in existing or []:
        target = target_of(record.get("answer"))
        if target:
            have[target] = record

    want = {item.target: item for item in desired}
    create = [item for target, item in want.items() if target not in have]
    remove = [record for target, record in have.items() if target not in want]

    warnings = []
    if not desired:
        # Removing every record would leave a name that resolves to nothing, and
        # a node with no other source configured could not join at all. Better a
        # stale target it fails over from than no answer to fail over within.
        warnings.append(
            "No healthy gateway qualifies, so no SRV records would remain. "
            "Refusing to empty the record set — a name that answers with "
            "nothing is worse for a joining node than a stale target it can "
            "skip.")
        remove = []
    return {"create": create, "remove": remove, "unchanged": len(have) - len(remove),
            "warnings": warnings}


async def reconcile(namecom, hostnames, limits: dict | None = None,
                    apply: bool = False) -> dict:
    """Bring the SRV set in line with the healthy gateways.

    Returns the plan either way. `apply` defaults to False because this writes
    to a live zone and the first run should be read, not trusted.
    """
    limits = {**DEFAULTS, **(limits or {})}
    desired = desired_records(hostnames, limits)
    try:
        existing = await namecom.list_srv_records(SERVICE_LABEL)
    except Exception:
        logger.exception("could not list SRV records; nothing changed")
        return {"create": [], "remove": [], "unchanged": 0, "applied": False,
                "warnings": ["Listing failed, so no plan could be made."]}

    steps = plan(existing, desired)
    steps["applied"] = False
    for warning in steps["warnings"]:
        logger.warning("bootstrap SRV: %s", warning)

    if not apply:
        logger.info("bootstrap SRV (dry run): would create %d, remove %d, "
                    "leave %d unchanged", len(steps["create"]),
                    len(steps["remove"]), steps["unchanged"])
        return steps

    # Create BEFORE removing. The other order leaves a window where the record
    # set is short or empty, and a node bootstrapping in that window sees fewer
    # sources than exist — or none.
    for item in steps["create"]:
        try:
            await namecom.create_srv_record(
                SERVICE_LABEL, item.target, int(limits["srv_ttl"]),
                priority=item.priority, weight=item.weight, port=item.port)
            logger.info("bootstrap SRV: published %s", item.target)
        except Exception:
            logger.exception("bootstrap SRV: could not publish %s", item.target)
    for record in steps["remove"]:
        try:
            await namecom.delete_record(int(record["id"]))
            logger.info("bootstrap SRV: removed %s", record.get("answer"))
        except Exception:
            logger.exception("bootstrap SRV: could not remove %s",
                             record.get("answer"))
    steps["applied"] = True
    return steps
