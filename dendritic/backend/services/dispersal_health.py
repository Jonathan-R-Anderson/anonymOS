"""Whether dispersal is WORKING, per node and across the fleet. Read-only.

Phase 4.3 (roadmap/dht-storage-roadmap.md). The admin panel could show what the
DHT *holds* and nothing about whether shards were reaching anybody, so every
fault this network has had was found by SSHing to a node and grepping its
journal. Five of them survived for days behind that blindness, and every one was
a number the node already had:

  * ``replicateOnce`` marked objects replicated unconditionally, so a backlog
    counter fell on schedule while every peer stayed empty — ``placed``/``failed``
    says so directly.
  * three peers refused every round (cache-only, capacity exceeded, invalid lease
    signature) and quietly held every object one holder short of durable —
    ``refusals`` carries the peer AND its answer.
  * lease requests died before leaving the box: ``placed 0, failed 9``.
  * an I2P router core-dumped and nothing restarted it — ``peers`` goes to zero.

NOTHING HERE TALKS TO A NODE
----------------------------
Every figure arrives on the five-minute signed heartbeat and is read out of a
database row. The admin panel polls every three seconds; asking nine nodes over
I2P inside that request handler would put slow network I/O back on a request
path, which this site has already taken a 504 from (an inline news sync in
``GET /``). Per-object detail lives on the gateway's SigV4 ``?placement`` surface
and is reached deliberately, one object at a time, from the DHT purge page.

ABSENT IS NOT ZERO
------------------
The one rule everything here obeys. A node that has not reported gets
``reporting: False`` and ``None`` in every numeric field — never 0, never
"healthy". A fleet with nobody reporting gets ``None`` totals, not zeros. This
project has repeatedly drawn an unknown as a number and it has cost it weeks.
"""

import json
import time


# A row older than this is not part of the picture. Matches the heartbeat's own
# active window: production carries roughly twice as many node rows as running
# machines, and counting the dead ones invents a fleet that does not exist.
ACTIVE_WITHIN_SECONDS = 15 * 60

# A dispersal report older than this is stale, whatever the row's last_seen_at
# says. Three heartbeats: a node that has missed that many has either stopped
# running its replicate loop or been downgraded to a build that cannot report,
# and in both cases its last figures are history rather than status.
REPORT_FRESH_SECONDS = 15 * 60

# Counters copied straight through from the validated block.
_COUNTERS = (
    "objects", "under_replicated", "local_only", "fully_dispersed",
    "placed", "failed", "unassignable", "attempted", "peers", "age_seconds",
    "recalls_outstanding", "recalls_deferred", "recalls_unreadable",
)

# What the fleet headline sums. Deliberately not everything: summing
# ``fully_dispersed`` across nodes would double-count objects several nodes hold,
# and an operator reading a total larger than the corpus stops trusting the page.
_FLEET_SUMS = ("under_replicated", "local_only", "failed", "unassignable")

NOT_REPORTING = "no dispersal report"
STALE = "dispersal report is stale"


class Node(object):
    """One candidate row, reduced to what this needs."""

    __slots__ = ("node_id", "last_seen", "reported_at", "health")

    def __init__(self, node_id, last_seen, reported_at=None, health=None):
        self.node_id = node_id
        self.last_seen = last_seen
        self.reported_at = reported_at
        self.health = health


def _blank(node_id, why):
    """A node with nothing to say. Every figure None, and a reason why.

    NOT zeros. A row of zeros renders as a node with no failures and nothing
    under-replicated, which is the single most misleading thing this page could
    put on a screen — it is indistinguishable from a healthy node and it is what
    a node that has never dispersed anything would look like.
    """
    row = {"node_id": node_id, "reporting": False, "why_not": why, "refusals": []}
    row.update({key: None for key in _COUNTERS})
    return row


def _row(node, now):
    """One node's rendered health, or a blank with the reason it is blank."""
    if node.health is None:
        return _blank(node.node_id, NOT_REPORTING)
    if node.reported_at is None or now - node.reported_at > REPORT_FRESH_SECONDS:
        # The node is still heartbeating -- otherwise it would not be in this
        # set at all -- but it has stopped saying anything about dispersal.
        # Its last figures are not current and must not be shown as if they were.
        return _blank(node.node_id, STALE)
    health = node.health
    if not isinstance(health, dict):
        return _blank(node.node_id, NOT_REPORTING)
    row = {"node_id": node.node_id, "reporting": True, "why_not": None}
    for key in _COUNTERS:
        value = health.get(key)
        row[key] = value if isinstance(value, int) and not isinstance(value, bool) else None
    refusals = health.get("refusals")
    row["refusals"] = [
        {
            "peer": str(entry.get("peer") or ""),
            "count": entry.get("count"),
            "reason": str(entry.get("reason") or "refused, reason not reported"),
        }
        for entry in (refusals if isinstance(refusals, list) else [])
        if isinstance(entry, dict)
    ]
    return row


def _worst_first(row):
    """Sort key: the nodes an operator has to look at, first.

    Not reporting sorts above everything, because a node nobody can see is a
    worse state than a node with a visible problem — it is the state all five of
    this quarter's faults were in.
    """
    return (
        0 if not row["reporting"] else 1,
        -(row.get("failed") or 0),
        -(row.get("under_replicated") or 0),
        row["node_id"],
    )


def summarise(nodes, now=None):
    """The whole fleet's dispersal health, from already-fetched rows."""
    now = int(now if now is not None else time.time())
    live = [
        n for n in nodes
        if n.last_seen is not None and now - n.last_seen <= ACTIVE_WITHIN_SECONDS
    ]
    rows = sorted((_row(n, now) for n in live), key=_worst_first)
    reporting = [r for r in rows if r["reporting"]]

    def total(key):
        # None when NOBODY reports. A zero here would say "the fleet has nothing
        # under-replicated" on the strength of no evidence at all.
        if not reporting:
            return None
        return sum(r[key] or 0 for r in reporting)

    summary = {
        "nodes": rows,
        "reporting": len(reporting),
        # Counted and named, never folded into the totals above. This is the
        # number that says how much of the page to believe.
        "silent": len(rows) - len(reporting),
        # Nodes that report a completed pass with NO connected peers. An I2P
        # router that has died looks exactly like this from here, and it is
        # otherwise indistinguishable from a quiet node.
        "isolated": None if not reporting else sum(
            1 for r in reporting if r.get("peers") == 0
        ),
        "refusals": _fleet_refusals(reporting),
        "note": (
            "reported by each node on its five-minute heartbeat; "
            "per-object detail lives on the gateway's ?placement surface"
        ),
    }
    for key in _FLEET_SUMS:
        summary[key] = total(key)
    summary["recalls_outstanding"] = total("recalls_outstanding")
    summary["recalls_unreadable"] = total("recalls_unreadable")
    return summary


def _fleet_refusals(reporting):
    """Refusals rolled up BY REASON across the fleet.

    The one view that turns a week of SSH into a glance: three peers refusing is
    ambiguous, "3 peers: storage capacity exceeded" is a disk to free and
    "3 peers: invalid coordinator lease signature" is a key to check.
    """
    by_reason = {}
    for row in reporting:
        for entry in row["refusals"]:
            reason = entry["reason"]
            bucket = by_reason.setdefault(
                reason, {"reason": reason, "count": 0, "peers": set(), "nodes": 0}
            )
            count = entry["count"]
            bucket["count"] += count if isinstance(count, int) else 0
            if entry["peer"]:
                bucket["peers"].add(entry["peer"])
            bucket["nodes"] += 1
    out = [
        {
            "reason": bucket["reason"],
            "count": bucket["count"],
            "peers": len(bucket["peers"]),
            "nodes": bucket["nodes"],
        }
        for bucket in by_reason.values()
    ]
    out.sort(key=lambda b: (-b["count"], b["reason"]))
    return out


def from_storage_nodes(rows, now=None):
    """Build the summary from model.StorageNode rows."""
    return summarise([
        Node(
            # Truncated exactly as the map's dots are, so an operator can match a
            # row here against a dot there without a full key in the DOM.
            row.node_id[:12],
            int(row.last_seen_at.timestamp()) if row.last_seen_at else None,
            (
                int(row.placement_reported_at.timestamp())
                if getattr(row, "placement_reported_at", None) else None
            ),
            _parse(getattr(row, "placement_health", None)),
        )
        for row in rows
    ], now=now)


def _parse(raw):
    """The stored block, or None if it will not read.

    A row that will not parse is UNKNOWN, not empty. Returning {} here would
    hand the renderer a reporting node with every counter missing, which reads
    as a healthy one.
    """
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None
