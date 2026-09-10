"""What WOULD move, if the storage pools were levelled. Read-only.

Phase 2b step 2 (roadmap/dht-storage-roadmap.md). Nothing here moves a byte;
it answers "which nodes are fat, which are thin, and how much should travel"
from the usage every node now reports. The mover comes later and must be
verifiable against this before it is trusted.

WHY A REPORT BEFORE A MOVER
---------------------------
A levelling loop that is wrong moves real bytes off real disks. This project has
just spent a week discovering that a subsystem which *looked* like it was working
had never worked at all -- a backfill counter that fell on schedule while every
node stayed empty. So the plan is computed, displayed and checked against the
fleet by a human first, and the mover executes the same computation afterwards.

EQUAL BYTES, NOT EQUAL PERCENTAGE
---------------------------------
The target is the same absolute byte count on every node, not the same fraction
of each node's capacity. Durability here is counted in DISTINCT HOLDERS, so a
20 GB volunteer buys a holder-slot exactly as cheaply as a 200 GB one; levelling
by percentage would send ten times as much to the big node and concentrate the
network on the machines whose loss hurts most. Filling small pools first is the
durability-maximising choice, not merely the fair-seeming one.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It does not name individual shards. Choosing WHICH shard moves needs the node's
placement ledger -- which peer already holds a sibling of that chunk, whether the
chunk is above the durability threshold right now -- and that lives on the node,
not here. Naming shards from the site would mean re-deriving the planner's
distinctness rule in a second place, which is a second chance to get it wrong.
This report is therefore node-level: it says how much should leave a node and
where it should go, and the mover on the node picks shards under the invariants
it already enforces.
"""

import time

# A node that has not checked in for this long is not part of the levelling set.
# Stale rows are the norm rather than the exception -- production carries 21 node
# rows for 9 running machines -- and including them computes the mean over
# machines that no longer exist, which makes every live node look fat and invents
# work for all of them.
ACTIVE_WITHIN_SECONDS = 15 * 60

# Do nothing while a node is within this fraction of the target. Without a
# deadband two nodes a megabyte apart trade shards forever, and every trade costs
# a lease, two I2P round trips and a deletion.
DEADBAND = 0.10

# Below this there is nothing worth moving whatever the percentages say.
MIN_MOVE_BYTES = 64 << 20


class Node(object):
    """One candidate, reduced to what levelling needs."""

    __slots__ = ("node_id", "used", "capacity", "last_seen", "draining")

    def __init__(self, node_id, used, capacity, last_seen, draining=False):
        self.node_id = node_id
        self.used = used
        self.capacity = capacity
        self.last_seen = last_seen
        self.draining = draining

    @property
    def headroom(self):
        return max(0, (self.capacity or 0) - (self.used or 0))


def eligible(nodes, now=None):
    """The levelling set: nodes that are alive AND have reported their usage.

    A node with used_bytes None is excluded rather than treated as empty. That
    distinction is the whole reason the column is nullable: reading "has not
    reported" as "holds nothing" would aim every surplus byte at a node that
    merely runs an older build.
    """
    now = int(time.time()) if now is None else now
    out = []
    for node in nodes:
        if node.used is None:
            continue
        if node.draining:
            # A machine being retired is not part of the fleet this target
            # describes. Its bytes are on their way back to everyone else, so
            # counting them sets a mean the remaining machines cannot hold once
            # they arrive; and it must never be proposed as a SINK, because the
            # nodes have already stopped writing to it and a report that
            # disagrees with the fleet is worse than no report. The drain empties
            # it; levelling must not also be trying to.
            continue
        if node.capacity is None or node.capacity <= 0:
            # A gateway or probe donates no disk. Not fat, not thin, not in the
            # set at all.
            continue
        if node.last_seen is None or now - node.last_seen > ACTIVE_WITHIN_SECONDS:
            continue
        out.append(node)
    return out


def target_bytes(nodes):
    """The byte count every node should converge on.

    The mean, except that a node cannot exceed its own capacity: any node whose
    capacity sits below the mean is pinned to its capacity and the remainder is
    shared among the rest. Without that, a 10 GB node would be permanently
    "behind" a 4 TB one and the plan would never converge.
    """
    if not nodes:
        return 0
    remaining = sum(n.used for n in nodes)
    open_set = list(nodes)
    pinned = 0
    while open_set:
        share = (remaining - pinned) / float(len(open_set))
        capped = [n for n in open_set if n.capacity < share]
        if not capped:
            return int(share)
        for n in capped:
            pinned += n.capacity
            open_set.remove(n)
    return 0


def plan(nodes, now=None):
    """A read-only levelling plan. Moves nothing.

    Returns a dict with the target, per-node deltas, and the moves that would
    close them -- largest surplus to largest deficit, which minimises the number
    of transfers rather than the bytes moved (each transfer costs a lease and two
    I2P round trips, so transfer count is the expensive axis).
    """
    active = eligible(nodes, now=now)
    target = target_bytes(active)

    rows = []
    sources, sinks = [], []
    for node in active:
        effective = min(target, node.capacity)
        delta = node.used - effective
        band = max(int(effective * DEADBAND), MIN_MOVE_BYTES)
        role = "balanced"
        if delta > band:
            role = "source"
            sources.append([node, delta])
        elif -delta > band:
            role = "sink"
            sinks.append([node, -delta])
        rows.append({
            "node_id": node.node_id,
            "used": node.used,
            "capacity": node.capacity,
            "target": effective,
            "delta": delta,
            "role": role,
        })

    sources.sort(key=lambda pair: -pair[1])
    sinks.sort(key=lambda pair: -pair[1])

    moves = []
    i = j = 0
    while i < len(sources) and j < len(sinks):
        source, surplus = sources[i]
        sink, deficit = sinks[j]
        amount = min(surplus, deficit, sink.headroom)
        if amount < MIN_MOVE_BYTES:
            # This sink cannot usefully take anything; try the next.
            j += 1
            continue
        moves.append({
            "from": source.node_id,
            "to": sink.node_id,
            "bytes": int(amount),
            # Stated per move so the report explains itself rather than needing
            # this module read alongside it.
            "why": "%s holds %d bytes over target; %s is %d under and has room"
                   % (source.node_id, surplus, sink.node_id, deficit),
        })
        sources[i][1] -= amount
        sinks[j][1] -= amount
        if sources[i][1] < MIN_MOVE_BYTES:
            i += 1
        if sinks[j][1] < MIN_MOVE_BYTES:
            j += 1

    return {
        "target": target,
        "nodes": sorted(rows, key=lambda r: -r["delta"]),
        "moves": moves,
        "excluded": len(list(nodes)) - len(active),
        # Named rather than merely dropped. A retiring machine leaving the
        # levelling set looks exactly like a node that went stale, and the two
        # need opposite reactions from whoever is reading: one is being emptied on
        # purpose and one has stopped checking in.
        "draining": sorted(n.node_id for n in nodes if n.draining),
        # Said out loud because a plan with no moves and a plan that could not be
        # computed look identical in a table, and this subsystem has already been
        # bitten once by a number that meant "not measured" being read as zero.
        "note": "read-only; shard selection happens on the node under its own "
                "distinctness and durability invariants",
    }


def from_storage_nodes(rows, now=None):
    """Build a plan from model.StorageNode rows."""
    return plan([
        Node(
            row.node_id,
            row.used_bytes,
            row.capacity_bytes,
            int(row.last_seen_at.timestamp()) if row.last_seen_at else None,
            bool(getattr(row, "draining", False)),
        )
        for row in rows
    ], now=now)
