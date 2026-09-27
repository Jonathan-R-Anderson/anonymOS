"""Who runs a compute job, and what it costs.

Two decisions the network makes, not the operator:

  1. WHICH node runs it — drawn at random from everyone advertising that device,
     never a configured address.
  2. WHAT it costs — from what is being asked for against what the network
     currently has.

WHY SELECTION IS NOT A CONFIGURED NODE
--------------------------------------
Pointing the site at one compute node makes that node the network. It gets every
job, earns every reward, and the "distributed" part is a diagram. Worse, it is
the operator choosing who gets paid, which is exactly the thing a volunteer
network cannot let the operator decide.

So selection draws from the pool of nodes that ADVERTISED the device in their
heartbeat. The site still reaches the network through one bridge — volunteer
nodes are behind NAT and only reachable over I2P, so something has to dial out —
but the bridge is transport, not choice. Which node runs the work is decided
here, from the pool, and the bridge is told where to send it.

WHY THE DRAW IS SEEDED AND NOT random.choice()
-----------------------------------------------
Payment follows selection, so selection is a thing people will dispute. A draw
nobody can reproduce cannot be audited: "the network picked you" has to be
checkable by the person who was not picked. Seeding from the job id and the
sorted candidate set means anyone holding the same inputs derives the same
winner, and the operator cannot quietly prefer their own node.

This is the same reasoning the witness selection already uses, and it fails in
the same place: a verifiable draw from a pool of one selects that one, every
time, correctly and uselessly. See `advisory()`.

WHY PRICE MOVES WITH SCARCITY
-----------------------------
A flat price says the same thing whether the network has one idle machine or a
hundred. It cannot tell a submitter "this is a bad moment to ask for 32 cores",
and it cannot tell a provider "now is worth being online for". A price that
tracks demand against supply does both, and it is the only signal that makes
lending hardware worth scheduling around.
"""

import hashlib

# Base rates in credits per core-second. GPU is dearer because the hardware is
# scarcer and its owner gives up more to lend it — a GPU is usually the thing
# its owner wants back first.
BASE_RATE = {"cpu": 1, "gpu": 8}

# The scarcity multiplier is clamped at both ends.
#
# A floor below 1.0 would mean an idle network pays providers less than the base
# rate for being available, which is backwards — availability is the thing being
# bought. A ceiling stops a transient spike pricing everyone out and, more
# practically, stops a tiny network from quoting absurd numbers: with two nodes
# online, utilisation swings between 0 and 1 on a single job.
MIN_MULTIPLIER = 1.0
MAX_MULTIPLIER = 6.0


def eligible_providers(device):
    """Active nodes advertising this device, newest heartbeat first.

    Reads the same flags the map colours use, so what the operator sees on the
    map and what the scheduler will actually consider cannot disagree.
    """
    from model.StorageNode import active_storage_nodes

    field = "gpu" if str(device).startswith("gpu") else "cpu"
    return [n for n in active_storage_nodes() if n.get(field)]


def capacity(device):
    """How much of this device the network is offering, in cores.

    Falls back to one core per advertising node when a node does not report a
    core count. Under-counting is the safe direction: it prices scarcity higher
    than reality rather than promising capacity that is not there.
    """
    total = 0
    for node in eligible_providers(device):
        total += int(node.get("cores") or 1)
    return total


def demand(device):
    """Cores currently spoken for: queued plus running."""
    from model.ComputeRental import STATUS_QUEUED, STATUS_RUNNING, ComputeRental
    from shared import db

    rows = (db.session.query(ComputeRental)
            .filter(ComputeRental.device == device,
                    ComputeRental.status.in_((STATUS_QUEUED, STATUS_RUNNING)))
            .all())
    return sum(int(getattr(r, "cores", 0) or 1) for r in rows)


def scarcity_multiplier(device, requested_cores=1):
    """How much dearer this moment is than an empty network.

    Includes the CALLER'S OWN request in demand. Asking for half the network
    should cost more than asking for one core of it, and pricing against demand
    that excludes your own request lets a large job pay the small-job rate.
    """
    available = capacity(device)
    if available <= 0:
        # Nothing is offering this device. Priced at the ceiling rather than
        # raising: the caller decides whether to queue and wait, and a quote of
        # "impossible" is less useful than "expensive, and nothing is online".
        return MAX_MULTIPLIER
    utilisation = (demand(device) + max(1, int(requested_cores))) / float(available)
    # Linear in utilisation up to the cap. Deliberately not exponential: a curve
    # that explodes near capacity is unpredictable for a submitter, and on a
    # small network utilisation crosses 1.0 constantly without meaning much.
    multiplier = MIN_MULTIPLIER + utilisation
    return max(MIN_MULTIPLIER, min(MAX_MULTIPLIER, multiplier))


def quote(device, cores=1, seconds=60):
    """What a job would cost right now, and why.

    Returns the breakdown rather than one number, because a price that moves
    needs to explain itself — a submitter who sees a figure double with no
    reason assumes they are being cheated.
    """
    cores = max(1, int(cores or 1))
    seconds = max(1, int(seconds or 1))
    device_key = "gpu" if str(device).startswith("gpu") else "cpu"
    base = BASE_RATE.get(device_key, BASE_RATE["cpu"])
    multiplier = scarcity_multiplier(device, cores)
    available = capacity(device)
    credits = int(round(base * cores * seconds * multiplier / 60.0))
    return {
        "device": device,
        "cores": cores,
        "seconds": seconds,
        "base_rate": base,
        "multiplier": round(multiplier, 2),
        "credits": max(1, credits),
        "providers_online": len(eligible_providers(device)),
        "cores_available": available,
        "cores_in_use": demand(device),
        "advisory": advisory(device),
    }


def select_provider(device, job_id, candidates=None):
    """Draw the node that will run this job.

    Deterministic given the same job and the same candidate set, so the choice
    can be re-derived by anyone who disputes it. Sorted before hashing because
    the pool arrives in whatever order the database returned it, and an
    order-dependent draw is not reproducible.
    """
    pool = candidates if candidates is not None else eligible_providers(device)
    if not pool:
        return None
    ids = sorted(str(n.get("id") or "") for n in pool if n.get("id"))
    if not ids:
        return None
    seed = hashlib.sha256(("%s|%s" % (job_id, "|".join(ids))).encode("utf-8")).digest()
    index = int.from_bytes(seed[:8], "big") % len(ids)
    chosen = ids[index]
    for node in pool:
        if str(node.get("id") or "") == chosen:
            return node
    return None


def advisory(device):
    """Why a price or a draw may not mean what it appears to.

    Surfaced rather than buried: a verifiable random draw from a pool of one
    picks that one every time, and a scarcity multiplier computed from two
    machines is noise. Both are correct and neither is meaningful, and a
    submitter reading a confident number deserves to know which case they are
    in.
    """
    count = len(eligible_providers(device))
    if count == 0:
        return ("No node is offering %s work right now. Jobs stay queued until "
                "one appears — nothing is charged for a job that has not run." % device)
    if count == 1:
        return ("Only one node offers %s work, so it receives every job. "
                "Selection is not meaningfully random and the price signal is "
                "not meaningful either until more providers join." % device)
    if count < 4:
        return ("%d nodes offer %s work. Prices will move sharply with a small "
                "pool." % (count, device))
    return ""
