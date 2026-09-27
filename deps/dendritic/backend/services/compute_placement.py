"""Choosing which node runs a submitted job.

THE RULE THIS MODULE EXISTS TO ENFORCE
--------------------------------------
Arbitrary submitted code may run ONLY on a node reporting microVM isolation.

The GPGPU roadmap forbids arbitrary payloads on volunteer hardware because a
container is not a boundary to bet somebody's desktop on. A microVM is — hardware
virtualisation means a guest cannot read host memory even having compromised its
own kernel — and that is the single place the rule may be relaxed.

So placement is not "find any node with capacity". It is "find a node whose
isolation is strong enough for what was submitted", and a job that cannot find
one stays queued rather than being placed somewhere weaker. Silently downgrading
would look identical to working until somebody submitted something hostile.

WHY SELECTION IS SEEDED AND NOT random.choice
---------------------------------------------
Payment follows placement, so placement gets disputed. A draw nobody can
reproduce cannot be audited: "the network picked you" has to be checkable by the
node that was not picked. Seeded from the job id and the sorted candidate set,
exactly as compute_market does for the same reason.
"""

import hashlib

# Isolation levels, weakest first. Ordered so "at least this strong" is a
# comparison rather than a table of special cases.
ISOLATION_NONE = 0
ISOLATION_CONTAINER = 1
ISOLATION_MICROVM = 2

ISOLATION_NAMES = {
    ISOLATION_CONTAINER: "container",
    ISOLATION_MICROVM: "microvm",
}


class NoEligibleNode(RuntimeError):
    """No node can run this job. The caller must leave it queued, not downgrade."""

    def __init__(self, reason, retryable=True):
        super().__init__(reason)
        self.reason = reason
        self.retryable = retryable


def isolation_of(node):
    """The strongest boundary a node reports.

    Reads the same heartbeat flag the map colours use, so what an operator sees
    and what the scheduler believes cannot disagree.
    """
    if node.get("microvm"):
        return ISOLATION_MICROVM
    if node.get("cpu") or node.get("gpu"):
        return ISOLATION_CONTAINER
    return ISOLATION_NONE


def required_isolation(arbitrary):
    """What a job needs. One line, because it is one rule."""
    return ISOLATION_MICROVM if arbitrary else ISOLATION_CONTAINER


def eligible_nodes(device, arbitrary):
    """Nodes that can run this job, isolation included.

    Reads the same listing the bootstrap document publishes, so what the network
    ADVERTISES and what this site dispatches to cannot disagree. A separate
    query would drift the first time one of them gained a filter the other
    lacked, and the symptom would be work sent to nodes that publicly say they
    do not take it.

    Filtering on isolation HERE rather than at dispatch means an ineligible node
    is never offered the work, so it cannot accept it by mistake.
    """
    from services.storage_coordination import live_compute_peers

    want = required_isolation(arbitrary)
    peers = live_compute_peers(
        device=device, microvm_only=(want >= ISOLATION_MICROVM))
    out = []
    for peer in peers:
        node = {
            "id": peer.get("node_id"),
            "cpu": peer.get("cpu"),
            "gpu": peer.get("gpu"),
            "microvm": peer.get("microvm"),
            "i2p_destination": peer.get("destination"),
        }
        # Re-checked rather than trusted from the filter above: the listing is a
        # convenience, and the rule that decides whether arbitrary code runs
        # somewhere should not depend on a caller having passed the right flag.
        if isolation_of(node) < want:
            continue
        out.append(node)
    return out


def place(job_id, device, arbitrary, candidates=None):
    """Pick the node that runs this job, or explain why none can.

    Deterministic given the same job and candidate set, so a disputed placement
    can be re-derived by whoever questions it.
    """
    pool = candidates if candidates is not None else eligible_nodes(device, arbitrary)
    if not pool:
        if arbitrary:
            raise NoEligibleNode(
                "No node with hardware isolation (microVM) is available. Arbitrary "
                "programs only run inside a virtual machine — a container is not a "
                "strong enough boundary for code somebody else wrote. The job stays "
                "queued until such a node appears.")
        raise NoEligibleNode(
            "No node is offering %s work right now. The job stays queued; "
            "nothing is charged until it runs." % device)

    ids = sorted(str(n.get("id") or "") for n in pool if n.get("id"))
    if not ids:
        raise NoEligibleNode("candidate nodes carry no identity", retryable=False)
    seed = hashlib.sha256(("%s|%s" % (job_id, "|".join(ids))).encode("utf-8")).digest()
    chosen = ids[int.from_bytes(seed[:8], "big") % len(ids)]
    for node in pool:
        if str(node.get("id") or "") == chosen:
            return node, ISOLATION_NAMES[isolation_of(node)]
    raise NoEligibleNode("selection did not resolve to a node", retryable=False)


def capability_summary(device):
    """What the network can currently run, for the submit page.

    Reported as two numbers because they answer different questions: a submitter
    choosing "arbitrary code" needs to know the microVM count, and one running a
    catalogue image needs the total. Collapsing them hides the choice.
    """
    from services.storage_coordination import live_compute_peers

    total = micro = 0
    for peer in live_compute_peers(device=device):
        total += 1
        if peer.get("microvm"):
            micro += 1
    return {
        "device": device,
        "nodes": total,
        "microvm_nodes": micro,
        "arbitrary_possible": micro > 0,
        "note": ("" if micro else
                 "No node currently offers hardware isolation, so arbitrary "
                 "programs cannot run. Catalogue images are unaffected."),
    }
