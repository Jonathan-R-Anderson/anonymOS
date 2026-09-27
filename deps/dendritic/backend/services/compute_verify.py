"""Running a job more than once and comparing the answers.

THE GAP THIS CLOSES
-------------------
Until now a node returned a result and the site believed it. That is not
verification, it is trust with extra steps — and on a network of strangers it
means the cheapest way to earn is to return plausible garbage instantly.

WHY HASH COMPARISON WORKS HERE AND NOT EVERYWHERE
-------------------------------------------------
CPU work in a catalogue image is bit-reproducible: the images pin their
interpreters, fix the locale and timezone, disable hash randomisation and run
single-threaded, so two honest nodes produce byte-identical output. That makes
verification a string comparison rather than a research problem.

GPU work is not. Different scheduling reorders reductions, so two honest cards
return different bytes and both are correct. Those results are marked
UNVERIFIED rather than compared — reporting a disagreement between two honest
GPUs as fraud would punish nodes for doing exactly what was asked.

WHAT VERIFICATION COSTS, AND WHY IT IS NOT ALWAYS ON
----------------------------------------------------
Every replica is another node's electricity. Verifying everything doubles the
network's cost to catch a liar who may not exist, so replication is sampled: a
fraction of jobs are verified, and the fraction is what makes lying unprofitable
rather than impossible. A node cannot tell which jobs are being checked, so the
only safe strategy is to compute honestly every time.
"""

import hashlib

# How many independent nodes must agree before a result is called verified.
#
# Two, not three. Two agreeing nodes make a lie require collusion; three would
# make verification cost 3x for a marginal gain over that. The number that
# actually matters is that they are INDEPENDENT, which is checked below.
QUORUM = 2

VERDICT_AGREED = "agreed"
VERDICT_DISAGREED = "disagreed"
VERDICT_UNVERIFIED = "unverified"
VERDICT_INSUFFICIENT = "insufficient"


class NotVerifiable(RuntimeError):
    """This job cannot be verified. Not a failure — a statement about the work."""


def output_digest(result):
    """The canonical hash of a result.

    stdout and exit code only. Stderr is deliberately excluded: it carries
    warnings, timings and paths that differ between honest runs, and including
    it would report two identical computations as a disagreement because one
    node's compiler was chattier.
    """
    stdout = (result or {}).get("stdout") or ""
    code = (result or {}).get("exit_code")
    payload = "%s\x00%s" % (stdout, "" if code is None else int(code))
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def is_verifiable(job):
    """Whether this job's output can be compared at all.

    GPU work is not: two honest cards disagree by construction. Arbitrary code
    may or may not be, and the image cannot make it so — a program that reads
    the clock is non-deterministic whatever it runs inside.
    """
    if str(job.device or "cpu").startswith("gpu"):
        return False
    return True


def independent(nodes):
    """Whether a set of results came from genuinely distinct nodes.

    The check that makes a quorum mean something. Two results from one node are
    one result counted twice, and a verification that accepted them would be
    theatre — it would pass exactly when a single dishonest node ran the job
    twice.
    """
    ids = {n for n in nodes if n}
    return len(ids) >= QUORUM


def compare(results):
    """Compare replica results and return (verdict, digest, agreeing_nodes).

    `results` is a list of (node_id, result) pairs.
    """
    usable = [(node, r) for node, r in results if r and node]
    if not usable:
        return VERDICT_INSUFFICIENT, None, []
    if not independent([node for node, _ in usable]):
        # Fewer than QUORUM distinct nodes. Reported as insufficient rather than
        # agreed: one node agreeing with itself is not corroboration, and
        # calling it agreement would be the whole mechanism failing silently.
        return VERDICT_INSUFFICIENT, None, [node for node, _ in usable]

    groups = {}
    for node, r in usable:
        groups.setdefault(output_digest(r), []).append(node)

    best_digest, best_nodes = None, []
    for digest, nodes in sorted(groups.items()):
        if len(nodes) > len(best_nodes):
            best_digest, best_nodes = digest, nodes

    if len(best_nodes) >= QUORUM:
        return VERDICT_AGREED, best_digest, sorted(best_nodes)
    # Every group is below quorum: the replicas disagree and none has enough
    # support to be believed. This does NOT say who is wrong.
    return VERDICT_DISAGREED, None, []


def should_verify(job_id, rate=0.25):
    """Whether to spend a replica on this job.

    Deterministic from the job id rather than random, so the decision is
    reproducible when disputed — a node that lost payment over a failed
    verification must be able to see that the job really was selected.

    Unpredictable to a node, though: it cannot know the id before accepting the
    work, so the only safe strategy is to compute honestly every time.
    """
    if rate >= 1.0:
        return True
    if rate <= 0:
        return False
    digest = hashlib.sha256(("verify|%s" % job_id).encode("utf-8")).digest()
    return (int.from_bytes(digest[:4], "big") % 10000) < int(rate * 10000)
