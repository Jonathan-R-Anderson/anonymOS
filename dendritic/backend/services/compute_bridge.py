"""Submitting arcade compute jobs to a volunteer node.

This is the link that was missing. The arcade queue could accept programs and a
node could advertise spare cores, and nothing connected them — jobs ran on the
site's own code-runner or not at all.

WHICH NODE GETS THE WORK
------------------------
Not a configured one. A single COMPUTE_NODE_URL would make one machine the entry
point for all compute: it receives every job, earns from every job, and when it
goes down the whole feature goes with it. That is the same mistake as choosing
the provider by configuration, one layer lower.

Instead the target comes from the NETWORK. Every node self-reports its identity
and its I2P destination in its heartbeat — the same fields the bootstrap service
and the gateway checks already use — and dispatch sends work to whichever node
placement chose, at the address that node advertised. That reasoning is
unchanged; only the transport below it moved.

HOW IT IS REACHED: THROUGH THIS SITE'S OWN NODE
-----------------------------------------------
It used to POST to http://<destination>.b32.i2p/compute/admit through an I2P HTTP
proxy. Nothing was ever listening there. A node's advertised destination carries
LIBP2P STREAMS, not HTTP; its compute API is plain TCP on a loopback/LAN port
that no proxy can reach from a VPS, and there is no HTTP-over-I2P listener in the
node at all. Measured on the live fleet: a node answered `{"admitted": true}` on
its own port while every dispatched unit failed with "none took this job".

So the site stops trying to be a peer. It is Python and cannot speak libp2p, and
volunteer nodes are behind home NAT and cannot be dialled directly. It hands the
job to the node it ALREADY talks to over plain HTTP — the same co-located
syndichan-node that serves /dcs/deploy and /dcs/blob — naming the target peer,
and that node carries it over libp2p/I2P:

    site --plain HTTP--> its own node --libp2p/I2P--> volunteer node

DCS_NODE_URL is that node, and is deliberately the same variable the container
service already uses: it is the same bridge on the same machine, and a second
name for it would be a second thing to get wrong. COMPUTE_NODE_BRIDGE overrides
it for a deployment where the two genuinely differ.

WHY A REFUSAL IS NOT A FAILURE
------------------------------
A node saying "I do not offer GPU work" or "I am busy" has not failed; it has
answered. Marking the job failed on a refusal would burn a submission because a
volunteer's laptop was warm. Refusals leave the job QUEUED and are surfaced as
a reason, and only a genuine execution error fails a job.

The relay hop makes that harder to keep true, and it is the one thing this module
must not get wrong. The peer's own status comes back verbatim, so everything
below reads exactly as it did over HTTP. A failure to REACH the peer cannot use a
status, because 5xx already means "the node declined" here — so the relay marks
it `"unreachable": true` in the body and that is checked first, before any status
is interpreted.
"""

import os

import requests

# Generous, because an I2P round trip is commonly 0.5-2 seconds and a tunnel
# still building is slower again. A timeout tuned for loopback would report
# healthy volunteers as unreachable. Still generous now that the first hop is
# loopback: the second hop is the same garlic round trip it always was, and the
# relay waits for it.
_TIMEOUT = 45


class BridgeUnavailable(RuntimeError):
    """No compute node is reachable. The caller should leave the job queued."""


class Refused(RuntimeError):
    """The node declined this job. Carries whether it is worth asking again."""

    def __init__(self, reason, retryable=True):
        super().__init__(reason)
        self.reason = reason
        self.retryable = retryable


def endpoint_for(node):
    """Where to send work for a chosen node — a PEER now, not a URL.

    Derived from what the NODE said in its heartbeat, not from configuration.
    A single configured address would make one machine the entry point for all
    compute: it gets every job, and when it goes down so does the whole feature.
    That is the same mistake as choosing the provider by config, one layer
    lower. That reasoning is untouched by the transport change; what moved is
    only what "an address" means here.

    Returns the two things the relay needs, or None when the node named nothing
    that can be dispatched to:

      peer         its libp2p identity, which is what the handshake proves and
                   therefore the only part that decides who runs the job;
      destination  its garlic address, a DIALLING HINT. A wrong one produces a
                   failed dial, never a conversation with the wrong node, which
                   is what makes it safe to pass along; and it may be absent
                   when our node is already connected to that peer.
    """
    node = node or {}
    peer = str(node.get("id") or "").strip()
    if not peer:
        return None
    return {"peer": peer, "destination": str(node.get("i2p_destination") or "").strip()}


def relay_base():
    """This site's own node, or None when no node is bridged to this site.

    The same address the container service uses. It is the same bridge on the
    same machine, and a second name for it would be a second thing to get wrong
    — so COMPUTE_NODE_BRIDGE exists only for a deployment where the two really
    are different processes.
    """
    for name in ("COMPUTE_NODE_BRIDGE", "DCS_NODE_URL"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value.rstrip("/")
    return None


def enabled():
    """Whether compute can be dispatched to the network at all.

    Needs a transport, not a target: targets come from nodes. The transport is
    now this site's own node, because that is the only thing here that can speak
    to a volunteer — the site cannot, at any address, with any proxy.
    """
    return relay_base() is not None


def _post(verb, payload, node=None):
    """Relay one compute verb to the chosen peer through this site's node."""
    base = relay_base()
    if not base:
        raise BridgeUnavailable("no compute node is bridged to this site")
    target = endpoint_for(node)
    if not target:
        raise BridgeUnavailable("the chosen node advertised no reachable address")
    try:
        resp = requests.post(
            "%s/compute/peer/%s" % (base, verb),
            json={"peer": target["peer"], "destination": target["destination"],
                  # Carried opaquely: the relay forwards these bytes without
                  # parsing them, so a field a newer site sends still reaches the
                  # node even through an older relay.
                  "request": payload},
            timeout=_TIMEOUT)
    except requests.RequestException as exc:
        # Our OWN node did not answer. Unreachable, not a refusal — nothing was
        # asked of any volunteer.
        raise BridgeUnavailable("compute node bridge unreachable: %s" % exc)
    try:
        data = resp.json()
    except ValueError:
        raise BridgeUnavailable("compute node returned a non-JSON response")
    if data.get("unreachable"):
        # The relay could not reach the PEER. Checked before any status is read,
        # because the status cannot carry this: 5xx below already means "the node
        # declined", so without this line every dial failure would be recorded as
        # a volunteer's considered refusal and the job would look answered.
        raise BridgeUnavailable(str(data.get("error") or "the chosen node could not be reached"))
    if resp.status_code == 404:
        return {"done": False, "error": "unknown job"}
    if resp.status_code >= 500 or resp.status_code == 503:
        raise Refused(data.get("reason") or "node unavailable",
                      retryable=bool(data.get("retryable", True)))
    if resp.status_code >= 400:
        # A 4xx is our request being wrong — an unsupported language, a missing
        # id, a payload over the node's cap. Not retryable, because asking again
        # with the same payload gets the same answer.
        raise Refused(data.get("error") or data.get("reason") or "rejected",
                      retryable=False)
    return data


def admit(node, device):
    """Would a node take this device's work right now?"""
    data = _post("admit", {"device": device}, node=node)
    if not data.get("admitted"):
        raise Refused(data.get("reason") or "not admitted",
                      retryable=bool(data.get("retryable", True)))
    return True


def submit(node, job_id, device, language, entrypoint, files, stdin="",
           timeout_seconds=60, workload=None, params=None, seed=None,
           arbitrary=False, needs_gpu=None):
    """Hand a job to the node. Returns a ticket.

    WHY `arbitrary` IS IN THE PAYLOAD
    ---------------------------------
    It was not, and that was a real hole rather than an omission of detail.
    Placement correctly routes an arbitrary job to a node reporting microVM
    isolation — and then the request arrived carrying nothing that said so, so
    the node read it as an ordinary catalogue job and ran it in a CONTAINER.
    The isolation rule was enforced on the site's side of the wire and nowhere
    else, which means it was enforced against accidents and not against a node
    that simply did what it was asked.

    WORKLOAD, PARAMS AND SEED
    -------------------------
    A workload job names a fixed image and carries DATA; there is no entry point
    and the language field is meaningless to it. `seed` is sent separately from
    `params` because verification depends on it: two replicas of a sampled
    workload only compare if the seed is part of the request rather than chosen
    by the image.

    Unknown JSON keys are ignored by the node, so this can be sent to a node
    that has not learned about workloads yet — it will simply run the language
    job it understands, or refuse.
    """
    payload = {
        "job_id": str(job_id),
        "device": device,
        "language": language,
        "entrypoint": entrypoint,
        "files": files,
        "stdin": stdin,
        "timeout_seconds": int(timeout_seconds),
        # Always sent, including false. Omitting it when false would make "this
        # node must isolate in hardware" and "this field was not in the build
        # that sent the request" the same wire state.
        "arbitrary": bool(arbitrary),
    }
    if needs_gpu is None:
        needs_gpu = str(device or "").startswith("gpu")
    payload["needs_gpu"] = bool(needs_gpu)
    if workload:
        payload["workload"] = str(workload)
    if params:
        payload["params"] = params
    if seed is not None:
        payload["seed"] = seed
    data = _post("submit", payload, node=node)
    if not data.get("accepted"):
        raise Refused(data.get("reason") or "not accepted",
                      retryable=bool(data.get("retryable", True)))
    return data.get("ticket") or str(job_id)


def result(node, job_id):
    """Poll for a finished job. Returns None while it is still running.

    The node's result object is returned WHOLE, unknown keys included. A
    workload run's product is a FILE, and the node sends it back as `outputs`
    (a name -> contents map) with `output_truncated` when it was too large to
    carry — so a caller that picked out stdout/stderr/exit_code and dropped the
    rest would throw away the only thing the job was submitted to produce, and
    the loss would look exactly like a workload that computed nothing.
    """
    data = _post("result", {"job_id": str(job_id)}, node=node)
    if data.get("done"):
        return data.get("result") or {}
    if data.get("error") == "unknown job":
        # The node has never heard of it — it restarted, or the job went to a
        # different node. Distinguished from "still running" so the caller can
        # requeue instead of polling something that will never finish.
        raise BridgeUnavailable("the node no longer has this job")
    return None
