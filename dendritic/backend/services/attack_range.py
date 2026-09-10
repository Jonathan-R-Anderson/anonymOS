"""Attack Range lab orchestration for the site.

Attack Range (github.com/splunk/attack_range) builds deliberately-vulnerable
hosts for security research. Here a user spins one up on the decentralized
container service (DCS), gets its private I2P address, does their research, and
spins it down -- or it auto-expires after 24h.

THE NODE SEAM, STATED PLAINLY
-----------------------------
The container runs on a volunteer DCS worker, reached over I2P. The site talks
to that network through a DCSClient. In production that client is a
NodeBridgeClient: an HTTP client to a co-located syndichan-node running its
loopback DCS bridge API (see storage-client/cmd/syndichan-node/dcsapi.go). That
node speaks the DCS RPC to workers and holds the shard store the build context
is published to.

Set DCS_NODE_URL (e.g. http://dcs-node:8760) and this module wires the bridge
automatically at import. With it unset the default DCSClient is unconfigured and
spin-up returns "no container network connected" -- the UI says so rather than
pretending. Everything else here (the one-instance rule, the 24h countdown, the
queue position, spin-down) is real and enforced at the site regardless.
"""
import datetime as _datetime
import os
import secrets

from shared import app, db
from model.LabInstance import (
    LAB_TTL,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    LabInstance,
    expired_active_instances,
    single_active_for,
)

def available_profiles():
    """The challenges a user can spin up, drawn from the ADMIN CATALOG -- not
    from any hardcoded list and not from a worker. See model.LabChallenge and
    services.lab_registry. This is the single source of what images exist."""
    from model.LabChallenge import active_challenges
    return {c.slug: c.to_public() for c in active_challenges()}


class DCSUnavailable(Exception):
    """No DCS worker network is reachable (no node bridged, or the node/network
    could not service the request)."""


class DCSTimeout(DCSUnavailable):
    """The worker did not answer in time. Distinct from a refusal, because the
    launch may well be proceeding: a container that takes longer than we waited
    is still a container, and recording it as failed would strand it."""


class DCSClient:
    """Bridge to the DCS worker network. The default is unconfigured; a
    deployment wires a NodeBridgeClient. Methods raise DCSUnavailable when no
    node is connected."""

    def deploy(self, *, build_digest=None, image=None, lab=False, primary_port=None,
               runtime_secs=None, owner_ref, deployment_id=None, ticket=None,
               worker_node=None, worker_destination=None, kind=None,
               content_key=None, env=None):
        raise DCSUnavailable("no container network is connected to this site")

    def destroy(self, *, worker_node, worker_destination=None, container_id):
        raise DCSUnavailable("no container network is connected to this site")

    def publish_blob(self, blob):
        raise DCSUnavailable("no container network is connected to this site")


class NodeBridgeClient(DCSClient):
    """HTTP client to a syndichan-node's loopback DCS bridge API.

    The node deploys on each user's behalf, sub-accounting them by owner_ref so a
    worker's one-container-per-user rule keys on the real user, not on the shared
    node identity. That is why the node id must be in each worker's
    policy.trusted_brokers.

    The site never targets a worker directly: it hands the node an owner ref and
    a build-context digest and gets back which worker took it (worker_node /
    worker_destination) plus the container id, so it can later poll or destroy
    that exact instance.
    """

    # Under a minute on purpose. Starting a box has been observed to take ~40s,
    # and something in front of this server gives up around 60 — so a 180s wait
    # never produced a slow success, only a browser timeout on top of a launch
    # that was still running. The caller treats the timeout as "still starting"
    # and lets the status poller finish the job.
    def __init__(self, base_url, timeout=55):
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _post(self, path, payload):
        import requests
        try:
            resp = requests.post(self._base + path, json=payload, timeout=self._timeout)
        except requests.Timeout as exc:
            raise DCSTimeout("container node did not answer within %ss: %s"
                             % (self._timeout, exc))
        except requests.RequestException as exc:
            raise DCSUnavailable("container node unreachable: %s" % exc)
        if resp.status_code >= 400:
            # The bridge returns {"error": "..."} for every failure.
            try:
                message = resp.json().get("error") or resp.text
            except ValueError:
                message = resp.text
            raise DCSUnavailable(message.strip() or ("HTTP %d" % resp.status_code))
        try:
            return resp.json()
        except ValueError:
            raise DCSUnavailable("container node returned a non-JSON response")

    def deploy(self, *, build_digest=None, image=None, lab=False, primary_port=None,
               runtime_secs=None, owner_ref, deployment_id=None, ticket=None,
               worker_node=None, worker_destination=None, kind=None,
               content_key=None, env=None):
        payload = {
            "on_behalf_of": owner_ref,
            "lab": bool(lab),
        }
        if kind:
            payload["kind"] = kind
        # Per-boot env vars injected into the container (e.g. LAB_SECRET). The
        # worker adds these to the primary service so a per-instance secret is
        # present inside the box; a lab question can then require it as its answer.
        if env:
            payload["env"] = list(env)
        if build_digest:
            payload["build_context_digest"] = build_digest
        # The base64 content key for an encrypted build context. The bridge seals
        # it to the chosen worker's Curve25519 content key before it leaves the
        # host, so only that worker can unlock exactly this one context.
        if content_key:
            payload["content_key"] = content_key
        if image:
            payload["image"] = image
        if primary_port:
            payload["primary_port"] = int(primary_port)
        if runtime_secs:
            payload["runtime_secs"] = int(runtime_secs)
        if deployment_id:
            payload["deployment_id"] = deployment_id
        # A queued re-poll returns to the exact worker holding the reservation.
        if ticket:
            payload["ticket"] = ticket
        if worker_node:
            payload["worker_node"] = worker_node
        if worker_destination:
            payload["worker_destination"] = worker_destination
        return _normalize(self._post("/dcs/deploy", payload))

    def destroy(self, *, worker_node, worker_destination=None, container_id):
        self._post("/dcs/destroy", {
            "worker_node": worker_node,
            "worker_destination": worker_destination or "",
            "container_id": container_id,
        })

    def publish_blob(self, blob):
        """Store a packed build context on the node's shard store (DHT) and
        return the digest it stored under. Uses PUT with the raw blob body."""
        import requests
        try:
            resp = requests.put(
                self._base + "/dcs/blob", data=bytes(blob),
                headers={"Content-Type": "application/x-tar"},
                timeout=self._timeout,
            )
        except requests.Timeout as exc:
            raise DCSTimeout("container node did not accept the build context within %ss: %s"
                             % (self._timeout, exc))
        except requests.RequestException as exc:
            raise DCSUnavailable("container node unreachable: %s" % exc)
        if resp.status_code >= 400:
            try:
                message = resp.json().get("error") or resp.text
            except ValueError:
                message = resp.text
            raise DCSUnavailable(message.strip() or ("HTTP %d" % resp.status_code))
        try:
            return resp.json().get("digest")
        except ValueError:
            raise DCSUnavailable("container node returned a non-JSON response")


def _normalize(data):
    """Fold the Go bridge's deploy/re-poll reply into the shape the site rows
    use. The bridge names the container's address `destination` and the worker
    `worker_node`; the site stores i2p_address and worker_node_id."""
    return {
        "queued": bool(data.get("queued")),
        "ticket": data.get("ticket"),
        "position": data.get("position"),
        "eta_seconds": data.get("eta_seconds"),
        "worker_node_id": data.get("worker_node"),
        "worker_destination": data.get("worker_destination"),
        "container_id": data.get("container_id"),
        "i2p_address": data.get("destination"),
        "instance_ttl": data.get("instance_ttl"),
        "note": data.get("note"),
    }


# The active client. A deployment replaces this via set_dcs_client() or by
# setting DCS_NODE_URL (wired at import, below).
_client = DCSClient()


def set_dcs_client(client):
    global _client
    _client = client


def dcs_connected():
    return not isinstance(_client, DCSClient) or isinstance(_client, NodeBridgeClient)


class LabError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def _grant_key_for(challenge):
    """The base64 content key to grant a worker for this challenge's context, or
    None when the context is not encrypted. Only the server can produce it (it
    holds the master); the bridge seals it to the worker before it leaves the
    host. Raises LabError if the context IS encrypted but the key can't be
    recovered -- deploying without it would just fail opaquely on the worker."""
    from services import content_keys

    if not content_keys.enabled():
        return None
    blob = challenge.build_context
    if not content_keys.is_encrypted_blob(blob):
        return None
    try:
        import base64

        return base64.b64encode(content_keys.recover_key(bytes(blob))).decode("ascii")
    except Exception as exc:
        app.logger.warning("lab content grant failed for %s", challenge.slug, exc_info=True)
        raise LabError("The lab's encryption key could not be prepared.") from exc


# How long a QUEUED instance may sit before the reaper frees the slot.
#
# A queued row counts as the slip's one active instance, and until now it was
# created with no expires_at at all — so the reaper, which only looks at rows
# with a deadline, could never touch it. One launch that never got promoted
# locked the account out of the lab permanently, with no way back short of an
# admin editing the database. Half an hour is far longer than any real queue and
# still finite.
QUEUE_TTL = _datetime.timedelta(minutes=30)


def _new_instance_secret():
    """A fresh per-boot secret. URL-safe (A-Za-z0-9_-), so it is safe to inject
    as an env value and to compare as an answer without escaping surprises."""
    return secrets.token_urlsafe(12)


def _lab_env(instance):
    """The env vars to inject into this instance's container. The per-boot secret
    is exposed under a couple of common names so a researcher who gains code
    execution can retrieve it (`env`, /proc/1/environ) and submit it as the
    answer to an instance-secret question. Returns None when there is no secret."""
    secret = getattr(instance, "container_password", None)
    if not secret:
        return None
    return ["LAB_SECRET=%s" % secret, "LAB_PASSWORD=%s" % secret]


def spin_up(slip, image_key):
    """Start (or queue) a lab instance for the slip. One active per slip.

    image_key is a challenge slug from the ADMIN catalog. The worker is handed
    that challenge's build-context digest; it never picks an image itself."""
    from model.LabChallenge import challenge_by_slug
    challenge = challenge_by_slug(image_key)
    if challenge is None:
        raise LabError("That challenge is not in the registry (an admin removed it, or it never existed).")
    _reap_expired()

    if single_active_for(slip.id) is not None:
        raise LabError("You already have an active lab instance. Spin it down before starting another.")

    # Make sure the build context is on the DHT before we ask a worker to fetch
    # it. No-op if already published or no node is bridged.
    _ensure_published(challenge)

    instance = LabInstance(slip_id=slip.id, image_key=image_key, status=STATUS_QUEUED,
                           build_digest=challenge.build_digest,
                           container_password=_new_instance_secret(),
                           expires_at=_datetime.datetime.utcnow() + QUEUE_TTL)
    db.session.add(instance)
    # COMMITTED, not flushed. Starting a box takes as long as it takes, and for
    # that whole window a flushed row is invisible to every other request — so
    # the "one active instance per slip" check above passes for a second click,
    # a second container is requested, and the worker refuses it with an error
    # about an instance the site never showed anyone. Committing first makes the
    # limit hold during the one window where it matters.
    db.session.commit()

    try:
        result = _client.deploy(
            build_digest=challenge.build_digest,
            lab=challenge.is_lab,
            primary_port=challenge.primary_port,
            kind=challenge.kind,
            owner_ref=str(slip.id),
            deployment_id="lab-%d" % instance.id,
            content_key=_grant_key_for(challenge),
            env=_lab_env(instance),
        )
    except DCSTimeout as exc:
        # NOT a failure. The worker may be pulling an image right now, and
        # marking this failed would both lie to the operator and strand a
        # container nobody has a row for. Left queued so /lab/status.json keeps
        # polling and promotes it the moment the worker answers.
        instance.status = STATUS_QUEUED
        instance.note = ("Still starting — the worker is taking longer than one "
                         "page load. This keeps polling.")[:255]
        db.session.commit()
        app.logger.info("lab %s: deploy timed out, left queued (%s)", instance.id, exc)
        return instance
    except DCSUnavailable as exc:
        if _is_owner_conflict(exc):
            # The worker still holds a container for this slip that the site no
            # longer has an active row for — a leak from an earlier failed or
            # expired launch. The site is the authority on whether someone has a
            # box, so it clears the orphan and tries once more rather than
            # leaving the account permanently unable to start anything.
            if _reclaim_orphan(slip, instance):
                try:
                    result = _client.deploy(
                        build_digest=challenge.build_digest,
                        lab=challenge.is_lab,
                        primary_port=challenge.primary_port,
                        kind=challenge.kind,
                        owner_ref=str(slip.id),
                        deployment_id="lab-%d" % instance.id,
                        content_key=_grant_key_for(challenge),
                        env=_lab_env(instance),
                    )
                    _apply_result(instance, result)
                    db.session.commit()
                    return instance
                except DCSUnavailable as retry_exc:
                    exc = retry_exc
        # Keep the row so the UI can show the honest state instead of a silent
        # failure, but mark it failed so it does not count as an active instance.
        instance.status = STATUS_FAILED
        # note is varchar(255); a worker/I2P error can be far longer, and letting
        # it overflow poisons the session (StringDataRightTruncation) and loses
        # the honest failure state. Truncate.
        instance.note = str(exc)[:255]
        db.session.commit()
        raise LabError(
            "The lab could not be launched right now. (%s)" % exc
        )

    _apply_result(instance, result)
    db.session.commit()
    return instance


def poll(slip, instance_id):
    """Refresh a queued instance: re-send its Launch to the worker holding the
    ticket, which either reports an updated position or promotes it to running.

    Promotion is a re-sent Launch, not a status read: the worker's reservation
    lives on one worker and only a Launch carrying the ticket advances it."""
    instance = _owned(slip, instance_id)
    if instance is None or instance.status != STATUS_QUEUED:
        return instance
    from model.LabChallenge import challenge_by_slug
    challenge = challenge_by_slug(instance.image_key)
    if challenge is None:
        return instance  # the challenge was removed; leave the row as-is
    try:
        result = _client.deploy(
            build_digest=instance.build_digest,
            lab=challenge.is_lab,
            primary_port=challenge.primary_port,
            kind=challenge.kind,
            owner_ref=str(slip.id),
            deployment_id="lab-%d" % instance.id,
            ticket=instance.ticket,
            worker_node=instance.worker_node_id,
            worker_destination=instance.worker_destination,
            content_key=_grant_key_for(challenge),
            env=_lab_env(instance),
        )
    except DCSUnavailable:
        return instance
    _apply_result(instance, result)
    db.session.commit()
    return instance


def spin_down(slip, instance_id):
    """Destroy the slip's instance now, before its TTL."""
    instance = _owned(slip, instance_id)
    if instance is None:
        raise LabError("No such lab instance.")
    _destroy_on_worker(instance)
    instance.status = STATUS_EXPIRED
    db.session.commit()
    return instance


def publish_pending_contexts(limit=20):
    """Push any not-yet-announced challenge build contexts to the bridged node's
    shard store and mark them published. No-op when no node is bridged. Called
    when an admin adds a challenge, and safe to call again as a sweep."""
    if not isinstance(_client, NodeBridgeClient):
        return 0
    from services import lab_registry
    published = 0
    for challenge in lab_registry.unpublished_contexts(limit=limit):
        if _publish_one(challenge):
            published += 1
        else:
            break  # node went away; stop and let a later sweep retry
    return published


def _ensure_published(challenge):
    """Guarantee a single challenge's context is on the DHT before deploy."""
    if challenge.dht_published_at is not None:
        return
    _publish_one(challenge)


def _publish_one(challenge):
    if not isinstance(_client, NodeBridgeClient):
        return False
    blob = challenge.build_context
    if not blob:
        return False
    try:
        digest = _client.publish_blob(bytes(blob))
    except DCSUnavailable:
        return False
    if digest and digest != challenge.build_digest:
        # The node re-hashes the blob; a mismatch means a worker would fetch a
        # blob whose digest is not what we told it to build. Do not mark it
        # published -- surface it instead of silently deploying the wrong thing.
        app.logger.error("lab: published digest %s != stored %s for challenge %s",
                         digest, challenge.build_digest, challenge.slug)
        return False
    from services import lab_registry
    lab_registry.mark_published(challenge.id)
    return True


# The worker's wording for "this owner already has a container here". Matched on
# substrings rather than an error code because the bridge returns prose; a
# missed match costs a retry, never a wrong action.
_OWNER_CONFLICT_MARKERS = ("already has a running or queued instance",
                           "owner already has")


def _is_owner_conflict(exc):
    text = str(exc).lower()
    return any(marker in text for marker in _OWNER_CONFLICT_MARKERS)


def _reclaim_orphan(slip, exclude_instance):
    """Destroy a container the worker still holds for this slip but the site does
    not consider active. Returns True if something was released.

    Only rows the site has already written off (failed/expired) are touched: a
    genuinely active instance is the user's, and tearing it down to make room for
    a new one would delete work they are in the middle of.
    """
    from model.LabInstance import LabInstance, STATUS_EXPIRED, STATUS_FAILED

    rows = (
        db.session.query(LabInstance)
        .filter(
            LabInstance.slip_id == slip.id,
            LabInstance.id != exclude_instance.id,
            LabInstance.status.in_((STATUS_EXPIRED, STATUS_FAILED)),
            LabInstance.container_id.isnot(None),
            LabInstance.worker_node_id.isnot(None),
        )
        .order_by(LabInstance.id.desc())
        .limit(5)
        .all()
    )
    released = False
    for row in rows:
        if _destroy_on_worker(row):
            released = True
    if released:
        db.session.commit()
    return released


def _apply_result(instance, result):
    """Fold a DCS deploy/re-poll result into the row."""
    # Whether queued or running, remember which worker took it so a later poll or
    # destroy returns to that exact worker.
    if result.get("worker_node_id"):
        instance.worker_node_id = result.get("worker_node_id")
    if result.get("worker_destination"):
        instance.worker_destination = result.get("worker_destination")

    if result.get("queued"):
        instance.status = STATUS_QUEUED
        instance.ticket = result.get("ticket")
        instance.queue_position = result.get("position")
        instance.eta_seconds = result.get("eta_seconds")
        instance.note = "Queued: the network is at capacity."
        return

    instance.status = STATUS_RUNNING
    instance.container_id = result.get("container_id")
    instance.i2p_address = result.get("i2p_address")
    instance.queue_position = None
    instance.eta_seconds = None
    instance.ticket = None
    # 24h auto spin-down, clamped by whatever the worker reported.
    ttl_seconds = result.get("instance_ttl") or int(LAB_TTL.total_seconds())
    instance.expires_at = _datetime.datetime.utcnow() + _datetime.timedelta(
        seconds=min(ttl_seconds, int(LAB_TTL.total_seconds()))
    )
    instance.note = (result.get("note") or "Running. Reachable only at its private I2P address.")[:255]


def _destroy_on_worker(instance):
    """Tear down the container on the worker. Returns True if it is gone.

    A failure used to be swallowed here in silence while the row was marked
    expired anyway, so the site forgot a container that kept running: six of
    them were found still up after forty hours, and because the worker counts
    them against the owner, the account they belonged to could no longer start
    anything. Now a failure is logged and the container_id is KEPT, which is
    what lets the retry below find it again — an id that no longer resolves is
    still the only handle anyone has on a container that does.
    """
    if not instance.container_id or not instance.worker_node_id:
        return True
    if not dcs_connected():
        return False
    try:
        _client.destroy(
            worker_node=instance.worker_node_id,
            worker_destination=instance.worker_destination,
            container_id=instance.container_id,
        )
    except DCSUnavailable as exc:
        app.logger.warning(
            "lab %s: could not destroy container %s on %s (%s) — it is still "
            "running and still counts against this account on that worker",
            instance.id, instance.container_id, instance.worker_node_id, exc)
        return False
    # Cleared only on success, so nothing retries a teardown that already
    # happened and nothing forgets one that did not.
    instance.container_id = None
    return True


def _retry_failed_teardowns(limit=20):
    """Re-attempt destroys that failed earlier.

    Without this the only thing that ever retried was the next launch by the
    same account, so a user who gave up left a container running indefinitely —
    and a container nobody is using is a vulnerable box on the internet with an
    owner who has stopped watching it.
    """
    from model.LabInstance import LabInstance

    rows = (
        db.session.query(LabInstance)
        .filter(
            LabInstance.status.in_((STATUS_EXPIRED, STATUS_FAILED)),
            LabInstance.container_id.isnot(None),
            LabInstance.worker_node_id.isnot(None),
        )
        .order_by(LabInstance.id.desc())
        .limit(limit)
        .all()
    )
    released = 0
    for row in rows:
        if _destroy_on_worker(row):
            released += 1
    if released:
        try:
            db.session.commit()
            app.logger.info("lab: released %d leaked container(s)", released)
        except Exception:
            db.session.rollback()
    return released


def _owned(slip, instance_id):
    return (
        db.session.query(LabInstance)
        .filter(LabInstance.id == instance_id, LabInstance.slip_id == slip.id)
        .one_or_none()
    )


def _reap_expired():
    """Site-side auto spin-down: mark past-TTL instances expired so the UI never
    shows a box that should be gone, and the per-slip limit frees up."""
    changed = False
    for instance in expired_active_instances():
        instance.status = STATUS_EXPIRED
        changed = True
        _destroy_on_worker(instance)
    if changed:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("lab reaper commit failed")
    # Sweep up teardowns that failed on an earlier pass, so a container outlives
    # its instance by one reaper interval rather than forever.
    try:
        _retry_failed_teardowns()
    except Exception:
        db.session.rollback()
        app.logger.exception("lab: leaked-container sweep failed")


# Wire the production bridge from the environment. Present as a URL only where an
# operator co-located a syndichan-node with its DCS bridge API enabled.
_NODE_URL = os.environ.get("DCS_NODE_URL", "").strip()
if _NODE_URL:
    set_dcs_client(NodeBridgeClient(_NODE_URL))
