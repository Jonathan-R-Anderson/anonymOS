import base64
import collections
import datetime
import json
import logging
import os
import re
import threading
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


# stdlib logging rather than app.logger: this module is deliberately importable
# without booting Flask, and the root logger is already configured by
# maniwani_logging.setup_logging() so the lines land in the same file either way.
logger = logging.getLogger(__name__)


HEX_ID = re.compile(r"^[0-9a-f]{64}$")
I2P_BOOTSTRAP = re.compile(
    r"^/garlic32/[a-z2-7]{52}/p2p/[1-9A-HJ-NP-Za-km-z]+$"
)
# A node's own garlic destination as it reports it in the heartbeat: the bare
# 52-character base32 hash, without the /garlic32/.../p2p/ wrapper.
I2P_DESTINATION = re.compile(r"^[a-z2-7]{52}$")
MAX_SHARD_BYTES = 32 * 1024 * 1024
LEASE_SECONDS = 10 * 60
MAX_LEASES_PER_MINUTE = 240
# A revocation is a signed authority to DELETE one shard from one named peer.
# Short-lived for the same reason a lease is: a leaked token must stop working,
# and the holder refuses anything whose expiry is more than an hour out anyway
# (storage-client/internal/p2p/recall.go, validateRevocation).
REVOCATION_SECONDS = 10 * 60
# One request covers a batch, because a 40 MB object is 39 chunks x 9 shards x
# however many holders each -- several hundred tokens. Asking one at a time
# would exhaust the per-minute allowance before the object was half recalled.
MAX_REVOCATIONS_PER_REQUEST = 128
# Its own allowance, separate from leases: a purge must not be able to starve
# the placement path that keeps everything else durable, and vice versa.
MAX_REVOCATION_REQUESTS_PER_MINUTE = 30
STORAGE_USER_AGENT = "Syndichan-Storage-Client/1.0"
MAX_CAPACITY_BYTES = 8 << 50
PLATFORM = re.compile(r"^[a-z0-9_-]{1,24}/[a-z0-9_-]{1,24}$")
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_VALUES = {char: index for index, char in enumerate(_BASE58_ALPHABET)}
_rate_lock = threading.Lock()
_recent_requests = collections.defaultdict(collections.deque)
_seen_nonces = {}


def _decode_unpadded(value):
    value = str(value or "").strip()
    return base64.b64decode(value + ("=" * (-len(value) % 4)), validate=True)


def _canonical_unsigned(value, signature_field="signature"):
    unsigned = dict(value)
    unsigned.pop(signature_field, None)
    encoded = json.dumps(unsigned, separators=(",", ":"), ensure_ascii=True)
    # Go's encoding/json HTML-escapes these three ASCII characters by default.
    # Match it byte-for-byte because client signatures cover the encoded JSON.
    encoded = encoded.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    return encoded.encode("utf-8")


def _trusted_gateway_probes():
    try:
        configured = json.loads(os.getenv("GATEWAY_TRUSTED_PROBES") or "{}")
    except json.JSONDecodeError:
        return {}
    return configured if isinstance(configured, dict) else {}


def _validate_gateway_registration(registration, candidate_node_id, now):
    """Validate the independent quorum before the admin map shows green."""
    if not isinstance(registration, dict):
        raise ValueError("verified gateway heartbeat requires a registration")
    if (
        registration.get("record_type") != "verified_gateway"
        or registration.get("node_id") != candidate_node_id
        or registration.get("protocol_version") != 1
        or registration.get("health_state") != "healthy"
        or not isinstance(registration.get("expires_at"), int)
        or registration["expires_at"] <= now
        or registration["expires_at"] - int(registration.get("issued_at") or 0) > 900
    ):
        raise ValueError("invalid or expired gateway registration")
    candidate_key = peer_verify_key(candidate_node_id)
    encoded_key = _decode_unpadded(registration.get("public_key"))
    if encoded_key != b"\x08\x01\x12\x20" + bytes(candidate_key):
        raise ValueError("gateway public key does not match node identity")
    try:
        candidate_key.verify(
            _canonical_unsigned(registration),
            _decode_unpadded(registration.get("signature")),
        )
    except (BadSignatureError, ValueError, TypeError):
        raise ValueError("invalid gateway registration signature")

    trusted = _trusted_gateway_probes()
    minimum = int(os.getenv("GATEWAY_MINIMUM_PROBES", "3") or 3)
    minimum_networks = int(os.getenv("GATEWAY_MINIMUM_NETWORKS", "2") or 2)
    seen_probes, networks = set(), set()
    for result in registration.get("probe_results") or []:
        if not isinstance(result, dict):
            continue
        probe_id = str(result.get("probe_node_id") or "")
        expected_key = trusted.get(probe_id)
        if not expected_key or probe_id == candidate_node_id or probe_id in seen_probes:
            continue
        if (
            result.get("candidate_node_id") != candidate_node_id
            or result.get("tested_port") != 443
            or not all(result.get(field) is True for field in (
                "tcp_reachable", "tls_valid", "identity_valid",
                "challenge_valid", "protocol_valid",
            ))
            or not isinstance(result.get("expires_at"), int)
            or result["expires_at"] <= now
        ):
            continue
        try:
            verify_key = peer_verify_key(probe_id)
            marshaled = b"\x08\x01\x12\x20" + bytes(verify_key)
            if _decode_unpadded(expected_key) != marshaled:
                continue
            verify_key.verify(
                _canonical_unsigned(result),
                _decode_unpadded(result.get("signature")),
            )
        except (BadSignatureError, ValueError, TypeError):
            continue
        seen_probes.add(probe_id)
        networks.add(str(result.get("probe_network") or ""))
    if len(seen_probes) < minimum or len(networks) < minimum_networks:
        raise ValueError("gateway verification quorum not met")


def _signing_key():
    configured = (os.getenv("STORAGE_COORDINATOR_SIGNING_KEY") or "").strip()
    if not configured:
        return None
    try:
        if len(configured) == 64 and all(char in "0123456789abcdefABCDEF" for char in configured):
            seed = bytes.fromhex(configured)
        else:
            seed = _decode_unpadded(configured)
        return SigningKey(seed)
    except Exception:
        return None


def coordinator_enabled():
    return _signing_key() is not None and bool(bootstrap_peers())


def bootstrap_peers():
    configured = (os.getenv("STORAGE_BOOTSTRAP_PEERS") or "").strip()
    if not configured:
        return []
    try:
        parsed = json.loads(configured)
        values = parsed if isinstance(parsed, list) else []
    except Exception:
        values = re.split(r"[\n,]+", configured)
    peers = []
    for value in values:
        address = str(value).strip()
        if not I2P_BOOTSTRAP.fullmatch(address):
            continue
        try:
            peer_verify_key(address.rsplit("/p2p/", 1)[1])
        except ValueError:
            continue
        peers.append(address)
    return peers


def _log(level, message, *args):
    """Log without importing the app at module scope. Never raises."""
    try:
        from shared import app

        getattr(app.logger, level)(message, *args)
    except Exception:
        pass


def _live_candidates(limit=8, exclude_node_id=None):
    """Heartbeat-fresh bootstrap multiaddrs, BEFORE the liveness filter.

    Over-fetches: peers the prober has struck out are removed afterwards, and
    asking for exactly `limit` rows would hand back two peers when one was
    withheld.
    """
    try:
        from model.StorageNode import active_bootstrap_peers

        return active_bootstrap_peers(
            limit=max(limit * 3, limit), exclude_node_id=exclude_node_id
        )
    except Exception:
        return []


def live_bootstrap_peers(limit=8, exclude_node_id=None):
    """Currently-active nodes that self-reported an I2P destination, as bootstrap
    multiaddrs. This is the live half of the bootstrap service: the returned
    addresses are peers heartbeating right now, not a static config value that may
    be stale. Never raises -- a DB hiccup just means we fall back to configured
    peers rather than failing a heartbeat or the well-known document.

    Heartbeat-fresh is NOT the same as reachable. The heartbeat is a clearnet
    POST, so it says nothing about whether the node's garlic destination still
    publishes a LeaseSet -- and record_storage_heartbeat never clears a stored
    destination, so a node whose I2P side broke keeps advertising a dead address
    forever. Destinations the background prober has struck out three times are
    dropped here, which covers BOTH consumers: the well-known document and the
    bootstrap_peers list every heartbeat reply carries. The filter never empties
    a non-empty list (services/peer_liveness.filter_reachable).
    """
    candidates = _live_candidates(limit=limit, exclude_node_id=exclude_node_id)
    if not candidates:
        return []
    try:
        from services.peer_liveness import filter_reachable

        return filter_reachable(candidates, label="live bootstrap peers")[:limit]
    except Exception:
        # Fail OPEN. A prober that cannot even be imported must not cost the
        # network its peers.
        return candidates[:limit]


def live_compute_peers(limit=32, device=None, microvm_only=False):
    """Nodes currently offering compute, as dialable I2P addresses.

    The discovery mechanism for compute, and deliberately the SAME one as for
    storage bootstrap rather than a second service. A separate compute directory
    would be another thing to sign, another thing to keep fresh, and another
    place for the two to disagree about which nodes exist.

    Reports what each node OFFERS, so a caller can filter without dialing: a
    scheduler asking every node whether it takes GPU work would be a round trip
    per node to learn something the node already published.

    Never raises. A database hiccup means an empty compute list, not a failed
    bootstrap document — a joining node must still be able to find storage peers
    when compute discovery is having a bad day.
    """
    try:
        from model.StorageNode import active_storage_nodes

        out = []
        for node in active_storage_nodes():
            dest = node.get("i2p_destination")
            if not dest:
                # A node with no destination cannot be dialed, so listing it
                # would only produce failures at dispatch.
                continue
            if not (node.get("cpu") or node.get("gpu")):
                continue
            if device == "cpu" and not node.get("cpu"):
                continue
            if device and device.startswith("gpu") and not node.get("gpu"):
                continue
            if microvm_only and not node.get("microvm"):
                continue
            out.append({
                "node_id": node.get("id"),
                "destination": dest,
                "cpu": bool(node.get("cpu")),
                "gpu": bool(node.get("gpu")),
                # Whether ARBITRARY code may be placed here. Published because
                # it decides eligibility, and a scheduler that had to ask would
                # be asking a node about its own trustworthiness.
                "microvm": bool(node.get("microvm")),
            })
            if len(out) >= limit:
                break
        # A destination whose LeaseSet is gone costs a dispatcher its full 45s
        # timeout per job, so the same struck-out verdict applies here.
        try:
            from services.peer_liveness import filter_reachable

            return filter_reachable(
                out, key=lambda entry: entry.get("destination") or "",
                label="compute peers")
        except Exception:
            return out
    except Exception:
        return []


def _dedupe(addresses):
    """De-duplicate while preserving order.

    Order is signed and it is meaningful: live peers come before the static
    seed, so a joining node dials nodes we know are heartbeating before it
    reaches for configuration.
    """
    out = []
    for address in addresses:
        if address not in out:
            out.append(address)
    return out


def _corroborated_seeds(seeds):
    """Configured bootstrap peers that a live heartbeat still vouches for.

    THE CHEAPEST HALF OF THE FIX, and it costs no network call at all.
    STORAGE_BOOTSTRAP_PEERS is appended to every document forever and nothing
    can expire it: if the machine behind that address ever rebuilt its i2pd
    state, its destination changed, the storage_node row followed within five
    minutes and the secret did not. The document then advertises an address
    whose LeaseSet no longer exists -- which is exactly what every node on the
    network was failing to dial.

    So a configured address is published only when some node heartbeating right
    now advertises that same destination. Unknowable (no DB, nothing
    heartbeating) means KEEP: this must fail open like everything else here, and
    a young network with no heartbeats still needs its seed.
    """
    if not seeds:
        return []
    try:
        from model.StorageNode import heartbeating_destinations

        known = heartbeating_destinations()
    except Exception:
        return list(seeds)
    if not known:
        return list(seeds)
    try:
        from services.peer_liveness import destination_of
    except Exception:
        return list(seeds)
    kept = [seed for seed in seeds if destination_of(seed) in known]
    if len(kept) != len(seeds):
        _log("info", "bootstrap: dropping %d configured peer(s) that no live node "
             "advertises any more", len(seeds) - len(kept))
    return kept


def bootstrap_document():
    key = _signing_key()
    if key is None:
        return None
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=20)
    # Two independent liveness gates, cheapest first: heartbeat recency retires
    # the configured tail (see _corroborated_seeds), and the background I2P
    # prober's cached verdict retires destinations that heartbeat over clearnet
    # while their garlic side is dead. Both run BEFORE signing, so the signature
    # covers exactly the list that is published.
    raw_seeds = bootstrap_peers()
    live = live_bootstrap_peers()
    seeds = _corroborated_seeds(raw_seeds)
    try:
        from services.peer_liveness import filter_reachable

        # floor=False: the never-empty guarantee belongs to the FINAL list, not
        # to each half. Flooring the seeds on their own would re-add a struck-out
        # seed even when live peers were available to replace it.
        seeds = filter_reachable(seeds, label="configured peers", floor=False)
    except Exception:
        pass
    peers = _dedupe(live + seeds)
    if not peers and (raw_seeds or live):
        # NEVER PUBLISH AN EMPTY PEER LIST. A node handed no peers has no
        # network at all, which is strictly worse than a node handed a stale
        # address it wastes one dial timeout on.
        _log("error",
             "bootstrap: liveness filtering left NO peers; publishing the "
             "unfiltered list instead -- a node with no peers cannot bootstrap")
        peers = _dedupe(live + raw_seeds)
    expires_at = expires.isoformat().replace("+00:00", "Z")
    public_key = base64.b64encode(
        key.verify_key.encode()).decode("ascii").rstrip("=")
    document = {
        "version": 1,
        "peers": peers,
        # Compute providers, discovered the same way and signed by the same key.
        # A node looking for somewhere to send work reads this rather than being
        # told an address by configuration — configuration names one machine and
        # fails with it.
        "compute": live_compute_peers(),
        "coordinator_public_key": public_key,
        "expires_at": expires_at,
    }
    # SIGNED, because this document decides two things for a joining node: which
    # peers it dials, and — until now, unbelievably — which coordinator key it
    # trusts for storage leases. A node that takes the key out of the document
    # is trusting whoever served the document, so serving it from anywhere other
    # than one host under our own TLS would hand that choice to a volunteer.
    #
    # The signature is what makes it safe to serve from gateways at all. A node
    # verifies against a coordinator key pinned in its own config, so the
    # document can travel over anything, from anyone.
    document["signature"] = base64.b64encode(
        key.sign(bootstrap_message(peers, public_key, expires_at)).signature
    ).decode("ascii")
    return document


def bootstrap_message(peers, public_key, expires_at):
    """The exact bytes signed over a bootstrap document.

    Line-based and explicit for the same reason the network directive is: two
    JSON encoders disagree about spacing and key order, and a signature is over
    bytes. The Go verifier rebuilds this from the parsed fields, so anything not
    listed here is NOT covered and must not be trusted.

    The peer count is signed before the peers themselves, so a truncated list
    cannot be passed off as a complete one — dropping peers is how you steer a
    node toward the few you control.
    """
    lines = [
        "syndichan-storage-bootstrap-v1",
        "expires_at: %s" % expires_at,
        "coordinator: %s" % public_key,
        "peers: %d" % len(peers),
    ]
    lines.extend(peers)
    return "\n".join(lines).encode("utf-8")


def _base58_decode(value):
    number = 0
    for char in value:
        if char not in _BASE58_VALUES:
            raise ValueError("invalid base58")
        number = number * 58 + _BASE58_VALUES[char]
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(value) - len(value.lstrip("1"))
    return (b"\x00" * leading) + decoded


def _read_varint(value, offset=0):
    result = 0
    shift = 0
    for index in range(offset, min(len(value), offset + 10)):
        byte = value[index]
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return result, index + 1
        shift += 7
    raise ValueError("invalid varint")


def peer_verify_key(peer_id):
    decoded = _base58_decode(peer_id)
    code, offset = _read_varint(decoded)
    length, offset = _read_varint(decoded, offset)
    if code != 0 or length != len(decoded) - offset:
        raise ValueError("peer ID does not embed an identity public key")
    public_key_message = decoded[offset:]
    # libp2p PublicKey protobuf: field 1 / varint = Ed25519(1), field 2 / bytes = 32-byte key.
    if len(public_key_message) != 36 or public_key_message[:4] != b"\x08\x01\x12\x20":
        raise ValueError("peer ID is not an embedded Ed25519 identity")
    return VerifyKey(public_key_message[4:])


def _authorized_requesters():
    return {
        value.strip()
        for value in re.split(r"[\n,]+", os.getenv("STORAGE_LEASE_REQUESTER_PEERS") or "")
        if value.strip()
    }


def _check_rate_and_replay(requester, nonce, now, scope="lease",
                           limit=MAX_LEASES_PER_MINUTE):
    """Per-requester rate limit and nonce replay window.

    `scope` keeps the two token kinds in separate queues. A recall of a large
    object issues hundreds of revocations, and sharing one counter with leases
    would mean a purge stops the network placing shards -- or, worse, that a
    burst of ordinary placements makes a purge silently give up half way.
    """
    with _rate_lock:
        cutoff = now - 60
        queue = _recent_requests[scope + "\x00" + requester]
        while queue and queue[0] < cutoff:
            queue.popleft()
        for seen_nonce, expiry in list(_seen_nonces.items()):
            if expiry < now:
                del _seen_nonces[seen_nonce]
        replay_key = scope + "\x00" + requester + "\x00" + nonce
        if replay_key in _seen_nonces:
            raise ValueError("request nonce was already used")
        if len(queue) >= limit:
            raise ValueError("%s rate limit exceeded" % scope)
        queue.append(now)
        _seen_nonces[replay_key] = now + 300


def _lease_message(lease):
    return (
        "syndichan-storage-lease-v1\n"
        f"{lease['version']}\n{lease['object_id']}\n{lease['shard_id']}\n"
        f"{lease['size']}\n{lease['recipient']}\n{lease['expires_at']}"
    ).encode("utf-8")


def issue_lease(raw_body, requester_header, signature_header):
    key = _signing_key()
    if key is None:
        raise RuntimeError("storage coordinator is not configured")
    if len(raw_body) > 4096:
        raise ValueError("lease request is too large")
    payload = json.loads(raw_body.decode("utf-8"))
    requester = str(payload.get("requester") or "")
    if requester != requester_header or requester not in _authorized_requesters():
        raise PermissionError("requester is not an authorized storage origin")
    try:
        signature = _decode_unpadded(signature_header)
        peer_verify_key(requester).verify(raw_body, signature)
    except (BadSignatureError, ValueError, TypeError):
        raise PermissionError("invalid node identity signature")

    now = int(time.time())
    timestamp = payload.get("timestamp")
    size = payload.get("size")
    nonce = str(payload.get("nonce") or "")
    if not isinstance(timestamp, int) or abs(now - timestamp) > 300:
        raise ValueError("request timestamp is outside the allowed clock skew")
    if not isinstance(size, int) or size <= 0 or size > MAX_SHARD_BYTES:
        raise ValueError("invalid shard size")
    if not HEX_ID.fullmatch(str(payload.get("object_id") or "")):
        raise ValueError("invalid object ID")
    if not HEX_ID.fullmatch(str(payload.get("shard_id") or "")):
        raise ValueError("invalid shard ID")
    if len(nonce) < 16 or len(nonce) > 128:
        raise ValueError("invalid nonce")
    peer_verify_key(str(payload.get("recipient") or ""))
    _check_rate_and_replay(requester, nonce, now)
    # The only moment this side ever learns who placed an object. Best effort on
    # purpose -- see record_object_owner.
    record_object_owner(payload["object_id"], requester)

    lease = {
        "version": 1,
        "object_id": payload["object_id"],
        "shard_id": payload["shard_id"],
        "size": size,
        "recipient": payload["recipient"],
        "expires_at": now + LEASE_SECONDS,
    }
    signature = key.sign(_lease_message(lease)).signature
    lease["signature"] = base64.b64encode(signature).decode("ascii").rstrip("=")
    return lease


def _revocation_message(revocation):
    """The exact bytes a holder verifies before deleting a shard.

    WHY THIS IS NOT _lease_message WITH A DIFFERENT WORD IN IT
    ---------------------------------------------------------
    A lease authorises a WRITE and covers (version, object_id, shard_id, size,
    recipient, expires_at) -- the same fields a revocation needs. If a revocation
    were signed under the lease's domain prefix, then every lease this
    coordinator has ever issued would also be a valid DELETE token for that shard
    on that peer. Leases travel in the clear inside the store frame, so anyone
    who ever watched a placement go by would hold one.

    So the two messages differ twice over: a different prefix, and a different
    field set (issued_at and a nonce, no size). Either alone would be enough;
    both together mean the messages cannot collide even if a future refactor got
    the prefix wrong.

    BOTH ENDS ARE NAMED
    -------------------
    `recipient` is the only peer that may HONOUR the token. `requester` is the
    only peer that may PRESENT it. Signing the requester in is what makes a
    delete token stop being a bearer instrument: the frame carrying it travels
    the network in the clear, so without this line the holder it was aimed at --
    or anything that watched the exchange -- could turn round and present the
    same bytes itself. The holder checks it against the peer libp2p
    authenticated on the other end of the stream (validateRevocation in
    storage-client/internal/p2p/recall.go), never against anything in the frame.

    Byte-identical twin of revocationMessage() in
    storage-client/internal/p2p/recall.go. Change one and you must change both.
    Adding `requester` changed both at once, and it is a WIRE BREAK in both
    directions on purpose -- see issue_revocations for which way each side fails.
    """
    return (
        "syndichan-storage-revocation-v1\n"
        f"{revocation['version']}\n{revocation['object_id']}\n{revocation['shard_id']}\n"
        f"{revocation['recipient']}\n{revocation['requester']}\n"
        f"{revocation['issued_at']}\n{revocation['expires_at']}\n{revocation['nonce']}"
    ).encode("utf-8")


class OwnershipUnavailable(RuntimeError):
    """The ownership record could not be read. NOT the same as 'no owner'."""


def object_owner(object_id):
    """The origin that first leased this object, or None if no row exists.

    Raises OwnershipUnavailable if the record could not be read at all. That
    distinction is the whole point of this wrapper: a database fault answering
    "nobody owns it" would silently hand out delete tokens, which is fault F6 of
    this feature's security review (a ledger read failure rendered as "no holders
    were ever placed") committed a second time on the other side of the wire.
    """
    try:
        from model.DhtObjectOwner import owner_of
    except Exception as exc:  # the model, its table, or the app is unavailable
        raise OwnershipUnavailable(
            "the DHT object ownership record is not available in this process"
        ) from exc
    try:
        return owner_of(object_id)
    except Exception as exc:
        raise OwnershipUnavailable(
            "the DHT object ownership record could not be read"
        ) from exc


def record_object_owner(object_id, requester):
    """Note that `requester` placed `object_id`, unless somebody already did.

    BEST EFFORT, AND THAT IS A CHOICE
    ---------------------------------
    A failure here is logged at ERROR and the lease is still signed. The other
    option -- refuse the lease when ownership cannot be recorded -- would mean a
    database blip stops the network placing shards, i.e. it would trade a
    durability outage for a bookkeeping guarantee.

    That is safe in the only direction that matters, because a MISSING row never
    grants more authority than the code had before this table existed: an object
    with no row falls back to the origin-count tautology in _check_object_origin,
    which signs only where there is exactly one authorised origin and every
    object necessarily belongs to it. So a failed write can delay or refuse a
    legitimate recall; it can never authorise somebody else's.
    """
    try:
        from model.DhtObjectOwner import record_owner

        record_owner(object_id, requester)
    except Exception:
        logger.error(
            "storage coordinator: could not record ownership of object %s by %s; "
            "the lease is still being issued, and a later recall of this object "
            "will fall back to the origin-count check",
            object_id, requester, exc_info=True,
        )
        # A half-finished transaction must not be left for whatever runs next on
        # this session. Swallowed in turn: if even the rollback fails there is
        # nothing useful to do here, and the lease still has to be signed.
        try:
            from shared import db

            db.session.rollback()
        except Exception:
            pass


def _check_object_origin(requester, object_id, origins):
    """Refuse to sign a delete token for an object the requester does not own.

    WHAT THE SITE NOW KNOWS, AND WHAT IT STILL DOES NOT
    ---------------------------------------------------
    `issue_lease` records the first origin to lease each object id
    (model/DhtObjectOwner.py). That is read here, and it gives three cases:

      - THE REQUESTER OWNS IT. Sign, however many origins are authorised. This
        is the case that did not exist before: a multi-origin deployment could
        not obtain a delete token for anything.
      - ANOTHER ORIGIN OWNS IT. Refuse, however few origins are authorised --
        including when the allow-list currently holds exactly one peer. An
        origin whose key was rotated, or one that was removed from the list and
        replaced, must not inherit authority over the previous origin's objects
        by being the only name left. Recovery is an operator changing the row,
        which is a deliberate act; the alternative is a silent inheritance of
        delete authority, which is not.
      - NO ROW AT ALL. Fall back to exactly the behaviour that existed before
        this table: sign if there is one authorised origin, refuse if there are
        two or more.

    WHY A ROW-LESS OBJECT IS NOT SIMPLY REFUSED
    -------------------------------------------
    Every object placed before this table existed has no row, and this
    deployment's entire stored corpus predates it. Refusing them all would make
    recall -- the destructive verb the whole of Phase 3 exists to make safe --
    stop working for everything currently in the DHT, and it would do so
    silently from an operator's point of view (a refused revocation just retries
    forever). The fallback is not a weakening: it is the code that shipped, and
    it is still tight where it needs to be, because with one authorised origin
    the requester provably is the only peer that could have placed anything.

    An unreadable record is NOT a row-less object -- see object_owner -- and is
    refused.

    Refusing remains the recoverable direction. A refused revocation leaves the
    node's recall tombstone in place (a refusal is not terminal in
    RecallRecord.Outstanding), so the purge retries and an operator sees "no
    delete token" in the report. Signing wrongly destroys other people's bytes
    and nothing brings them back.
    """
    try:
        owner = object_owner(object_id)
    except OwnershipUnavailable as exc:
        logger.error(
            "storage coordinator: refusing delete tokens for object %s because "
            "the ownership record could not be read (%s)", object_id, exc,
        )
        raise PermissionError(
            "the coordinator could not read who owns object %s (%s), and will "
            "not treat an unreadable record as an unowned object" % (object_id, exc)
        )

    if owner is not None:
        if owner == requester:
            return
        # Logged as well as refused: the legitimate way to reach this is an
        # origin whose identity key was replaced, and the operator needs to be
        # able to find out that THAT is why recall stopped working, rather than
        # reading it as the network being broken. The fix is to retarget the
        # dht_object_owner rows, which is deliberately a manual act.
        logger.warning(
            "storage coordinator: %s asked to delete shards of object %s, which "
            "%s placed; refusing", requester, object_id, owner,
        )
        raise PermissionError(
            "object %s was placed by %s, not by %s: a delete token is only ever "
            "issued to the origin that placed the object"
            % (object_id, owner, requester)
        )

    if len(origins) <= 1:
        return
    raise PermissionError(
        "the coordinator has no record of who placed object %s -- it predates "
        "the ownership table -- and with more than one authorized origin %s "
        "cannot be assumed to own it, so a delete token cannot be issued "
        "without risking another origin's data" % (object_id, requester)
    )


def issue_revocations(raw_body, requester_header, signature_header):
    """Sign a batch of shard-delete tokens for ONE object.

    Same trust model as issue_lease, deliberately and entirely: the requester
    must be on STORAGE_LEASE_REQUESTER_PEERS, must sign the request body with the
    ed25519 key embedded in its own peer id, and gets tokens signed with the
    coordinator key every storage node already pins. Nothing new is distributed
    and no new authority exists -- a node that can be written to can now be
    revoked from, by exactly the same party that authorised the write.

    Each token names ONE shard, ONE recipient and ONE requester. A recipient is
    mandatory here where it is optional for a lease: a recipient-less delete
    token would work against every peer holding those bytes, and any peer that
    saw it could replay it against all the others. The requester closes the other
    half of the same hole -- the token names who may PRESENT it, not merely who
    may honour it, so a token captured in flight is inert in other hands.

    OWNERSHIP
    ---------
    That the requester owns object_id IS checked, against the row `issue_lease`
    writes on the first lease for each object (model/DhtObjectOwner.py). See
    _check_object_origin for the three cases and for what happens to an object
    that predates the table.

    ROLLOUT: SIGN FIRST, THEN UPGRADE THE NODES
    -------------------------------------------
    `requester` is inside the signed message, so it is a wire break, and both
    directions fail closed:

      - an OLD holder given a NEW token rebuilds the message without the
        requester line, so the signature does not verify and it refuses to
        delete;
      - a NEW holder given an OLD token sees an empty requester, which cannot
        equal a real peer id, and refuses before reaching the signature. An
        unbound token is never honoured once a node knows about binding.

    Because a refusal is not a terminal answer in the node's recall ledger, the
    tombstone survives and the background pass retries every ten minutes. So
    deploying this coordinator ahead of the nodes costs delayed recalls, not lost
    ones: recalls against not-yet-upgraded holders sit refused-and-retrying and
    complete on their own as those holders are upgraded. Deploying in the other
    order is not possible anyway -- there is one coordinator and it is here.
    """
    key = _signing_key()
    if key is None:
        raise RuntimeError("storage coordinator is not configured")
    if len(raw_body) > 65536:
        raise ValueError("revocation request is too large")
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("revocation request is not valid JSON")
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("unsupported revocation request version")
    requester = str(payload.get("requester") or "")
    origins = _authorized_requesters()
    if requester != requester_header or requester not in origins:
        raise PermissionError("requester is not an authorized storage origin")
    try:
        signature = _decode_unpadded(signature_header)
        peer_verify_key(requester).verify(raw_body, signature)
    except (BadSignatureError, ValueError, TypeError):
        raise PermissionError("invalid node identity signature")

    now = int(time.time())
    timestamp = payload.get("timestamp")
    nonce = str(payload.get("nonce") or "")
    object_id = str(payload.get("object_id") or "")
    if not isinstance(timestamp, int) or abs(now - timestamp) > 300:
        raise ValueError("request timestamp is outside the allowed clock skew")
    if not HEX_ID.fullmatch(object_id):
        raise ValueError("invalid object ID")
    if len(nonce) < 16 or len(nonce) > 128:
        raise ValueError("invalid nonce")
    shards = payload.get("shards")
    if not isinstance(shards, list) or not shards:
        raise ValueError("no shards were named")
    if len(shards) > MAX_REVOCATIONS_PER_REQUEST:
        raise ValueError("too many shards in one revocation request")
    # Ahead of the rate limit, because a request that can never be signed should
    # not spend a trusted origin's allowance or burn its nonce.
    _check_object_origin(requester, object_id, origins)
    _check_rate_and_replay(requester, nonce, now, scope="revocation",
                           limit=MAX_REVOCATION_REQUESTS_PER_MINUTE)

    issued = []
    for entry in shards:
        if not isinstance(entry, dict):
            raise ValueError("invalid shard entry")
        shard_id = str(entry.get("shard_id") or "")
        recipient = str(entry.get("recipient") or "")
        if not HEX_ID.fullmatch(shard_id):
            raise ValueError("invalid shard ID")
        # Raises if the recipient is not a real peer id, which is also what
        # guarantees the token can only ever be honoured by one node.
        peer_verify_key(recipient)
        revocation = {
            "version": 1,
            "object_id": object_id,
            "shard_id": shard_id,
            "recipient": recipient,
            # The authenticated requester, never a value out of the payload: the
            # body is signed by this peer, so the two are the same here, but
            # taking it from the verified variable means a future edit to the
            # payload shape cannot quietly unbind the token.
            "requester": requester,
            "issued_at": now,
            "expires_at": now + REVOCATION_SECONDS,
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
        }
        signed = key.sign(_revocation_message(revocation)).signature
        revocation["signature"] = base64.b64encode(signed).decode("ascii").rstrip("=")
        issued.append(revocation)
    return {"revocations": issued}


def validate_heartbeat(raw_body, node_header, signature_header, user_agent):
    if user_agent != STORAGE_USER_AGENT:
        raise PermissionError("invalid storage client user agent")
    if len(raw_body) > 65536:
        raise ValueError("heartbeat is too large")
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("heartbeat is not valid JSON")
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("unsupported heartbeat version")
    node_id = str(payload.get("node_id") or "")
    if node_id != str(node_header or ""):
        raise PermissionError("heartbeat node identity mismatch")
    try:
        signature = _decode_unpadded(signature_header)
        peer_verify_key(node_id).verify(raw_body, signature)
    except (BadSignatureError, ValueError, TypeError):
        raise PermissionError("invalid heartbeat identity signature")
    now = int(time.time())
    timestamp = payload.get("timestamp")
    nonce = str(payload.get("nonce") or "")
    capacity = payload.get("capacity_bytes")
    # used_bytes: what the node is holding, measured on its own disk. ABSENT is
    # not zero -- a node on an older build reports nothing, and treating that as
    # "empty" would make the pool-levelling planner aim every surplus shard at
    # it. None survives all the way to the column, which is nullable for this
    # reason (roadmap/dht-storage-roadmap.md phase 2b).
    used_bytes = payload.get("used_bytes")
    if used_bytes is not None:
        if not isinstance(used_bytes, int) or isinstance(used_bytes, bool):
            raise ValueError("invalid used_bytes")
        # Negative is nonsense; above the declared capacity is a node
        # misreporting or mis-measuring, and either way it must not be trusted
        # to plan moves against. Clamp rather than refuse the whole heartbeat:
        # losing presence over a bad gauge is worse than an imprecise gauge.
        if used_bytes < 0:
            used_bytes = None
    platform = str(payload.get("platform") or "")
    gateway_enabled = payload.get("gateway_enabled", False)
    gateway_verified = payload.get("gateway_verified", False)
    dcs_worker = payload.get("dcs_worker", False)
    monitor = payload.get("monitor", False)
    # Default False, like every role added after the first clients shipped. A
    # node that has never heard of these fields is not broken and must not be
    # refused — see the note on `monitor` below.
    gpu_compute = payload.get("gpu_compute", False)
    cpu_compute = payload.get("cpu_compute", False)
    payment_channel = payload.get("payment_channel", False)
    microvm = payload.get("microvm", False)
    i2p_destination = str(payload.get("i2p_destination") or "")
    if not isinstance(timestamp, int) or abs(now - timestamp) > 300:
        raise ValueError("heartbeat timestamp is outside the allowed clock skew")
    if len(nonce) < 16 or len(nonce) > 128:
        raise ValueError("invalid heartbeat nonce")
    # Zero is a legitimate report, not a missing field: a dedicated gateway or
    # probe node donates no disk at all. Anything above zero must still clear
    # the 64 MiB floor, so a storage node cannot claim a useless sliver.
    # network_capacity_bytes sums this, and active_storage_node_count counts
    # only nodes above zero, so a gateway never inflates storage figures.
    if not isinstance(capacity, int) or isinstance(capacity, bool):
        raise ValueError("invalid storage capacity")
    if capacity != 0 and (capacity < 64 << 20 or capacity > MAX_CAPACITY_BYTES):
        raise ValueError("invalid storage capacity")
    if not PLATFORM.fullmatch(platform):
        raise ValueError("invalid storage platform")
    if not isinstance(gateway_enabled, bool) or not isinstance(gateway_verified, bool):
        raise ValueError("invalid gateway role flags")
    if not isinstance(dcs_worker, bool):
        raise ValueError("invalid dcs role flag")
    # Absent is normal for clients that predate the role, so default rather
    # than refuse -- rejecting the heartbeat would take a working node off the
    # map over a field it has never heard of.
    if not isinstance(monitor, bool):
        raise ValueError("invalid monitor role flag")
    if not isinstance(gpu_compute, bool) or not isinstance(cpu_compute, bool):
        raise ValueError("invalid compute role flags")
    if not isinstance(payment_channel, bool):
        raise ValueError("invalid payment channel flag")
    if not isinstance(microvm, bool):
        raise ValueError("invalid microvm flag")
    # The destination is optional (older clients and probes may omit it), but a
    # malformed one is rejected rather than stored -- the bootstrap service would
    # otherwise hand a broken address to every joining node.
    if i2p_destination and not I2P_DESTINATION.fullmatch(i2p_destination):
        raise ValueError("invalid i2p destination")
    if gateway_verified and not gateway_enabled:
        raise ValueError("a disabled gateway cannot be verified")
    if gateway_verified:
        _validate_gateway_registration(
            payload.get("gateway_registration"), node_id, now
        )
    traffic = _validate_traffic(payload.get("traffic"))
    placement = _validate_placement(payload.get("placement"))
    _check_rate_and_replay(node_id, nonce, now)
    return {
        "node_id": node_id,
        "placement": placement,
        "capacity_bytes": capacity,
        "used_bytes": used_bytes,
        "platform": platform,
        "gateway_enabled": gateway_enabled,
        "gateway_verified": gateway_verified,
        "dcs_worker": dcs_worker,
        "monitor": monitor,
        "gpu_compute": gpu_compute,
        "cpu_compute": cpu_compute,
        "payment_channel": payment_channel,
        "microvm": microvm,
        "i2p_destination": i2p_destination,
        "traffic": traffic,
    }


# A node's own account of what it moved in its last window. Self-reported and
# unverifiable, which is why it is bounded rather than trusted: the figure is
# published as network throughput, so an unbounded value would let one node
# decide what the whole network appears to be doing.
#
# 100 Gbit/s over the window is far above anything a volunteer machine does and
# far below overflow. A node claiming more is not describing a fast link, it is
# describing a bug or a lie, and either way the number should not reach a page.
MAX_TRAFFIC_BYTES = 100 * 1000 ** 3 // 8 * 3600
MAX_TRAFFIC_REQUESTS = 100_000_000
MIN_TRAFFIC_WINDOW_SECONDS = 5
MAX_TRAFFIC_WINDOW_SECONDS = 86400


def _validate_traffic(block):
    """Optional traffic report. Returns a clean dict, never raises on absence.

    Absent is the normal case for older clients, so a missing block is zeroed
    rather than refused — rejecting the heartbeat would take a working node
    off the map over a field it has never heard of.
    """
    zero = {"bytes": 0, "requests": 0, "window_seconds": 0}
    if block is None:
        return zero
    if not isinstance(block, dict):
        raise ValueError("invalid traffic report")

    def whole(value, limit, name):
        if value is None:
            return 0
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("invalid traffic %s" % name)
        return min(value, limit)

    window = whole(block.get("window_seconds"), MAX_TRAFFIC_WINDOW_SECONDS, "window")
    # A window shorter than a few seconds turns rounding into throughput: one
    # request in a claimed 1-second window is a very different number from the
    # same request measured over a minute, and the node chooses the divisor.
    if window and window < MIN_TRAFFIC_WINDOW_SECONDS:
        raise ValueError("traffic window is too short to be a rate")
    if not window:
        return zero
    return {
        "bytes": whole(block.get("bytes"), MAX_TRAFFIC_BYTES, "bytes"),
        "requests": whole(block.get("requests"), MAX_TRAFFIC_REQUESTS, "requests"),
        "window_seconds": window,
    }


# --- dispersal health -------------------------------------------------------
#
# A node's own account of whether dispersal is WORKING, as opposed to what it
# holds. Carried on the heartbeat rather than fetched from the node, because the
# alternative is an admin page that dials nine nodes over I2P inside a request
# handler -- see roadmap/dht-storage-roadmap.md phase 4.3 and the note on the Go
# side's heartbeat.Placement.
#
# Every field here is optional and every one of them is bounded. The block is
# self-reported and unverifiable, exactly like traffic: a node cannot be allowed
# to decide how big a number reaches an operator's page, and a node running a
# build that has never heard of the block must still be accepted.

# A ledger figure. Well above anything the fleet holds (production carries
# ~12,000 objects) and far below anything that breaks a bigint column.
MAX_PLACEMENT_COUNT = 1 << 40
# A pass older than a week is "very stale" whatever the node claims.
MAX_PLACEMENT_AGE_SECONDS = 7 * 86400
# The node sends at most five. Headroom, then a hard stop -- this list is
# rendered, and an unbounded one is an unbounded page.
MAX_REPORTED_REFUSALS = 8
MAX_REFUSAL_REASON_CHARS = 64
MAX_REFUSAL_PEER_CHARS = 64
_REFUSAL_PEER = re.compile(r"^[A-Za-z0-9]{1,%d}$" % MAX_REFUSAL_PEER_CHARS)


def _placement_count(block, key):
    """One optional counter. ABSENT STAYS ABSENT -- None, never 0.

    The whole point of this block is that an operator can tell "this node has
    nothing to report" from "this node reports nothing wrong". A missing counter
    defaulted to zero would put the second on screen when the first is true,
    which is the failure shape phase 4.3 exists to end.
    """
    value = block.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("invalid placement %s" % key)
    if value < 0:
        # Nonsense rather than a measurement. Discarded to None, not clamped to
        # zero: a negative count means the gauge is broken, and a broken gauge
        # must not read as a healthy one.
        return None
    return min(value, MAX_PLACEMENT_COUNT)


def _validate_refusals(raw):
    """Who is refusing this node's shards, and what they said.

    The reason is the entire reason this exists. "3 failures" sends an operator
    to SSH and grep, which is how three peers spent a week refusing every round
    -- one cache-only, one out of capacity, one rejecting the coordinator's lease
    signature -- while the site showed the same number for all three.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("invalid placement refusals")
    out = []
    for entry in raw[:MAX_REPORTED_REFUSALS]:
        if not isinstance(entry, dict):
            raise ValueError("invalid placement refusal")
        peer = str(entry.get("peer") or "")
        if not _REFUSAL_PEER.fullmatch(peer):
            # A peer id is base58 and nothing else. Skipped rather than fatal:
            # one malformed entry must not take a node off the map, and the
            # count below still says somebody is refusing.
            continue
        count = entry.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("invalid placement refusal count")
        # Truncated and stripped of control characters. The node chooses this
        # string and it is rendered; the template writes it with textContent, so
        # this is about length and legibility rather than injection.
        reason = "".join(
            ch for ch in str(entry.get("reason") or "") if ch.isprintable()
        ).strip()[:MAX_REFUSAL_REASON_CHARS]
        out.append({
            "peer": peer,
            "count": min(count, MAX_PLACEMENT_COUNT),
            # Never blank. A blank cell reads as "no reason, therefore no
            # problem", which is the opposite of what a refusal means.
            "reason": reason or "refused, reason not reported",
        })
    return out


def _validate_placement(block):
    """Optional dispersal-health report. Returns None on absence, NEVER zeros.

    A node running a build that predates this block sends nothing, and that is
    not an error -- the fleet upgrades at different times and refusing the
    heartbeat would take working nodes off the map. It is also not a node with
    zero failures: None survives all the way to a nullable column so the admin
    panel can render "not reporting".
    """
    if block is None:
        return None
    if not isinstance(block, dict):
        raise ValueError("invalid placement report")
    report = {
        key: _placement_count(block, key)
        for key in (
            "objects", "under_replicated", "local_only", "fully_dispersed",
            "placed", "failed", "unassignable", "attempted", "peers",
            # Absent when the node's recall ledger would not read. Distinct from
            # zero outstanding, and the distinction is why they are counted at
            # all -- an unreadable row used to vanish from every total.
            "recalls_outstanding", "recalls_deferred", "recalls_unreadable",
        )
    }
    age = _placement_count(block, "age_seconds")
    report["age_seconds"] = (
        None if age is None else min(age, MAX_PLACEMENT_AGE_SECONDS)
    )
    report["refusals"] = _validate_refusals(block.get("refusals"))
    return report
