from flask import Blueprint, jsonify, make_response, request

from services.storage_coordination import (
    bootstrap_document,
    issue_lease,
    issue_revocations,
    live_bootstrap_peers,
    validate_heartbeat,
)


storage_nodes_blueprint = Blueprint("storage_nodes", __name__)


def _no_store(response):
    response = make_response(response)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@storage_nodes_blueprint.route("/.well-known/syndichan/storage-node.json")
def storage_bootstrap():
    document = bootstrap_document()
    if document is None:
        return _no_store(jsonify({"error": "storage_coordinator_unavailable"})), 503
    return _no_store(jsonify(document))


@storage_nodes_blueprint.route("/api/v1/storage/leases", methods=["POST"])
def storage_lease():
    raw_body = request.get_data(cache=False, as_text=False)
    try:
        lease = issue_lease(
            raw_body,
            request.headers.get("X-Syndichan-Node"),
            request.headers.get("X-Syndichan-Signature"),
        )
    except PermissionError as exc:
        return _no_store(jsonify({"error": str(exc)})), 403
    except ValueError as exc:
        return _no_store(jsonify({"error": str(exc)})), 400
    except RuntimeError as exc:
        return _no_store(jsonify({"error": str(exc)})), 503
    return _no_store(jsonify(lease)), 201


@storage_nodes_blueprint.route("/api/v1/storage/revocations", methods=["POST"])
def storage_revocations():
    """Sign shard-DELETE tokens. Sits beside the lease route because it is the
    same authority answering the opposite question.

    A lease says "this peer may hold these bytes". A revocation says "this peer
    must drop them". Both are signed by the coordinator key every storage node
    already pins, and both are gated by the same requester allow-list, so no new
    trust root exists -- but the two are separate token types with separate
    signed messages so neither can ever be replayed as the other.
    """
    raw_body = request.get_data(cache=False, as_text=False)
    try:
        issued = issue_revocations(
            raw_body,
            request.headers.get("X-Syndichan-Node"),
            request.headers.get("X-Syndichan-Signature"),
        )
    except PermissionError as exc:
        return _no_store(jsonify({"error": str(exc)})), 403
    except ValueError as exc:
        return _no_store(jsonify({"error": str(exc)})), 400
    except RuntimeError as exc:
        return _no_store(jsonify({"error": str(exc)})), 503
    return _no_store(jsonify(issued)), 201


@storage_nodes_blueprint.route(
    "/api/v1/storage/nodes/heartbeat", methods=["POST"]
)
def storage_node_heartbeat():
    from model.StorageNode import (
        active_storage_node_count,
        record_storage_heartbeat,
    )
    from shared import db

    raw_body = request.get_data(cache=False, as_text=False)
    try:
        payload = validate_heartbeat(
            raw_body,
            request.headers.get("X-Syndichan-Node"),
            request.headers.get("X-Syndichan-Signature"),
            request.headers.get("User-Agent"),
        )
        # Same client-IP resolution the rest of the app uses, so a node behind
        # the same proxy chain as ordinary traffic is placed consistently.
        from services.client_ip import get_client_ip

        record_storage_heartbeat(
            payload, request.headers.get("User-Agent"), remote_ip=get_client_ip()
        )
        db.session.commit()
        count = active_storage_node_count()
        # The bootstrap service: answer every heartbeat with a few random peers
        # that are alive right now (never the node itself). A joining node keeps
        # heartbeating until these let it into the DHT, then keeps heartbeating
        # for presence -- the same beacon does double duty.
        peers = live_bootstrap_peers(limit=3, exclude_node_id=payload["node_id"])
    except PermissionError as exc:
        db.session.rollback()
        return _no_store(jsonify({"error": str(exc)})), 403
    except ValueError as exc:
        db.session.rollback()
        return _no_store(jsonify({"error": str(exc)})), 400
    except Exception:
        db.session.rollback()
        # Logged, not swallowed. This handler returned a bare 503 with no trace,
        # so a node heartbeating into a broken table reported "returned HTTP 503"
        # on its side and left nothing at all on ours -- the failure was real,
        # continuous, and invisible from both ends.
        from shared import app as _app
        _app.logger.exception("storage heartbeat could not be recorded")
        return _no_store(jsonify({"error": "heartbeat could not be recorded"})), 503
    return _no_store(jsonify({
        "ok": True,
        "active_nodes": count,
        "active_window_seconds": 15 * 60,
        "bootstrap_peers": peers,
    }))


@storage_nodes_blueprint.route("/api/v1/storage/nodes/status")
def storage_node_status():
    from model.StorageNode import network_summary

    summary = network_summary()
    return _no_store(jsonify({
        "active_nodes": summary["nodes"],
        "active_window_seconds": summary["active_window_seconds"],
        # Offered capacity across active nodes -- self-reported, so an upper
        # bound rather than guaranteed free space.
        "capacity_bytes": summary["capacity_bytes"],
        "capacity_human": summary["capacity_human"],
    }))


@storage_nodes_blueprint.route("/api/v1/network/peers")
def network_peers():
    """Per-peer view for the status page's peer canvas.

    Deliberately narrow. The heartbeat table stores `last_ip`, `latitude` and
    `longitude`; none of the three appear here and none ever should. A public
    endpoint that maps a node id to an address is a deanonymisation tool, and
    the canvas does not need one to be useful -- ring position is derived from
    the node id itself, which is exactly what the DHT does.

    Ring position mirrors Kademlia keyspace placement: sha256(node_id) folded
    into [0,1). Two nodes near each other on the ring are near each other in
    the keyspace, which is the property the drawing is trying to show.
    """
    import datetime

    import hashlib
    from model.StorageNode import ACTIVE_WINDOW_SECONDS, StorageNode, network_summary
    from shared import db

    def ring_position(node_id):
        digest = hashlib.sha256(node_id.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") / float(1 << 64)

    # Deliberately NOT active_storage_nodes(): that helper serves the admin
    # world map, so it (a) filters to nodes with known lat/lon -- which drops
    # every node that has not been geolocated, including the whole LAN fleet --
    # and (b) includes `last_ip`, which must never reach a public endpoint.
    # Query the model directly and select only publishable columns.
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=ACTIVE_WINDOW_SECONDS)
    nodes = (
        db.session.query(StorageNode)
        .filter(StorageNode.last_seen_at >= cutoff)
        .all()
    )
    summary = network_summary()
    peers = []
    for node in nodes:
        roles = []
        if node.gateway_enabled:
            roles.append("gateway")
        if node.dcs_worker:
            roles.append("worker")
        if node.monitor_enabled:
            roles.append("monitor")
        if node.payment_channel:
            roles.append("payment")
        if node.gpu_compute or node.cpu_compute:
            roles.append("compute")
        if node.microvm:
            roles.append("microvm")
        if node.probe_enabled:
            roles.append("probe")
        if node.validator_enabled:
            roles.append("validator")
        if node.mailbox_enabled:
            roles.append("mailbox")
        if node.delegate_enabled:
            roles.append("delegate")
        # Every heartbeating node stores; it is the baseline role rather than
        # an advertised capability, so it is appended last and never omitted.
        roles.append("storage")
        peers.append({
            # Truncated: enough to correlate across a page reload and to match
            # an operator's own logs, short enough not to be a durable handle.
            "id": node.node_id[:12],
            "pos": round(ring_position(node.node_id), 6),
            "roles": roles,
            "capacity_bytes": int(node.capacity_bytes or 0),
            "used_bytes": int(node.used_bytes or 0),
            "draining": bool(node.draining),
            "country": node.country_code or None,
        })
    peers.sort(key=lambda p: p["pos"])

    # Edges are DERIVED, not observed. We do not collect a peer graph, and the
    # canvas must not imply we do: each node is joined to its ring-adjacent
    # neighbours (the sibling list) plus a small number of longer chords at
    # exponentially increasing keyspace distance, which is the shape a Kademlia
    # routing table takes. The `derived` flag below is what the legend renders.
    count = len(peers)
    edges = []
    if count > 1:
        for index in range(count):
            edges.append([index, (index + 1) % count])
            step = 2
            while step < count:
                target = (index + step) % count
                if index < target:
                    edges.append([index, target])
                step *= 2
    return _no_store(jsonify({
        "peers": peers,
        "edges": edges,
        "edges_derived": True,
        "active_window_seconds": summary["active_window_seconds"],
        "capacity_bytes": summary["capacity_bytes"],
        "capacity_human": summary["capacity_human"],
    }))
