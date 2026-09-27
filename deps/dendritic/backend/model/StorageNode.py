"""Last-seen records for native storage clients.

The heartbeat endpoint deliberately does not persist source IP addresses. A
signed libp2p node ID provides stable deduplication for the active-node count.
"""

import datetime as _datetime
import json as _json
import re as _re

from shared import app, db
from sqlalchemy.exc import IntegrityError as _IntegrityError


ACTIVE_WINDOW_SECONDS = 15 * 60


class StorageNode(db.Model):
    __tablename__ = "storage_node"

    node_id = db.Column(db.String(128), primary_key=True)
    first_seen_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow
    )
    last_seen_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True
    )
    capacity_bytes = db.Column(db.BigInteger, nullable=False)
    # used_bytes is what the node is ACTUALLY holding, as measured on its own
    # disk. Nullable and defaulted to NULL on purpose: a node running a build
    # that predates the field reports nothing, and NULL means "not measured"
    # while 0 means "measured, and empty". Levelling the storage pools has to
    # tell those apart -- treating an unreporting node as empty would send every
    # surplus shard at it (roadmap/dht-storage-roadmap.md phase 2b).
    used_bytes = db.Column(db.BigInteger, nullable=True)
    # The operator is retiring this machine (roadmap phase 2b step 4). The node
    # says so in the DHT capacity record too, which is what makes OWNERS move
    # shards off it -- only an owner can, because only an owner has the placement
    # ledger and can obtain a revocation. This copy exists so the SITE's report
    # does not go on proposing a machine as a destination while the fleet has
    # already stopped using it as one, and so the admin panel can say which
    # machines are on their way out.
    #
    # NOT NULL with a default, unlike used_bytes: false is the honest reading of
    # a node that does not report the field, because a build old enough to omit
    # it has no drain to describe.
    draining = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )
    platform = db.Column(db.String(64), nullable=False)
    user_agent = db.Column(db.String(128), nullable=False)
    # Egress IP of the last heartbeat, and its country-centroid coordinates.
    #
    # The privacy guarantee this system makes is PEER-TO-PEER: volunteers must
    # not be able to identify one another, which is why shard exchange runs over
    # I2P and peers only ever see a .b32.i2p destination. It was never a promise
    # that the site operator cannot see an egress IP -- the heartbeat is a plain
    # HTTPS POST, so the same address already appears in the web server's logs,
    # exactly as it does when that person simply visits the site.
    #
    # Country-level only (services/geoip.py): enough to place a dot on the right
    # region, with no city database and no street-level precision.
    last_ip = db.Column(db.String(64), nullable=True)
    country_code = db.Column(db.String(2), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    gateway_enabled = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )
    gateway_verified = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )
    # Accepts container deployments (DCS worker). Drives the yellow role on the
    # admin map and marks the node as a container host on the network.
    dcs_worker = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )
    # Runs the status monitor: checks the site from where it is and publishes
    # the result. Reported so the map can draw the role, and so the operator can
    # see at a glance how many vantage points the status page actually has —
    # a page measured from one place is barely measured at all.
    monitor_enabled = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # Compute roles. Split into two because they are two different offers: most
    # volunteers have idle cores and no usable GPU, the two are scheduled and
    # priced separately, and collapsing them into one "compute" flag would hide
    # which of the two the network is actually short of.
    #
    # AVAILABLE, not busy. A node paused because its owner started a game is
    # still a compute provider — dropping it while paused would make the network
    # look like it collapses every evening when people get home.
    gpu_compute = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )
    cpu_compute = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # Holds at least one open payment channel and can settle off-chain.
    #
    # Reported separately from every other role because it is orthogonal to all
    # of them: a storage node, a gateway or a compute node may or may not be
    # settling through a channel, and which ones do is the single most useful
    # thing to see on a map while the channel layer is being rolled out.
    payment_channel = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # Whether this node can host a microVM. The one flag that decides whether
    # ARBITRARY submitted code may be placed here — a container node runs signed
    # catalogue images only, and no amount of spare capacity changes that.
    microvm = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # -- roles a visitor can pick that had nowhere to be recorded --------------
    #
    # node_release.ROLES offers seven roles on /network. Four of them —
    # probe, validator, mailbox, delegate — had NO COLUMN, so a visitor could
    # select one, download a config carrying it, run the node, and the network
    # would never show it. The heartbeat had nowhere to put the flag and the
    # peer API had nothing to emit.
    #
    # That is not a graph bug with a graph fix: the site was offering roles it
    # could not observe. These four columns are the missing half.

    # Independently checks that other gateways are reachable.
    probe_enabled = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # Re-fetches published content and confirms it matches what was signed.
    validator_enabled = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # Holds tip messages for creators who are offline. Holds NO keys and no
    # money; it forwards. Tracked separately from `delegate` because the
    # difference between them is the entire security question.
    mailbox_enabled = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # Authorised on chain to co-sign incoming tips for a creator who is offline.
    # Holds a signing key for that one purpose; the contract refuses to let it
    # withdraw, close a channel, or be paid.
    delegate_enabled = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    # Traffic the node moved during its last reporting window.
    #
    # A WINDOW, not a lifetime counter. A cumulative counter has to be
    # differenced against the previous heartbeat to become a rate, and it resets
    # to zero whenever the node restarts — which reads as a large negative
    # delta, i.e. as an enormous burst of traffic exactly when a node is
    # flapping. Reporting "bytes in the last N seconds" makes a restart worth
    # nothing rather than worth a spike.
    traffic_bytes = db.Column(db.BigInteger, nullable=False, default=0, server_default="0")
    traffic_requests = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    traffic_window_seconds = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    # The node's own base32 garlic destination, self-reported in the heartbeat.
    # It is what other nodes dial, so the bootstrap service can hand this node out
    # as a LIVE peer instead of relying on one hardcoded bootstrap address.
    i2p_destination = db.Column(db.String(70), nullable=True)

    # Whether DISPERSAL IS WORKING on this node, as opposed to what it holds.
    #
    # The site could see the size of every pool and nothing about whether shards
    # were reaching anybody, so every fault this network has had was diagnosed by
    # SSHing to a node and grepping its journal — five of them survived for days
    # that way (roadmap/dht-storage-roadmap.md phase 4.3). The node already knows
    # all of it: ledger totals, per-pass placed/failed, which peers are refusing
    # and WHY, and the recall counters.
    #
    # Stored as the validated JSON document rather than a column per counter.
    # There are a dozen figures plus a variable-length list of refusing peers,
    # the site does no SQL aggregation over them (the fleet is ten machines and
    # the roll-up is a Python loop in services/dispersal_health.py), and a
    # nullable text column makes "this node has never reported" structural rather
    # than a convention every reader has to remember.
    #
    # NULL means NOT REPORTING and must render as such. It is not a node with
    # zero failures. Drawing an unknown as a number is the single most repeated
    # mistake in this codebase — it is what made a draining backfill counter pass
    # for replication while every peer's shard directory stayed empty.
    placement_health = db.Column(db.Text, nullable=True)
    # When the node last sent that block. Separate from last_seen_at because the
    # two go stale independently: a node that downgrades, or whose replicate loop
    # dies, keeps heartbeating happily while its dispersal report stops moving.
    # Without this the last figures it managed would stay on screen forever,
    # authoritative and wrong.
    placement_reported_at = db.Column(db.DateTime, nullable=True)


def record_storage_heartbeat(payload, user_agent, remote_ip=None):
    now = _datetime.datetime.utcnow()
    node = db.session.query(StorageNode).get(payload["node_id"])
    if node is None:
        # Insert-if-absent is a race: two heartbeats from the same node (or a
        # retry overlapping the original) both read None and both INSERT, and
        # the loser dies on storage_node_pkey. That surfaced as a 503 to the
        # node, which retried, raced again, and never appeared in the fleet --
        # so a node could be healthy and permanently invisible.
        #
        # Reserve the row in a SAVEPOINT so a conflict rolls back only the
        # INSERT, not the caller's transaction, then re-read the winner's row
        # and fall through to the update path.
        try:
            with db.session.begin_nested():
                node = StorageNode(
                    node_id=payload["node_id"],
                    first_seen_at=now,
                    last_seen_at=now,
                    capacity_bytes=payload["capacity_bytes"],
                    used_bytes=payload.get("used_bytes"),
                    platform=payload["platform"],
                    user_agent=user_agent,
                )
                db.session.add(node)
                db.session.flush()
        except _IntegrityError:
            node = db.session.query(StorageNode).get(payload["node_id"])
            if node is None:
                raise
            node.last_seen_at = now
            node.capacity_bytes = payload["capacity_bytes"]
            if payload.get("used_bytes") is not None:
                node.used_bytes = payload["used_bytes"]
            node.platform = payload["platform"]
            node.user_agent = user_agent
    else:
        node.last_seen_at = now
        node.capacity_bytes = payload["capacity_bytes"]
        # Only overwrite when the node actually reported. A build that predates
        # the field sends nothing, and blanking the last known figure on every
        # such heartbeat would make an upgraded fleet look unmeasured whenever
        # one old node checked in.
        if payload.get("used_bytes") is not None:
            node.used_bytes = payload["used_bytes"]
        node.platform = payload["platform"]
        node.user_agent = user_agent
    node.draining = bool(payload.get("draining", False))
    node.gateway_enabled = bool(payload.get("gateway_enabled", False))
    node.gateway_verified = bool(payload.get("gateway_verified", False))
    node.dcs_worker = bool(payload.get("dcs_worker", False))
    node.monitor_enabled = bool(payload.get("monitor", False))
    node.gpu_compute = bool(payload.get("gpu_compute", False))
    node.cpu_compute = bool(payload.get("cpu_compute", False))
    node.payment_channel = bool(payload.get("payment_channel", False))
    node.microvm = bool(payload.get("microvm", False))
    node.probe_enabled = bool(payload.get("probe", False))
    node.validator_enabled = bool(payload.get("validator", False))
    node.mailbox_enabled = bool(payload.get("mailbox", False))
    node.delegate_enabled = bool(payload.get("delegate", False))
    traffic = payload.get("traffic") or {}
    if isinstance(traffic, dict):
        node.traffic_bytes = max(0, int(traffic.get("bytes") or 0))
        node.traffic_requests = max(0, int(traffic.get("requests") or 0))
        node.traffic_window_seconds = max(0, int(traffic.get("window_seconds") or 0))
    # Only written when the node actually reported, exactly like used_bytes: a
    # build that predates the block sends nothing, and blanking the last figures
    # on every such heartbeat would make an upgraded fleet flicker to "unknown"
    # whenever one old node checked in. Staleness is handled by
    # placement_reported_at instead, which only moves when there is a real
    # report behind it -- so a node that stops reporting ages out of the panel
    # rather than freezing its last good numbers there.
    placement = payload.get("placement")
    if placement is not None:
        node.placement_health = _json.dumps(placement, sort_keys=True)
        node.placement_reported_at = now
    dest = payload.get("i2p_destination")
    if dest:
        node.i2p_destination = str(dest)[:70]
    if remote_ip:
        node.last_ip = str(remote_ip)[:64]
        try:
            from services.geoip import latlon_for_ip

            lat, lon, code = latlon_for_ip(remote_ip)
            node.latitude, node.longitude, node.country_code = lat, lon, code
        except Exception:
            # Geolocation is decoration; never fail a heartbeat over it.
            app.logger.debug("storage node geoip failed", exc_info=True)
    db.session.add(node)
    return node


def active_storage_nodes(now=None):
    """Active nodes with map coordinates, for the admin world map.

    Only nodes we could actually place are returned -- a node whose country is
    unknown gets no dot rather than a misleading one at (0, 0).
    """
    now = now or _datetime.datetime.utcnow()
    cutoff = now - _datetime.timedelta(seconds=ACTIVE_WINDOW_SECONDS)
    rows = (
        db.session.query(StorageNode)
        .filter(
            StorageNode.last_seen_at >= cutoff,
            StorageNode.latitude.isnot(None),
            StorageNode.longitude.isnot(None),
        )
        .all()
    )
    return [
        {
            # Truncated node id, not the full key: enough to tell dots apart in
            # a tooltip without publishing a stable identifier in the DOM.
            "id": node.node_id[:12],
            # Needed so the map can tell when a node is ALSO a visitor right
            # now and draw one alternating dot instead of separate dots stacked
            # on the same spot.
            "ip": node.last_ip,
            "lat": node.latitude,
            "lon": node.longitude,
            "country": node.country_code,
            "capacity_bytes": int(node.capacity_bytes or 0),
            # How full this pool is. None rather than 0 when the node has not
            # reported: the map draws "unmeasured" differently from "empty", and
            # collapsing them is the same mistake that made a backfill counter
            # look like progress while every node stayed empty.
            "used_bytes": None if node.used_bytes is None else int(node.used_bytes),
            # Being retired. Reported so a machine on its way out is visible as
            # such rather than as a pool that is mysteriously emptying.
            "draining": bool(node.draining),
            "platform": node.platform,
            "kind": "storage",
            # The two roles are reported separately so the map can colour a dot
            # per role it actually holds. A storage node that also gateways
            # draws blue+green; a dedicated -gateway-only host reports zero
            # capacity and draws green alone.
            "storage": bool(node.capacity_bytes and node.capacity_bytes > 0),
            # gateway_verified, NOT gateway_enabled: green means a quorum of
            # external probes reached it on TCP 443, not that it asked to.
            "gateway": bool(node.gateway_verified),
            # Container host (DCS worker): the map draws this role yellow.
            "dcs": bool(node.dcs_worker),
            # Status monitor: the map draws this role purple.
            "monitor": bool(node.monitor_enabled),
            # Compute providers: orange for GPU, pink for CPU. Two roles rather
            # than one, because a node offering both should draw both — the map
            # is the quickest read on how much of each the network has, and
            # collapsing them hides exactly that.
            "gpu": bool(node.gpu_compute),
            "cpu": bool(node.cpu_compute),
            # Settles through a payment channel: cyan. Orthogonal to every
            # other role, so it cycles alongside whatever else the node does.
            "channel": bool(node.payment_channel),
            # Hardware isolation. Placement refuses to send arbitrary code to a
            # node without it, so this is a capability rather than a detail.
            "microvm": bool(node.microvm),
            # How to REACH this node for compute. Self-reported in the
            # heartbeat, exactly as gateways report theirs — so dispatch
            # discovers where to send work from the network rather than from a
            # configured address that names one machine and fails with it.
            "i2p_destination": node.i2p_destination or "",
        }
        for node in rows
    ]


_B32_RE = _re.compile(r"^[a-z2-7]{52}$")


def active_bootstrap_peers(limit=3, exclude_node_id=None, now=None):
    """A random sample of currently-active nodes that reported an I2P destination,
    formatted as libp2p bootstrap multiaddrs. This is the live bootstrap service:
    a joining node's heartbeat is answered with several REACHABLE peers, not one
    hardcoded address that may be down. Random order so bootstrap load spreads and
    one dead node is never always first; the requester excludes itself."""
    now = now or _datetime.datetime.utcnow()
    cutoff = now - _datetime.timedelta(seconds=ACTIVE_WINDOW_SECONDS)
    query = (
        db.session.query(StorageNode.node_id, StorageNode.i2p_destination)
        .filter(
            StorageNode.last_seen_at >= cutoff,
            StorageNode.i2p_destination.isnot(None),
            StorageNode.i2p_destination != "",
        )
    )
    if exclude_node_id:
        query = query.filter(StorageNode.node_id != exclude_node_id)
    # Over-fetch then trim: a few rows may fail validation, and randomising in SQL
    # is what makes each answer a different reachable set.
    rows = query.order_by(db.func.random()).limit(max(limit * 3, limit)).all()
    peers = []
    for node_id, dest in rows:
        dest = (dest or "").strip().lower()
        if not _B32_RE.match(dest) or not node_id:
            continue
        peers.append("/garlic32/%s/p2p/%s" % (dest, node_id))
        if len(peers) >= limit:
            break
    return peers


def active_i2p_destinations(now=None):
    """Every distinct garlic destination a currently-active node advertises.

    The probe list. Distinct DESTINATIONS rather than rows on purpose: several
    rows can name the same address, and probing per row would double the I2P
    work and let two probes of one address disagree with each other.
    """
    now = now or _datetime.datetime.utcnow()
    cutoff = now - _datetime.timedelta(seconds=ACTIVE_WINDOW_SECONDS)
    rows = (
        db.session.query(StorageNode.i2p_destination)
        .filter(
            StorageNode.last_seen_at >= cutoff,
            StorageNode.i2p_destination.isnot(None),
            StorageNode.i2p_destination != "",
        )
        .distinct()
        .all()
    )
    out = []
    for (dest,) in rows:
        dest = (dest or "").strip().lower()
        if _B32_RE.match(dest) and dest not in out:
            out.append(dest)
    return out


def heartbeating_destinations(now=None):
    """Set form of active_i2p_destinations, for corroborating configured peers."""
    return set(active_i2p_destinations(now=now))


def active_storage_node_count(now=None):
    """Active nodes that actually donate storage.

    Zero-capacity nodes are excluded: a dedicated gateway heartbeats with the
    same signed document but donates no disk, and counting it here would
    overstate the storage network.
    """
    now = now or _datetime.datetime.utcnow()
    cutoff = now - _datetime.timedelta(seconds=ACTIVE_WINDOW_SECONDS)
    return (
        db.session.query(db.func.count(StorageNode.node_id))
        .filter(StorageNode.last_seen_at >= cutoff)
        .filter(StorageNode.capacity_bytes > 0)
        .scalar()
        or 0
    )


def network_capacity_bytes(now=None):
    """Total storage the ACTIVE p2p network is offering, in bytes.

    Sums the capacity each node reported in its most recent heartbeat, counting
    only nodes seen inside ACTIVE_WINDOW_SECONDS -- a node that stopped
    heartbeating has taken its disk with it, and counting it would overstate
    what the site can actually place.

    This is offered capacity, not free space, and it is self-reported by
    volunteers. Treat it as an upper bound.
    """
    now = now or _datetime.datetime.utcnow()
    cutoff = now - _datetime.timedelta(seconds=ACTIVE_WINDOW_SECONDS)
    return int(
        db.session.query(db.func.coalesce(db.func.sum(StorageNode.capacity_bytes), 0))
        .filter(StorageNode.last_seen_at >= cutoff)
        .scalar()
        or 0
    )


def network_throughput(now=None):
    """Bytes and requests per second across nodes that reported recently.

    Summed from each node's own window rather than measured here: this server
    never sees peer-to-peer shard traffic at all, so any figure it derived from
    its own logs would describe the website and call it the network.

    A node reporting a window of zero is skipped rather than treated as
    instantaneous — dividing by it is both a crash and, conceptually, a claim of
    infinite throughput.
    """
    now = now or _datetime.datetime.utcnow()
    cutoff = now - _datetime.timedelta(seconds=ACTIVE_WINDOW_SECONDS)
    rows = (
        db.session.query(
            StorageNode.traffic_bytes,
            StorageNode.traffic_requests,
            StorageNode.traffic_window_seconds,
        )
        .filter(StorageNode.last_seen_at >= cutoff)
        .all()
    )
    bytes_per_second = 0.0
    requests_per_second = 0.0
    reporting = 0
    for total_bytes, requests, window in rows:
        if not window or window <= 0:
            continue
        reporting += 1
        bytes_per_second += (total_bytes or 0) / float(window)
        requests_per_second += (requests or 0) / float(window)
    return {
        "bytes_per_second": bytes_per_second,
        "requests_per_second": requests_per_second,
        # Published so the page can say how many nodes the figure covers. A
        # throughput number without it invites reading a partial sample as the
        # whole network.
        "reporting_nodes": reporting,
    }


def human_rate(bytes_per_second):
    """A rate somebody can read. Bits are the convention for network speed."""
    bits = float(bytes_per_second or 0) * 8
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"):
        if bits < 1000 or unit == "Tbit/s":
            return "%.1f %s" % (bits, unit)
        bits /= 1000
    return "0 bit/s"


def network_summary(now=None):
    """{nodes, capacity_bytes, capacity_human} for the admin panel."""
    total = network_capacity_bytes(now=now)
    value = float(total)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            human = "%.1f %s" % (value, unit)
            break
        value /= 1024
    throughput = network_throughput(now=now)
    return {
        "nodes": active_storage_node_count(now=now),
        "capacity_bytes": total,
        "capacity_human": human,
        "active_window_seconds": ACTIVE_WINDOW_SECONDS,
        "bytes_per_second": throughput["bytes_per_second"],
        "requests_per_second": throughput["requests_per_second"],
        "traffic_human": human_rate(throughput["bytes_per_second"]),
        "traffic_reporting_nodes": throughput["reporting_nodes"],
    }
