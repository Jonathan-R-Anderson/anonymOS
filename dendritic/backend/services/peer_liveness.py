"""Does this peer's I2P destination still answer? Measured, not assumed.

THE FAULT THIS EXISTS TO FIX
----------------------------
The signed bootstrap document handed every joining node two destinations whose
LeaseSet no longer resolves. Five volunteer nodes on one LAN were all up, all
heartbeating, all listed in `compute`, and none of them could find each other --
they spent every bootstrap round dialling the dead pair:

    I2P stream connect failed: RESULT=CANT_REACH_PEER MESSAGE="LeaseSet not found"

The site knew those nodes were alive over CLEARNET, because that is what a
heartbeat measures, and cheerfully published garlic destinations that nothing
could reach. One fault, network-wide.

TWO LAYERS, CHEAPEST FIRST
--------------------------
1. RECENCY (free, no network at all). The configured seed in
   STORAGE_BOOTSTRAP_PEERS is appended to every document forever and nothing can
   ever expire it. bootstrap_document() now publishes it only when a node
   heartbeating right now actually advertises that destination. That alone very
   likely removes today's two dead entries, at the cost of one SQL query.
2. THIS PROBE, for what recency cannot catch. The heartbeat is deliberately
   clearnet, so a node whose i2pd is down, whose tunnels never built, or whose
   key was regenerated keeps heartbeating happily and keeps advertising a dead
   destination -- record_storage_heartbeat only writes i2p_destination `if dest`,
   so it is never cleared. Recency cannot see any of that. A stream-level dial
   can.

WHY A STREAM, NOT AN HTTP REQUEST
---------------------------------
Nothing HTTP listens on a node's destination -- /healthz lives on the DCS bridge,
bound to a loopback/cluster address. The only listener on the garlic destination
is the libp2p host, and it accepts an inbound stream on any port. So the probe
asks exactly one question: does the LeaseSet resolve and does the destination
accept a stream. That is precisely the CANT_REACH_PEER boundary, and it draws
the distinction that matters:

  * SOCKS reply says the peer could not be reached -> GONE. The destination
    publishes no LeaseSet; the node behind it is not on the network.
  * The stream comes up -> the destination is live, EVEN IF libp2p later fails.
    One destination in production resolves fine and only fails Noise
    ("failed to negotiate security protocol: context deadline exceeded"). It is
    reachable, other nodes can still talk to it, and it may recover on its own.
    Judging on the full handshake would evict it; judging on the stream keeps it.
  * The stream comes up and the peer then says nothing -> UNHEALTHY. Reachable
    and broken. Counted as a failure like GONE, but logged as itself, because
    the two send whoever debugs this next to completely different places.

NEVER INLINE. NEVER EMPTY.
--------------------------
Both properties are load-bearing; see peer_liveness_loop.py for the first and
filter_reachable() for the second.
"""

import concurrent.futures
import os
import re
import socket
import struct

from shared import app

from model.PeerLiveness import STATE_GONE, STATE_LIVE, STATE_UNHEALTHY


# Ceiling we impose on ourselves, not one the network offers. A DEAD destination
# does not fail fast: i2pd keeps retrying floodfill lookups for tens of seconds,
# so the probe has to cut it off and call the timeout a failure. It must still be
# generous enough for a cold-but-alive destination, which needs a floodfill
# lookup plus tunnel selection -- commonly 5-10s. (The node's own dialler budgets
# two minutes, but that covers the full libp2p handshake; we only need a stream.)
PROBE_CONNECT_TIMEOUT = float(os.getenv("PEER_PROBE_TIMEOUT", "15") or 15)
# After the stream is up, how long to wait for the peer to say anything at all.
# go-libp2p's listener writes its multistream header proactively on connect, so a
# healthy peer answers immediately.
PROBE_READ_TIMEOUT = float(os.getenv("PEER_PROBE_READ_TIMEOUT", "5") or 5)
# Bounded so a large peer list can never become an unbounded burst of sockets
# through one I2P proxy, and sized to the peer count so a small list does not
# start eight threads to do three dials.
MAX_PROBE_WORKERS = int(os.getenv("PEER_PROBE_WORKERS", "8") or 8)
# Whole-sweep ceiling. Probes are CONCURRENT, so a sweep costs about one probe
# timeout no matter how many peers there are -- this only catches a probe that
# somehow outlives its own socket timeouts, so the sweep can never wedge.
SWEEP_DEADLINE_SECONDS = PROBE_CONNECT_TIMEOUT + PROBE_READ_TIMEOUT + 15.0

# Any port works: the node's I2P listener issues a bare STREAM ACCEPT with no
# port filter, so an inbound stream on any port lands on the libp2p host.
PROBE_PORT = 80

_GARLIC32 = re.compile(r"^/garlic32/([a-z2-7]{52})(?:/|$)")
_B32 = re.compile(r"^[a-z2-7]{52}$")


class ProberUnavailable(Exception):
    """The probe could not be attempted -- our side, not the peer's.

    Raised when there is no usable SOCKS proxy to dial through. It is NOT a
    verdict about any destination, and it must never be recorded as one: in
    production the app pod may have no I2P proxy reachable at all, and a prober
    that read its own lack of transport as "every peer is dead" would empty the
    bootstrap list and take the network down far harder than a stale entry does.
    """


class _Unreachable(Exception):
    """The proxy says it could not reach the destination: no LeaseSet."""


def destination_of(address):
    """The bare base32 destination inside a /garlic32/<b32>/p2p/<id> multiaddr."""
    match = _GARLIC32.match(str(address or "").strip().lower())
    return match.group(1) if match else ""


def _open_stream(destination, connect_timeout, read_timeout):
    """SOCKS5 CONNECT to <destination>.b32.i2p. Returns a connected socket.

    Deliberately phase-aware rather than a call to the NNTP client's
    _i2p_socks_connect: the two failure phases mean opposite things here. A
    failure to reach the PROXY is ProberUnavailable (fail open, record nothing);
    a failure reported BY the proxy about the peer is a verdict. Collapsing them
    into one exception is how a prober with no transport quietly evicts a healthy
    network. The proxy address and framing plumbing are still the ones the NNTP
    client uses -- one proxy setting, one SOCKS implementation.
    """
    from services.i2p_addresses import normalize_i2p_host
    from services.nntpchan.client import NNTPError, _proxy_address, _recv_exact

    host = normalize_i2p_host(str(destination or "").strip().lower() + ".b32.i2p")
    encoded = host.encode("ascii")

    try:
        proxy = _proxy_address()
    except NNTPError as exc:
        raise ProberUnavailable(str(exc))
    try:
        sock = socket.create_connection(proxy, connect_timeout)
    except OSError as exc:
        raise ProberUnavailable("I2P SOCKS proxy %s:%s is not reachable (%s)" % (
            proxy[0], proxy[1], exc))

    try:
        # Greeting. Anything wrong here is the proxy, not the peer.
        try:
            sock.sendall(b"\x05\x01\x00")
            if _recv_exact(sock, 2) != b"\x05\x00":
                raise ProberUnavailable("I2P SOCKS proxy rejected unauthenticated access")
        except ProberUnavailable:
            raise
        except (OSError, NNTPError) as exc:
            raise ProberUnavailable("I2P SOCKS handshake failed (%s)" % exc)

        # CONNECT. From here on, failures are about the DESTINATION. The
        # hostname goes over the wire verbatim so no DNS happens locally and the
        # router performs the LeaseSet lookup -- which is the thing being tested.
        sock.settimeout(connect_timeout)
        sock.sendall(
            b"\x05\x01\x00\x03"
            + bytes((len(encoded),))
            + encoded
            + struct.pack("!H", PROBE_PORT)
        )
        header = _recv_exact(sock, 4)
        if header[:3] != b"\x05\x00\x00":
            code = header[1] if len(header) > 1 else -1
            raise _Unreachable("SOCKS reply code %s" % code)
        address_type = header[3]
        if address_type == 1:
            _recv_exact(sock, 4)
        elif address_type == 4:
            _recv_exact(sock, 16)
        elif address_type == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        _recv_exact(sock, 2)
        sock.settimeout(read_timeout)
        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def probe_destination(destination, connect_timeout=None, read_timeout=None):
    """One destination -> STATE_LIVE / STATE_GONE / STATE_UNHEALTHY.

    Raises ProberUnavailable if the probe could not be attempted at all.
    """
    connect_timeout = PROBE_CONNECT_TIMEOUT if connect_timeout is None else connect_timeout
    read_timeout = PROBE_READ_TIMEOUT if read_timeout is None else read_timeout
    try:
        sock = _open_stream(destination, connect_timeout, read_timeout)
    except ProberUnavailable:
        raise
    except _Unreachable:
        return STATE_GONE
    except Exception:
        # socket.timeout, a proxy that closed mid-CONNECT, a malformed reply:
        # every one of them means the stream did not come up. A dead destination
        # is EXACTLY the case that times out rather than erroring, so a timeout
        # has to count.
        return STATE_GONE
    try:
        # The listener side of multistream-select writes its header before
        # reading anything, so a healthy peer speaks first. Silence means the
        # destination is published and reachable but the node behind it is not
        # answering -- a different fault from "not there at all".
        greeting = sock.recv(19)
        return STATE_LIVE if greeting else STATE_UNHEALTHY
    except Exception:
        return STATE_UNHEALTHY
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe_all(destinations, probe=None, deadline=None):
    """Probe every destination CONCURRENTLY. Returns {destination: state}.

    Concurrency is not a micro-optimisation here. A dead destination does not
    fail fast, it waits out the whole timeout, so a sequential sweep costs
    (dead peers x timeout) -- with today's list that is minutes -- while a
    concurrent one costs roughly ONE timeout however many peers there are.

    The pool is bounded: sized to the peer count so three peers do not start
    eight threads, capped so a hundred peers cannot open a hundred sockets
    through one I2P proxy at once.
    """
    probe = probe or probe_destination
    deadline = SWEEP_DEADLINE_SECONDS if deadline is None else deadline
    targets = [d for d in dict.fromkeys(
        (str(value or "").strip().lower() for value in destinations or [])) if d]
    if not targets:
        return {}

    results = {}
    pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, min(len(targets), MAX_PROBE_WORKERS)),
        thread_name_prefix="peer-probe",
    )
    try:
        futures = {pool.submit(probe, target): target for target in targets}
        done, pending = concurrent.futures.wait(futures, timeout=deadline)
        for future in done:
            target = futures[future]
            try:
                results[target] = future.result()
            except ProberUnavailable:
                # Our transport, not their destination. Abandon the whole sweep
                # rather than record verdicts we did not earn.
                raise
            except Exception:
                app.logger.debug("peer probe of %s raised", target, exc_info=True)
        if pending:
            # A probe that outlived its own socket timeouts. Record nothing for
            # it: an unfinished measurement is not a failed peer.
            app.logger.warning(
                "peer liveness: %d probe(s) did not finish within %.0fs; "
                "no verdict recorded for them", len(pending), deadline)
    finally:
        # wait=False so one wedged probe cannot hold the sweep thread; the socket
        # timeouts guarantee the workers exit on their own.
        pool.shutdown(wait=False)
    return results


def _probe_targets():
    """Every distinct destination worth probing.

    Includes destinations we currently WITHHOLD. Eviction must never be
    permanent -- a peer that starts answering again has to be able to come back
    on its own, and it cannot do that if we stop asking.
    """
    targets = []
    try:
        from model.StorageNode import active_i2p_destinations

        targets.extend(active_i2p_destinations())
    except Exception:
        app.logger.debug("peer liveness: could not list active destinations", exc_info=True)
    try:
        from services.storage_coordination import bootstrap_peers

        targets.extend(destination_of(address) for address in bootstrap_peers())
    except Exception:
        app.logger.debug("peer liveness: could not list configured peers", exc_info=True)
    return [target for target in dict.fromkeys(targets) if target and _B32.match(target)]


def _is_probably_our_fault(results):
    """True when the RESULT PATTERN accuses the prober rather than the network.

    GONE is judged on an explicit SOCKS error, so it is unambiguous. UNHEALTHY
    is judged on silence, which is also what a wrong assumption about the
    protocol would look like. If a whole sweep of several peers came back silent
    with nothing live and nothing explicitly unreachable, the likeliest
    explanation is us, and striking out the entire network on that reading is
    not a risk worth taking.
    """
    if len(results) < 3:
        return False
    states = set(results.values())
    return states == {STATE_UNHEALTHY}


def sweep(now=None):
    """One full pass: probe every destination concurrently, record the verdicts.

    Background use only -- see peer_liveness_loop.py. Returns a summary dict and
    never raises.
    """
    from shared import db

    summary = {"probed": 0, "live": 0, "gone": 0, "unhealthy": 0, "withheld": 0}
    targets = _probe_targets()
    if not targets:
        return summary
    try:
        results = probe_all(targets)
    except ProberUnavailable as exc:
        # No transport. Every peer stays advertised, exactly as before this
        # feature existed. Warn rather than fail: this is the expected state
        # anywhere the app has no I2P SOCKS proxy configured.
        app.logger.warning(
            "peer liveness: no I2P probe transport (%s); all %d peers stay advertised",
            exc, len(targets))
        summary["prober_unavailable"] = True
        return summary
    if not results:
        return summary
    if _is_probably_our_fault(results):
        app.logger.error(
            "peer liveness: all %d probes came back silent and none was explicitly "
            "unreachable; treating that as a prober fault and recording nothing",
            len(results))
        summary["prober_unavailable"] = True
        return summary

    from model.PeerLiveness import record_probe, unreachable_destinations

    for destination, state in results.items():
        summary["probed"] += 1
        summary[state] = summary.get(state, 0) + 1
        if state == STATE_GONE:
            app.logger.info(
                "peer liveness: %s is GONE (no LeaseSet -- the node behind this "
                "destination is not on the network)", destination)
        elif state == STATE_UNHEALTHY:
            app.logger.info(
                "peer liveness: %s is UNHEALTHY (reachable, accepted a stream, "
                "then said nothing)", destination)
        record_probe(destination, state, now=now)
    db.session.commit()
    summary["withheld"] = len(unreachable_destinations(now=now))
    return summary


def withheld_destinations():
    """Destinations that have failed MAX_CONSECUTIVE_FAILURES probes in a row.

    Read-only and cheap: one indexed query, safe on the request path. FAILS OPEN
    -- if the table is missing, the DB hiccups, or the prober has never run, the
    answer is "withhold nothing".
    """
    try:
        from model.PeerLiveness import unreachable_destinations

        return unreachable_destinations()
    except Exception:
        app.logger.debug("peer liveness: verdicts unavailable", exc_info=True)
        return set()


def filter_reachable(items, key=destination_of, label="peers", withheld=None,
                     floor=True):
    """Drop items whose destination is currently struck out.

    NEVER RETURNS AN EMPTY LIST FOR A NON-EMPTY INPUT. This is the most
    important property in the file. A node handed zero peers cannot bootstrap at
    all, which is strictly worse than a node handed one stale peer: the stale
    entry costs a dial timeout, the empty list costs the whole network. So if
    filtering would empty the list, the UNFILTERED list is served and the fact is
    logged loudly.

    `floor=False` is for callers that are filtering one HALF of a list they will
    combine with another (bootstrap_document filters the configured seeds
    separately from the live peers). Such a caller owns the never-empty
    guarantee for the combined result; applying it per half would re-add a
    struck-out seed even when live peers were available to replace it.
    """
    items = list(items or [])
    if not items:
        return items
    if withheld is None:
        withheld = withheld_destinations()
    if not withheld:
        return items
    kept = [item for item in items if (key(item) or "") not in withheld]
    if not kept and not floor:
        app.logger.info(
            "peer liveness: withholding all %d %s (the caller combines these "
            "with another list and owns the never-empty guarantee)",
            len(items), label)
        return kept
    if not kept:
        app.logger.error(
            "peer liveness: every one of the %d %s candidates is currently marked "
            "unreachable -- serving the UNFILTERED list instead, because a node "
            "with no peers cannot bootstrap at all", len(items), label)
        return items
    if len(kept) != len(items):
        app.logger.info(
            "peer liveness: withholding %d unreachable %s of %d",
            len(items) - len(kept), label, len(items))
    return kept
