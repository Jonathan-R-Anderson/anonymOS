"""Withholding bootstrap peers that no longer answer over I2P.

THE FAULT
---------
The signed bootstrap document published two garlic destinations whose LeaseSet
no longer resolves. Five volunteer nodes on one LAN were all up, all
heartbeating, all listed under `compute`, and not one of them could find another
-- every bootstrap round was spent dialling the dead pair:

    I2P stream connect failed: RESULT=CANT_REACH_PEER MESSAGE="LeaseSet not found"

The heartbeat is clearnet, so it proved those nodes' processes were alive and
proved nothing whatsoever about their destinations.

WHAT THESE TESTS PIN
--------------------
Every property here is one that, if it broke, would be WORSE than the bug:

  * three consecutive failures before a peer is dropped, and the counter resets
    on any success -- a count that only rose would evict the whole network;
  * a dropped peer is still probed and comes straight back when it answers;
  * filtering NEVER yields an empty peer list, whatever the verdicts say;
  * probes run simultaneously, because a dead destination waits out its whole
    timeout and a sequential sweep would cost one timeout per dead peer;
  * a probe that cannot be ATTEMPTED (no proxy) is never read as a dead peer;
  * filtering happens before signing, so the signature covers what is published.

The modules are loaded by AST extraction rather than imported, because importing
them pulls in `shared` (Flask + flask_migrate), which is not installed here.
"""

import ast
import base64
import concurrent.futures
import contextlib
import datetime
import json
import os
import pathlib
import re
import socket
import struct
import sys
import threading
import time
import types
import unittest
from unittest import mock

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from nacl.signing import SigningKey, VerifyKey  # noqa: E402

import services.storage_coordination as SC  # noqa: E402


def _load_pure(relative_path, wanted, extra=None):
    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


class _FakeLogger:
    def __init__(self):
        self.messages = []

    def _record(self, level, message, *args):
        self.messages.append((level, message % args if args else message))

    def debug(self, message, *args, **kwargs):
        self._record("debug", message, *args)

    def info(self, message, *args, **kwargs):
        self._record("info", message, *args)

    def warning(self, message, *args, **kwargs):
        self._record("warning", message, *args)

    def error(self, message, *args, **kwargs):
        self._record("error", message, *args)

    def exception(self, message, *args, **kwargs):
        self._record("error", message, *args)


class _FakeApp:
    def __init__(self):
        self.logger = _FakeLogger()


APP = _FakeApp()

MODEL = _load_pure(
    "model/PeerLiveness.py",
    {"MAX_CONSECUTIVE_FAILURES", "VERDICT_MAX_AGE_SECONDS", "STATE_LIVE",
     "STATE_GONE", "STATE_UNHEALTHY", "apply_probe", "is_unreachable"},
    extra={"_datetime": datetime},
)

MAX_CONSECUTIVE_FAILURES = MODEL["MAX_CONSECUTIVE_FAILURES"]
LIVE = MODEL["STATE_LIVE"]
GONE = MODEL["STATE_GONE"]
UNHEALTHY = MODEL["STATE_UNHEALTHY"]

SERVICE = _load_pure(
    "services/peer_liveness.py",
    {"PROBE_CONNECT_TIMEOUT", "PROBE_READ_TIMEOUT", "MAX_PROBE_WORKERS",
     "SWEEP_DEADLINE_SECONDS", "PROBE_PORT", "_GARLIC32", "_B32",
     "ProberUnavailable", "_Unreachable", "destination_of", "_open_stream",
     "probe_destination", "probe_all", "_is_probably_our_fault",
     "withheld_destinations", "filter_reachable"},
    extra={"app": APP, "os": os, "re": re, "socket": socket, "struct": struct,
           "concurrent": concurrent, "STATE_LIVE": LIVE, "STATE_GONE": GONE,
           "STATE_UNHEALTHY": UNHEALTHY},
)

ProberUnavailable = SERVICE["ProberUnavailable"]
destination_of = SERVICE["destination_of"]
filter_reachable = SERVICE["filter_reachable"]
probe_all = SERVICE["probe_all"]
probe_destination = SERVICE["probe_destination"]

DEST_A = "a" * 52
DEST_B = "b" * 52
DEST_C = "c" * 52


def peer(destination, node_id="12D3KooWNode"):
    return "/garlic32/%s/p2p/%s" % (destination, node_id)


class _Row:
    """The columns of one peer_liveness row, without a database."""

    def __init__(self):
        self.first_probed_at = None
        self.last_probe_at = None
        self.last_ok_at = None
        self.consecutive_failures = 0
        self.last_state = None


class _Verdicts:
    """The real bookkeeping (model.apply_probe / model.is_unreachable) held in a
    dict, so the eviction policy can be exercised sweep by sweep."""

    def __init__(self):
        self.rows = {}

    def probe(self, destination, state, now=None):
        row = self.rows.setdefault(destination, _Row())
        MODEL["apply_probe"](row, state, now=now or datetime.datetime.utcnow())

    def withheld(self, now=None):
        return {destination for destination, row in self.rows.items()
                if MODEL["is_unreachable"](row, now=now)}

    def advertised(self, peers, now=None):
        return filter_reachable(peers, withheld=self.withheld(now=now))


class ThreeStrikesTest(unittest.TestCase):
    """Exactly three chances, and the counter resets on any success."""

    def setUp(self):
        self.verdicts = _Verdicts()
        self.peers = [peer(DEST_A), peer(DEST_B)]

    def test_the_limit_is_a_named_constant_worth_three(self):
        self.assertEqual(3, MAX_CONSECUTIVE_FAILURES)

    def test_a_peer_is_still_advertised_after_one_and_two_failures(self):
        """A probe can fail for reasons that are not the peer's fault -- the
        node's I2P listener accepts serially and sleeps after an accept error,
        so a probe can land in a gap on a perfectly healthy node."""
        for attempt in (1, 2):
            self.verdicts.probe(DEST_A, GONE)
            self.assertIn(
                peer(DEST_A), self.verdicts.advertised(self.peers),
                "dropped after %d failure(s); it gets three" % attempt)

    def test_the_third_consecutive_failure_drops_it(self):
        for _ in range(MAX_CONSECUTIVE_FAILURES):
            self.verdicts.probe(DEST_A, GONE)
        advertised = self.verdicts.advertised(self.peers)
        self.assertNotIn(peer(DEST_A), advertised)
        self.assertIn(peer(DEST_B), advertised)

    def test_one_success_in_the_middle_resets_the_count(self):
        """Otherwise a node that blips during one sweep is punished for it, and
        a counter that only ever rises evicts every peer on the network."""
        self.verdicts.probe(DEST_A, GONE)
        self.verdicts.probe(DEST_A, GONE)
        self.verdicts.probe(DEST_A, LIVE)
        self.verdicts.probe(DEST_A, GONE)
        self.verdicts.probe(DEST_A, GONE)
        self.assertIn(peer(DEST_A), self.verdicts.advertised(self.peers))
        self.verdicts.probe(DEST_A, GONE)
        self.assertNotIn(peer(DEST_A), self.verdicts.advertised(self.peers))

    def test_a_dropped_peer_that_answers_again_is_advertised_again(self):
        """Eviction is from the ADVERTISED list only. A dropped destination is
        still probed, so it can come back on its own -- without that the list
        decays monotonically toward empty."""
        for _ in range(5):
            self.verdicts.probe(DEST_A, GONE)
        self.assertNotIn(peer(DEST_A), self.verdicts.advertised(self.peers))
        self.verdicts.probe(DEST_A, LIVE)
        self.assertIn(peer(DEST_A), self.verdicts.advertised(self.peers))

    def test_gone_and_unhealthy_both_count_toward_the_three(self):
        self.verdicts.probe(DEST_A, GONE)
        self.verdicts.probe(DEST_A, UNHEALTHY)
        self.assertIn(peer(DEST_A), self.verdicts.advertised(self.peers))
        self.verdicts.probe(DEST_A, GONE)
        self.assertNotIn(peer(DEST_A), self.verdicts.advertised(self.peers))

    def test_a_verdict_nobody_is_refreshing_stops_being_acted_on(self):
        """If the prober dies, its last verdicts must expire. Otherwise peers
        stay withheld forever on the strength of a measurement nobody takes."""
        old = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        for _ in range(MAX_CONSECUTIVE_FAILURES):
            self.verdicts.probe(DEST_A, GONE, now=old)
        self.assertEqual(set(), self.verdicts.withheld())


class NeverEmptyTest(unittest.TestCase):
    """The most important property: a node with no peers has no network."""

    def test_filtering_never_empties_a_non_empty_list(self):
        peers = [peer(DEST_A), peer(DEST_B)]
        kept = filter_reachable(peers, withheld={DEST_A, DEST_B})
        self.assertEqual(peers, kept)

    def test_and_it_says_so_loudly(self):
        APP.logger.messages = []
        filter_reachable([peer(DEST_A)], withheld={DEST_A})
        self.assertTrue(
            any(level == "error" for level, _ in APP.logger.messages),
            "an all-withheld peer list must be logged as an error")

    def test_a_half_list_may_be_emptied_when_the_caller_owns_the_floor(self):
        """bootstrap_document filters the configured seeds separately from the
        live peers; flooring each half would re-add a struck-out seed even when
        live peers were there to replace it."""
        self.assertEqual(
            [], filter_reachable([peer(DEST_A)], withheld={DEST_A}, floor=False))

    def test_no_verdicts_means_no_filtering(self):
        peers = [peer(DEST_A), peer(DEST_B)]
        self.assertEqual(peers, filter_reachable(peers, withheld=set()))

    def test_unavailable_verdicts_fail_open(self):
        """Here the model cannot even be imported (no `shared`), which is the
        same shape as a DB hiccup or a prober that has never run: withhold
        nothing."""
        self.assertEqual(set(), SERVICE["withheld_destinations"]())
        peers = [peer(DEST_A)]
        self.assertEqual(peers, filter_reachable(peers))

    def test_an_unparseable_address_is_never_withheld(self):
        self.assertEqual("", destination_of("/dns4/example.org/tcp/443"))
        self.assertEqual(
            ["/dns4/example.org/tcp/443"],
            filter_reachable(["/dns4/example.org/tcp/443"], withheld={DEST_A}))


class ConcurrentSweepTest(unittest.TestCase):
    """Dead destinations do not fail fast -- they wait out the timeout."""

    def test_every_destination_is_probed_at_once(self):
        destinations = [chr(ord("a") + index) * 52 for index in range(6)]
        peak = {"value": 0}
        running = {"value": 0}
        lock = threading.Lock()

        def probe(destination):
            with lock:
                running["value"] += 1
                peak["value"] = max(peak["value"], running["value"])
            time.sleep(0.2)
            with lock:
                running["value"] -= 1
            return GONE

        started = time.time()
        results = probe_all(destinations, probe=probe)
        elapsed = time.time() - started

        self.assertEqual(6, len(results))
        self.assertEqual(6, peak["value"], "probes must overlap, not queue")
        # Sequential would be 6 x 0.2s. Concurrent is one probe, plus slack.
        self.assertLess(elapsed, 0.8, "the sweep ran sequentially")

    def test_the_pool_is_capped_so_a_long_list_is_not_a_socket_storm(self):
        destinations = ["%s%s" % (chr(ord("a") + index // 26),
                                  chr(ord("a") + index % 26)) * 26
                        for index in range(40)]
        peak = {"value": 0}
        running = {"value": 0}
        lock = threading.Lock()

        def probe(destination):
            with lock:
                running["value"] += 1
                peak["value"] = max(peak["value"], running["value"])
            time.sleep(0.05)
            with lock:
                running["value"] -= 1
            return LIVE

        probe_all(destinations, probe=probe)
        self.assertLessEqual(peak["value"], SERVICE["MAX_PROBE_WORKERS"])

    def test_one_hung_destination_cannot_stall_the_sweep(self):
        def probe(destination):
            if destination == DEST_C:
                time.sleep(5)
            return LIVE

        started = time.time()
        results = probe_all([DEST_A, DEST_B, DEST_C], probe=probe, deadline=0.5)
        self.assertLess(time.time() - started, 2.0)
        self.assertEqual({DEST_A, DEST_B}, set(results))
        # An unfinished measurement is not a failed peer, so it gets no verdict.
        self.assertNotIn(DEST_C, results)

    def test_a_probe_that_could_not_be_attempted_abandons_the_whole_sweep(self):
        """No transport is a fact about US. Recording it as a verdict about
        every destination would empty the bootstrap list network-wide."""
        def probe(destination):
            raise ProberUnavailable("no I2P SOCKS proxy")

        with self.assertRaises(ProberUnavailable):
            probe_all([DEST_A, DEST_B], probe=probe)

    def test_duplicate_destinations_are_probed_once(self):
        seen = []

        def probe(destination):
            seen.append(destination)
            return LIVE

        probe_all([DEST_A, DEST_A.upper(), DEST_A], probe=probe)
        self.assertEqual([DEST_A], seen)

    def test_an_all_silent_sweep_is_read_as_our_fault_not_the_networks(self):
        every_peer_silent = {DEST_A: UNHEALTHY, DEST_B: UNHEALTHY, DEST_C: UNHEALTHY}
        self.assertTrue(SERVICE["_is_probably_our_fault"](every_peer_silent))
        # An explicitly unreachable destination is unambiguous, so a sweep that
        # contains one is believed -- that is today's actual outage.
        self.assertFalse(SERVICE["_is_probably_our_fault"](
            {DEST_A: GONE, DEST_B: UNHEALTHY, DEST_C: UNHEALTHY}))


class _FakeSocket:
    def __init__(self, script, raise_on_read=None):
        self.buffer = bytearray(script)
        self.sent = bytearray()
        self.raise_on_read = raise_on_read
        self.closed = False
        self.reads = 0

    def sendall(self, value):
        self.sent.extend(value)

    def recv(self, size):
        self.reads += 1
        if self.raise_on_read is not None and self.reads >= self.raise_on_read:
            raise socket.timeout("timed out")
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value

    def settimeout(self, value):
        pass

    def close(self):
        self.closed = True


GREETING = b"\x05\x00"
CONNECTED = b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00"
REFUSED = b"\x05\x04\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00"
MULTISTREAM = b"\x13/multistream/1.0.0\n"


class ProbeClassificationTest(unittest.TestCase):
    """GONE and UNHEALTHY mean different things, and neither means 'our proxy
    is missing'."""

    def probe(self, fake):
        with mock.patch("socket.create_connection", return_value=fake):
            return probe_destination(DEST_A, connect_timeout=1, read_timeout=1)

    def test_a_stream_that_comes_up_and_speaks_is_live(self):
        state = self.probe(_FakeSocket(GREETING + CONNECTED + MULTISTREAM))
        self.assertEqual(LIVE, state)

    def test_the_destination_is_sent_verbatim_so_no_dns_happens_here(self):
        fake = _FakeSocket(GREETING + CONNECTED + MULTISTREAM)
        self.probe(fake)
        host = (DEST_A + ".b32.i2p").encode("ascii")
        self.assertIn(b"\x05\x01\x00\x03" + bytes((len(host),)) + host, fake.sent)

    def test_a_proxy_that_cannot_reach_the_peer_is_gone(self):
        """This is the LeaseSet-not-found case, and the whole reason for the
        change."""
        self.assertEqual(GONE, self.probe(_FakeSocket(GREETING + REFUSED)))

    def test_a_connect_that_times_out_is_gone(self):
        """A dead destination does not error, it hangs: i2pd keeps retrying
        floodfill lookups. If the timeout did not count, nothing ever would."""
        fake = _FakeSocket(GREETING, raise_on_read=2)
        self.assertEqual(GONE, self.probe(fake))

    def test_a_stream_that_comes_up_and_says_nothing_is_unhealthy(self):
        """Reachable and broken. Distinct from GONE because it sends whoever
        debugs this next somewhere completely different -- and because one
        production destination resolves fine and only fails Noise afterwards."""
        self.assertEqual(UNHEALTHY, self.probe(_FakeSocket(GREETING + CONNECTED)))

    def test_no_proxy_at_all_is_not_a_verdict_about_the_peer(self):
        with mock.patch("socket.create_connection",
                        side_effect=ConnectionRefusedError("no proxy here")):
            with self.assertRaises(ProberUnavailable):
                probe_destination(DEST_A, connect_timeout=1, read_timeout=1)

    def test_a_proxy_that_refuses_the_handshake_is_not_a_verdict_either(self):
        with mock.patch("socket.create_connection",
                        return_value=_FakeSocket(b"\x05\xff")):
            with self.assertRaises(ProberUnavailable):
                probe_destination(DEST_A, connect_timeout=1, read_timeout=1)

    def test_a_clearnet_host_never_reaches_the_proxy(self):
        with mock.patch("socket.create_connection") as connect:
            self.assertEqual(
                GONE, probe_destination("192.0.2.1", connect_timeout=1, read_timeout=1))
        connect.assert_not_called()


_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(value):
    leading = len(value) - len(value.lstrip(b"\x00"))
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _ALPHABET[remainder] + encoded
    return ("1" * leading) + encoded


def _peer_id(signing_key):
    public_message = b"\x08\x01\x12\x20" + signing_key.verify_key.encode()
    return _base58_encode(b"\x00" + bytes([len(public_message)]) + public_message)


class BootstrapDocumentTest(unittest.TestCase):
    """The published document: filtered first, signed second, never empty."""

    def setUp(self):
        self.coordinator = SigningKey.generate()
        self.seed_id = _peer_id(SigningKey.generate())
        self.seed = peer(DEST_C, self.seed_id)
        self.environment = mock.patch.dict(os.environ, {
            "STORAGE_COORDINATOR_SIGNING_KEY": base64.b64encode(
                self.coordinator.encode()).decode("ascii"),
            "STORAGE_BOOTSTRAP_PEERS": json.dumps([self.seed]),
        })
        self.environment.start()

    def tearDown(self):
        self.environment.stop()

    @contextlib.contextmanager
    def network(self, live=(), heartbeating=None, withheld=()):
        """Stand in for the two modules bootstrap_document reaches for."""
        live = list(live)
        withheld = set(withheld)
        heartbeating = (set(heartbeating) if heartbeating is not None
                        else {destination_of(address) for address in live})

        storage_node = types.ModuleType("model.StorageNode")
        storage_node.active_bootstrap_peers = (
            lambda limit=3, exclude_node_id=None, now=None: list(live))
        storage_node.heartbeating_destinations = lambda now=None: set(heartbeating)
        storage_node.active_storage_nodes = lambda now=None: []

        liveness = types.ModuleType("services.peer_liveness")
        liveness.destination_of = destination_of
        liveness.filter_reachable = filter_reachable

        previous = SERVICE["withheld_destinations"]
        SERVICE["withheld_destinations"] = lambda: set(withheld)
        try:
            with mock.patch.dict(sys.modules, {
                "model.StorageNode": storage_node,
                "services.peer_liveness": liveness,
            }):
                yield
        finally:
            SERVICE["withheld_destinations"] = previous

    def assert_signature_covers_published_peers(self, document):
        public = document["coordinator_public_key"]
        message = SC.bootstrap_message(
            document["peers"], public, document["expires_at"])
        VerifyKey(base64.b64decode(public + "=" * (-len(public) % 4))).verify(
            message, base64.b64decode(document["signature"]))

    def test_a_seed_no_live_node_advertises_any_more_is_dropped(self):
        """The configured tail is the entry nothing can expire. If the machine
        behind it rebuilt its i2pd state its destination changed, the DB row
        followed within five minutes and the secret did not -- so the document
        kept publishing an address with no LeaseSet. Recency alone catches this,
        with no network call at all."""
        with self.network(live=[peer(DEST_A)]):
            document = SC.bootstrap_document()
        self.assertEqual([peer(DEST_A)], document["peers"])
        self.assertNotIn(self.seed, document["peers"])
        self.assert_signature_covers_published_peers(document)

    def test_a_seed_a_live_node_still_advertises_survives(self):
        with self.network(live=[peer(DEST_A)], heartbeating={DEST_A, DEST_C}):
            document = SC.bootstrap_document()
        self.assertIn(self.seed, document["peers"])

    def test_a_struck_out_live_peer_is_not_published(self):
        """What recency cannot catch: the node heartbeats happily over clearnet
        while its garlic side is dead, and the stored destination is never
        cleared."""
        with self.network(live=[peer(DEST_A), peer(DEST_B)], withheld={DEST_A}):
            document = SC.bootstrap_document()
        self.assertEqual([peer(DEST_B)], document["peers"])
        self.assert_signature_covers_published_peers(document)

    def test_a_struck_out_seed_is_not_published_either(self):
        with self.network(live=[peer(DEST_A)],
                          heartbeating={DEST_A, DEST_C}, withheld={DEST_C}):
            document = SC.bootstrap_document()
        self.assertEqual([peer(DEST_A)], document["peers"])

    def test_the_document_is_never_published_empty(self):
        """Filtering to zero peers is strictly worse than one stale entry: the
        stale entry costs a dial timeout, the empty list costs the network."""
        with self.network(live=[], heartbeating={DEST_C}, withheld={DEST_C}):
            document = SC.bootstrap_document()
        self.assertEqual([self.seed], document["peers"])
        self.assert_signature_covers_published_peers(document)

    def test_live_peers_still_come_before_the_seed(self):
        """Order is signed and it is meaningful: a joining node dials peers we
        know are heartbeating before it reaches for configuration."""
        with self.network(live=[peer(DEST_A)], heartbeating={DEST_A, DEST_C}):
            document = SC.bootstrap_document()
        self.assertEqual([peer(DEST_A), self.seed], document["peers"])

    def test_unknown_liveness_publishes_everything(self):
        """No DB, no prober: exactly the state of the existing unit tests, and
        the state of a fresh install. Everything is served."""
        document = SC.bootstrap_document()
        self.assertEqual([self.seed], document["peers"])
        self.assert_signature_covers_published_peers(document)

    def test_the_signature_is_over_the_filtered_list_not_the_raw_one(self):
        """Signing the unfiltered list (or filtering after signing) makes every
        node reject the document and takes the whole network off the DHT."""
        with self.network(live=[peer(DEST_A), peer(DEST_B)], withheld={DEST_A}):
            document = SC.bootstrap_document()
        unfiltered = SC.bootstrap_message(
            [peer(DEST_A), peer(DEST_B)],
            document["coordinator_public_key"], document["expires_at"])
        with self.assertRaises(Exception):
            VerifyKey(self.coordinator.verify_key.encode()).verify(
                unfiltered, base64.b64decode(document["signature"]))
        self.assert_signature_covers_published_peers(document)

    def test_the_heartbeat_reply_is_filtered_too(self):
        """The second, unsigned peer handout: every node hits it every five
        minutes, so filtering only the well-known document leaves half the
        problem live."""
        with self.network(live=[peer(DEST_A), peer(DEST_B)], withheld={DEST_A}):
            peers = SC.live_bootstrap_peers(limit=3, exclude_node_id="somebody")
        self.assertEqual([peer(DEST_B)], peers)


if __name__ == "__main__":
    unittest.main()
