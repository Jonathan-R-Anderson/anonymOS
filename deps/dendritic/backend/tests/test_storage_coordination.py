import base64
import json
import os
import sys
import time
import types
import unittest
from unittest import mock

from nacl.signing import SigningKey

from services.storage_coordination import (
    MAX_REVOCATIONS_PER_REQUEST,
    STORAGE_USER_AGENT,
    _lease_message,
    _revocation_message,
    bootstrap_document,
    issue_lease,
    issue_revocations,
    validate_heartbeat,
)


class _OwnershipStub(object):
    """An in-memory stand-in for model/DhtObjectOwner, with the same contract.

    Installed into sys.modules rather than monkeypatching
    services.storage_coordination, so the code under test stays the REAL
    wrappers -- object_owner() and record_object_owner() -- including the
    distinction they draw between "no row" and "the record could not be read",
    which is the whole point of the ownership check.
    """

    def __init__(self, rows=None, unavailable=False):
        self.rows = dict(rows or {})
        self.contests = []
        self.recorded = []
        self.unavailable = unavailable

    def install(self, test):
        module = types.ModuleType("model.DhtObjectOwner")
        module.owner_of = self.owner_of
        module.record_owner = self.record_owner
        saved = sys.modules.get("model.DhtObjectOwner")
        sys.modules["model.DhtObjectOwner"] = module

        def restore():
            if saved is None:
                sys.modules.pop("model.DhtObjectOwner", None)
            else:
                sys.modules["model.DhtObjectOwner"] = saved

        test.addCleanup(restore)
        return self

    def owner_of(self, object_id):
        if self.unavailable:
            raise RuntimeError("the ownership table could not be read")
        return self.rows.get(object_id)

    def record_owner(self, object_id, requester):
        if self.unavailable:
            raise RuntimeError("the ownership table could not be written")
        existing = self.rows.get(object_id)
        if existing is None:
            self.rows[object_id] = requester
            self.recorded.append((object_id, requester))
            return requester, "recorded"
        if existing == requester:
            return existing, "unchanged"
        self.contests.append((object_id, requester))
        return existing, "contested"


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


class StorageCoordinationTest(unittest.TestCase):
    def setUp(self):
        self.coordinator = SigningKey.generate()
        self.requester = SigningKey.generate()
        self.recipient = SigningKey.generate()
        self.requester_id = _peer_id(self.requester)
        self.recipient_id = _peer_id(self.recipient)
        self.environment = mock.patch.dict(os.environ, {
            "STORAGE_COORDINATOR_SIGNING_KEY": base64.b64encode(
                self.coordinator.encode()
            ).decode("ascii"),
            "STORAGE_BOOTSTRAP_PEERS": json.dumps([
                "/garlic32/" + ("a" * 52) + "/p2p/" + self.recipient_id,
            ]),
            "STORAGE_LEASE_REQUESTER_PEERS": self.requester_id,
        })
        self.environment.start()
        self.ownership = _OwnershipStub().install(self)

    def tearDown(self):
        self.environment.stop()

    def _lease_request(self, **overrides):
        payload = {
            "version": 1,
            "requester": self.requester_id,
            "recipient": self.recipient_id,
            "object_id": "a" * 64,
            "shard_id": "b" * 64,
            "size": 65536,
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
        }
        payload.update(overrides)
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(
            self.requester.sign(raw).signature
        ).decode("ascii").rstrip("=")
        return raw, signature

    def test_bootstrap_is_i2p_only(self):
        document = bootstrap_document()
        self.assertEqual(1, document["version"])
        self.assertEqual(1, len(document["peers"]))
        self.assertTrue(document["peers"][0].startswith("/garlic32/"))

    def test_clearnet_bootstrap_peer_is_rejected(self):
        with mock.patch.dict(os.environ, {
            "STORAGE_BOOTSTRAP_PEERS":
                "/dns4/node.syndichan.org/tcp/4001/p2p/" + self.recipient_id,
        }):
            self.assertEqual([], bootstrap_document()["peers"])

    def test_signed_request_receives_verifiable_lease(self):
        payload = {
            "version": 1,
            "requester": self.requester_id,
            "recipient": self.recipient_id,
            "object_id": "a" * 64,
            "shard_id": "b" * 64,
            "size": 65536,
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(self.requester.sign(raw).signature).decode("ascii").rstrip("=")
        lease = issue_lease(raw, self.requester_id, signature)
        self.coordinator.verify_key.verify(
            _lease_message(lease),
            base64.b64decode(lease["signature"] + "=="),
        )

    def test_unauthorized_requester_is_rejected(self):
        payload = {
            "requester": _peer_id(SigningKey.generate()),
        }
        raw = json.dumps(payload).encode("utf-8")
        with self.assertRaises(PermissionError):
            issue_lease(raw, payload["requester"], base64.b64encode(b"x" * 64).decode())

    def test_a_lease_records_who_placed_the_object(self):
        """The lease is the ONLY moment this side ever learns an object's owner.

        Without this write the coordinator has no basis at all for deciding who
        may delete an object later, which is the state the whole check was stuck
        in: `issue_lease` held (requester, object_id, shard_id) and discarded all
        three.
        """
        raw, signature = self._lease_request()
        issue_lease(raw, self.requester_id, signature)
        self.assertEqual([("a" * 64, self.requester_id)], self.ownership.recorded)
        self.assertEqual(self.requester_id, self.ownership.rows["a" * 64])

    def test_a_later_lease_from_the_same_requester_writes_nothing_new(self):
        # One object is hundreds of shards and each one leases separately. If
        # every lease rewrote the row this would be hundreds of writes per
        # upload, and a rewrite is also exactly how first-write-wins would stop
        # being first-write-wins.
        for shard in ("b" * 64, "c" * 64, "d" * 64):
            raw, signature = self._lease_request(shard_id=shard)
            issue_lease(raw, self.requester_id, signature)
        self.assertEqual(1, len(self.ownership.recorded))
        self.assertEqual([], self.ownership.contests)

    def test_a_lease_from_another_origin_is_signed_but_takes_no_ownership(self):
        """A second origin may add bytes and may never delete them.

        Refusing the lease instead would be the wrong direction: a lease
        authorises a WRITE, and an object id is sha256 over a manifest that
        carries a nanosecond timestamp, so a second claimant is an anomaly and
        not deduplication -- but turning an anomaly into a refused write turns an
        ownership question into an under-replicated object. It is recorded as
        contested and the row is left alone, which is what actually denies the
        second origin anything: the delete token is decided from the row.
        """
        intruder = SigningKey.generate()
        intruder_id = _peer_id(intruder)
        self.ownership.rows["a" * 64] = self.requester_id
        with mock.patch.dict(os.environ, {
            "STORAGE_LEASE_REQUESTER_PEERS": self.requester_id + "," + intruder_id,
        }):
            payload = {
                "version": 1,
                "requester": intruder_id,
                "recipient": self.recipient_id,
                "object_id": "a" * 64,
                "shard_id": "e" * 64,
                "size": 4096,
                "timestamp": int(time.time()),
                "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
            }
            raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            signature = base64.b64encode(
                intruder.sign(raw).signature).decode("ascii").rstrip("=")
            lease = issue_lease(raw, intruder_id, signature)
        self.assertIn("signature", lease)
        self.assertEqual(self.requester_id, self.ownership.rows["a" * 64],
                         "a second origin took ownership of an existing object")
        self.assertEqual([("a" * 64, intruder_id)], self.ownership.contests)

    def test_a_lease_is_still_issued_when_ownership_cannot_be_recorded(self):
        """Bookkeeping must never be able to stop placement.

        Safe in the only direction that matters: a missing row falls back to the
        origin-count check, which never signs a delete token that the code
        before this table would not have signed.
        """
        self.ownership.unavailable = True
        raw, signature = self._lease_request()
        lease = issue_lease(raw, self.requester_id, signature)
        self.coordinator.verify_key.verify(
            _lease_message(lease),
            base64.b64decode(lease["signature"] + "=="),
        )

    def test_signed_storage_heartbeat_is_verified(self):
        payload = {
            "version": 1,
            "node_id": self.requester_id,
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
            "capacity_bytes": 20 << 30,
            "platform": "linux/amd64",
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(
            self.requester.sign(raw).signature
        ).decode("ascii").rstrip("=")
        validated = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )
        self.assertEqual(self.requester_id, validated["node_id"])
        self.assertEqual(20 << 30, validated["capacity_bytes"])

    def _signed_heartbeat(self, **overrides):
        payload = {
            "version": 1,
            "node_id": self.requester_id,
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
            "capacity_bytes": 20 << 30,
            "platform": "linux/amd64",
        }
        payload.update(overrides)
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(
            self.requester.sign(raw).signature
        ).decode("ascii").rstrip("=")
        return raw, signature

    def test_dedicated_gateway_may_report_zero_capacity(self):
        # A -gateway-only host donates no disk. Its presence beacon must still
        # be accepted, or a dedicated gateway never appears to the operator.
        raw, signature = self._signed_heartbeat(
            capacity_bytes=0, gateway_enabled=True
        )
        validated = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )
        self.assertEqual(0, validated["capacity_bytes"])
        self.assertTrue(validated["gateway_enabled"])

    def test_probe_only_node_may_report_zero_capacity(self):
        raw, signature = self._signed_heartbeat(capacity_bytes=0)
        validated = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )
        self.assertEqual(0, validated["capacity_bytes"])

    def test_nonzero_capacity_below_the_floor_is_still_rejected(self):
        # Zero means "no storage role". A sliver is still a malformed claim.
        raw, signature = self._signed_heartbeat(capacity_bytes=1024)
        with self.assertRaises(ValueError):
            validate_heartbeat(raw, self.requester_id, signature, STORAGE_USER_AGENT)

    def test_boolean_capacity_is_rejected(self):
        # bool is an int subclass in Python; True must not read as 1 byte.
        raw, signature = self._signed_heartbeat(capacity_bytes=True)
        with self.assertRaises(ValueError):
            validate_heartbeat(raw, self.requester_id, signature, STORAGE_USER_AGENT)

    def test_i2p_destination_is_accepted_and_returned(self):
        # A well-formed 52-char base32 destination feeds the live bootstrap
        # service, so it must survive validation into the recorded payload.
        dest = "a" * 52
        raw, signature = self._signed_heartbeat(i2p_destination=dest)
        validated = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )
        self.assertEqual(dest, validated["i2p_destination"])

    def test_missing_i2p_destination_defaults_to_empty(self):
        # Older clients and probes omit it; that is not an error, just no peer.
        raw, signature = self._signed_heartbeat()
        validated = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )
        self.assertEqual("", validated["i2p_destination"])

    def test_malformed_i2p_destination_is_rejected(self):
        # A broken destination must never be stored -- the bootstrap service
        # would hand it to every joining node.
        for bad in ("A" * 52, "a" * 51, "a" * 53, "not!base32!" + "a" * 41):
            raw, signature = self._signed_heartbeat(i2p_destination=bad)
            with self.assertRaises(ValueError):
                validate_heartbeat(
                    raw, self.requester_id, signature, STORAGE_USER_AGENT
                )

    def test_gateway_green_role_requires_independent_signed_quorum(self):
        now = int(time.time())
        probes = [SigningKey.generate() for _ in range(3)]
        probe_ids = [_peer_id(key) for key in probes]
        trusted = {
            node_id: base64.b64encode(
                b"\x08\x01\x12\x20" + key.verify_key.encode()
            ).decode("ascii").rstrip("=")
            for node_id, key in zip(probe_ids, probes)
        }
        results = []
        for index, (node_id, key) in enumerate(zip(probe_ids, probes)):
            result = {
                "request_id": "request",
                "candidate_node_id": self.requester_id,
                "probe_node_id": node_id,
                "probe_network": "network-%d" % index,
                "tested_address": "8.8.8.8",
                "tested_port": 443,
                "tcp_reachable": True,
                "tls_valid": True,
                "identity_valid": True,
                "challenge_valid": True,
                "protocol_valid": True,
                "latency_ms": 10,
                "observed_at": now,
                "expires_at": now + 120,
                "failure_reason": None,
            }
            raw_result = json.dumps(result, separators=(",", ":")).encode()
            result["signature"] = base64.b64encode(
                key.sign(raw_result).signature
            ).decode().rstrip("=")
            results.append(result)
        registration = {
            "record_type": "verified_gateway",
            "node_id": self.requester_id,
            "public_key": base64.b64encode(
                b"\x08\x01\x12\x20" + self.requester.verify_key.encode()
            ).decode().rstrip("="),
            "addresses": [{"family": "ipv4", "address": "8.8.8.8", "port": 443}],
            "protocol_version": 1,
            "software_version": "test",
            "capabilities": ["https_gateway", "dht_lookup", "content_proxy"],
            "successful_probes": 3,
            "distinct_networks": 3,
            "verified_at": now,
            "health_state": "healthy",
            "issued_at": now,
            "expires_at": now + 120,
            "sequence": 1,
            "probe_results": results,
        }
        raw_registration = json.dumps(registration, separators=(",", ":")).encode()
        registration["signature"] = base64.b64encode(
            self.requester.sign(raw_registration).signature
        ).decode().rstrip("=")
        payload = {
            "version": 1,
            "node_id": self.requester_id,
            "timestamp": now,
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="),
            "capacity_bytes": 20 << 30,
            "platform": "linux/amd64",
            "gateway_enabled": True,
            "gateway_verified": True,
            "gateway_registration": registration,
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        signature = base64.b64encode(self.requester.sign(raw).signature).decode().rstrip("=")
        with mock.patch.dict(os.environ, {"GATEWAY_TRUSTED_PROBES": json.dumps(trusted)}):
            validated = validate_heartbeat(
                raw, self.requester_id, signature, STORAGE_USER_AGENT
            )
        self.assertTrue(validated["gateway_verified"])

    def test_gateway_cannot_self_declare_verified(self):
        payload = {
            "version": 1,
            "node_id": self.requester_id,
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="),
            "capacity_bytes": 20 << 30,
            "platform": "linux/amd64",
            "gateway_enabled": True,
            "gateway_verified": True,
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        signature = base64.b64encode(self.requester.sign(raw).signature).decode().rstrip("=")
        with self.assertRaises(ValueError):
            validate_heartbeat(raw, self.requester_id, signature, STORAGE_USER_AGENT)

    def test_heartbeat_requires_storage_user_agent(self):
        payload = {
            "version": 1,
            "node_id": self.requester_id,
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
            "capacity_bytes": 20 << 30,
            "platform": "linux/amd64",
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(
            self.requester.sign(raw).signature
        ).decode("ascii").rstrip("=")
        with self.assertRaises(PermissionError):
            validate_heartbeat(raw, self.requester_id, signature, "Mozilla/5.0")

    # --- dispersal health (roadmap phase 4.3) ------------------------------
    #
    # The block that makes an operator able to see whether shards are reaching
    # other machines. Carried on the heartbeat because the admin page must not
    # dial nine nodes over I2P inside a request handler.

    def _placement_block(self, **overrides):
        block = {
            "objects": 11640, "under_replicated": 402, "local_only": 7,
            "fully_dispersed": 11238, "placed": 6, "failed": 3,
            "unassignable": 0, "attempted": 40, "peers": 9, "age_seconds": 118,
            "recalls_outstanding": 2, "recalls_deferred": 1,
            "recalls_unreadable": 0,
            "refusals": [
                {"peer": "12D3KooWFullDis", "count": 3,
                 "reason": "storage capacity exceeded"},
            ],
        }
        block.update(overrides)
        return block

    def test_a_heartbeat_carrying_dispersal_health_still_validates(self):
        raw, signature = self._signed_heartbeat(placement=self._placement_block())
        validated = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )
        placement = validated["placement"]
        self.assertEqual(placement["under_replicated"], 402)
        self.assertEqual(placement["failed"], 3)
        self.assertEqual(placement["recalls_outstanding"], 2)

    def test_a_refusal_reason_survives_validation(self):
        # The reason is the entire point of the block. A count with the reason
        # stripped is what an operator already had, and it took a week to act on.
        raw, signature = self._signed_heartbeat(placement=self._placement_block())
        placement = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )["placement"]
        self.assertEqual(
            placement["refusals"],
            [{"peer": "12D3KooWFullDis", "count": 3,
              "reason": "storage capacity exceeded"}])

    def test_a_node_that_omits_dispersal_health_is_still_accepted(self):
        # The fleet upgrades at different times. Refusing a heartbeat over a
        # field the node has never heard of would take working machines off the
        # map -- and None must survive, because "not reporting" is the answer the
        # panel needs, not zero.
        raw, signature = self._signed_heartbeat()
        validated = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )
        self.assertIsNone(validated["placement"])

    def test_a_counter_the_node_omits_stays_absent_rather_than_becoming_zero(self):
        # A node whose recall ledger would not open sends no recall counts. Zero
        # would report "nothing outstanding" off a ledger nobody could read.
        block = self._placement_block()
        for key in ("recalls_outstanding", "recalls_deferred", "recalls_unreadable"):
            block.pop(key)
        raw, signature = self._signed_heartbeat(placement=block)
        placement = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )["placement"]
        self.assertIsNone(placement["recalls_outstanding"])
        self.assertEqual(placement["objects"], 11640)

    def test_a_negative_counter_is_discarded_rather_than_clamped_to_zero(self):
        raw, signature = self._signed_heartbeat(
            placement=self._placement_block(failed=-1))
        placement = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )["placement"]
        self.assertIsNone(placement["failed"])

    def test_a_boolean_counter_is_rejected(self):
        raw, signature = self._signed_heartbeat(
            placement=self._placement_block(failed=True))
        with self.assertRaises(ValueError):
            validate_heartbeat(raw, self.requester_id, signature, STORAGE_USER_AGENT)

    def test_a_malformed_placement_block_is_rejected(self):
        for bad in ("not a dict", 7, [1, 2, 3]):
            raw, signature = self._signed_heartbeat(placement=bad)
            with self.assertRaises(ValueError):
                validate_heartbeat(
                    raw, self.requester_id, signature, STORAGE_USER_AGENT)

    def test_the_refusal_list_is_bounded_and_its_strings_are_capped(self):
        # Self-reported and rendered. A node must not decide how long this page
        # is, nor what characters reach it.
        from services.storage_coordination import (
            MAX_REFUSAL_REASON_CHARS, MAX_REPORTED_REFUSALS,
        )
        raw, signature = self._signed_heartbeat(placement=self._placement_block(
            refusals=[
                {"peer": "peer%d" % i, "count": 1, "reason": "x" * 400}
                for i in range(MAX_REPORTED_REFUSALS + 20)
            ]))
        placement = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )["placement"]
        self.assertEqual(len(placement["refusals"]), MAX_REPORTED_REFUSALS)
        for entry in placement["refusals"]:
            self.assertLessEqual(len(entry["reason"]), MAX_REFUSAL_REASON_CHARS)

    def test_a_malformed_peer_id_is_dropped_without_losing_the_heartbeat(self):
        raw, signature = self._signed_heartbeat(placement=self._placement_block(
            refusals=[
                {"peer": "not a peer id!", "count": 1, "reason": "node is cache-only"},
                {"peer": "12D3KooWReal", "count": 2, "reason": "node is cache-only"},
            ]))
        placement = validate_heartbeat(
            raw, self.requester_id, signature, STORAGE_USER_AGENT
        )["placement"]
        self.assertEqual([e["peer"] for e in placement["refusals"]], ["12D3KooWReal"])


class RevocationTest(unittest.TestCase):
    """Shard-DELETE tokens.

    A revocation is signed by the SAME key as a placement lease, by the same
    party, for the same shard. The properties worth testing are therefore not
    "does it sign" but the ones that keep the two apart and keep a token from
    working anywhere it was not meant to.
    """

    def setUp(self):
        self.coordinator = SigningKey.generate()
        self.requester = SigningKey.generate()
        self.recipient = SigningKey.generate()
        self.requester_id = _peer_id(self.requester)
        self.recipient_id = _peer_id(self.recipient)
        self.environment = mock.patch.dict(os.environ, {
            "STORAGE_COORDINATOR_SIGNING_KEY": base64.b64encode(
                self.coordinator.encode()
            ).decode("ascii"),
            "STORAGE_LEASE_REQUESTER_PEERS": self.requester_id,
        })
        self.environment.start()
        # Empty by default: an object with no recorded owner, which is the state
        # of everything placed before the ownership table existed.
        self.ownership = _OwnershipStub().install(self)

    def tearDown(self):
        self.environment.stop()

    def _request(self, **overrides):
        payload = {
            "version": 1,
            "requester": self.requester_id,
            "object_id": "a" * 64,
            "shards": [{"shard_id": "b" * 64, "recipient": self.recipient_id}],
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
        }
        payload.update(overrides)
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(
            self.requester.sign(raw).signature
        ).decode("ascii").rstrip("=")
        return raw, signature

    def test_a_revocation_is_signed_and_bound_to_one_shard_and_one_peer(self):
        raw, signature = self._request()
        issued = issue_revocations(raw, self.requester_id, signature)["revocations"]
        self.assertEqual(len(issued), 1)
        token = issued[0]
        self.assertEqual(token["shard_id"], "b" * 64)
        self.assertEqual(token["recipient"], self.recipient_id)
        self.assertEqual(token["requester"], self.requester_id)
        self.assertGreater(token["expires_at"], token["issued_at"])
        # A ten-minute life, well inside the hour the holder will tolerate.
        self.assertLessEqual(token["expires_at"] - token["issued_at"], 3600)
        self.coordinator.verify_key.verify(
            _revocation_message(token),
            base64.b64decode(token["signature"] + "=="),
        )

    def test_every_token_in_a_batch_gets_its_own_nonce(self):
        # The holder now REFUSES a revocation nonce it has already honoured
        # (dendritic-node/internal/store/recall.go, ClaimRevocationNonce), so a
        # batch that shared one nonce across its tokens would delete the first
        # shard and have every other one refused as a replay -- a recall that
        # silently stopped after one shard per peer. Minting the nonce inside
        # the per-shard loop is therefore load-bearing, not hygiene.
        raw, signature = self._request(shards=[
            {"shard_id": "b" * 64, "recipient": self.recipient_id},
            {"shard_id": "c" * 64, "recipient": self.recipient_id},
            {"shard_id": "d" * 64, "recipient": self.recipient_id},
        ])
        issued = issue_revocations(raw, self.requester_id, signature)["revocations"]
        self.assertEqual(len(issued), 3)
        nonces = {token["nonce"] for token in issued}
        self.assertEqual(len(nonces), 3,
                         "tokens in one batch share a nonce, so a holder that "
                         "refuses replays would honour only the first")

    def test_the_requester_is_inside_the_signed_message(self):
        """A delete token names who may PRESENT it, not only who may honour it.

        The frame carrying a revocation crosses the network in the clear, so a
        token that is merely *addressed* to a holder is a bearer instrument: the
        holder it was aimed at, or anything that watched the exchange, can
        present the same bytes itself. Binding is only worth anything if the
        requester is covered by the coordinator's signature -- otherwise the
        holder's identity check is defeated by editing one JSON field.
        """
        raw, signature = self._request()
        token = issue_revocations(raw, self.requester_id, signature)["revocations"][0]
        message = _revocation_message(token)
        self.assertIn(self.requester_id.encode("ascii"), message)
        # A whole line of its own, so it cannot be a coincidental substring of
        # some neighbouring field.
        self.assertIn(
            b"\n" + self.requester_id.encode("ascii") + b"\n", message)

        # And rewriting it invalidates the signature, which is the property the
        # holder actually relies on.
        stolen = dict(token, requester=self.recipient_id)
        self.assertNotEqual(_revocation_message(stolen), message)
        with self.assertRaises(Exception):
            self.coordinator.verify_key.verify(
                _revocation_message(stolen),
                base64.b64decode(token["signature"] + "=="),
            )

    def test_an_object_with_no_ownership_row_falls_back_to_the_origin_count(self):
        """THE PINNED DECISION for objects that predate the ownership table.

        Everything this deployment has ever stored has no row. Refusing all of
        them would stop recall working for the entire existing corpus -- and
        silently, because a refused revocation just retries. So a row-less object
        keeps exactly the behaviour that shipped before the table: with a single
        authorized origin the requester is necessarily the only peer that could
        have placed anything, so sign; with two or more it is a guess, and
        guessing means one origin can order the other's data destroyed
        everywhere, so refuse.

        The fallback therefore never signs anything the previous code would not
        have signed. It is not a weakening; it is the floor the table is built
        on top of.
        """
        self.assertEqual({}, self.ownership.rows)
        other_origin = _peer_id(SigningKey.generate())
        with mock.patch.dict(os.environ, {
            "STORAGE_LEASE_REQUESTER_PEERS": self.requester_id + "," + other_origin,
        }):
            raw, signature = self._request()
            with self.assertRaises(PermissionError):
                issue_revocations(raw, self.requester_id, signature)

        # Same request, one origin: signed. So the refusal above is about not
        # knowing the owner, not about the endpoint being broken.
        raw, signature = self._request()
        issued = issue_revocations(raw, self.requester_id, signature)["revocations"]
        self.assertEqual(len(issued), 1)

    def test_a_delete_token_is_signed_when_the_requester_owns_the_object(self):
        """The case that did not exist before: TWO origins, and it still signs.

        The old check was a tautology that collapsed at two origins and refused
        everything. With a row naming the requester the coordinator is not
        guessing, so the origin count stops being the deciding fact.
        """
        other_origin = _peer_id(SigningKey.generate())
        self.ownership.rows["a" * 64] = self.requester_id
        with mock.patch.dict(os.environ, {
            "STORAGE_LEASE_REQUESTER_PEERS": self.requester_id + "," + other_origin,
        }):
            raw, signature = self._request()
            issued = issue_revocations(raw, self.requester_id, signature)["revocations"]
        self.assertEqual(1, len(issued))
        self.assertEqual(self.requester_id, issued[0]["requester"])

    def test_a_delete_token_is_refused_when_another_origin_owns_the_object(self):
        """And refused even though this is the ONE-origin configuration.

        That is the point. The allow-list holding a single peer used to be
        sufficient proof of ownership; it is not, because a key can be rotated or
        an origin removed and replaced, and the peer left standing must not
        inherit authority over the previous origin's objects by elimination. The
        row beats the count.
        """
        placer = _peer_id(SigningKey.generate())
        self.ownership.rows["a" * 64] = placer
        raw, signature = self._request()
        with self.assertRaises(PermissionError) as caught:
            issue_revocations(raw, self.requester_id, signature)
        self.assertIn(placer, str(caught.exception))

    def test_an_unreadable_ownership_record_is_not_read_as_an_unowned_object(self):
        """Fault F6, on this side of the wire, refused rather than repeated.

        F6 was a ledger READ FAILURE on the node rendered as "no holders were
        ever placed". The identical mistake here is a database fault rendered as
        "nobody owns this object", and it is worse, because "nobody owns this"
        leads to signing in the single-origin configuration -- so a database blip
        would hand out delete tokens.
        """
        self.ownership.unavailable = True
        raw, signature = self._request()
        with self.assertRaises(PermissionError) as caught:
            issue_revocations(raw, self.requester_id, signature)
        self.assertIn("could not read who owns", str(caught.exception))

    def test_the_ownership_check_runs_before_the_nonce_is_burned(self):
        # A request that can never be signed must not spend the requester's
        # replay nonce, or a misconfiguration turns into "and now you cannot
        # retry either".
        self.ownership.rows["a" * 64] = _peer_id(SigningKey.generate())
        raw, signature = self._request()
        with self.assertRaises(PermissionError):
            issue_revocations(raw, self.requester_id, signature)
        # Same nonce, ownership now correct: it must still be accepted.
        self.ownership.rows["a" * 64] = self.requester_id
        issued = issue_revocations(raw, self.requester_id, signature)["revocations"]
        self.assertEqual(1, len(issued))

    def test_a_revocation_is_not_a_lease_and_a_lease_is_not_a_revocation(self):
        """The one mistake that would be catastrophic and silent.

        A lease and a revocation cover the same object, shard, recipient and
        expiry. If they shared a domain prefix, every lease this coordinator has
        ever signed -- each of which travels in the clear inside a store frame --
        would also be a valid DELETE token for that shard on that peer.
        """
        raw, signature = self._request()
        token = issue_revocations(raw, self.requester_id, signature)["revocations"][0]
        lease_shaped = {
            "version": token["version"], "object_id": token["object_id"],
            "shard_id": token["shard_id"], "size": 1024,
            "recipient": token["recipient"], "expires_at": token["expires_at"],
        }
        self.assertNotEqual(_lease_message(lease_shaped), _revocation_message(token))
        self.assertTrue(_revocation_message(token).startswith(
            b"syndichan-storage-revocation-v1\n"))
        # A lease signature must not verify as a revocation.
        lease_signature = self.coordinator.sign(_lease_message(lease_shaped)).signature
        with self.assertRaises(Exception):
            self.coordinator.verify_key.verify(_revocation_message(token), lease_signature)

    def test_only_an_authorized_requester_can_obtain_delete_tokens(self):
        stranger = SigningKey.generate()
        stranger_id = _peer_id(stranger)
        payload = {
            "version": 1, "requester": stranger_id, "object_id": "a" * 64,
            "shards": [{"shard_id": "b" * 64, "recipient": self.recipient_id}],
            "timestamp": int(time.time()),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = base64.b64encode(
            stranger.sign(raw).signature
        ).decode("ascii").rstrip("=")
        with self.assertRaises(PermissionError):
            issue_revocations(raw, stranger_id, signature)

    def test_a_body_the_requester_did_not_sign_is_refused(self):
        # The shard id is swapped AFTER signing: a token must never be obtained
        # for bytes the requesting node did not name.
        raw, signature = self._request()
        tampered = raw.replace(b"b" * 64, b"c" * 64)
        self.assertNotEqual(raw, tampered)
        with self.assertRaises(PermissionError):
            issue_revocations(tampered, self.requester_id, signature)

    def test_a_recipient_that_is_not_a_peer_id_is_refused(self):
        raw, signature = self._request(
            shards=[{"shard_id": "b" * 64, "recipient": "not-a-peer"}])
        with self.assertRaises(ValueError):
            issue_revocations(raw, self.requester_id, signature)

    def test_a_replayed_nonce_is_refused(self):
        raw, signature = self._request()
        issue_revocations(raw, self.requester_id, signature)
        with self.assertRaises(ValueError):
            issue_revocations(raw, self.requester_id, signature)

    def test_the_batch_is_bounded(self):
        raw, signature = self._request(shards=[
            {"shard_id": "b" * 64, "recipient": self.recipient_id}
            for _ in range(MAX_REVOCATIONS_PER_REQUEST + 1)
        ])
        with self.assertRaises(ValueError):
            issue_revocations(raw, self.requester_id, signature)

    def test_a_stale_request_is_refused(self):
        raw, signature = self._request(timestamp=int(time.time()) - 3600)
        with self.assertRaises(ValueError):
            issue_revocations(raw, self.requester_id, signature)


if __name__ == "__main__":
    unittest.main()
