"""The DHT purge: what it deletes, what it refuses to, and what it must never
claim to have done.

The property under test is not "does it delete" -- an S3 DELETE is three lines.
It is that the report is TRUE. Two specific lies are cheap to write and
expensive to discover:

  1. "purged", when the node's gateway answered 204 without deleting anything.
     It answers 204 unconditionally (s3api/server.go:624 discards the error), so
     any code that trusts the status code is reporting the request, not the
     result.

  2. "purged", when shards of the object are still sitting on other peers. They
     always are, and they always will be, because the peer protocol has no
     delete operation. A report that omits that is worse than no report.

So most of what follows checks the SHAPE of the answer rather than the deletion.
"""
import ast
import os
import pathlib
import sys
import types
import unittest
from unittest.mock import MagicMock

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


# --- stubs, installed before the module under test is imported ---------------

class _FakeSession(object):
    """Enough SQLAlchemy shape to drive the row-cleanup path deterministically.

    Deliberately not a MagicMock: a MagicMock returns a truthy Mock for
    one_or_none(), which would make "media not found" untestable and would let a
    delete count of `<MagicMock>` sail through a format string looking fine.
    """

    def __init__(self):
        self.results = {}
        self.deleted = []
        self.committed = 0
        self.rolled_back = 0

    def query(self, *entities):
        return _FakeQuery(self, entities)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1

    def add(self, row):
        pass


class _FakeQuery(object):
    def __init__(self, session, entities):
        self._session = session
        self._key = getattr(entities[0], "__name__", str(entities[0]))

    def filter(self, *a, **k):
        return self

    def join(self, *a, **k):
        return self

    def limit(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def distinct(self):
        return self

    def one_or_none(self):
        return self._session.results.get(self._key, {}).get("one")

    def all(self):
        return self._session.results.get(self._key, {}).get("all", [])

    def scalar(self):
        return self._session.results.get(self._key, {}).get("scalar", 0)

    def delete(self, **k):
        self._session.deleted.append(self._key)
        return self._session.results.get(self._key, {}).get("deleted", 0)


def _install_stubs():
    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        shared.app = MagicMock()
        shared.app.config = {}
        db = types.SimpleNamespace()
        db.session = _FakeSession()
        db.func = MagicMock()
        shared.db = db
        sys.modules["shared"] = shared
    elif not hasattr(sys.modules["shared"].db, "session"):
        sys.modules["shared"].db.session = _FakeSession()

    # A missing-object error the module can recognise without boto3.
    class _Missing(Exception):
        pass

    media_mod = types.ModuleType("model.Media")

    class _S3Storage(object):
        pass

    media_mod.S3Storage = _S3Storage
    media_mod.storage = None
    media_mod.Media = type("Media", (), {"id": 0, "ext": "", "sha256": ""})
    media_mod._is_missing_storage_error = lambda exc: isinstance(exc, _Missing)
    media_mod.Missing = _Missing
    sys.modules["model.Media"] = media_mod

    post_mod = types.ModuleType("model.Post")
    post_mod.Post = type("Post", (), {"id": 0, "media": 0, "thread": 0, "body": ""})
    sys.modules["model.Post"] = post_mod

    video_mod = types.ModuleType("model.Video")
    video_mod.Video = type("Video", (), {"media_id": 0})
    sys.modules["model.Video"] = video_mod

    board_mod = types.ModuleType("model.Board")
    board_mod.Board = type("Board", (), {"id": 0, "uri": ""})
    sys.modules["model.Board"] = board_mod

    thread_mod = types.ModuleType("model.Thread")
    thread_mod.Thread = type("Thread", (), {"id": 0, "board": 0})
    sys.modules["model.Thread"] = thread_mod

    blocked_mod = types.ModuleType("model.BlockedMediaHash")
    blocked_mod.blocked = []
    blocked_mod.block_media_hash = lambda sha, **k: blocked_mod.blocked.append(sha)
    sys.modules["model.BlockedMediaHash"] = blocked_mod

    audit_mod = types.ModuleType("model.DhtPurgeAudit")
    audit_mod.rows = []

    def _record(target, kind, layers, outcome, **kwargs):
        row = dict(kwargs)
        row.update({"target": target, "kind": kind, "layers": layers,
                    "outcome": outcome})
        audit_mod.rows.append(row)
        return row

    audit_mod.record = _record
    sys.modules["model.DhtPurgeAudit"] = audit_mod


_install_stubs()

import shared  # noqa: E402
from services import dht_object_purge as purge_mod  # noqa: E402

_MISSING = sys.modules["model.Media"].Missing
_AUDIT = sys.modules["model.DhtPurgeAudit"]
_BLOCKED = sys.modules["model.BlockedMediaHash"]


class FakeGateway(object):
    """An S3-shaped store whose delete can be made to silently do nothing.

    `honour_delete=False` reproduces the node exactly: the request is accepted,
    204 comes back, the object is still there.
    """

    def __init__(self, objects=None, honour_delete=True, head_error=None):
        self._objects = dict(objects or {})
        self.honour_delete = honour_delete
        self.head_error = head_error
        self.deletes = []
        self.heads = []
        self._bucket_uuid = "uuid-"
        client = MagicMock()
        client.head_object.side_effect = self._head
        self._s3_client = MagicMock()
        self._s3_client.meta.client = client

    def _head(self, Bucket=None, Key=None):
        self.heads.append((Bucket, Key))
        if self.head_error is not None:
            raise self.head_error
        bucket = Bucket[len(self._bucket_uuid):]
        size = self._objects.get((bucket, Key))
        if size is None:
            raise _MISSING("no such key")
        return {"ContentLength": size, "ETag": '"objectid-%s"' % Key}

    def _s3_remove_key(self, bucket, key):
        self.deletes.append((bucket, key))
        if self.honour_delete:
            self._objects.pop((bucket, key), None)


class FakeMedia(object):
    def __init__(self, media_id=77, ext="png", sha256="a" * 64):
        self.id = media_id
        self.ext = ext
        self.sha256 = sha256
        self.nsfw_score = 0.1
        self.dht_offloaded_at = object()


class PurgeTestBase(unittest.TestCase):
    def setUp(self):
        _AUDIT.rows[:] = []
        _BLOCKED.blocked[:] = []
        self.session = _FakeSession()
        shared.db.session = self.session
        self.dht = FakeGateway({("arcade", "game.wasm"): 3 * (1 << 20)})
        self.primary = FakeGateway({("arcade", "game.wasm"): 3 * (1 << 20)})
        purge_mod._dht_store = lambda: self.dht
        purge_mod._primary_store = lambda: self.primary
        # media_cache pulls in the real module; keep it out of the way.
        cache_mod = types.ModuleType("services.media_cache")
        cache_mod.cache = lambda: MagicMock()
        sys.modules["services.media_cache"] = cache_mod

    def tearDown(self):
        sys.modules.pop("services.media_cache", None)


# --------------------------------------------------------------------------
# 1. The admin gate. A non-admin must get what every other admin route gives.
# --------------------------------------------------------------------------

class AdminGateTest(unittest.TestCase):
    """Structural, because the app cannot be booted without a database.

    Checking the source for the decorator is weaker than a request test, but it
    catches the failure that actually happens -- a new route added next to
    gated ones without the decorator -- and it can run in CI.
    """

    @classmethod
    def setUpClass(cls):
        cls.source = pathlib.Path(BACKEND, "blueprints", "admin.py").read_text()
        cls.tree = ast.parse(cls.source)

    def _routes(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            routes, guards = [], []
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) \
                        and dec.func.attr == "route":
                    routes.extend(a.value for a in dec.args
                                  if isinstance(a, ast.Constant))
                elif isinstance(dec, ast.Name):
                    guards.append(dec.id)
            if routes:
                yield node.name, routes, guards

    def test_every_dht_purge_route_uses_the_shared_admin_gate(self):
        seen = {}
        for name, routes, guards in self._routes():
            for route in routes:
                if route.startswith("/dht-purge"):
                    seen[route] = guards
        self.assertEqual(
            sorted(seen), ["/dht-purge", "/dht-purge/execute", "/dht-purge/object",
                           "/dht-purge/preview", "/dht-purge/recall"],
            "the purge/list/recall routes should exist and be the only "
            "/dht-purge routes")
        for route, guards in seen.items():
            self.assertIn("_admin_required", guards,
                          "%s is not behind the admin gate" % route)

    def test_the_gate_is_the_one_every_other_admin_route_uses(self):
        # A non-admin gets the SAME redirect-to-login as for any other admin
        # route, because there is exactly one gate and these routes use it.
        # (Note the pre-existing property this inherits: an admin route answers
        # 302 while an unknown path answers 404, so existence is distinguishable
        # for every admin route alike. That is the site's behaviour, not this
        # feature's, and these routes do not deviate from it.)
        self.assertIn('return redirect(url_for("admin.login"))', self.source)
        self.assertEqual(self.source.count("def _admin_required("), 1)

    def test_the_purge_page_is_reachable_from_the_admin_nav(self):
        """A destructive tool nobody can find is a tool that gets reached for in
        a hurry, from a URL somebody half-remembers.

        This used to assert a link on the dashboard, because a hardcoded button
        row there was the only navigation in the admin panel. The row is gone:
        navigation now comes from services/admin_nav.py and is rendered by the
        shell on EVERY admin screen, so the guarantee is stronger and lives in
        one place. tests/test_admin_nav.py additionally asserts that no admin
        page is missing from that map.
        """
        from services import admin_nav

        self.assertIn("admin.dht_purge", admin_nav.all_endpoints())

        item = dict(
            (i.endpoint, i)
            for group in admin_nav.SITE_MAP for i in group.items
        )["admin.dht_purge"]
        # And it is marked as destructive, so it does not read like a report.
        self.assertTrue(item.danger)


# --------------------------------------------------------------------------
# 2. Targets
# --------------------------------------------------------------------------

class TargetParsingTest(unittest.TestCase):
    def test_media_and_object_forms_round_trip(self):
        self.assertEqual(purge_mod.parse_target("media:12")["canonical"], "media:12")
        self.assertEqual(
            purge_mod.parse_target("  arcade/sub/game.wasm ")["canonical"],
            "arcade/sub/game.wasm")

    def test_a_bare_number_is_refused_rather_than_guessed(self):
        with self.assertRaises(purge_mod.TargetError) as caught:
            purge_mod.parse_target("1234")
        self.assertIn("Ambiguous", str(caught.exception))

    def test_unknown_bucket_is_refused(self):
        with self.assertRaises(purge_mod.TargetError):
            purge_mod.parse_target("nosuchbucket/thing.bin")

    def test_a_prefix_is_not_an_object(self):
        with self.assertRaises(purge_mod.TargetError):
            purge_mod.parse_target("arcade/some/dir/")

    def test_empty_is_refused(self):
        with self.assertRaises(purge_mod.TargetError):
            purge_mod.parse_target("   ")

    def test_shard_count_follows_the_nodes_geometry(self):
        # 3 MiB -> 3 chunks -> 27 shards at 6+3.
        maths = purge_mod._shard_math(3 * (1 << 20))
        self.assertEqual((maths["chunks"], maths["shards"]), (3, 27))
        # One byte over a chunk boundary is a whole extra chunk.
        self.assertEqual(purge_mod._shard_math((1 << 20) + 1)["chunks"], 2)
        self.assertEqual(purge_mod._shard_math(0)["shards"], 0)


# --------------------------------------------------------------------------
# 3. Preview must not delete
# --------------------------------------------------------------------------

class PreviewTest(PurgeTestBase):
    def test_preview_deletes_nothing(self):
        result = purge_mod.preview("arcade/game.wasm")
        self.assertEqual(self.dht.deletes, [])
        self.assertEqual(self.primary.deletes, [])
        self.assertEqual(result["totals"]["present"], 1)

    def test_preview_writes_no_audit_row(self):
        purge_mod.preview("arcade/game.wasm")
        self.assertEqual(_AUDIT.rows, [])

    def test_preview_shows_size_bucket_key_and_shard_count(self):
        result = purge_mod.preview("arcade/game.wasm")
        row = result["objects"][0]
        self.assertEqual(row["bucket"], "arcade")
        self.assertEqual(row["key"], "game.wasm")
        self.assertEqual(row["dht"]["size"], 3 * (1 << 20))
        self.assertEqual(row["shards"]["shards"], 27)
        self.assertEqual(result["totals"]["shards"], 27)

    def test_remote_holders_are_unknown_not_zero_when_the_ledger_is_unreadable(self):
        # No ledger stub is installed, so _ledger_call fails. The one thing that
        # must never happen is printing 0: a node that cannot be asked is not a
        # node with nothing placed.
        result = purge_mod.preview("arcade/game.wasm")
        self.assertFalse(result["remote_holders"]["known"])
        self.assertIsNone(result["remote_holders"]["count"])
        self.assertIn("not zero", result["remote_holders"]["reason"])
        # Recall is possible in principle now -- the verb exists -- which is a
        # different claim from "this particular read worked".
        self.assertTrue(result["remote_shards_recallable"])
        self.assertTrue(result["objects"][0]["shards"]["derived"])

    def test_holder_and_shard_counts_are_observed_when_the_ledger_answers(self):
        # 6 shards over 2 chunks with 4 holders is deliberately NOT what the
        # 6+3-of-a-3MiB-object arithmetic would produce, so a result matching
        # the ledger proves the ledger was read rather than recomputed.
        self.addCleanup(setattr, purge_mod, "_ledger_call", purge_mod._ledger_call)
        purge_mod._ledger_call = lambda *a, **k: ({
            "object_id": "b" * 64, "chunks": 2, "shard_count": 6,
            "data_shards": 4, "parity_shards": 2, "distinct_holders": 4,
        }, None)
        result = purge_mod.preview("arcade/game.wasm")
        row = result["objects"][0]
        self.assertFalse(row["shards"]["derived"])
        self.assertEqual((row["shards"]["chunks"], row["shards"]["shards"]), (2, 6))
        self.assertTrue(result["remote_holders"]["known"])
        self.assertEqual(result["remote_holders"]["count"], 4)

    def test_absent_object_is_previewed_not_pretended(self):
        result = purge_mod.preview("arcade/never-existed.wasm")
        self.assertEqual(result["totals"]["present"], 0)
        self.assertTrue(any("delete no bytes" in w for w in result["warnings"]))

    def test_a_site_critical_bucket_is_called_out(self):
        self.dht._objects[("static", "js/app.js")] = 10
        result = purge_mod.preview("static/js/app.js")
        self.assertTrue(any("404" in w for w in result["warnings"]))


# --------------------------------------------------------------------------
# 4. Confirmation
# --------------------------------------------------------------------------

class ConfirmationTest(PurgeTestBase):
    def test_wrong_confirmation_deletes_nothing(self):
        result = purge_mod.purge("arcade/game.wasm", "arcade/other.wasm")
        self.assertEqual(result["outcome"], "refused")
        self.assertEqual(self.dht.deletes, [])
        self.assertEqual(self.primary.deletes, [])

    def test_empty_confirmation_deletes_nothing(self):
        result = purge_mod.purge("arcade/game.wasm", "")
        self.assertEqual(result["outcome"], "refused")
        self.assertEqual(self.dht.deletes, [])

    def test_a_refusal_is_still_audited(self):
        purge_mod.purge("arcade/game.wasm", "nope")
        self.assertEqual(len(_AUDIT.rows), 1)
        self.assertEqual(_AUDIT.rows[0]["outcome"], "refused")

    def test_matching_confirmation_proceeds(self):
        result = purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        self.assertEqual(result["outcome"], "purged")
        self.assertIn(("arcade", "game.wasm"), self.dht.deletes)


# --------------------------------------------------------------------------
# 5. The per-layer report
# --------------------------------------------------------------------------

class LayerReportTest(PurgeTestBase):
    def _layers(self, result):
        return {l["layer"]: l["status"] for l in result["layers"]}

    def test_each_layer_is_reported_separately(self):
        layers = self._layers(purge_mod.purge("arcade/game.wasm", "arcade/game.wasm"))
        self.assertEqual(layers["dht_gateway_object"], "deleted")
        self.assertEqual(layers["primary_store_object"], "deleted")
        self.assertEqual(layers["node_local_shards"], "released")
        self.assertEqual(layers["placement_ledger"], "retired")
        # No ledger reachable in this harness, so the honest answer is that the
        # holders were not asked -- distinct from "asked and nobody answered".
        self.assertEqual(layers["remote_shard_holders"], "unavailable")

    def test_a_remote_holder_layer_is_reported_on_every_outcome(self):
        # Including when nothing was there to delete: the shards of a
        # previously-purged object are still out there.
        for target in ("arcade/game.wasm", "arcade/absent.wasm"):
            result = purge_mod.purge(target, target)
            statuses = [l for l in result["layers"]
                        if l["layer"] == "remote_shard_holders"]
            self.assertTrue(statuses, "no remote-holder layer for %s" % target)
            for layer in statuses:
                self.assertEqual(layer["status"], "unavailable")
                self.assertFalse(layer["holders_known"])
                self.assertIsNone(layer["holders"])

    def test_each_holder_answer_is_reported_separately(self):
        # The whole point of the recall protocol: deleted, refused and
        # unreachable are three different true outcomes and the report must
        # keep them apart rather than collapsing them into one word.
        self.addCleanup(setattr, purge_mod, "_ledger_call", purge_mod._ledger_call)

        def _ledger(method, path, params=None, timeout=None):
            if method == "POST":
                return ({
                    "object_id": "c" * 64, "outstanding": 2, "resolved": False,
                    "counts": {"deleted": 1, "refused": 1, "unreachable": 1},
                    "shards": [{"shard_id": "d" * 64, "chunk_index": 0,
                                "shard_index": 0, "size": 1024, "holders": [
                                    {"peer_id": "peerA", "state": "deleted",
                                     "detail": "removed"},
                                    {"peer_id": "peerB", "state": "refused",
                                     "detail": "still referenced"},
                                    {"peer_id": "peerC", "state": "unreachable",
                                     "detail": "no answer"},
                                ]}],
                }, None)
            return ({"chunks": 1, "shard_count": 1, "data_shards": 6,
                     "parity_shards": 3, "distinct_holders": 3}, None)

        purge_mod._ledger_call = _ledger
        result = purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        layer = [l for l in result["layers"]
                 if l["layer"] == "remote_shard_holders"][0]
        self.assertEqual(layer["status"], "partial")
        self.assertEqual(layer["counts"]["deleted"], 1)
        self.assertEqual(layer["counts"]["refused"], 1)
        self.assertEqual(layer["counts"]["unreachable"], 1)
        self.assertEqual(layer["holders"], 3)
        # A holder that deleted makes the audit column true; the two that did
        # not are still reported, and the outcome is not dressed up as complete.
        self.assertTrue(result["remote_shards_recalled"])
        self.assertTrue(_AUDIT.rows[0]["remote_shards_recalled"])

    def test_a_recall_that_reaches_nobody_never_claims_it_did(self):
        self.addCleanup(setattr, purge_mod, "_ledger_call", purge_mod._ledger_call)
        purge_mod._ledger_call = lambda method, path, params=None, timeout=None: (
            ({"counts": {"unreachable": 4}, "outstanding": 4, "shards": []}, None)
            if method == "POST" else ({"chunks": 1, "shard_count": 9}, None))
        result = purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        layer = [l for l in result["layers"]
                 if l["layer"] == "remote_shard_holders"][0]
        self.assertEqual(layer["status"], "partial")
        self.assertFalse(result["remote_shards_recalled"])
        self.assertFalse(_AUDIT.rows[0]["remote_shards_recalled"])

    def test_the_recall_happens_before_the_object_is_deleted(self):
        # Order is load-bearing: the recall needs the placement row, and a
        # failure to reach the node must leave the object intact rather than
        # deleted-and-unrecallable.
        self.addCleanup(setattr, purge_mod, "_ledger_call", purge_mod._ledger_call)
        order = []

        def _ledger(method, path, params=None, timeout=None):
            if method == "POST":
                order.append("recall")
            return ({"counts": {}, "shards": [], "chunks": 1,
                     "shard_count": 9}, None)

        original_delete = purge_mod._delete_from

        def _delete(store, label, bucket, key):
            order.append("delete:%s" % label)
            return original_delete(store, label, bucket, key)

        purge_mod._ledger_call = _ledger
        self.addCleanup(setattr, purge_mod, "_delete_from", original_delete)
        purge_mod._delete_from = _delete
        purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        self.assertEqual(order[0], "recall",
                         "the object was deleted before its holders were asked")

    def test_a_gateway_that_lies_with_204_is_reported_as_still_present(self):
        # The node's deleteObject discards the error and always answers 204, so
        # trusting the response is exactly the bug. The confirming HEAD is what
        # decides.
        self.dht.honour_delete = False
        result = purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        layers = self._layers(result)
        self.assertEqual(layers["dht_gateway_object"], "still_present")
        # And nothing downstream may claim the shards went with it.
        self.assertEqual(layers["node_local_shards"], "not_reached")

    def test_nothing_found_is_not_reported_as_purged(self):
        result = purge_mod.purge("arcade/absent.wasm", "arcade/absent.wasm")
        self.assertEqual(result["outcome"], "nothing_found")
        layers = self._layers(result)
        self.assertEqual(layers["dht_gateway_object"], "absent")

    def test_a_gateway_error_is_not_silently_a_success(self):
        self.dht.head_error = RuntimeError("gateway on fire")
        self.primary.head_error = RuntimeError("gateway on fire")
        result = purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(self._layers(result)["dht_gateway_object"], "error")

    def test_no_dht_configured_is_stated_not_counted_as_deleted(self):
        purge_mod._dht_store = lambda: None
        result = purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        self.assertEqual(self._layers(result)["dht_gateway_object"], "not_configured")

    def test_the_result_has_no_single_success_flag(self):
        result = purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        for forbidden in ("ok", "success", "purged_everywhere"):
            self.assertNotIn(forbidden, result)


# --------------------------------------------------------------------------
# 6. Audit
# --------------------------------------------------------------------------

class AuditTest(PurgeTestBase):
    def test_an_audit_row_records_who_what_and_the_layers(self):
        purge_mod.purge("arcade/game.wasm", "arcade/game.wasm",
                        reason="dmca 41", acting_slip_id=9,
                        acting_wallet="0xabc", acting_ip="10.0.0.1")
        self.assertEqual(len(_AUDIT.rows), 1)
        row = _AUDIT.rows[0]
        self.assertEqual(row["target"], "arcade/game.wasm")
        self.assertEqual(row["outcome"], "purged")
        self.assertEqual(row["reason"], "dmca 41")
        self.assertEqual(row["acting_slip_id"], 9)
        self.assertEqual(row["acting_wallet"], "0xabc")
        self.assertEqual(row["acting_ip"], "10.0.0.1")
        self.assertTrue(row["layers"])

    def test_the_audit_row_records_that_remote_shards_were_not_recalled(self):
        purge_mod.purge("arcade/game.wasm", "arcade/game.wasm")
        self.assertFalse(_AUDIT.rows[0]["remote_shards_recalled"])

    def test_a_purge_that_found_nothing_is_still_audited(self):
        purge_mod.purge("arcade/absent.wasm", "arcade/absent.wasm")
        self.assertEqual(len(_AUDIT.rows), 1)
        self.assertEqual(_AUDIT.rows[0]["outcome"], "nothing_found")

    def test_an_unparseable_target_is_audited_before_it_raises(self):
        with self.assertRaises(purge_mod.TargetError):
            purge_mod.purge("1234", "1234")
        self.assertEqual(len(_AUDIT.rows), 1)
        self.assertEqual(_AUDIT.rows[0]["outcome"], "refused")


# --------------------------------------------------------------------------
# 7. Nothing is left pointing at bytes that are gone
# --------------------------------------------------------------------------

class DanglingRowTest(PurgeTestBase):
    def _media_session(self, media):
        self.session.results["Media"] = {"one": media, "deleted": 1}
        self.session.results["Post"] = {"scalar": 2, "all": [], "deleted": 2}
        self.session.results["Video"] = {"scalar": 0, "deleted": 0}

    def test_a_media_purge_deletes_the_rows_that_referenced_it(self):
        media = FakeMedia(media_id=77, ext="png")
        self._media_session(media)
        self.dht._objects[("attachments", "77.png")] = 1024
        result = purge_mod.purge("media:77", "media:77")
        layers = {l["layer"]: l for l in result["layers"]}
        self.assertEqual(layers["database_rows"]["status"], "deleted")
        self.assertIn("Media", self.session.deleted)
        self.assertIn("Post", self.session.deleted)

    def test_a_media_purge_blocklists_the_hash(self):
        self._media_session(FakeMedia(sha256="b" * 64))
        purge_mod.purge("media:77", "media:77")
        self.assertEqual(_BLOCKED.blocked, ["b" * 64])

    def test_declining_row_deletion_says_the_rows_now_dangle(self):
        self._media_session(FakeMedia())
        result = purge_mod.purge("media:77", "media:77", delete_rows=False)
        layers = {l["layer"]: l for l in result["layers"]}
        self.assertEqual(layers["database_rows"]["status"], "left_dangling")
        self.assertNotIn("Media", self.session.deleted)

    def test_purging_a_raw_media_key_warns_that_the_row_survives(self):
        # The trap: deleting attachments/77.png by key leaves media #77 and
        # every post using it pointing at nothing.
        self.session.results["Media"] = {"one": FakeMedia(media_id=77)}
        self.dht._objects[("attachments", "77.png")] = 1024
        result = purge_mod.purge("attachments/77.png", "attachments/77.png")
        layers = {l["layer"]: l for l in result["layers"]}
        self.assertEqual(layers["database_rows"]["status"], "left_dangling")
        self.assertIn("media:77", layers["database_rows"]["detail"])

    def test_an_unknown_media_id_is_refused_before_anything_is_deleted(self):
        self.session.results["Media"] = {"one": None}
        with self.assertRaises(purge_mod.TargetError):
            purge_mod.purge("media:4242", "media:4242")
        self.assertEqual(self.dht.deletes, [])
        # Confirmation had already matched, so this was an attempted purge.
        self.assertEqual(len(_AUDIT.rows), 1)
        self.assertEqual(_AUDIT.rows[0]["outcome"], "refused")


# --------------------------------------------------------------------------
# 8. The read cache must actually give up the bytes
# --------------------------------------------------------------------------

class CacheEvictionTest(unittest.TestCase):
    """mark_unavailable() is not eviction. media_read.attachment_bytes calls
    cache.get() BEFORE is_unavailable(), so an entry that is only marked stays
    served -- the purged bytes would keep coming out of RAM."""

    def test_drop_removes_the_bytes_and_get_misses_afterwards(self):
        sys.modules.pop("services.media_cache", None)
        from services.media_cache import MediaCache

        cache = MediaCache(capacity_bytes=1 << 20)
        cache.put("attachment:5", b"secret-bytes")
        self.assertEqual(cache.get("attachment:5"), b"secret-bytes")
        self.assertTrue(cache.drop("attachment:5"))
        self.assertIsNone(cache.get("attachment:5"))

    def test_dropping_something_absent_is_not_an_error(self):
        sys.modules.pop("services.media_cache", None)
        from services.media_cache import MediaCache

        self.assertFalse(MediaCache(capacity_bytes=1 << 20).drop("attachment:9"))

    def test_marking_unavailable_alone_would_not_have_been_enough(self):
        # Pins the reason drop() exists at all.
        sys.modules.pop("services.media_cache", None)
        from services.media_cache import MediaCache

        cache = MediaCache(capacity_bytes=1 << 20)
        cache.put("attachment:5", b"secret-bytes")
        cache.mark_unavailable("attachment:5")
        self.assertEqual(cache.get("attachment:5"), b"secret-bytes")


# --------------------------------------------------------------------------
# 9. The bulk moderation purge must reach the DHT too
# --------------------------------------------------------------------------

class BulkPurgeReachesTheDhtTest(unittest.TestCase):
    """services/media_purge.py claimed to delete from the DHT and did not --
    Media.delete_attachment() goes to model.Media.storage, the PRIMARY store.
    Offloaded media is read from the DHT gateway, so a "purge" left the bytes
    live and fetchable."""

    def test_the_source_deletes_from_both_stores(self):
        source = pathlib.Path(BACKEND, "services", "media_purge.py").read_text()
        self.assertIn("delete_attachment()", source)
        self.assertIn("_DHTStorage.get().delete_attachment(", source)
        self.assertIn("dht_write_enabled()", source)

    def test_the_source_evicts_the_read_cache(self):
        source = pathlib.Path(BACKEND, "services", "media_purge.py").read_text()
        self.assertIn('drop("attachment:', source)


# --------------------------------------------------------------------------
# 10. Listing the ledger, and recalling shards without deleting the object
# --------------------------------------------------------------------------

class LedgerListingTest(PurgeTestBase):
    def _stub(self, payload, error=None):
        self.addCleanup(setattr, purge_mod, "_ledger_call", purge_mod._ledger_call)
        self.calls = []

        def _ledger(method, path, params=None, timeout=None):
            self.calls.append((method, path, dict(params or {})))
            return (payload, error)

        purge_mod._ledger_call = _ledger

    def test_a_listing_row_carries_the_canonical_target_the_purge_form_takes(self):
        # Otherwise list-then-delete means retyping from a different vocabulary,
        # which is how the wrong key gets purged.
        self._stub({"objects": [{
            "object_id": "a" * 64, "bucket": "arcade", "key": "game.wasm",
            "chunks": 3, "shard_count": 27, "distinct_holders": 5,
            "holder_shards": {"peerA": 3, "peerB": 9},
        }], "next_marker": ""})
        listing = purge_mod.list_placements("arcade")
        self.assertTrue(listing["available"])
        row = listing["objects"][0]
        self.assertEqual(row["canonical"], "arcade/game.wasm")
        self.assertEqual(purge_mod.parse_target(row["canonical"])["canonical"],
                         "arcade/game.wasm")
        # Holders are rolled up per peer, biggest first -- the axis a per-peer
        # decision is made on, which the ledger's own index cannot provide.
        self.assertEqual(row["holders"][0], ("peerB", 9))

    def test_an_unknown_bucket_is_refused_before_the_node_is_called(self):
        self._stub({"objects": []})
        with self.assertRaises(purge_mod.TargetError):
            purge_mod.list_placements("not-a-bucket")
        self.assertEqual(self.calls, [])

    def test_an_unreadable_ledger_is_reported_not_shown_as_empty(self):
        self._stub(None, "connection refused")
        listing = purge_mod.list_placements("arcade")
        self.assertFalse(listing["available"])
        self.assertIn("connection refused", listing["error"])

    def test_the_listing_asks_for_placement_not_for_objects(self):
        self._stub({"objects": []})
        purge_mod.list_placements("arcade", prefix="sub/", marker="ff")
        method, path, params = self.calls[0]
        self.assertEqual(method, "GET")
        self.assertIn("placement", params)
        self.assertEqual(params["prefix"], "sub/")
        self.assertEqual(params["marker"], "ff")


class ShardRecallTest(PurgeTestBase):
    def _stub(self, payload, error=None):
        self.addCleanup(setattr, purge_mod, "_ledger_call", purge_mod._ledger_call)
        self.calls = []

        def _ledger(method, path, params=None, timeout=None):
            self.calls.append((method, path, dict(params or {})))
            return (payload, error)

        purge_mod._ledger_call = _ledger

    def test_a_wrong_confirmation_recalls_nothing(self):
        self._stub({"counts": {"deleted": 9}})
        result = purge_mod.recall("arcade/game.wasm", "arcade/wrong.wasm",
                                  shard_ids=["a" * 64])
        self.assertEqual(result["outcome"], "refused")
        self.assertEqual(self.calls, [])
        self.assertEqual(_AUDIT.rows[0]["outcome"], "refused")

    def test_named_shards_are_passed_through_to_the_node(self):
        self._stub({"counts": {"deleted": 1}, "shards": [], "outstanding": 0})
        purge_mod.recall("arcade/game.wasm", "arcade/game.wasm",
                         shard_ids=["a" * 64, "b" * 64])
        method, path, params = self.calls[0]
        self.assertEqual(method, "POST")
        self.assertIn("recall", params)
        self.assertEqual(params["shard"], ["a" * 64, "b" * 64])

    def test_a_per_shard_recall_says_the_object_will_be_re_dispersed(self):
        # An operator who recalls one shard usually means "get it off THAT
        # machine". The object survives, so the node will place a replacement --
        # elsewhere, because the holder blocklisted the shard id. Saying so is
        # the difference between a surprise and a decision.
        self._stub({"counts": {"deleted": 1}, "shards": [], "outstanding": 0})
        result = purge_mod.recall("arcade/game.wasm", "arcade/game.wasm",
                                  shard_ids=["a" * 64])
        scope = [l for l in result["layers"] if l["layer"] == "recall_scope"][0]
        self.assertEqual(scope["status"], "per_shard")
        self.assertIn("blocklists the shard id", scope["detail"])

    def test_a_recall_is_audited_even_when_the_node_cannot_be_reached(self):
        self._stub(None, "connection refused")
        result = purge_mod.recall("arcade/game.wasm", "arcade/game.wasm")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(len(_AUDIT.rows), 1)
        self.assertFalse(_AUDIT.rows[0]["remote_shards_recalled"])

    def test_a_media_target_is_refused_because_recall_is_per_object(self):
        self._stub({"counts": {}})
        with self.assertRaises(purge_mod.TargetError):
            purge_mod.recall("media:12", "media:12")


class LedgerReadFailureTest(PurgeTestBase):
    """UNKNOWN IS NOT ZERO.

    The node used to answer a failed read of its own recall ledger with an empty
    record and no error. That arrived here as counts of zero and printed "the
    placement ledger recorded no confirmed remote holder for this object" -- a
    settled fact, on the page an operator uses to answer a takedown, standing in
    for a number nobody knew. The node now says which of the two it is, and this
    class is about that distinction surviving to the layer.
    """

    def _stub(self, payload, error=None):
        self.addCleanup(setattr, purge_mod, "_ledger_call", purge_mod._ledger_call)

        def _ledger(method, path, params=None, timeout=None):
            if method == "POST":
                return (payload, error)
            return ({"chunks": 1, "shard_count": 9}, None)

        purge_mod._ledger_call = _ledger

    def _recall_layer(self, result):
        return [l for l in result["layers"]
                if l["layer"] == "remote_shard_holders"][0]

    def test_an_unreadable_ledger_is_not_reported_as_no_holders(self):
        self._stub({"error": "recall_ledger_unreadable",
                    "detail": "the recall ledger could not be read (abc): "
                              "unexpected end of JSON input"})
        layer = self._recall_layer(
            purge_mod.purge("arcade/game.wasm", "arcade/game.wasm"))

        self.assertNotEqual(layer["status"], "no_holders")
        self.assertEqual(layer["status"], "ledger_unreadable")
        # Not a count. Not zero. Unknown.
        self.assertFalse(layer["holders_known"])
        self.assertIsNone(layer["holders"])
        self.assertIn("UNKNOWN", layer["detail"])
        self.assertIn("not zero", layer["detail"])
        # And the node's own words are carried through, so an operator can act
        # on them rather than guess at what broke.
        self.assertIn("unexpected end of JSON input", layer["detail"])

    def test_an_unreadable_ledger_is_told_apart_from_an_unreachable_node(self):
        # Both are failures; only one of them means the node answered.
        self._stub(None, "connection refused")
        unreachable = self._recall_layer(
            purge_mod.purge("arcade/game.wasm", "arcade/game.wasm"))
        self.assertEqual(unreachable["status"], "unavailable")

    def test_a_genuinely_absent_ledger_entry_still_reports_as_absent(self):
        # The node read its ledger and it named nobody. That is an observation,
        # and it must not be dragged into the unknown bucket by the fix above.
        self._stub({"counts": {}, "shards": [], "outstanding": 0, "resolved": True})
        layer = self._recall_layer(
            purge_mod.purge("arcade/game.wasm", "arcade/game.wasm"))

        self.assertEqual(layer["status"], "no_holders")
        self.assertTrue(layer["holders_known"])
        self.assertEqual(layer["holders"], 0)

    def test_a_404_from_the_node_is_still_an_answer_not_a_failure(self):
        # No ledger row for the key: the node looked and there was nothing.
        self._stub(None, "the node answered HTTP 404: NoSuchKey")
        layer = self._recall_layer(
            purge_mod.purge("arcade/game.wasm", "arcade/game.wasm"))

        self.assertEqual(layer["status"], "no_holders")
        self.assertTrue(layer["holders_known"])

    def test_an_unreadable_ledger_fails_a_standalone_recall(self):
        self._stub({"error": "recall_ledger_unreadable", "detail": "bolt: io error"})
        result = purge_mod.recall("arcade/game.wasm", "arcade/game.wasm")
        self.assertEqual(result["outcome"], "failed")
        self.assertNotEqual(result["outcome"], "nothing_found")
        self.assertFalse(_AUDIT.rows[0]["remote_shards_recalled"])

    def test_a_deferred_tombstone_says_so_on_the_page(self):
        # The node backs off to a long retry interval for a holder that keeps
        # refusing. An operator watching for progress has to be told the clock
        # changed, or a page that is merely slow looks stuck.
        self._stub({"counts": {"refused": 2}, "shards": [], "outstanding": 2,
                    "deferred": True})
        layer = self._recall_layer(
            purge_mod.purge("arcade/game.wasm", "arcade/game.wasm"))
        self.assertEqual(layer["status"], "partial")
        self.assertTrue(layer["deferred"])
        self.assertIn("long retry interval", layer["detail"])


if __name__ == "__main__":
    unittest.main()
