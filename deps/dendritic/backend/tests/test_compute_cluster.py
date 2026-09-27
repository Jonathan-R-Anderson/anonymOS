"""Clusters: the split, the clamp, the refusal, and one machine per unit.

The properties defended here are the ones that make a cluster a cluster rather
than a queue with a new name:

  * the corpus is split contiguously, in order, and totally — every line goes
    somewhere, exactly once, carrying its position in the WHOLE corpus;
  * N is clamped to what the network can actually give;
  * fewer than two machines is refused outright, because a unit with no
    independent verifier is one anonymous node's word;
  * units of one wave land on DISTINCT machines;
  * the cluster's verification rate reaches the runner (embeddings verify at
    1.0, and a page that says "bit-exact" while sampling a quarter is lying);
  * output is reassembled in corpus order, not completion order.

Loaded standalone with `shared`, the models and the rental service stubbed, so
none of this needs a database. The CATALOGUE and PLACEMENT modules are the real
ones: the workload spec and the seeded draw are exactly what is under test, and
a fake of either would test the fake.
"""

import ast
import datetime
import importlib.util
import os
import sys
import threading
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# A database's worth of fakes, and nothing more
# ---------------------------------------------------------------------------

class _Col(object):
    """Stands in for a mapped column so `Model.id == 5` is a filter, not a bool."""

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return ("eq", self.name, other)

    def __hash__(self):
        return hash(("col", self.name))

    def in_(self, values):
        return ("in", self.name, tuple(values))

    def asc(self):
        return ("asc", self.name)


class FakeRental(object):
    id = _Col("id")
    cluster_id = _Col("cluster_id")
    shard_index = _Col("shard_index")
    status = _Col("status")

    def __init__(self, **kwargs):
        self.id = None
        self.cluster_id = None
        self.shard_index = None
        self.status = STATUS_QUEUED
        self.credits_paid = 0
        self.worker_node_id = None
        self.isolation = None
        self.verdict = None
        self.verified_by = None
        self.exit_code = None
        self.runtime_ms = None
        self.stdout = ""
        self.stderr = ""
        self.output_text = None
        self.finished_at = None
        self.files = {}
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeCluster(object):
    id = _Col("id")
    status = _Col("status")
    created_at = _Col("created_at")

    def __init__(self, **kwargs):
        self.id = None
        self.name = "cluster"
        self.workload = "embed"
        self.device = "cpu"
        self.node_count = 1
        self.cores = 1
        self.seconds = 120
        self.status = STATUS_QUEUED
        self.started_at = None
        self.finished_at = None
        self.created_at = datetime.datetime.utcnow()
        self.priority = 0
        self.credits_paid = 0
        self.verify_rate = 1.0
        self.corpus_lines = 0
        for key, value in kwargs.items():
            setattr(self, key, value)


class Store(object):
    def __init__(self):
        self.reset()

    def reset(self):
        self.units = []
        self.clusters = []
        self.next_id = 1
        self.commits = 0
        self.removes = 0


STORE = Store()


class FakeQuery(object):
    def __init__(self, rows):
        self.rows = list(rows)

    def filter(self, *predicates):
        rows = self.rows
        for predicate in predicates:
            kind, field, value = predicate
            if kind == "eq":
                rows = [r for r in rows if getattr(r, field, None) == value]
            elif kind == "in":
                rows = [r for r in rows if getattr(r, field, None) in value]
        return FakeQuery(rows)

    def order_by(self, *_args):
        return self

    def limit(self, count):
        return FakeQuery(self.rows[:count])

    def all(self):
        return list(self.rows)

    def one_or_none(self):
        return self.rows[0] if self.rows else None


class FakeSession(object):
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()

    def _bucket(self, model):
        return self.store.clusters if model is FakeCluster else self.store.units

    def query(self, model):
        return FakeQuery(self._bucket(model))

    def add(self, row):
        with self.lock:
            if getattr(row, "id", None) is None:
                row.id = self.store.next_id
                self.store.next_id += 1
            bucket = (self.store.clusters if isinstance(row, FakeCluster)
                      else self.store.units)
            if row not in bucket:
                bucket.append(row)

    def flush(self):
        pass

    def commit(self):
        with self.lock:
            self.store.commits += 1

    def rollback(self):
        pass

    def expire_all(self):
        pass

    def remove(self):
        with self.lock:
            self.store.removes += 1


class FakeLogger(object):
    def __init__(self):
        self.messages = []

    def _record(self, *args, **_kwargs):
        self.messages.append(args[0] if args else "")

    info = warning = error = debug = exception = _record


class FakeApp(object):
    def __init__(self):
        self.logger = FakeLogger()

    def app_context(self):
        app = self

        class _Ctx(object):
            def __enter__(self):
                return app

            def __exit__(self, *_exc):
                return False

        return _Ctx()


# ---------------------------------------------------------------------------
# Loading the module under test
# ---------------------------------------------------------------------------

def _real_module(name, filename):
    """Load one of the real, dependency-free service modules by path."""
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(BACKEND, "services", filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _model_stub(module_name, filename):
    """A model stub carrying the file's real module-level constants.

    Read from the source rather than retyped: a test asserting against its own
    copy of MAX_FILE_BYTES would keep passing after somebody changed the limit.
    """
    path = os.path.join(BACKEND, "model", filename)
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)
    module = types.ModuleType(module_name)
    for node in tree.body:
        if isinstance(node, ast.Assign) and all(
                isinstance(t, ast.Name) for t in node.targets):
            try:
                exec(compile(ast.Module([node], []), path, "exec"),
                     module.__dict__)
            except Exception:
                continue
    return module


SAVED = {}
cluster_service = None
catalogue = None
placement = None
rental_stub = None
market_stub = None
fake_app = None


def setUpModule():
    global cluster_service, catalogue, placement, rental_stub, market_stub, fake_app

    names = ("shared", "services", "services.compute_rental",
             "services.compute_catalogue", "services.compute_placement",
             "services.compute_market", "model", "model.ComputeRental",
             "model.ComputeCluster")
    for name in names:
        SAVED[name] = sys.modules.get(name)

    fake_app = FakeApp()
    shared = types.ModuleType("shared")
    shared.app = fake_app
    shared.db = types.SimpleNamespace(session=FakeSession(STORE))
    sys.modules["shared"] = shared

    services = types.ModuleType("services")
    services.__path__ = [os.path.join(BACKEND, "services")]
    sys.modules["services"] = services

    model = types.ModuleType("model")
    model.__path__ = [os.path.join(BACKEND, "model")]
    sys.modules["model"] = model

    rental_model = _model_stub("model.ComputeRental", "ComputeRental.py")
    rental_model.ComputeRental = FakeRental
    rental_model.units_for_cluster = lambda cluster_id: sorted(
        [u for u in STORE.units if u.cluster_id == cluster_id],
        key=lambda u: (u.shard_index if u.shard_index is not None else 0, u.id))
    sys.modules["model.ComputeRental"] = rental_model
    model.ComputeRental = rental_model

    cluster_model = _model_stub("model.ComputeCluster", "ComputeCluster.py")
    cluster_model.ComputeCluster = FakeCluster
    sys.modules["model.ComputeCluster"] = cluster_model
    model.ComputeCluster = cluster_model

    # The real catalogue and the real placement rule. Both are pure, and both
    # are the thing being relied on rather than mocked around.
    catalogue = _real_module("services.compute_catalogue", "compute_catalogue.py")
    services.compute_catalogue = catalogue
    placement = _real_module("services.compute_placement", "compute_placement.py")
    services.compute_placement = placement

    rental_stub = _make_rental_stub()
    sys.modules["services.compute_rental"] = rental_stub
    services.compute_rental = rental_stub

    market_stub = types.ModuleType("services.compute_market")
    market_stub.quote = lambda device, cores=1, seconds=60: {
        "device": device, "cores": cores, "seconds": seconds, "credits": 7}
    sys.modules["services.compute_market"] = market_stub
    services.compute_market = market_stub

    spec = importlib.util.spec_from_file_location(
        "compute_cluster_under_test",
        os.path.join(BACKEND, "services", "compute_cluster.py"))
    cluster_service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cluster_service)


def tearDownModule():
    for name, module in SAVED.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def _make_rental_stub():
    module = types.ModuleType("services.compute_rental")

    class RentalError(RuntimeError):
        pass

    module.RentalError = RentalError
    module.calls = []
    module.run_calls = []
    module.fail_on_unit = None
    module.behaviour = "done"
    module.barrier = None

    def submit(slip, name=None, files=None, entrypoint=None, workload=None,
               device="cpu", cores=1, seconds=60, priority_tier=0, **_kwargs):
        index = len(module.calls)
        module.calls.append({
            "name": name, "files": dict(files or {}), "entrypoint": entrypoint,
            "workload": workload, "device": device, "cores": cores,
            "seconds": seconds, "priority_tier": priority_tier,
        })
        if module.fail_on_unit is not None and index == module.fail_on_unit:
            raise RentalError("the queue refused this unit.")
        unit = FakeRental(name=name, workload=workload, device=device,
                          credits_paid=7, files=dict(files or {}))
        sys.modules["shared"].db.session.add(unit)
        return unit

    def cancel(job):
        if job.status != STATUS_QUEUED:
            raise RentalError("Only a waiting job can be cancelled.")
        job.status = STATUS_CANCELLED
        refund = job.credits_paid
        job.credits_paid = 0
        return refund

    def run_unit(unit, candidates=None, verify_rate=None):
        if module.barrier is not None:
            # Deterministic proof of concurrency: a serial dispatcher never gets
            # every unit here at once, and the barrier times out.
            module.barrier.wait(timeout=5)
        chosen, _isolation = placement.place(str(unit.id), unit.device, False,
                                             list(candidates or []))
        module.run_calls.append({
            "unit_id": unit.id, "shard_index": unit.shard_index,
            "candidates": [n["id"] for n in (candidates or [])],
            "verify_rate": verify_rate, "node": chosen["id"],
            "thread": threading.current_thread().name,
        })
        if module.behaviour == "queued":
            return unit
        unit.worker_node_id = chosen["id"]
        unit.status = STATUS_DONE if module.behaviour == "done" else STATUS_FAILED
        unit.verdict = "agreed"
        return unit

    def effective_priority(job, now=None):
        now = now or datetime.datetime.utcnow()
        created = job.created_at or now
        waited = max((now - created).total_seconds(), 0) / 60.0
        return int(job.priority or 0) + int(waited // 6)

    module.submit = submit
    module.cancel = cancel
    module.run_unit = run_unit
    module.effective_priority = effective_priority
    return module


def node(nid):
    return {"id": nid, "cpu": True, "gpu": False, "microvm": False,
            "i2p_destination": "%s.b32.i2p" % nid}


def use_pool(size):
    """Point the real placement module at a pool of `size` fake machines."""
    pool = [node("n%02d" % i) for i in range(size)]
    placement.eligible_nodes = lambda device, arbitrary: list(pool)
    return pool


class Slip(object):
    id = 42


# ---------------------------------------------------------------------------
# The split
# ---------------------------------------------------------------------------

class ShardTest(unittest.TestCase):
    def lines(self, count):
        return ["line %d" % i for i in range(count)]

    def parse(self, shards):
        import json

        out = []
        for text in shards:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
            out.append(rows)
        return out

    def test_split_is_total_contiguous_and_in_order(self):
        lines = self.lines(10)
        shards = self.parse(cluster_service.shard(lines, 3))
        self.assertEqual(len(shards), 3)
        # Total: every line appears exactly once, and in the order sent.
        flat = [row for chunk in shards for row in chunk]
        self.assertEqual([r["text"] for r in flat], lines)
        # Contiguous: ids are 0..9 with no gaps and no reordering.
        self.assertEqual([r["id"] for r in flat], list(range(10)))
        # Balanced to within one, so no machine gets double the work.
        sizes = [len(chunk) for chunk in shards]
        self.assertEqual(sizes, [4, 3, 3])

    def test_ids_are_global_so_output_can_be_reassembled(self):
        shards = self.parse(cluster_service.shard(self.lines(9), 3))
        # THE property: shard 1 does not start again at 0. Per-shard ids would
        # give three units that each claim to hold line 0.
        self.assertEqual(shards[0][0]["id"], 0)
        self.assertEqual(shards[1][0]["id"], 3)
        self.assertEqual(shards[2][0]["id"], 6)

    def test_more_shards_than_lines_leaves_empties_rather_than_losing_lines(self):
        shards = cluster_service.shard(self.lines(2), 5)
        self.assertEqual(len(shards), 5)
        flat = [row for chunk in self.parse(shards) for row in chunk]
        self.assertEqual(len(flat), 2)

    def test_one_shard_is_the_whole_corpus(self):
        shards = self.parse(cluster_service.shard(self.lines(7), 1))
        self.assertEqual(len(shards), 1)
        self.assertEqual(len(shards[0]), 7)

    def test_blank_lines_are_dropped_not_embedded(self):
        # The image skips blank lines, so an embedded one would silently produce
        # no vector and break "one output line per input line".
        lines = cluster_service.corpus_to_lines("a\n\n  \r\nb\n")
        self.assertEqual(lines, ["a", "b"])


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------

class SubmitTest(unittest.TestCase):
    def setUp(self):
        STORE.reset()
        rental_stub.calls = []
        rental_stub.run_calls = []
        rental_stub.fail_on_unit = None
        rental_stub.behaviour = "done"
        rental_stub.barrier = None
        self.corpus = "\n".join("line %d" % i for i in range(50))

    def submit(self, **kwargs):
        params = dict(slip=Slip(), name="vectors", workload="embed",
                      corpus=self.corpus, node_count=4)
        params.update(kwargs)
        return cluster_service.submit(**params)

    def test_node_count_is_clamped_to_the_pool(self):
        use_pool(3)
        cluster = self.submit(node_count=10)
        self.assertEqual(cluster.node_count, 3)
        self.assertEqual(len(rental_stub.calls), 3)

    def test_node_count_is_clamped_to_the_ceiling(self):
        use_pool(64)
        cluster = self.submit(node_count=1000)
        self.assertEqual(cluster.node_count, cluster_service.MAX_NODES)

    def test_node_count_is_clamped_to_the_corpus(self):
        # Nine machines for three lines is six machines paid to read nothing.
        use_pool(20)
        cluster = self.submit(corpus="a\nb\nc", node_count=9)
        self.assertEqual(cluster.node_count, 3)

    def test_a_pool_of_one_is_refused_and_nothing_is_created(self):
        use_pool(1)
        with self.assertRaises(cluster_service.ClusterError) as ctx:
            self.submit()
        message = str(ctx.exception)
        # The refusal has to say WHY, because "try again" invites the same
        # request: the missing thing is an independent verifier.
        self.assertIn("verify", message.lower())
        self.assertIn("charged", message.lower())
        self.assertEqual(rental_stub.calls, [])
        self.assertEqual(STORE.units, [])
        self.assertEqual(STORE.clusters, [])

    def test_cluster_error_is_a_rental_error(self):
        # So a caller catching either name catches both.
        self.assertTrue(issubclass(cluster_service.ClusterError,
                                   rental_stub.RentalError))

    def test_an_unknown_workload_is_refused(self):
        use_pool(4)
        with self.assertRaises(cluster_service.ClusterError) as ctx:
            self.submit(workload="finetune")
        self.assertIn("embed", str(ctx.exception))

    def test_units_carry_the_workload_the_shard_and_no_entrypoint(self):
        use_pool(4)
        cluster = self.submit(node_count=4)
        self.assertEqual(len(rental_stub.calls), 4)
        for call in rental_stub.calls:
            self.assertEqual(call["workload"], "embed")
            self.assertIsNone(call["entrypoint"])
            self.assertEqual(list(call["files"]), ["input.jsonl"])
        units = sorted(STORE.units, key=lambda u: u.shard_index)
        self.assertEqual([u.shard_index for u in units], [0, 1, 2, 3])
        self.assertTrue(all(u.cluster_id == cluster.id for u in units))

    def test_embeddings_verify_every_unit_by_default(self):
        # 1.0, not the rental's 0.25. A page promising bit-exact verification
        # while checking a quarter of the units is a page that is lying.
        use_pool(4)
        cluster = self.submit()
        self.assertEqual(cluster.verify_rate, 1.0)
        self.assertEqual(catalogue.default_verify_rate("embed"), 1.0)

    def test_an_explicit_verify_rate_is_honoured_and_clamped(self):
        use_pool(4)
        self.assertEqual(self.submit(verify_rate=0.5).verify_rate, 0.5)
        self.assertEqual(self.submit(verify_rate=9).verify_rate, 1.0)

    def test_the_total_is_the_per_unit_quote_times_the_units(self):
        use_pool(4)
        cluster = self.submit(node_count=4)
        self.assertEqual(cluster.credits_paid, 4 * 7)

    def test_a_market_failure_does_not_take_submit_down(self):
        use_pool(4)
        broken = market_stub.quote
        market_stub.quote = lambda *a, **k: 1 / 0
        try:
            cluster = self.submit(node_count=2)
        finally:
            market_stub.quote = broken
        self.assertEqual(cluster.node_count, 2)
        self.assertEqual(cluster.credits_paid, 0)

    def test_an_empty_corpus_is_refused(self):
        use_pool(4)
        with self.assertRaises(cluster_service.ClusterError):
            self.submit(corpus="   \n\n")

    def test_an_oversized_shard_is_refused_before_anything_is_created(self):
        use_pool(2)
        model = sys.modules["model.ComputeRental"]
        big = "x" * (model.MAX_FILE_BYTES // 2)
        with self.assertRaises(cluster_service.ClusterError) as ctx:
            self.submit(corpus="\n".join([big] * 6), node_count=2)
        self.assertIn("machines", str(ctx.exception))
        self.assertEqual(rental_stub.calls, [])

    def test_a_half_created_cluster_is_withdrawn_whole(self):
        # Half a cluster is worse than none: its units would run and be charged
        # for a result that could never be assembled.
        use_pool(4)
        rental_stub.fail_on_unit = 2
        with self.assertRaises(cluster_service.ClusterError):
            self.submit(node_count=4)
        self.assertTrue(STORE.clusters)
        self.assertEqual(STORE.clusters[0].status, STATUS_CANCELLED)
        self.assertEqual(STORE.clusters[0].credits_paid, 0)
        self.assertTrue(all(u.status == STATUS_CANCELLED for u in STORE.units))
        self.assertTrue(all(u.credits_paid == 0 for u in STORE.units))


# ---------------------------------------------------------------------------
# The fan-out
# ---------------------------------------------------------------------------

class WavePlanTest(unittest.TestCase):
    def setUp(self):
        STORE.reset()

    def units(self, count):
        out = []
        for index in range(count):
            unit = FakeRental(shard_index=index)
            sys.modules["shared"].db.session.add(unit)
            out.append(unit)
        return out

    def test_each_unit_gets_its_own_machine(self):
        pool = use_pool(5)
        plan = cluster_service.wave_plan(pool, self.units(4), "cpu")
        self.assertEqual(len(plan), 4)
        chosen = [a.node_id for a in plan]
        self.assertEqual(len(set(chosen)), 4, "two units went to one machine")

    def test_one_machine_is_kept_free_for_the_verifier(self):
        pool = use_pool(4)
        plan = cluster_service.wave_plan(pool, self.units(4), "cpu")
        # Four units, four machines, but only three go out: verification runs a
        # replica on an INDEPENDENT node, and a wave that used every machine
        # would leave it nowhere to go.
        self.assertEqual(len(plan), 3)
        used = {a.node_id for a in plan}
        self.assertEqual(len(set(n["id"] for n in pool) - used), 1)

    def test_candidate_pools_shrink_as_machines_are_taken(self):
        pool = use_pool(6)
        plan = cluster_service.wave_plan(pool, self.units(5), "cpu")
        sizes = [len(a.candidates) for a in plan]
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        self.assertEqual(sizes[0], 6)
        # A unit is never offered a machine an earlier unit in this wave took.
        taken = set()
        for assignment in plan:
            offered = {n["id"] for n in assignment.candidates}
            self.assertFalse(taken & offered)
            taken.add(assignment.node_id)

    def test_a_wave_is_never_empty_even_with_one_machine(self):
        # Verification degrades; the work still goes out. A wave of zero would
        # stall the cluster forever.
        pool = use_pool(1)
        plan = cluster_service.wave_plan(pool, self.units(3), "cpu")
        self.assertEqual(len(plan), 1)


class DispatchTest(unittest.TestCase):
    def setUp(self):
        STORE.reset()
        rental_stub.calls = []
        rental_stub.run_calls = []
        rental_stub.fail_on_unit = None
        rental_stub.behaviour = "done"
        rental_stub.barrier = None

    def make(self, units=4, pool=6, verify_rate=1.0):
        use_pool(pool)
        cluster = FakeCluster(workload="embed", device="cpu", node_count=units,
                              verify_rate=verify_rate)
        sys.modules["shared"].db.session.add(cluster)
        for index in range(units):
            unit = FakeRental(shard_index=index, cluster_id=cluster.id,
                              device="cpu")
            sys.modules["shared"].db.session.add(unit)
        return cluster

    def test_every_unit_lands_on_a_distinct_machine(self):
        cluster = self.make(units=4, pool=6)
        dispatched = cluster_service.dispatch(cluster, flask_app=fake_app)
        self.assertEqual(dispatched, 4)
        nodes = [call["node"] for call in rental_stub.run_calls]
        self.assertEqual(len(set(nodes)), 4, "units doubled up on a machine")
        self.assertEqual(cluster.status, STATUS_DONE)

    def test_the_clusters_verify_rate_reaches_the_runner(self):
        cluster = self.make(units=3, pool=6, verify_rate=1.0)
        cluster_service.dispatch(cluster, flask_app=fake_app)
        self.assertTrue(rental_stub.run_calls)
        self.assertTrue(all(call["verify_rate"] == 1.0
                            for call in rental_stub.run_calls))

    def test_units_run_at_the_same_time_and_not_one_after_another(self):
        # The barrier is the assertion: it releases only when all four units are
        # inside run_unit together. A serial dispatcher deadlocks it, every unit
        # reports a failure, and `dispatched` comes back 0.
        cluster = self.make(units=4, pool=6)
        rental_stub.barrier = threading.Barrier(4)
        try:
            dispatched = cluster_service.dispatch(cluster, flask_app=fake_app)
        finally:
            rental_stub.barrier = None
        self.assertEqual(dispatched, 4)

    def test_more_units_than_machines_run_in_waves(self):
        # Not double-booked: a node runs one job per device at a time and would
        # refuse the second.
        cluster = self.make(units=5, pool=3)
        dispatched = cluster_service.dispatch(cluster, flask_app=fake_app)
        self.assertEqual(dispatched, 5)
        self.assertEqual(cluster.status, STATUS_DONE)
        # Two machines per wave (three, less the spare), so three waves.
        first_wave = [c["node"] for c in rental_stub.run_calls[:2]]
        self.assertEqual(len(set(first_wave)), 2)

    def test_a_wave_that_makes_no_progress_stops_rather_than_spinning(self):
        cluster = self.make(units=4, pool=6)
        rental_stub.behaviour = "queued"
        # Zero, although four units were handed out: the count is units that
        # LEFT the queue, which is what makes the drainer sleep instead of
        # retrying a refusal as fast as the network will answer.
        self.assertEqual(cluster_service.dispatch(cluster, flask_app=fake_app), 0)
        # One wave of four attempted, then it gave up: the units keep their
        # place for the next pass instead of the loop retrying a refusal for
        # as fast as the network will answer.
        self.assertEqual(len(rental_stub.run_calls), 4)
        self.assertTrue(all(u.status == STATUS_QUEUED for u in STORE.units))

    def test_an_empty_pool_leaves_everything_queued(self):
        cluster = self.make(units=3, pool=0)
        self.assertEqual(cluster_service.dispatch(cluster, flask_app=fake_app), 0)
        self.assertEqual(cluster.status, STATUS_QUEUED)
        self.assertEqual(rental_stub.run_calls, [])

    def test_every_worker_returns_its_session(self):
        before = STORE.removes
        cluster = self.make(units=3, pool=6)
        cluster_service.dispatch(cluster, flask_app=fake_app)
        # One per unit. A worker that leaks a session holds a connection from a
        # pool sized for request handling.
        self.assertEqual(STORE.removes - before, 3)


# ---------------------------------------------------------------------------
# Status and output
# ---------------------------------------------------------------------------

class RollUpTest(unittest.TestCase):
    def roll(self, *statuses):
        return cluster_service.rollup_status(list(statuses))

    def test_all_queued_is_queued(self):
        self.assertEqual(self.roll(STATUS_QUEUED, STATUS_QUEUED), STATUS_QUEUED)

    def test_any_in_flight_is_running(self):
        self.assertEqual(self.roll(STATUS_DONE, STATUS_RUNNING), STATUS_RUNNING)
        self.assertEqual(self.roll(STATUS_DONE, STATUS_QUEUED), STATUS_RUNNING)
        # Including when one unit has already failed: six machines are still
        # working for this person, and "failed" would make them cancel.
        self.assertEqual(self.roll(STATUS_FAILED, STATUS_RUNNING), STATUS_RUNNING)

    def test_all_done_is_done(self):
        self.assertEqual(self.roll(STATUS_DONE, STATUS_DONE), STATUS_DONE)

    def test_a_failure_settles_the_cluster_once_nothing_is_in_flight(self):
        self.assertEqual(self.roll(STATUS_DONE, STATUS_FAILED), STATUS_FAILED)

    def test_a_wholly_cancelled_cluster_is_cancelled(self):
        self.assertEqual(self.roll(STATUS_CANCELLED, STATUS_CANCELLED),
                         STATUS_CANCELLED)
        self.assertEqual(self.roll(STATUS_DONE, STATUS_CANCELLED), STATUS_DONE)

    def test_the_statuses_match_the_model(self):
        # Two vocabularies that mean the same thing drift; this fails the moment
        # they do.
        model = sys.modules["model.ComputeCluster"]
        for name in ("STATUS_QUEUED", "STATUS_RUNNING", "STATUS_DONE",
                     "STATUS_FAILED", "STATUS_CANCELLED"):
            self.assertEqual(getattr(cluster_service, name),
                             getattr(model, name), name)


class OutputTest(unittest.TestCase):
    def setUp(self):
        STORE.reset()

    def cluster_with(self, chunks):
        cluster = FakeCluster(workload="embed", device="cpu")
        sys.modules["shared"].db.session.add(cluster)
        # Added out of order on purpose: units come back in whatever order N
        # machines finish, and the reassembly must not depend on that.
        for index, text in reversed(list(enumerate(chunks))):
            unit = FakeRental(shard_index=index, cluster_id=cluster.id,
                              status=STATUS_DONE, output_text=text)
            sys.modules["shared"].db.session.add(unit)
        return cluster

    def test_output_is_reassembled_in_corpus_order(self):
        cluster = self.cluster_with(['{"id":0}\n', '{"id":1}\n', '{"id":2}\n'])
        self.assertEqual(cluster_service.combined_output(cluster),
                         '{"id":0}\n{"id":1}\n{"id":2}\n')

    def test_a_shard_without_a_trailing_newline_does_not_glue_to_the_next(self):
        cluster = self.cluster_with(['{"id":0}', '{"id":1}'])
        self.assertEqual(cluster_service.combined_output(cluster),
                         '{"id":0}\n{"id":1}\n')

    def test_a_missing_unit_leaves_the_others_in_order(self):
        cluster = self.cluster_with(['{"id":0}\n', "", '{"id":2}\n'])
        self.assertEqual(cluster_service.combined_output(cluster),
                         '{"id":0}\n{"id":2}\n')

    def test_as_json_reports_the_machine_and_the_verdict_per_unit(self):
        cluster = self.cluster_with(['{"id":0}\n', '{"id":1}\n'])
        for index, unit in enumerate(sorted(STORE.units,
                                            key=lambda u: u.shard_index)):
            unit.worker_node_id = "n%02d" % index
            unit.verdict = "agreed"
            unit.stdout = "embed-digest sha256:abc count:1\n"
        state = cluster_service.as_json(cluster)
        self.assertEqual(state["done_units"], 2)
        self.assertEqual(state["verified_units"], 2)
        self.assertEqual([u["node"] for u in state["units"]], ["n00", "n01"])
        self.assertEqual([u["shard_index"] for u in state["units"]], [0, 1])
        self.assertIn("embed-digest", state["units"][0]["digest_line"])


class CancelTest(unittest.TestCase):
    def setUp(self):
        STORE.reset()

    def test_only_undispatched_units_are_refunded(self):
        cluster = FakeCluster(workload="embed", device="cpu", credits_paid=21)
        sys.modules["shared"].db.session.add(cluster)
        ran = FakeRental(shard_index=0, cluster_id=cluster.id,
                         status=STATUS_DONE, credits_paid=7)
        waiting = FakeRental(shard_index=1, cluster_id=cluster.id,
                             status=STATUS_QUEUED, credits_paid=7)
        for unit in (ran, waiting):
            sys.modules["shared"].db.session.add(unit)

        refund = cluster_service.cancel(cluster)
        # The unit that ran cost a volunteer electricity whatever the submitter
        # decided afterwards, so it is not refunded.
        self.assertEqual(refund, 7)
        self.assertEqual(cluster.credits_paid, 14)
        self.assertEqual(ran.credits_paid, 7)
        self.assertEqual(waiting.status, STATUS_CANCELLED)

    def test_a_cluster_with_nothing_waiting_cannot_be_cancelled(self):
        cluster = FakeCluster(workload="embed", device="cpu")
        sys.modules["shared"].db.session.add(cluster)
        sys.modules["shared"].db.session.add(
            FakeRental(shard_index=0, cluster_id=cluster.id, status=STATUS_RUNNING))
        with self.assertRaises(cluster_service.ClusterError):
            cluster_service.cancel(cluster)


if __name__ == "__main__":
    unittest.main()
