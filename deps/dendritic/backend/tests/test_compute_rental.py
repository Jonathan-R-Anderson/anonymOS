"""The rental queue: ordering, wait estimates, and what may be edited when.

The one property worth defending hardest is that the queue cannot starve. Paid
priority with no counterweight means an unpaid job never reaches the front while
anybody is paying, and "queued" quietly becomes "never".
"""

import ast
import datetime
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)


def _load_pure():
    """Load services/compute_rental.py with `shared` stubbed.

    The module imports the app for its logger and session. Everything under
    test here is arithmetic over plain objects, so the stub is enough — and it
    is removed afterwards, because a leaked stub in sys.modules once broke four
    unrelated test modules.
    """
    path = os.path.join(BACKEND, "services", "compute_rental.py")
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)

    shared = types.ModuleType("shared")
    shared.app = types.SimpleNamespace(
        logger=types.SimpleNamespace(exception=lambda *a, **k: None,
                                     warning=lambda *a, **k: None,
                                     info=lambda *a, **k: None))
    shared.db = types.SimpleNamespace(session=types.SimpleNamespace())

    # The functions import model.ComputeRental lazily, inside their bodies, so
    # the constants have to be stubbed too. Read from the real file rather than
    # retyped: a test asserting against its own copy of MAX_FILES would keep
    # passing after somebody changed the limit.
    model_path = os.path.join(BACKEND, "model", "ComputeRental.py")
    with open(model_path, encoding="utf-8") as handle:
        model_tree = ast.parse(handle.read(), model_path)
    model = types.ModuleType("model.ComputeRental")
    for node in model_tree.body:
        # Executed rather than literal_eval'd: several of these are written as
        # expressions (256 * 1024) because that reads better than 262144.
        if isinstance(node, ast.Assign) and all(
                isinstance(t, ast.Name) for t in node.targets):
            try:
                exec(compile(ast.Module([node], []), model_path, "exec"), model.__dict__)
            except Exception:
                continue
    # Filled in per-test by the cases that need them.
    model.queued_jobs = lambda device=None: []
    model.recent_durations = lambda device="cpu", limit=40: []
    model.jobs_for_slip = lambda slip_id, limit=50: []

    # The stubs stay installed for the LIFETIME of this module's tests, not just
    # the exec: compute_rental imports model.ComputeRental lazily inside each
    # function, so a stub removed after loading is gone by the time it is
    # needed. tearDownModule puts sys.modules back — a leaked stub here once
    # broke four unrelated test modules, which is why it is undone explicitly
    # rather than left for the process to end.
    saved = {name: sys.modules.get(name) for name in ("shared", "model.ComputeRental")}
    sys.modules["shared"] = shared
    sys.modules["model.ComputeRental"] = model

    module = types.ModuleType("compute_rental_pure")
    exec(compile(tree, path, "exec"), module.__dict__)
    module._model = model
    module._saved_modules = saved
    return module


rental = None


def setUpModule():
    global rental
    rental = _load_pure()


def tearDownModule():
    for name, previous in (rental._saved_modules or {}).items():
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


class Job:
    """Enough of a ComputeRental for the ordering arithmetic."""

    def __init__(self, id, priority=0, minutes_ago=0, status="queued", device="cpu",
                 cluster_id=None):
        self.id = id
        self.priority = priority
        self.status = status
        self.device = device
        self.cluster_id = cluster_id
        self.created_at = (datetime.datetime(2026, 8, 3, 12, 0)
                           - datetime.timedelta(minutes=minutes_ago))


NOW = datetime.datetime(2026, 8, 3, 12, 0)


class StarvationTest(unittest.TestCase):
    """A queue that can starve is an auction with a waiting room attached."""

    def test_paying_moves_you_forward_now(self):
        free = Job(1, priority=0, minutes_ago=0)
        paid = Job(2, priority=25, minutes_ago=0)
        self.assertGreater(rental.effective_priority(paid, NOW),
                           rental.effective_priority(free, NOW))

    def test_waiting_eventually_overtakes_any_paid_tier(self):
        # THE property: no paid tier can hold the front forever. If this fails,
        # an unpaid job is blocked indefinitely by paying ones.
        #
        # Asserted as ORDERING rather than as a raw score. At exactly
        # 25 * AGE_MINUTES_PER_STEP the two scores tie and the oldest-first
        # tiebreak already decides it — an assertion on the number alone would
        # read as a failure while the queue was behaving correctly.
        express = Job(1, priority=25, minutes_ago=0)
        patient = Job(2, priority=0, minutes_ago=26 * rental.AGE_MINUTES_PER_STEP)
        self.assertGreater(rental.effective_priority(patient, NOW),
                           rental.effective_priority(express, NOW))

        rental._model.queued_jobs = lambda device=None: [express, patient]
        self.assertEqual([j.id for j in rental.ordered_queue("cpu", NOW)], [2, 1],
                         "a long-waiting free job never reached the front")

    def test_the_bound_is_arithmetic_anyone_can_check(self):
        # Not a vague promise: the wait to overtake tier N is exactly
        # N * AGE_MINUTES_PER_STEP minutes.
        steps = 25
        just_short = Job(1, priority=0, minutes_ago=steps * rental.AGE_MINUTES_PER_STEP - 1)
        express = Job(2, priority=steps, minutes_ago=0)
        self.assertLess(rental.effective_priority(just_short, NOW),
                        rental.effective_priority(express, NOW))

    def test_equal_priority_is_served_oldest_first(self):
        old = Job(1, priority=0, minutes_ago=5)
        new = Job(2, priority=0, minutes_ago=0)
        rental._model.queued_jobs = lambda device=None: [new, old]
        order = [j.id for j in rental.ordered_queue("cpu", NOW)]
        self.assertEqual(order, [1, 2])

    def test_ordering_is_deterministic(self):
        # Two equal jobs must not swap between page loads, or somebody watching
        # their position sees it flap.
        jobs = [Job(3, 0, 5), Job(1, 0, 5), Job(2, 0, 5)]
        rental._model.queued_jobs = lambda device=None: list(jobs)
        first = [j.id for j in rental.ordered_queue("cpu", NOW)]
        for _ in range(5):
            self.assertEqual([j.id for j in rental.ordered_queue("cpu", NOW)], first)


class PositionTest(unittest.TestCase):
    def setUp(self):
        self.jobs = [Job(1, 0, 30), Job(2, 25, 0), Job(3, 0, 0)]
        rental._model.queued_jobs = lambda device=None: list(self.jobs)

    def test_position_is_one_based(self):
        # Job 2 paid for Express and has the front.
        self.assertEqual(rental.position_of(self.jobs[1], NOW), 1)

    def test_a_finished_job_has_no_position(self):
        done = Job(9, status="done")
        self.assertEqual(rental.position_of(done, NOW), 0)


class EstimateTest(unittest.TestCase):
    def setUp(self):
        self.jobs = [Job(1, 0, 10), Job(2, 0, 5), Job(3, 0, 0)]
        rental._model.queued_jobs = lambda device=None: list(self.jobs)

    def test_the_front_of_the_queue_waits_for_nothing(self):
        rental._model.recent_durations = lambda device="cpu", limit=40: [10000] * 10
        seconds, _ = rental.estimate_wait(self.jobs[0], NOW)
        self.assertEqual(seconds, 0)

    def test_the_estimate_scales_with_what_is_ahead(self):
        rental._model.recent_durations = lambda device="cpu", limit=40: [10000] * 10
        first, _ = rental.estimate_wait(self.jobs[1], NOW)
        second, _ = rental.estimate_wait(self.jobs[2], NOW)
        self.assertEqual(first, 10)
        self.assertEqual(second, 20)

    def test_thin_history_is_labelled_estimated_not_measured(self):
        # A confident-looking number from three data points is worse than an
        # obviously rough one, because people plan around whatever they see.
        rental._model.recent_durations = lambda device="cpu", limit=40: [5000, 6000]
        _, confidence = rental.estimate_wait(self.jobs[2], NOW)
        self.assertEqual(confidence, "estimated")

        rental._model.recent_durations = lambda device="cpu", limit=40: [5000] * 12
        _, confidence = rental.estimate_wait(self.jobs[2], NOW)
        self.assertEqual(confidence, "measured")

    def test_no_history_falls_back_to_a_stated_default(self):
        rental._model.recent_durations = lambda device="cpu", limit=40: []
        self.assertEqual(rental.average_seconds("cpu"), rental.DEFAULT_JOB_SECONDS)


class ValidationTest(unittest.TestCase):
    def test_the_entry_point_must_be_one_of_the_files(self):
        # Guessing "main.py" wrongly wastes a queue slot to produce a confusing
        # error, so it is refused at submission instead.
        with self.assertRaises(rental.RentalError):
            rental._validate({"a.py": "x"}, "main.py")

    def test_path_traversal_is_refused_at_the_edge(self):
        for bad in ("../etc/passwd", "/etc/passwd", "a\\b.py"):
            with self.assertRaises(rental.RentalError):
                rental._validate({bad: "x", "main.py": "y"}, "main.py")

    def test_an_empty_submission_is_refused(self):
        with self.assertRaises(rental.RentalError):
            rental._validate({}, "main.py")

    def test_a_reasonable_program_passes(self):
        rental._validate({"main.py": "print(1)", "lib/util.py": "x = 1"}, "main.py")


class WorkloadValidationTest(unittest.TestCase):
    """A workload job carries DATA, and is validated as such.

    It is not a program with the entry point left blank: the image is fixed at
    build time, so there is nothing to name and exactly one file it will read.
    """

    def test_a_workload_job_needs_no_entry_point(self):
        # The "entry point must be one of the files" rule does not merely relax
        # here, it stops applying — there is no entry point.
        rental._validate({"input.jsonl": '{"id":"1","text":"a"}'}, "",
                         workload="embed")
        rental._validate({"input.jsonl": "x"}, None, workload="embed")

    def test_naming_an_entry_point_is_refused_rather_than_ignored(self):
        with self.assertRaises(rental.RentalError):
            rental._validate({"input.jsonl": "x"}, "main.py", workload="embed")

    def test_the_workloads_input_file_must_be_there(self):
        with self.assertRaises(rental.RentalError):
            rental._validate({"data.txt": "x"}, "", workload="embed")

    def test_files_the_image_would_ignore_are_refused(self):
        # Accepting and silently dropping them means a submitter watches their
        # input never appear in the result with no error anywhere to explain it.
        with self.assertRaises(rental.RentalError):
            rental._validate({"input.jsonl": "x", "extra.jsonl": "y"}, "",
                             workload="embed")

    def test_an_unknown_workload_is_refused_at_submission(self):
        with self.assertRaises(rental.RentalError):
            rental._validate({"input.jsonl": "x"}, "", workload="fine-tune")

    def test_every_size_cap_still_applies(self):
        big = "x" * (rental_model_limit("MAX_FILE_BYTES") + 1)
        with self.assertRaises(rental.RentalError):
            rental._validate({"input.jsonl": big}, "", workload="embed")
        with self.assertRaises(rental.RentalError):
            rental._validate({}, "", workload="embed")

    def test_path_traversal_is_still_refused(self):
        with self.assertRaises(rental.RentalError):
            rental._validate({"../input.jsonl": "x"}, "", workload="embed")


def rental_model_limit(name):
    return getattr(rental._model, name)


class ClusterUnitsAreNotInTheQueueTest(unittest.TestCase):
    """The serial drainer must never steal a cluster unit.

    run_next runs one job at a time and blocks for its whole timeout, so a
    cluster drained through it would be N units executed one after another —
    a cluster in name only. Worse, both drainers claiming the same row means one
    of them charges for a run it never saw.
    """

    def test_cluster_units_are_excluded(self):
        loose = Job(1, 0, 5)
        unit = Job(2, 0, 10, cluster_id=7)
        rental._model.queued_jobs = lambda device=None: [loose, unit]
        self.assertEqual([j.id for j in rental.ordered_queue("cpu", NOW)], [1],
                         "the per-device drainer must not see cluster units")

    def test_a_job_with_no_cluster_attribute_at_all_still_queues(self):
        # Rows predating the column, and the fakes in older tests.
        class Bare:
            id, priority, status, device = 5, 0, "queued", "cpu"
            created_at = NOW
        rental._model.queued_jobs = lambda device=None: [Bare()]
        self.assertEqual([j.id for j in rental.ordered_queue("cpu", NOW)], [5])


class DispatchJob:
    """Enough of a ComputeRental for the dispatch path."""

    def __init__(self, workload=None, cluster_id=None, arbitrary=False):
        self.id = 11
        self.workload = workload
        self.cluster_id = cluster_id
        self.arbitrary = arbitrary
        self.device = "cpu"
        self.language = "python"
        self.entrypoint = "main.py"
        self.stdin_text = ""
        self.seconds = 60
        self.worker_node_id = None
        self.isolation = None


class LocalFallbackTest(unittest.TestCase):
    """What the local judge may and may not be asked to stand in for."""

    # What the bridge reads to decide whether it has a transport at all. It used
    # to be the I2P HTTP proxy; it is now this site's own node, because the proxy
    # path led to a listener that never existed. Both are cleared, so this test
    # keeps meaning the same thing on a machine that still has either set.
    _TRANSPORT_VARS = ("COMPUTE_NODE_BRIDGE", "DCS_NODE_URL", "I2P_HTTP_PROXY")

    def setUp(self):
        # No node bridged, so compute_bridge.enabled() is false and every
        # dispatch reaches the fallback — which is the branch under test.
        self._saved = {name: os.environ.get(name) for name in self._TRANSPORT_VARS}
        for name in self._TRANSPORT_VARS:
            os.environ[name] = ""
        self.addCleanup(self._restore)

    def _restore(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_code_runner_is_importable_where_the_fallback_calls_it(self):
        # THE LIVE BUG this replaces: code_runner was imported only inside
        # run_next, so the call at the bottom of _dispatch raised NameError and
        # every locally-run job died as "the runner is unavailable: name
        # 'code_runner' is not defined" and was marked FAILED.
        from services import code_runner

        calls = []
        original = code_runner.run_program
        code_runner.run_program = lambda *a, **k: calls.append(a) or {"ok": True}
        self.addCleanup(setattr, code_runner, "run_program", original)

        job = DispatchJob()
        result = rental._dispatch(job, {"main.py": "print(1)"})
        self.assertTrue(result.get("ok"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(job.worker_node_id, "local")

    def test_a_workload_job_is_refused_not_run_locally(self):
        # The local judge has no catalogue image, no /work and no way to produce
        # the file the job exists to produce.
        from services import code_runner

        original = code_runner.run_program

        def explode(*a, **k):
            raise AssertionError("a workload must never reach the local judge")

        code_runner.run_program = explode
        self.addCleanup(setattr, code_runner, "run_program", original)

        with self.assertRaises(rental.RentalError):
            rental._dispatch(DispatchJob(workload="embed"), {"input.jsonl": "x"})

    def test_a_cluster_unit_is_refused_not_run_locally(self):
        from services import code_runner

        original = code_runner.run_program

        def explode(*a, **k):
            raise AssertionError("a cluster unit must never run on one local box")

        code_runner.run_program = explode
        self.addCleanup(setattr, code_runner, "run_program", original)

        with self.assertRaises(rental.RentalError):
            rental._dispatch(DispatchJob(cluster_id=3), {"main.py": "print(1)"})


class UnitJob:
    """Enough of a ComputeRental for run_unit to finish one."""

    def __init__(self, workload="embed", worker_node_id="node-1"):
        self.id = 42
        self.workload = workload
        self.device = "cpu"
        self.language = "python"
        self.entrypoint = None
        self.stdin_text = ""
        self.seconds = 60
        self.cluster_id = None
        self.arbitrary = False
        self.worker_node_id = worker_node_id
        self.isolation = "container"
        self.status = "queued"
        self.started_at = None
        self.finished_at = None
        self.runtime_ms = None
        self.stdout = ""
        self.stderr = ""
        self.exit_code = None
        self.output_text = None
        self.verdict = None
        self.credits_paid = 100
        self.files = []


class MissingProductTest(unittest.TestCase):
    """A workload's answer is a FILE, and a job without one has not succeeded.

    THE DEFECT
    ----------
    The node built its jobs without ever naming the file the workload produces,
    so the worker fetched nothing and the result was deleted with the container.
    What reached the site was exit 0, a stdout digest, and an empty outputs map
    — which passed `ok`, was marked DONE, was verified by hash equality against
    a replica's identical digest, and paid the volunteers. The submitter was
    charged for vectors that did not exist, and nothing anywhere said so.

    These pin the two refusals that close it: such a result is not verified, and
    it is not bought.
    """

    def setUp(self):
        # run_unit commits; the pure loader's session is a bare namespace.
        rental.db.session.commit = lambda: None

        self.paid = []
        earnings = types.ModuleType("services.compute_earnings")
        earnings.credit_provider = (
            lambda job, node_id, succeeded=True, now=None:
            self.paid.append((node_id, succeeded)))
        self._saved_earnings = sys.modules.get("services.compute_earnings")
        sys.modules["services.compute_earnings"] = earnings

        self._saved_dispatch = rental._dispatch
        self.addCleanup(setattr, rental, "_dispatch", self._saved_dispatch)
        self.addCleanup(self._restore_earnings)

    def _restore_earnings(self):
        if self._saved_earnings is None:
            sys.modules.pop("services.compute_earnings", None)
        else:
            sys.modules["services.compute_earnings"] = self._saved_earnings

    def _run(self, job, result):
        rental._dispatch = lambda *a, **k: result
        return rental.run_unit(job)

    # --- the contradiction: success claimed, nothing produced ---

    def test_a_workload_that_returned_no_file_is_not_done(self):
        job = self._run(UnitJob(), {"ok": True, "exit_code": 0,
                                    "stdout": "embed-digest sha256:abc count:3\n",
                                    "outputs": {}})
        self.assertEqual(job.status, "failed",
                         "a job that produced nothing was recorded as done")

    def test_a_workload_that_returned_no_file_is_not_paid(self):
        self._run(UnitJob(), {"ok": True, "exit_code": 0,
                              "stdout": "embed-digest sha256:abc count:3\n",
                              "outputs": {}})
        self.assertEqual(self.paid, [],
                         "the network bought a result that does not exist")

    def test_the_submitter_is_told_what_was_missing(self):
        job = self._run(UnitJob(), {"ok": True, "exit_code": 0,
                                    "stdout": "digest\n", "outputs": {}})
        self.assertIn("output.jsonl", job.stderr)
        # Never in stdout: compute_verify.output_digest hashes stdout, and a
        # note appended there would make an honest node disagree with its own
        # replica.
        self.assertNotIn("output.jsonl", job.stdout)

    def test_an_empty_file_is_not_a_product(self):
        # Zero bytes is not a smaller result. Accepting it would leave the same
        # hole open with one extra step in it.
        job = self._run(UnitJob(), {"ok": True, "exit_code": 0,
                                    "stdout": "digest\n",
                                    "outputs": {"output.jsonl": ""}})
        self.assertEqual(job.status, "failed")
        self.assertEqual(self.paid, [])

    # --- what must keep working ---

    def test_a_workload_that_returned_its_file_is_done_and_paid(self):
        job = self._run(UnitJob(), {
            "ok": True, "exit_code": 0, "stdout": "digest\n",
            "outputs": {"output.jsonl": "{\"id\":0,\"vec\":\"beef\"}\n"}})
        self.assertEqual(job.status, "done")
        self.assertEqual(self.paid, [("node-1", True)])
        self.assertIn("beef", job.output_text)

    def test_an_honest_failure_still_earns_the_reduced_share(self):
        # The node spent the same electricity on a job that failed for a stated
        # reason — a malformed input line, say. Refusing to pay here would make
        # running risky-looking work irrational, so nodes would cherry-pick and
        # the jobs nobody would take are the ones that most need running. What
        # is refused above is the CONTRADICTION, not failure.
        job = self._run(UnitJob(), {
            "ok": False, "exit_code": 3, "stdout": "",
            "stderr": "line 5 is not a JSON object\n", "outputs": {}})
        self.assertEqual(job.status, "failed")
        self.assertEqual(self.paid, [("node-1", False)])

    def test_a_language_job_is_not_asked_for_a_file(self):
        # Its product IS its stdout, and a program that writes no files has
        # still answered.
        job = self._run(UnitJob(workload=None),
                        {"ok": True, "exit_code": 0, "stdout": "hello\n"})
        self.assertEqual(job.status, "done")
        self.assertEqual(self.paid, [("node-1", True)])

    # --- the helper itself ---

    def test_missing_product_reads_the_catalogue_not_a_guess(self):
        from services.compute_catalogue import output_file

        job = UnitJob()
        self.assertEqual(rental._missing_product(job, {"outputs": {}}),
                         output_file("embed"))
        self.assertIsNone(rental._missing_product(
            job, {"outputs": {output_file("embed"): "x"}}))
        self.assertIsNone(rental._missing_product(UnitJob(workload=None),
                                                  {"outputs": {}}))


class NoProductIsNotVerifiableTest(unittest.TestCase):
    """A digest is a description OF the file. It is not the file.

    Two nodes agreeing on the digest while neither returned anything is two
    descriptions of nothing, and recording that as `agreed` is what let the
    defect pass verification. No replica is spent on it either — every replica
    is a volunteer's electricity.
    """

    def setUp(self):
        # Placement is RECORDED rather than made to raise: _verify_if_sampled
        # catches every exception and records `insufficient`, so an exploding
        # stub would be swallowed and prove nothing about whether it was called.
        self.placed = []
        placement = types.ModuleType("services.compute_placement")

        def eligible_nodes(device, arbitrary):
            self.placed.append(device)
            return []

        placement.eligible_nodes = eligible_nodes
        placement.place = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("placement should not be reached with an empty pool"))
        self._saved = sys.modules.get("services.compute_placement")
        sys.modules["services.compute_placement"] = placement
        self.addCleanup(self._restore)

    def _restore(self):
        if self._saved is None:
            sys.modules.pop("services.compute_placement", None)
        else:
            sys.modules["services.compute_placement"] = self._saved

    def test_a_result_with_no_product_is_never_marked_verified(self):
        from services import compute_verify

        job = UnitJob()
        primary = {"ok": True, "exit_code": 0, "stdout": "digest\n", "outputs": {}}
        rental._verify_if_sampled(job, {}, {"id": "node-1"}, primary,
                                  verify_rate=1.0)
        self.assertEqual(job.verdict, compute_verify.VERDICT_UNVERIFIED)
        self.assertNotEqual(job.verdict, compute_verify.VERDICT_AGREED)
        self.assertEqual(self.placed, [],
                         "a volunteer's electricity was spent corroborating "
                         "a description of a file that never arrived")

    def test_a_loud_failure_is_still_checked_against_a_replica(self):
        # A node that answered "your data is bad" to everything would otherwise
        # earn the failed share forever without anybody ever contradicting it.
        # Its product is legitimately absent, so the refusal above must be
        # narrow enough not to swallow this case.
        job = UnitJob()
        primary = {"ok": False, "exit_code": 3, "stdout": "", "outputs": {}}
        rental._verify_if_sampled(job, {}, {"id": "node-1"}, primary,
                                  verify_rate=1.0)
        self.assertEqual(self.placed, ["cpu"],
                         "a failed run was excused from verification, which is "
                         "the cheapest fraud on the network")


# These tests read files removed with the stripped features: blueprints/compute_rental.py.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED, matching the civil-rights
# classes in test_evidence_upload.py. The assertions are still correct and
# worth keeping; a skipUnless brings them back the moment the files exist
# again, which a deletion cannot do. PER METHOD, not per class: these
# classes are MIXED, and skipping a whole one destroys its working tests.
_COMPUTE_RENTAL_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/compute_rental.py",
    )
)
_COMPUTE_RENTAL_PRESENT_GONE = "the compute-rental blueprint was removed; these read it"

class SourceContractTest(unittest.TestCase):
    """Things the code must keep doing, checked by reading it."""

    def _source(self, *parts):
        with open(os.path.join(BACKEND, *parts), encoding="utf-8") as handle:
            return handle.read()

    def test_files_are_only_editable_while_queued(self):
        # Editing a running job would mean the output belongs to code the
        # submitter can no longer see.
        source = self._source("model", "ComputeRental.py")
        start = source.index("def editable")
        self.assertIn("STATUS_QUEUED", source[start:start + 600])

    def test_a_job_is_claimed_before_it_is_handed_to_the_runner(self):
        # Two workers racing would otherwise both take the same job and the
        # user would be charged once for two executions.
        #
        # Checked in run_unit, which is where the body now lives: run_next picks
        # the front of the queue and delegates, and a cluster drainer calls
        # run_unit directly, so the invariant has to hold THERE or it holds for
        # rentals only.
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def run_unit"):]
        claim = body.index("STATUS_RUNNING")
        commit = body.index("db.session.commit()", claim)
        # The handoff is now _dispatch, which chooses a node and sends the work.
        # Checked by name rather than by the runner call it eventually makes,
        # so the assertion survives the dispatch path changing again — what
        # matters is that the CLAIM is committed first, not which function does
        # the running.
        handoff = body.index("_dispatch(")
        self.assertLess(commit, handoff,
                        "the job must be committed as running before it is dispatched")

    def test_run_next_is_the_queue_pick_and_nothing_else(self):
        # One execution path, used by both drainers. Two would drift, and the
        # thing that drifted would be payment or verification.
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def run_next"):source.index("def run_unit")]
        self.assertIn("ordered_queue(device)", body)
        self.assertIn("run_unit(", body)
        self.assertNotIn("_dispatch(", body)

    def test_the_provider_is_credited_with_the_terminal_status(self):
        # A job marked done with no earning is a volunteer who supplied
        # electricity for nothing, and it is invisible until they go looking.
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def run_unit"):source.index("def expire_stale")]
        credit = body.index("credit_provider(")
        self.assertLess(credit, body.rindex("db.session.commit()"),
                        "the earning must be in the same transaction as the status")

    def test_truncation_is_recorded_in_stderr_and_never_in_stdout(self):
        # compute_verify.output_digest hashes stdout and the exit code. A note
        # appended there would change the digest and make an honest node
        # disagree with its own replica.
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def run_unit"):source.index("def expire_stale")]
        note = body.index("output truncated at")
        after = body[note:]
        self.assertIn("job.stderr", body[body.index("job.output_text"):])
        self.assertNotIn("job.stdout =", after)

    def test_the_replica_runs_the_same_workload_as_the_primary(self):
        # If the workload is threaded through one call site and not the other,
        # the replica runs a DIFFERENT IMAGE, every sampled job reports
        # DISAGREED, and M8 charges that to an honest node's reputation.
        source = self._source("services", "compute_rental.py")
        dispatch = source[source.index("def _dispatch"):source.index("def _verify_if_sampled")]
        verify = source[source.index("def _verify_if_sampled"):source.index("def _await_remote")]
        for name, body in (("_dispatch", dispatch), ("_verify_if_sampled", verify)):
            call = body.index("compute_bridge.submit(")
            self.assertIn("workload=", body[call:call + 600],
                          "%s must send the workload with the job" % name)

    def test_a_cluster_can_narrow_the_pool_and_the_sampling_rate(self):
        # Both are what make N units mean N machines checked at the workload's
        # own rate, rather than N jobs at the rental default.
        source = self._source("services", "compute_rental.py")
        dispatch = source[source.index("def _dispatch"):source.index("def _verify_if_sampled")]
        self.assertIn("candidates", dispatch[dispatch.index("place("):dispatch.index("place(") + 120])
        verify = source[source.index("def _verify_if_sampled"):source.index("def _await_remote")]
        self.assertIn("should_verify(str(job.id), rate)", verify)

    def test_cluster_units_are_kept_out_of_the_serial_queue(self):
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def ordered_queue"):source.index("def position_of")]
        self.assertIn("cluster_id", body)

    def test_the_produced_file_survives_the_round_trip(self):
        # A verified job with a correct digest and no vectors reads as success
        # and delivers nothing.
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def _await_remote"):source.index("def _output_for")]
        self.assertIn("outputs", body)

    def test_an_arbitrary_job_is_never_run_locally(self):
        # The isolation rule is not a preference to fall back from. A job that
        # needs a microVM and cannot find one stays queued; running it in the
        # local container path would be exactly what the rule forbids, and it
        # would look like success.
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def _dispatch"):source.index("def _await_remote")]
        local = body.index("code_runner.run_program")
        guard = body.rindex("if arbitrary:", 0, local)
        self.assertLess(guard, local,
                        "arbitrary jobs must be refused before the local fallback")

    def test_the_worker_node_is_recorded_before_the_job_is_sent(self):
        # Without it a completed job has no worker_node_id and the provider who
        # spent the electricity cannot be paid.
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def _dispatch"):source.index("def _await_remote")]
        record = body.index("worker_node_id")
        send = body.index("compute_bridge.submit")
        self.assertLess(record, send,
                        "the chosen node must be recorded before the work is sent")

    def test_cancelling_refunds(self):
        source = self._source("services", "compute_rental.py")
        body = source[source.index("def cancel"):source.index("def run_next")]
        self.assertIn("credits_paid = 0", body)

    @unittest.skipUnless(_COMPUTE_RENTAL_PRESENT, _COMPUTE_RENTAL_PRESENT_GONE)
    def test_a_boost_charges_only_the_difference(self):
        # Billing the full tier again would charge twice for the position the
        # job already holds.
        source = self._source("blueprints", "compute_rental.py")
        body = source[source.index("def boost"):]
        self.assertIn("cost - job.credits_paid", body)

    @unittest.skipUnless(_COMPUTE_RENTAL_PRESENT, _COMPUTE_RENTAL_PRESENT_GONE)
    def test_another_slip_cannot_read_a_job(self):
        source = self._source("blueprints", "compute_rental.py")
        body = source[source.index("def _job_or_404"):source.index("@rental_blueprint.route(\"/rent\")")]
        self.assertIn("job.slip_id != slip.id", body)
        self.assertIn("abort(404)", body)

    def test_this_never_runs_on_volunteer_machines(self):
        # The security model of roadmap/gpgpu-roadmap.md forbids arbitrary
        # submitted code on volunteer hardware. This feature is only safe
        # because it runs on the operator's own sandbox.
        source = self._source("services", "compute_rental.py")
        self.assertIn("code_runner", source)
        for forbidden in ("compute.Plan", "WorkerRecord", "dcs."):
            self.assertNotIn(forbidden, source,
                             "rented code must never be scheduled onto volunteer nodes")


if __name__ == "__main__":
    unittest.main()
