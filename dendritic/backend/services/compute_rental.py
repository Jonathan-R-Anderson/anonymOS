"""The rental queue: ordering, wait estimates, priority, and running a job.

THE ORDERING RULE, WHICH IS THE ONLY INTERESTING PART
------------------------------------------------------
    effective priority = paid priority + (minutes waited / AGE_MINUTES_PER_STEP)

Paying moves you forward NOW. Waiting moves you forward EVENTUALLY. Both, so
neither can win outright.

Ordering on paid priority alone is the obvious implementation and it starves:
while anybody is paying, an unpaid job never reaches the front, and "queued"
becomes a polite word for "never". Ordering on age alone makes the paid tier a
lie. Adding them means a free job's wait is BOUNDED rather than hopeful, and the
bound is arithmetic anybody can check: at 6 minutes per step, an Express job
(+25) is overtaken by a free job that has waited two and a half hours.

That number is a policy choice and it is meant to be argued with. What is not
negotiable is that the bound exists.
"""

import datetime
import time
import json

from shared import app, db

# One priority step per this many minutes of waiting. See the module comment.
AGE_MINUTES_PER_STEP = 6

# Nothing may sit in the queue forever, even unclaimed by a runner.
MAX_QUEUE_AGE_HOURS = 24

# What we tell somebody when there is no measured history to estimate from.
DEFAULT_JOB_SECONDS = 12

# How often a rental is checked against a second node. A quarter, because every
# replica is a volunteer's electricity spent to catch a liar who may not exist,
# and a node cannot tell which quarter it is in. A cluster passes its own rate
# (embeddings verify at 1.0 — bit-exact and cheap), which is why this is a
# default rather than a constant read at the point of use.
DEFAULT_VERIFY_RATE = 0.25

# The largest produced file we will store on the job row. 8 MiB is roughly
# 20,000 embedding vectors, and past that the answer is a store reference rather
# than a database column. Truncation is RECORDED rather than silent: a caller
# that got half a vector file and no warning would index it as if it were whole.
MAX_OUTPUT_BYTES = 8 * 1024 * 1024


def effective_priority(job, now=None):
    """Paid priority plus one step per AGE_MINUTES_PER_STEP waited."""
    now = now or datetime.datetime.utcnow()
    created = job.created_at or now
    waited = max((now - created).total_seconds(), 0) / 60.0
    return int(job.priority or 0) + int(waited // AGE_MINUTES_PER_STEP)


def ordered_queue(device=None, now=None):
    """The queue in the order it will actually be served."""
    from model.ComputeRental import queued_jobs

    now = now or datetime.datetime.utcnow()
    # Cluster units are NOT in this queue. The per-device drainer runs one job
    # at a time and blocks for its whole timeout, so a cluster drained through
    # here would be N nodes' worth of work executed one after another on
    # whichever node placement happened to pick — a cluster in name only. The
    # cluster drainer owns those rows and dispatches them in parallel, one node
    # each; leaving them visible to both would let the two steal jobs from each
    # other, and the loser would be charged for a run it never saw.
    jobs = [j for j in queued_jobs(device)
            if getattr(j, "cluster_id", None) is None]
    # Sorted by effective priority DESC, then oldest first. The second key is
    # what makes two equal-priority jobs deterministic rather than dependent on
    # database iteration order.
    return sorted(jobs, key=lambda j: (-effective_priority(j, now),
                                       j.created_at or now, j.id))


def position_of(job, now=None):
    """1-based position, or 0 once the job is no longer waiting."""
    from model.ComputeRental import STATUS_QUEUED

    if job.status != STATUS_QUEUED:
        return 0
    for index, other in enumerate(ordered_queue(job.device, now), start=1):
        if other.id == job.id:
            return index
    return 0


def average_seconds(device="cpu"):
    """Mean runtime of recent finished jobs, in seconds."""
    from model.ComputeRental import recent_durations

    durations = recent_durations(device)
    if not durations:
        return DEFAULT_JOB_SECONDS
    return max(sum(durations) / len(durations) / 1000.0, 0.5)


def estimate_wait(job, now=None):
    """Seconds until this job is expected to START.

    Position ahead times the measured average, and no more sophisticated than
    that on purpose. A queue this size does not support a better model, and a
    confident-looking estimate derived from three data points is worse than an
    obviously rough one — people plan around the number they are shown.

    Returns (seconds, confidence) where confidence is "measured" or "estimated",
    so the page can say which it is instead of presenting a guess as a fact.
    """
    from model.ComputeRental import recent_durations, STATUS_QUEUED

    if job.status != STATUS_QUEUED:
        return 0, "measured"
    ahead = max(position_of(job, now) - 1, 0)
    seconds = ahead * average_seconds(job.device)
    confidence = "measured" if len(recent_durations(job.device)) >= 5 else "estimated"
    return int(seconds), confidence


def queue_summary(device="cpu", now=None):
    """What the page shows above the queue."""
    jobs = ordered_queue(device, now)
    average = average_seconds(device)
    return {
        "device": device,
        "waiting": len(jobs),
        "average_seconds": int(average),
        "drain_seconds": int(len(jobs) * average),
    }


class RentalError(RuntimeError):
    """Something the submitter can act on. The message is shown to them."""


def _validate(files, entrypoint, workload=None):
    """Refuse a submission that cannot run, before it takes a queue slot.

    A WORKLOAD job is validated against a different rule than a language job,
    because it is a different kind of thing. It carries data for a fixed image:
    the image's input file must be there, an entry point must NOT be (there is
    nothing to name — the image is the program), and the "entry point must be
    one of the files" rule is not merely relaxed but meaningless.

    Every size cap still applies. They are about what the queue and the node
    will carry, which does not change because the payload is data.
    """
    from model.ComputeRental import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES

    spec = None
    if workload:
        from services.compute_catalogue import workload as workload_spec

        spec = workload_spec(workload)
        if spec is None:
            raise RentalError(
                "There is no %r workload in the catalogue." % str(workload))

    if not files:
        raise RentalError("Add at least one file.")
    if len(files) > MAX_FILES:
        raise RentalError("At most %d files." % MAX_FILES)

    total = 0
    for path, content in files.items():
        path = (path or "").strip()
        if not path:
            raise RentalError("A file with no name cannot be saved.")
        # Path traversal is meaningless to the runner (it gets a flat dict, not
        # a filesystem) but it is stored, displayed and used as a dict key, so
        # it is refused at the edge rather than sanitised in three places later.
        if path.startswith("/") or ".." in path or "\\" in path:
            raise RentalError("File names cannot contain .. or start with /: %s" % path)
        size = len(content or "")
        if size > MAX_FILE_BYTES:
            raise RentalError("%s is larger than %d KB." % (path, MAX_FILE_BYTES // 1024))
        total += size
    if total > MAX_TOTAL_BYTES:
        raise RentalError("The whole program must be under %d KB." % (MAX_TOTAL_BYTES // 1024))

    if spec is not None:
        if entrypoint:
            raise RentalError(
                "A %s job runs fixed catalogue code, so it takes no entry "
                "point — send only %s." % (workload, spec["input_file"]))
        wanted = spec["input_file"]
        if wanted not in files:
            raise RentalError(
                "A %s job needs its data in a file called %s."
                % (workload, wanted))
        extra = sorted(set(files) - {wanted})
        if extra:
            # Refused rather than ignored. The image reads exactly one path and
            # nothing else, so an accepted-and-dropped file is a submitter
            # watching their input never appear in the result with no error
            # anywhere to explain it.
            raise RentalError(
                "A %s job reads only %s; these were also sent and would be "
                "ignored: %s" % (workload, wanted, ", ".join(extra)))
        return

    if entrypoint not in files:
        raise RentalError("The entry point %r is not one of the files." % entrypoint)


def submit(slip, name, files, entrypoint, language="python", device="cpu",
           arbitrary=False, cores=1, seconds=60,
           priority_tier=0, workload=None):
    """Queue a program, or a workload's data. Returns the job.

    Charging happens HERE and the job is created paid — a job that exists
    unpaid, or a charge with no job, are both states somebody has to reconcile
    by hand later.

    `workload` names a catalogue image instead of supplying a program. The two
    are exclusive: a workload job has no entry point and its language field is
    inert, because the image is fixed at build time.
    """
    from model.ComputeRental import (
        ComputeRental, ComputeRentalFile, PRIORITY_TIERS,
    )

    if slip is None:
        raise RentalError("Sign in to submit a program.")
    workload = (str(workload).strip() or None) if workload else None
    if workload and arbitrary:
        # Not a contradiction to resolve quietly in favour of one of them: a
        # workload IS the catalogue rule, and "arbitrary" is the request to be
        # exempt from it. Accepting both would mean the isolation requirement
        # depended on which field a later reader happened to check.
        raise RentalError(
            "A catalogue workload is not arbitrary code — it runs a fixed "
            "image over data you supply. Send one or the other.")
    _validate(files, entrypoint, workload)

    tier = next((t for t in PRIORITY_TIERS if t[0] == priority_tier), PRIORITY_TIERS[0])
    priority_cost, boost, _label = tier

    # What the WORK costs, from what is being asked for against what the network
    # has spare. Separate from the priority tier, which buys queue position and
    # nothing else — charging one number for both would mean a submitter who
    # wanted to skip the queue paid more for the same compute, which is not what
    # a priority tier is.
    #
    # Falls back to the flat tier if the market cannot be read. A pricing engine
    # that took the submit path down with it would be worse than one that was
    # occasionally imprecise.
    work_cost = 0
    quote = None
    try:
        from services.compute_market import quote as market_quote

        quote = market_quote(device, cores=cores, seconds=seconds)
        work_cost = int(quote.get("credits") or 0)
    except Exception:
        from shared import app

        app.logger.exception("compute market quote failed; falling back to the flat tier")

    cost = priority_cost + work_cost

    # Arbitrary code needs hardware isolation, and refusing at SUBMIT is much
    # kinder than accepting a job that can never be placed. A submitter who
    # learns at queue position 1 that no node can ever run their program has
    # been misled by the queue.
    if arbitrary:
        from services.compute_placement import capability_summary

        summary = capability_summary(device)
        if not summary["arbitrary_possible"]:
            raise RentalError(
                "Arbitrary programs need a node with hardware isolation (a "
                "microVM), and none is available right now. Pick a catalogue "
                "language instead, or try again later — nothing is charged.")

    job = ComputeRental(
        slip_id=slip.id, name=(name or "untitled")[:120], language=language,
        # Null, not "" and not a guessed default: a workload job has no entry
        # point at all, and storing a plausible-looking one would make a row
        # that looks like a language job to anything reading it later.
        entrypoint=(None if workload else entrypoint),
        workload=workload,
        device=device, priority=boost, credits_paid=cost,
        arbitrary=bool(arbitrary),
        cores=max(1, int(cores or 1)), seconds=max(1, int(seconds or 60)),
    )
    db.session.add(job)
    db.session.flush()
    for path, content in files.items():
        db.session.add(ComputeRentalFile(rental_id=job.id, path=path.strip(),
                                         content=content or ""))
    db.session.commit()
    return job


def save_file(job, path, content):
    """Correct one file of a queued job.

    Refused once the job is running: the runner already holds a copy, so an edit
    would not be what ran, and the output would belong to code the submitter can
    no longer see. That is a worse outcome than refusing the edit.
    """
    from model.ComputeRental import ComputeRentalFile, MAX_FILE_BYTES

    if not job.editable:
        raise RentalError("This job is %s — its files can no longer be changed."
                          % job.status)
    if len(content or "") > MAX_FILE_BYTES:
        raise RentalError("That file is too large.")
    row = next((f for f in job.files if f.path == path), None)
    if row is None:
        raise RentalError("No such file in this job: %s" % path)
    row.content = content or ""
    db.session.commit()
    return row


def cancel(job):
    """Withdraw a job that has not started, and refund any boost.

    Refunding is the only defensible choice: the user paid to skip a queue they
    then left, so the service delivered nothing.
    """
    from model.ComputeRental import STATUS_CANCELLED, STATUS_QUEUED

    if job.status != STATUS_QUEUED:
        raise RentalError("Only a waiting job can be cancelled.")
    job.status = STATUS_CANCELLED
    job.finished_at = datetime.datetime.utcnow()
    refund = job.credits_paid
    job.credits_paid = 0
    db.session.commit()
    return refund


def _dispatch(job, files, candidates=None, verify_rate=None):
    """Run a job on a volunteer node, or locally if none can take it.

    `candidates` narrows the pool placement may choose from. A cluster passes a
    SHRINKING pool — the nodes it has not used yet — so that N units genuinely
    means N machines rather than N jobs that placement happened to send to the
    same popular node.

    THE ORDER MATTERS
    -----------------
    A node is chosen BEFORE the job is sent, and the choice is recorded on the
    job. Without that, a completed job has no worker_node_id, and the provider
    who spent the electricity cannot be paid — the payment path exists but is
    unreachable, which is worse than absent because it looks finished.

    WHY LOCAL IS A FALLBACK AND NOT A PEER
    -------------------------------------
    Running on the operator's own hardware is what this network exists to stop
    doing. It stays as a fallback because a queue that stalled whenever no
    volunteer was available would be worse for a submitter than one that ran
    their job somewhere. But it is recorded as `local`, so a result carries the
    truth about where it ran rather than being indistinguishable from a
    distributed one.

    An ARBITRARY job is never run locally. The isolation rule is not a
    preference to fall back from: a job that needs a microVM and cannot find one
    stays queued. Neither is a WORKLOAD job or a CLUSTER unit — see the refusals
    below the remote path.
    """
    # Imported HERE rather than inside run_next. It used to be imported only in
    # run_next, so the local fallback at the bottom of this function raised
    # NameError on every job that reached it, and the queue reported "the runner
    # is unavailable: name 'code_runner' is not defined" and marked the job
    # FAILED. A fallback that cannot run is worse than no fallback: it looks
    # like the runner is broken rather than absent.
    from services import code_runner, compute_bridge

    arbitrary = bool(getattr(job, "arbitrary", False))
    workload = getattr(job, "workload", None) or None
    cluster_id = getattr(job, "cluster_id", None)
    needs_gpu = str(job.device or "cpu").startswith("gpu")

    if compute_bridge.enabled():
        try:
            from services.compute_placement import place

            node, isolation = place(str(job.id), job.device, arbitrary, candidates)
            job.worker_node_id = str(node.get("id") or "")[:80]
            job.isolation = isolation
            db.session.commit()

            compute_bridge.submit(
                node, job.id, job.device, job.language, job.entrypoint, files,
                stdin=job.stdin_text or "", timeout_seconds=job.seconds or 60,
                workload=workload, params=getattr(job, "params", None),
                seed=getattr(job, "seed", None),
                arbitrary=arbitrary, needs_gpu=needs_gpu)
            primary = _await_remote(node, job)
            return _verify_if_sampled(job, files, node, primary,
                                      verify_rate=verify_rate)
        except compute_bridge.Refused as exc:
            # A refusal is an answer, not a failure. Leave the job for the next
            # pass rather than burning it because one node was busy.
            raise RentalError(str(exc))
        except Exception:
            from shared import app

            app.logger.exception("remote dispatch failed for job %s", job.id)
            if arbitrary:
                # Never silently downgrade an arbitrary job to the local
                # container path — that is exactly what the isolation rule
                # forbids, and it would look like success.
                raise

    if arbitrary:
        raise RentalError(
            "This job needs a node with hardware isolation and none took it. "
            "It stays queued — nothing is charged for a job that has not run.")

    if workload:
        # The local judge understands python and javascript SOURCE. It has no
        # catalogue image, no /work, and no way to produce the file this job
        # exists to produce, so "falling back" to it would run something else
        # entirely and report it as this job's result.
        raise RentalError(
            "The %s workload runs only on a catalogue node, and none took this "
            "job. It was NOT run here: a fallback that ran different software "
            "over your data and reported it as this job's result would be "
            "worse than no result." % workload)

    if cluster_id is not None:
        # A cluster is a claim about WHERE the work happened: N units on N
        # machines. Quietly running one unit here would make that claim false
        # while the page still displayed it, which is the exact failure this
        # whole design exists to prevent.
        raise RentalError(
            "This is one unit of a cluster and it must run on its own node. "
            "None took it, so it was NOT run here — a cluster that quietly ran "
            "on one local machine is not a cluster, and the page would have "
            "gone on saying it was.")

    job.worker_node_id = "local"
    job.isolation = "container"
    return code_runner.run_program(job.language, files, job.entrypoint, job.stdin_text)


def _verify_if_sampled(job, files, primary_node, primary_result, verify_rate=None):
    """Run a second replica and compare, when this job was sampled.

    THE REPLICA MUST BE THE SAME WORK
    ---------------------------------
    Same workload, same language, same entry point, same files. A replica
    submitted without the workload runs a DIFFERENT IMAGE over the same data,
    which produces different output for entirely honest reasons — and the
    comparison below would score it DISAGREED, which M8 then charges to the
    reputation of a node that did nothing wrong. The bug would be invisible
    until somebody wondered why every sampled job disagreed.

    WHY A SECOND NODE AND NOT A SECOND RUN
    --------------------------------------
    Re-running on the same node verifies nothing: a node that returns garbage
    returns the same garbage twice, and the comparison would agree with itself.
    The replica has to be somewhere else, which is why this refuses rather than
    falling back when no second node is available.

    WHY A FAILED VERIFICATION DOES NOT FAIL THE JOB
    ----------------------------------------------
    A disagreement says one of two nodes is wrong; it does not say which. Failing
    the submitter's job would punish them for a dispute between providers they
    never chose. So the result is returned with its verdict attached, and the
    verdict is what decides PAYMENT.

    WHAT IS NOT VERIFIED AT ALL
    ---------------------------
    A result that CLAIMS success and carries no product. There is nothing to
    corroborate: the digest on stdout is a description OF the file, so two nodes
    agreeing on it while neither returned a file is two descriptions of nothing,
    recorded as "verified". That reading is what made the defect below payable.
    """
    from services import compute_verify

    rate = DEFAULT_VERIFY_RATE if verify_rate is None else float(verify_rate)

    if primary_result.get("ok") and _missing_product(job, primary_result):
        # No product to check, so no replica is spent on it — every replica is a
        # volunteer's electricity, and this one would buy an agreement about a
        # file that does not exist.
        #
        # UNVERIFIED, not DISAGREED: nothing was compared, and a disagreement is
        # a claim about two nodes when only one was ever asked. Payment is
        # refused in run_unit on the missing file itself rather than by bending
        # a verdict into carrying the decision, so that a later reader of
        # `verdict` is not being told a second, invented fact.
        job.verdict = compute_verify.VERDICT_UNVERIFIED
        return primary_result

    if not compute_verify.is_verifiable(job):
        job.verdict = compute_verify.VERDICT_UNVERIFIED
        return primary_result
    if not compute_verify.should_verify(str(job.id), rate):
        job.verdict = compute_verify.VERDICT_UNVERIFIED
        return primary_result

    try:
        from services import compute_bridge
        from services.compute_placement import eligible_nodes, place

        pool = [n for n in eligible_nodes(job.device, bool(job.arbitrary))
                if str(n.get("id") or "") != str(primary_node.get("id") or "")]
        if not pool:
            # No independent second node. Reported honestly rather than
            # verified against the same machine, which would agree with itself
            # and call it corroboration.
            job.verdict = compute_verify.VERDICT_INSUFFICIENT
            return primary_result

        second, _ = place("%s-verify" % job.id, job.device, bool(job.arbitrary), pool)
        compute_bridge.submit(
            second, "%s-v" % job.id, job.device, job.language, job.entrypoint,
            files, stdin=job.stdin_text or "", timeout_seconds=job.seconds or 60,
            workload=getattr(job, "workload", None) or None,
            params=getattr(job, "params", None), seed=getattr(job, "seed", None),
            arbitrary=bool(job.arbitrary),
            needs_gpu=str(job.device or "cpu").startswith("gpu"))
        replica = _await_remote(second, job)

        verdict, _digest, agreeing = compute_verify.compare([
            (str(primary_node.get("id")), primary_result),
            (str(second.get("id")), replica),
        ])
        job.verdict = verdict
        job.verified_by = ",".join(agreeing)[:200] or None
    except Exception:
        from shared import app

        # Verification failing is not the job failing. A network problem while
        # checking must not cost the submitter their result.
        app.logger.exception("verification failed for job %s", job.id)
        job.verdict = compute_verify.VERDICT_INSUFFICIENT
    return primary_result


def _await_remote(node, job, timeout_seconds=None):
    """Poll the bridge until the job finishes.

    Bounded, because a node that accepted a job and then vanished must not hold
    this worker forever — one silent node would stop the whole queue draining.

    `outputs` is carried through unchanged. For a workload the produced FILE is
    the product; stdout only carries the digest that lets two replicas be
    compared. Dropping it here would leave a verified job with a correct hash
    and no vectors, which reads as success and delivers nothing.
    """
    from services import compute_bridge

    deadline = time.time() + float(timeout_seconds or (job.seconds or 60) + 30)
    while time.time() < deadline:
        result = compute_bridge.result(node, job.id)
        if result is not None:
            return {
                "ok": int(result.get("exit_code") or 0) == 0 and not result.get("timed_out"),
                "stdout": result.get("stdout") or "",
                "stderr": result.get("stderr") or result.get("error") or "",
                "exit_code": result.get("exit_code"),
                "outputs": result.get("outputs") or {},
                "output_truncated": bool(result.get("output_truncated")),
            }
        time.sleep(1)
    return {"ok": False, "stdout": "", "exit_code": None, "outputs": {},
            "stderr": "the node accepted this job and did not return a result in time"}


def _missing_product(job, result):
    """The file this job's workload declares and did not return, or None.

    None for a job that declares no output file — a language job's product IS
    its stdout, and a program that writes no files has still answered — and None
    once the declared file has come back with something in it.

    An EMPTY file counts as missing. Zero bytes is not a smaller result: for a
    workload whose whole answer is the file, it is the same nothing as never
    having written one, and accepting it would leave this hole open with one
    extra step in it.
    """
    name = getattr(job, "workload", None) or None
    if not name:
        return None
    try:
        from services.compute_catalogue import output_file

        wanted = output_file(name)
    except Exception:
        # A catalogue that cannot be read cannot convict a node. Logged nowhere
        # and treated as "no declared product", because the alternative — every
        # workload job failing because an import broke — is worse than the
        # window it leaves.
        return None
    if not wanted:
        return None
    if ((result or {}).get("outputs") or {}).get(wanted):
        return None
    return wanted


def _output_for(job, outputs):
    """Which produced file becomes job.output_text, and its text."""
    if not outputs:
        return None
    wanted = None
    name = getattr(job, "workload", None)
    if name:
        try:
            from services.compute_catalogue import output_file

            wanted = output_file(name)
        except Exception:
            wanted = None
    if wanted and wanted in outputs:
        return outputs[wanted] or ""
    if len(outputs) == 1:
        return next(iter(outputs.values())) or ""
    # Several files and no named one. Kept together as JSON rather than picking
    # one arbitrarily: guessing would silently discard the rest, and a caller
    # cannot tell a chosen file from the only file.
    return json_dumps({k: outputs[k] for k in sorted(outputs)})


def run_next(device="cpu"):
    """Take the front of the queue and run it. Returns the job, or None.

    The queue this reads EXCLUDES cluster units — see ordered_queue. This is the
    serial per-device drainer, and it blocks for a job's whole timeout.
    """
    queue = ordered_queue(device)
    if not queue:
        return None
    return run_unit(queue[0])


def run_unit(job, candidates=None, verify_rate=None):
    """Run one job to completion. The single execution path.

    Public because a cluster drainer runs UNITS: rows that never enter
    ordered_queue and are dispatched in parallel, each against its own slice of
    the node pool. Factoring this out of run_next is what keeps a cluster on the
    existing path rather than beside it — the same claim, the same dispatch, the
    same verification, the same payment.

    TWO INVARIANTS, BOTH LOAD-BEARING
    ---------------------------------
    1. The job is claimed by flipping it to running and COMMITTING before it is
       dispatched. Two workers racing would otherwise both take it, and the user
       would be charged once for two executions.
    2. The provider is credited in the SAME transaction as the terminal status.
       A job marked done with no earning is a volunteer who supplied electricity
       for nothing, and it stays invisible until they go looking.

    A MISSING PRODUCT IS A FAILURE, AND IT IS NOT BOUGHT
    ----------------------------------------------------
    A workload's answer is a FILE; stdout carries only a digest OF that file.
    A result that claims exit 0 and returns no file is therefore not a small
    problem to note in stderr — it is the job not having happened, dressed as
    success. It used to pass every gate: ok, DONE, verified by hash equality
    against a replica's identical digest, and paid.

    The check lives here as well as on the node because the two answer different
    questions. The node's is the truthful one — only it can see inside the
    container — but it is also the party being paid, and a build that predates
    the fix reports the same empty `outputs` a lying one would. This site can
    tell that a job DECLARED a product, so it can refuse to buy a result without
    one no matter what the node says.

    The refusal is narrow on purpose. A run that exited NON-ZERO and wrote
    nothing is an honest failure: the node spent the same electricity, and
    compute_earnings.FAILED_SHARE exists precisely so that running risky-looking
    work stays rational. Widening this to "no output, no pay" would make nodes
    cherry-pick, and the jobs nobody would take are the ones that most need
    running. What is refused is the CONTRADICTION — a run reported as successful
    whose product is absent — which is no more work than answering instantly
    with nothing.
    """
    from model.ComputeRental import STATUS_DONE, STATUS_FAILED, STATUS_RUNNING

    job.status = STATUS_RUNNING
    job.started_at = datetime.datetime.utcnow()
    db.session.commit()

    files = {f.path: f.content for f in job.files}
    started = datetime.datetime.utcnow()
    try:
        result = _dispatch(job, files, candidates=candidates,
                           verify_rate=verify_rate)
    except Exception as exc:  # the runner being down must not wedge the queue
        app.logger.exception("compute_rental: runner failed for job %s", job.id)
        result = {"ok": False, "error": "the runner is unavailable: %s" % exc}

    # What the node claimed, kept apart from what this site concludes. The two
    # differ exactly in the case worth catching, and collapsing them would leave
    # nothing to distinguish "the run failed" from "the run says it worked and
    # produced nothing" — which are paid differently.
    node_claimed_success = bool(result.get("ok"))
    missing_product = _missing_product(job, result)
    ok = node_claimed_success and not missing_product

    job.runtime_ms = int((datetime.datetime.utcnow() - started).total_seconds() * 1000)
    job.stdout = (result.get("stdout") or "")[:200000]
    job.stderr = (result.get("stderr") or result.get("error") or "")[:200000]
    job.exit_code = result.get("exit_code")
    job.status = STATUS_DONE if ok else STATUS_FAILED
    job.finished_at = datetime.datetime.utcnow()

    # The produced FILE, for a workload that returned one.
    #
    # Note carefully where truncation is recorded: in stderr, never in stdout.
    # compute_verify.output_digest hashes stdout and the exit code, so a note
    # appended there would change the digest and make an honest node's result
    # disagree with its own replica.
    text = _output_for(job, result.get("outputs") or {})
    if text is not None:
        truncated = bool(result.get("output_truncated"))
        encoded = text.encode("utf-8", "replace")
        if len(encoded) > MAX_OUTPUT_BYTES:
            text = encoded[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore")
            truncated = True
        job.output_text = text
        if truncated:
            note = ("\n[output truncated at %d bytes — the full file was larger "
                    "than this job can store]" % MAX_OUTPUT_BYTES)
            job.stderr = ((job.stderr or "") + note)[:200000]

    # Said to the submitter, in stderr rather than stdout for the same reason
    # truncation is: output_digest hashes stdout, and a note appended there
    # would make an honest node disagree with its own replica.
    if node_claimed_success and missing_product:
        note = ("\n[this node reported the run as successful and returned no "
                "%s — the file this %s job exists to produce. The job is "
                "recorded as FAILED and the node is not paid for it, because a "
                "digest of a file that never arrived is not the file.]"
                % (missing_product, job.workload))
        job.stderr = ((job.stderr or "") + note)[:200000]

    # Pay the machine that did the work. In the same transaction as the status,
    # so a completed job and its earning are recorded together or not at all —
    # a job marked done with no earning is a volunteer who provided electricity
    # for nothing, and it would be invisible until they went looking.
    if job.worker_node_id:
        if node_claimed_success and missing_product:
            # Not bought at any rate — not even the reduced one a failed job
            # earns. FAILED_SHARE pays for honest work that did not come off,
            # and this is a report the network cannot accept as work at all:
            # returning "done" with nothing attached is exactly what a node that
            # ran nothing would send, and paying 0.3 for it makes that the
            # cheapest way to earn. The volunteer who genuinely lost the file to
            # a plumbing fault loses one job; the strategy loses everything.
            app.logger.warning(
                "compute_rental: node %s reported job %s successful but returned "
                "no %s; not credited", job.worker_node_id, job.id, missing_product)
        else:
            try:
                from services.compute_earnings import credit_provider

                credit_provider(job, job.worker_node_id, succeeded=ok)
            except Exception:
                # Logged, not raised: losing the result of a job that ran because
                # the payment row failed would be a worse outcome than an earning
                # that has to be reconciled.
                #
                # `app` is the module-level import. A local `from shared import
                # app` here would make the name local to the WHOLE function, and
                # the warning above — which runs before this line — would raise
                # UnboundLocalError instead of refusing the payment.
                app.logger.exception("could not credit provider for job %s", job.id)

    db.session.commit()
    return job


def expire_stale(now=None):
    """Fail anything that has sat unclaimed past MAX_QUEUE_AGE_HOURS.

    A job nobody ever picked up is not queued, it is lost, and leaving it in the
    queue makes every wait estimate behind it wrong.
    """
    from model.ComputeRental import ComputeRental, STATUS_FAILED, STATUS_QUEUED

    now = now or datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(hours=MAX_QUEUE_AGE_HOURS)
    rows = (
        db.session.query(ComputeRental)
        .filter(ComputeRental.status == STATUS_QUEUED,
                ComputeRental.created_at < cutoff)
        .all()
    )
    for row in rows:
        row.status = STATUS_FAILED
        row.stderr = ("This job waited more than %d hours without being picked "
                      "up and was withdrawn. Nothing ran, and any boost you paid "
                      "for it is refunded." % MAX_QUEUE_AGE_HOURS)
        row.credits_paid = 0
        row.finished_at = now
    if rows:
        db.session.commit()
    return len(rows)


def as_json(job, now=None):
    """What the page and the poller read."""
    seconds, confidence = estimate_wait(job, now)
    output = getattr(job, "output_text", None)
    return {
        "id": job.id,
        "name": job.name,
        "status": job.status,
        "device": job.device,
        "language": job.language,
        "entrypoint": job.entrypoint,
        # A workload job's language and entrypoint are inert, so the page needs
        # this to know which of the two things it is looking at.
        "workload": getattr(job, "workload", None),
        "cluster_id": getattr(job, "cluster_id", None),
        "shard_index": getattr(job, "shard_index", None),
        # Whether there is a file to download, not the file itself: a unit's
        # output can be megabytes, and the poller reads this every second.
        "output_available": bool(output),
        "output_bytes": len(output or ""),
        "position": position_of(job, now),
        "wait_seconds": seconds,
        "wait_confidence": confidence,
        "priority": job.priority,
        "runtime_ms": job.runtime_ms,
        "exit_code": job.exit_code,
        "stdout": job.stdout,
        "stderr": job.stderr,
        "editable": job.editable,
        "files": sorted(f.path for f in job.files),
    }


def json_dumps(value):
    return json.dumps(value, ensure_ascii=False)
