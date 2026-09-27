"""Spinning up a cluster: N machines, one catalogue workload, one corpus.

WHAT THIS ADDS, AND WHAT IT DELIBERATELY DOES NOT
--------------------------------------------------
Everything a unit of work needs already exists. `compute_placement.place()`
picks a machine for it, `compute_bridge` ships it, `compute_verify.compare()`
checks it, `compute_earnings.credit_provider()` pays for it, and
`compute_market.quote()` prices it. None of that is re-implemented here and
none of it is forked "for clusters".

What did not exist is the FAN-OUT: splitting one corpus into N shards, putting
each shard on a DIFFERENT machine, and doing it at the same time rather than one
after another. That is this file, and it is deliberately thin — a cluster is a
parent row plus N ordinary rentals (model/ComputeCluster.py explains why), so
anything that reads a rental can already read a unit.

WHY CONCURRENCY IS THE POINT AND NOT AN OPTIMISATION
-----------------------------------------------------
The serial drainer runs one job per device at a time and blocks inside
`_await_remote` for the job's whole timeout. Ten shards dispatched through it
take ten times one shard's runtime and land on whichever node placement happened
to choose each time — usually a handful of nodes, often the same one twice.
That is not a cluster; it is a queue with a cluster's name on it. Ten shards
dispatched HERE take one shard's runtime and occupy ten machines, which is the
product.

The concurrency is bounded and every worker owns its own session, because the
failure mode of getting that wrong is not a slow page — it is the connection
pool being drained by background threads and the site refusing requests. See
MAX_CONCURRENT_UNITS.

WHY A NODE IS LEFT OUT OF EVERY WAVE
-------------------------------------
Verification runs a second replica on an INDEPENDENT node. If a wave assigns
every eligible machine, the verifier has nowhere to go and every unit comes back
`insufficient` — verified in name, unverified in fact, on the one workload
chosen for M10 precisely because it can be checked bit-exactly. So a wave takes
at most `len(pool) - 1` units and the rest wait for the next one.
"""

import collections
import concurrent.futures
import datetime
import json

from shared import app, db

try:
    # ClusterError IS a RentalError, so a caller that catches either one catches
    # both. Guarded because a test may load this module with the rental service
    # stubbed out, and a hard import would make that impossible.
    from services.compute_rental import RentalError as _SubmitError
except Exception:  # pragma: no cover - only when loaded standalone
    _SubmitError = RuntimeError


# Cluster states. The same STRINGS as a rental's, mirrored from
# model/ComputeCluster.py rather than imported so that the roll-up below is a
# pure function of statuses and can be tested without a database.
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

TERMINAL = (STATUS_DONE, STATUS_FAILED, STATUS_CANCELLED)

# The most machines one request may occupy.
#
# A ceiling rather than "as many as are online", because one submitter taking
# the entire network is indistinguishable from an outage to everybody else, and
# because a cluster wider than its corpus is machines paid to read nothing.
MAX_NODES = 32

# Below this the request is refused outright. Two, not one: a cluster of one
# machine has no independent verifier, so its result is one anonymous node's
# word — which is exactly the thing this network exists not to sell.
MIN_POOL = 2

# How many machines are kept out of an assignment wave, for the verifier.
SPARE_NODES = 1

# How many units may be in flight at once.
#
# Small on purpose. Every worker holds a database session for as long as its
# job runs — minutes, on the wrong side of a slow node — and that session is a
# connection out of a pool sized for HTTP requests. This site has taken itself
# down by letting background work hold connections before; eight is a fan-out
# worth having and a number the pool does not notice.
MAX_CONCURRENT_UNITS = 8

# Per-unit wall-clock ceiling when the caller does not say. Matches
# ComputeCluster.seconds' default; stated here so the service and the column do
# not drift into disagreeing about what "unspecified" means.
DEFAULT_SECONDS = 120

# One shard's assignment: which unit, which machines it may be placed on, and
# which of them placement will actually pick.
Assignment = collections.namedtuple(
    "Assignment", "unit_id shard_index candidates node_id")


class ClusterError(_SubmitError):
    """Something the submitter can act on. The message is shown to them."""


# ---------------------------------------------------------------------------
# Splitting the corpus
# ---------------------------------------------------------------------------

def corpus_to_lines(corpus):
    """The submitted corpus as a list of non-empty lines.

    Blank lines are dropped rather than embedded. The image skips them, so a
    blank line would silently produce no vector and break the one property that
    makes a reassembled result checkable: one output line per input line.
    """
    if corpus is None:
        return []
    if isinstance(corpus, str):
        raw = corpus.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    else:
        raw = list(corpus)
    return [str(line).strip() for line in raw if str(line).strip()]


def shard(corpus_lines, n):
    """Split lines into n contiguous JSONL shards, in order.

    WHY THE IDS ARE GLOBAL AND NOT PER-SHARD
    ----------------------------------------
    Each line carries its index in the WHOLE corpus, not in its shard. The units
    come back in whatever order N machines finish, and the ids are what let the
    detail page put the result back in the order the user sent it — and what
    lets them check that every line they submitted came back. Per-shard ids
    would make eight units that all claim to start at 0.

    Contiguous, in order, and total: every line appears exactly once, and
    concatenating the shards reproduces the corpus. Shards differ in length by
    at most one.
    """
    lines = list(corpus_lines)
    count = max(1, int(n or 1))
    base, extra = divmod(len(lines), count)

    shards = []
    start = 0
    for index in range(count):
        size = base + (1 if index < extra else 0)
        chunk = lines[start:start + size]
        shards.append("".join(
            json.dumps({"id": start + offset, "text": text},
                       ensure_ascii=False, sort_keys=True) + "\n"
            for offset, text in enumerate(chunk)))
        start += size
    return shards


# ---------------------------------------------------------------------------
# Pricing and submission
# ---------------------------------------------------------------------------

def eligible_pool(device):
    """The machines that could take a unit of this cluster.

    Catalogue work only: `arbitrary=False` is not a parameter here because a
    cluster runs a SIGNED IMAGE over the submitter's data, never the
    submitter's code. Making it an argument would be the first step of the
    drift the roadmap warns about — the catalogue rule relaxed as an
    implementation detail rather than on purpose.
    """
    from services.compute_placement import eligible_nodes

    return list(eligible_nodes(device, False))


def quote_cluster(device, node_count, cores=1, seconds=DEFAULT_SECONDS,
                  priority_tier=0):
    """What N machines for `seconds` would cost right now.

    The market is quoted for ONE unit and multiplied, not called once per unit
    in a loop. Both give the same answer — nothing has been created yet, so the
    market state cannot move between calls — and this way asking the price of a
    32-node cluster is one query rather than thirty-two.
    """
    from model.ComputeRental import PRIORITY_TIERS

    tier = next((t for t in PRIORITY_TIERS if t[0] == priority_tier),
                PRIORITY_TIERS[0])
    priority_cost, boost, label = tier

    unit_quote = None
    work_cost = 0
    try:
        from services.compute_market import quote as market_quote

        unit_quote = market_quote(device, cores=cores, seconds=seconds)
        work_cost = int(unit_quote.get("credits") or 0)
    except Exception:
        # Exactly as compute_rental.submit does it, and for the same reason: a
        # pricing engine that took the submit path down with it would be worse
        # than one that was occasionally imprecise.
        app.logger.exception(
            "compute market quote failed; falling back to the flat tier")

    units = max(1, int(node_count or 1))
    per_unit = priority_cost + work_cost
    return {
        "device": device,
        "units": units,
        "cores": cores,
        "seconds": seconds,
        "priority_tier": priority_tier,
        "priority_label": label,
        "priority_boost": boost,
        "per_unit_credits": per_unit,
        "credits": per_unit * units,
        "market": unit_quote,
    }


def submit(slip, name, workload, corpus, node_count, device="cpu", cores=1,
           seconds=DEFAULT_SECONDS, priority_tier=0, verify_rate=None):
    """Create a cluster and its N units. Returns the cluster.

    EVERY REFUSAL HAPPENS BEFORE ANYTHING IS CREATED
    ------------------------------------------------
    Unknown workload, empty corpus, too few machines, a shard too large for the
    queue — all of them are answered here, with nothing charged and no rows to
    reconcile. The alternative is discovering at unit 6 of 8 that the seventh
    shard is oversized, having already charged for six.
    """
    from model.ComputeCluster import ComputeCluster
    from model.ComputeRental import ComputeRental, MAX_FILE_BYTES
    from services import compute_catalogue, compute_rental

    if slip is None:
        raise ClusterError("Sign in to start a cluster.")

    # The columns a unit needs in order to BE a unit. Checked rather than
    # assumed: without them `unit.cluster_id = ...` below would set a plain
    # Python attribute that is never written, and the cluster would exist with
    # N units it does not own and cannot find.
    for column in ("cluster_id", "shard_index"):
        if not hasattr(ComputeRental, column):
            raise ClusterError(
                "This deployment cannot run clusters yet: compute_rental has no "
                "%s column, so the database migration has not been applied. "
                "Nothing has been charged." % column)

    spec = compute_catalogue.workload(workload)
    if spec is None:
        raise ClusterError(
            "There is no %r workload in the catalogue. Available: %s."
            % (str(workload), ", ".join(compute_catalogue.workload_names())))

    # The workload decides the device, not the form. An embedding image has no
    # GPU build, and accepting "gpu" for it would price the job at GPU rates and
    # then place it on a machine that runs the CPU image anyway.
    wanted = str(spec.get("device") or device or "cpu")
    device = str(device or wanted)
    if device != wanted:
        raise ClusterError(
            "The %s workload runs on %s, not %s." % (workload, wanted, device))

    lines = corpus_to_lines(corpus)
    if not lines:
        raise ClusterError(
            "Add a corpus: one item per line. Nothing has been charged.")

    try:
        pool = eligible_pool(device)
    except Exception:
        app.logger.exception("could not read the compute pool for a cluster")
        raise ClusterError(
            "The network could not be read just now, so this cannot be priced "
            "or placed. Nothing has been charged — try again in a moment.")

    if len(pool) < MIN_POOL:
        raise ClusterError(
            "A cluster needs at least %d independent machines: one to run each "
            "shard, and another to check it. %d %s offering %s work right now, "
            "and one machine with nobody to verify it is not a cluster — it is "
            "one anonymous node's word for your result. Nothing has been "
            "charged; try again when more of the network is awake."
            % (MIN_POOL, len(pool), "is" if len(pool) == 1 else "are", device))

    # Clamped, never refused. Somebody asking for 200 machines wants the widest
    # fan-out available, and the honest answer is "here is what the network can
    # actually give you" rather than an error about a number they guessed.
    requested = max(1, int(node_count or 1))
    count = min(requested, MAX_NODES, len(pool), len(lines))

    shards = shard(lines, count)
    input_file = spec.get("input_file") or "input.jsonl"
    largest = max(len(s) for s in shards)
    if largest > MAX_FILE_BYTES:
        raise ClusterError(
            "Split across %d machines, the biggest shard is %d KB and the queue "
            "carries at most %d KB per file. Ask for more machines, or send a "
            "shorter corpus. Nothing has been charged."
            % (count, largest // 1024, MAX_FILE_BYTES // 1024))

    if verify_rate is None:
        rate = compute_catalogue.default_verify_rate(workload)
    else:
        rate = float(verify_rate)
    rate = max(0.0, min(1.0, rate))

    price = quote_cluster(device, count, cores=cores, seconds=seconds,
                          priority_tier=priority_tier)

    cluster = ComputeCluster(
        slip_id=slip.id, name=(name or "untitled")[:120], workload=workload,
        device=device, node_count=count, cores=max(1, int(cores or 1)),
        seconds=max(1, int(seconds or DEFAULT_SECONDS)),
        # The boost the tier buys, resolved once in quote_cluster with the
        # price it was charged for. Looking it up twice is how the row and the
        # receipt end up describing different tiers.
        priority=int(price["priority_boost"]),
        status=STATUS_QUEUED, verify_rate=rate,
        credits_paid=int(price["credits"]), corpus_lines=len(lines),
    )
    db.session.add(cluster)
    db.session.flush()

    units = []
    try:
        for index, payload in enumerate(shards):
            unit = compute_rental.submit(
                slip,
                name="%s [%d/%d]" % ((name or "cluster")[:100], index + 1, count),
                files={input_file: payload},
                # A workload job has no entry point of the submitter's: the
                # image is the program. compute_rental._validate refuses one.
                entrypoint=None,
                workload=workload,
                device=device,
                cores=cores,
                seconds=seconds,
                priority_tier=priority_tier,
            )
            unit.cluster_id = cluster.id
            unit.shard_index = index
            units.append(unit)
        db.session.commit()
    except Exception as exc:
        # Half a cluster is worse than none: its units would be dispatched, run
        # and charged while the result could never be assembled. Everything
        # created so far is withdrawn and refunded, and the submitter is told
        # what happened.
        _abandon(cluster, units)
        if isinstance(exc, _SubmitError):
            raise ClusterError(
                "This cluster could not be created: %s Nothing has been "
                "charged." % exc)
        app.logger.exception("cluster %s could not be created", cluster.id)
        raise ClusterError(
            "This cluster could not be created and nothing has been charged.")

    return cluster


def _abandon(cluster, units):
    """Undo a half-created cluster. Best effort, and it must not raise."""
    from model.ComputeRental import STATUS_CANCELLED

    try:
        for unit in units:
            unit.status = STATUS_CANCELLED
            unit.credits_paid = 0
            unit.finished_at = datetime.datetime.utcnow()
        cluster.status = STATUS_CANCELLED
        cluster.credits_paid = 0
        cluster.finished_at = datetime.datetime.utcnow()
        db.session.commit()
    except Exception:
        app.logger.exception("could not withdraw a half-created cluster")
        try:
            db.session.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def wave_plan(pool, units, device, spare=SPARE_NODES):
    """Assign units to DISTINCT machines, keeping `spare` of them free.

    THE DRAW IS NOT MADE HERE
    -------------------------
    `compute_placement.place()` still chooses, exactly as it does for a lone
    rental, so a disputed placement is re-derivable by whoever questions it. All
    this does is hand each unit a candidate pool with the machines already
    spoken for removed, then re-derive — with the same function, the same unit
    id and the same candidate set — which machine that unit will land on, so the
    NEXT unit's pool can exclude it.

    Re-deriving rather than remembering is what makes the fan-out safe to run in
    parallel: the whole assignment is known before any thread starts, so two
    units cannot race into the same machine.
    """
    from services.compute_placement import place

    capacity = len(pool) - max(0, int(spare))
    if capacity < 1:
        # Fewer machines than the spare rule wants. One unit still goes out —
        # a wave of zero would stall the cluster forever — and it is the
        # verification that degrades, not the work.
        capacity = 1

    plan = []
    remaining = list(pool)
    for unit in list(units)[:capacity]:
        if not remaining:
            break
        candidates = list(remaining)
        try:
            node, _isolation = place(str(unit.id), device, False, candidates)
            node_id = str(node.get("id") or "")
        except Exception:
            # Placement refusing (or a candidate with no identity) is not a
            # reason to lose the whole wave. The unit is still offered the pool;
            # it is only the prediction — and therefore the guarantee of
            # distinctness for the units after it — that is lost.
            node_id = ""
        plan.append(Assignment(unit_id=unit.id,
                               shard_index=getattr(unit, "shard_index", None),
                               candidates=candidates, node_id=node_id))
        if node_id:
            remaining = [n for n in remaining
                         if str(n.get("id") or "") != node_id]
    return plan


def queued_units(cluster):
    """This cluster's units that have not been dispatched yet."""
    from model.ComputeRental import STATUS_QUEUED, units_for_cluster

    return [u for u in units_for_cluster(cluster.id) if u.status == STATUS_QUEUED]


def dispatch(cluster, flask_app=None, max_workers=None):
    """Fan this cluster's queued units out over the network. Returns the count.

    Runs in WAVES. One wave is as many units as there are machines to give them
    (less the spare), dispatched at the same time and waited on together; the
    next wave starts when the last one is finished. Asking for more machines
    than the network has is therefore slower rather than broken — the
    alternative, double-booking a node, ends in a retryable refusal for the
    second job, which is a wave with extra steps and a confusing error.

    Blocks for as long as the work takes. That is what the background drainer is
    for, and why nothing on a request path should call this.
    """
    flask_app = flask_app or app
    if cluster is None:
        return 0
    if cluster.status in TERMINAL:
        return 0

    pending = queued_units(cluster)
    if not pending:
        # Nothing to send. Still worth a roll-up: this is how a cluster whose
        # last unit finished during a restart reaches "done" instead of sitting
        # at "running" forever.
        roll_up(cluster)
        return 0

    try:
        pool = eligible_pool(cluster.device)
    except Exception:
        flask_app.logger.exception(
            "cluster %s: could not read the compute pool", cluster.id)
        return 0

    if not pool:
        # Left queued rather than failed. Nobody is online; that is a statement
        # about the network at this moment, not about the work.
        return 0

    if cluster.status == STATUS_QUEUED:
        cluster.status = STATUS_RUNNING
        cluster.started_at = cluster.started_at or datetime.datetime.utcnow()
        db.session.commit()

    rate = cluster.verify_rate
    rate = None if rate is None else float(rate)

    dispatched = 0
    while pending:
        plan = wave_plan(pool, pending, cluster.device)
        if not plan:
            break
        handed_out = _run_wave(flask_app, plan, rate, max_workers)

        # The units were run in other sessions, so this one is holding stale
        # copies. Expired rather than re-queried blindly: the identity map would
        # hand back the same "queued" rows it loaded before the wave, and the
        # loop would dispatch them again.
        db.session.expire_all()
        still = queued_units(cluster)

        # Counted as units that LEFT THE QUEUE, not units handed to the runner.
        # The two differ exactly when nothing is working, and that is the case
        # the count exists for: the drainer sleeps on a zero, so a cluster that
        # cannot be placed backs off instead of retrying a refusal as fast as
        # the network will answer.
        moved = len(pending) - len(still)
        if moved <= 0:
            flask_app.logger.info(
                "cluster %s: %d unit(s) went out and none left the queue; "
                "leaving %d for the next pass",
                cluster.id, handed_out, len(still))
            break
        dispatched += moved
        pending = still

    roll_up(cluster)
    return dispatched


def _run_wave(flask_app, plan, verify_rate, max_workers=None):
    """Run one wave concurrently. Returns how many units were handed out."""
    workers = max(1, min(int(max_workers or MAX_CONCURRENT_UNITS), len(plan)))
    ran = 0
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="cluster-unit") as pool:
        futures = [pool.submit(_run_one, flask_app, assignment, verify_rate)
                   for assignment in plan]
        for future in concurrent.futures.as_completed(futures):
            try:
                if future.result():
                    ran += 1
            except Exception:
                # _run_one already logs; this is the belt for a thread that
                # died before its own handler could.
                flask_app.logger.exception("a cluster unit worker failed")
    return ran


def _run_one(flask_app, assignment, verify_rate):
    """Run one unit, in its own app context and its own session.

    The session is the whole reason this is not a plain function call. A
    SQLAlchemy session is not safe to share between threads, and a worker that
    leaked one would hold a connection out of a pool sized for request handling
    until the process restarted.
    """
    from model.ComputeRental import ComputeRental

    with flask_app.app_context():
        try:
            from services import compute_rental

            runner = getattr(compute_rental, "run_unit", None)
            if runner is None:
                raise ClusterError(
                    "services.compute_rental.run_unit is missing, so cluster "
                    "units cannot be dispatched.")
            unit = (db.session.query(ComputeRental)
                    .filter(ComputeRental.id == assignment.unit_id)
                    .one_or_none())
            if unit is None:
                return False
            runner(unit, candidates=assignment.candidates,
                   verify_rate=verify_rate)
            return True
        except Exception:
            flask_app.logger.exception(
                "cluster unit %s could not be run", assignment.unit_id)
            try:
                db.session.rollback()
            except Exception:
                pass
            return False
        finally:
            try:
                db.session.remove()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Status, output, cancellation
# ---------------------------------------------------------------------------

def rollup_status(statuses):
    """One status for the whole cluster, from its units'.

    FAILED IS ONLY REPORTED ONCE EVERYTHING HAS STOPPED
    ---------------------------------------------------
    A cluster with one failed unit and six still running is still running: the
    person watching it has six machines working for them, and telling them the
    job failed would be wrong in the direction that makes them cancel it. The
    failed unit is visible per-unit in as_json() the moment it happens, and the
    cluster settles on `failed` when there is nothing left in flight.
    """
    statuses = list(statuses)
    if not statuses:
        return STATUS_QUEUED
    if all(s == STATUS_QUEUED for s in statuses):
        return STATUS_QUEUED
    if any(s in (STATUS_QUEUED, STATUS_RUNNING) for s in statuses):
        return STATUS_RUNNING
    if any(s == STATUS_FAILED for s in statuses):
        return STATUS_FAILED
    if all(s == STATUS_CANCELLED for s in statuses):
        return STATUS_CANCELLED
    return STATUS_DONE


def roll_up(cluster):
    """Recompute the cluster's status from its units and commit it."""
    from model.ComputeRental import units_for_cluster

    units = units_for_cluster(cluster.id)
    status = rollup_status([u.status for u in units])
    changed = False

    if cluster.status != status:
        cluster.status = status
        changed = True
    if status in TERMINAL and cluster.finished_at is None:
        cluster.finished_at = datetime.datetime.utcnow()
        changed = True
    if status == STATUS_RUNNING and cluster.started_at is None:
        cluster.started_at = datetime.datetime.utcnow()
        changed = True

    if changed:
        db.session.commit()
    return cluster


def combined_output(cluster):
    """Every unit's produced file, concatenated in corpus order.

    Shard order, not completion order. The units come back in whatever order N
    machines finish, and a result assembled in that order would be the right
    vectors against the wrong lines — which is exactly the failure the global
    ids in shard() exist to make impossible.

    A missing unit leaves a HOLE rather than shifting everything after it up:
    the remaining lines keep their ids, so a partial result is still usable and
    still checkable against the corpus.
    """
    from model.ComputeRental import units_for_cluster

    parts = []
    for unit in units_for_cluster(cluster.id):
        text = getattr(unit, "output_text", None) or ""
        if not text:
            continue
        parts.append(text if text.endswith("\n") else text + "\n")
    return "".join(parts)


def as_json(cluster, now=None):
    """What the cluster page and its poller read."""
    from model.ComputeRental import units_for_cluster

    units = units_for_cluster(cluster.id)
    statuses = [u.status for u in units]

    return {
        "id": cluster.id,
        "name": cluster.name,
        "workload": cluster.workload,
        "device": cluster.device,
        "status": cluster.status,
        # Asked for vs. actually created. Two different facts: if the network
        # could only offer six machines for a request of eight, the difference
        # is the entire explanation of what happened.
        "node_count": cluster.node_count,
        "units_created": len(units),
        "corpus_lines": cluster.corpus_lines,
        "verify_rate": cluster.verify_rate,
        "credits_paid": cluster.credits_paid,
        "created_at": _iso(cluster.created_at),
        "started_at": _iso(cluster.started_at),
        "finished_at": _iso(cluster.finished_at),
        "queued_units": sum(1 for s in statuses if s == STATUS_QUEUED),
        "running_units": sum(1 for s in statuses if s == STATUS_RUNNING),
        "done_units": sum(1 for s in statuses if s == STATUS_DONE),
        "failed_units": sum(1 for s in statuses if s == STATUS_FAILED),
        "verified_units": sum(1 for u in units
                              if (u.verdict or "") == "agreed"),
        "output_bytes": sum(len(getattr(u, "output_text", None) or "")
                            for u in units),
        "units": [_unit_json(u) for u in units],
    }


def _unit_json(unit):
    # The node id and the verdict are the two facts a cluster page exists to
    # show: WHICH machine ran this shard, and whether anybody checked it.
    # Without them a cluster looks like one job that took a while.
    stderr = unit.stderr or ""
    return {
        "id": unit.id,
        "shard_index": unit.shard_index,
        "node": unit.worker_node_id,
        "isolation": unit.isolation,
        "status": unit.status,
        "verdict": unit.verdict,
        "verified_by": unit.verified_by,
        "exit_code": unit.exit_code,
        "runtime_ms": unit.runtime_ms,
        # The last line of stdout, which for an embed unit is the
        # `embed-digest sha256:... count:...` line M5 compared. Shown because
        # it is the thing two nodes agreed ON, and a verdict with no visible
        # subject is a claim the reader has to take on trust.
        "digest_line": _last_line(unit.stdout),
        "output_bytes": len(getattr(unit, "output_text", None) or ""),
        "error": stderr[:500] if unit.status == STATUS_FAILED else "",
    }


def _last_line(text):
    lines = (text or "").strip().splitlines()
    return lines[-1][:200] if lines else ""


def _iso(value):
    return value.isoformat() if value else None


def cancel(cluster):
    """Withdraw a cluster's undispatched units and refund them.

    Mirrors compute_rental.cancel: only work that has not started is refunded,
    because a unit that ran cost a volunteer electricity whatever the submitter
    decided afterwards. A cluster that is half-run therefore refunds half, and
    says so by leaving the units that ran alone.
    """
    from model.ComputeRental import STATUS_CANCELLED, units_for_cluster
    from services import compute_rental

    if cluster.status in TERMINAL:
        raise ClusterError("This cluster has already finished.")

    units = units_for_cluster(cluster.id)
    refund = 0
    cancelled = 0
    for unit in units:
        if unit.status != STATUS_QUEUED:
            continue
        try:
            refund += int(compute_rental.cancel(unit) or 0)
            cancelled += 1
        except Exception:
            app.logger.exception("could not cancel cluster unit %s", unit.id)

    if not cancelled:
        raise ClusterError(
            "Every unit of this cluster has already started, so there is "
            "nothing left to withdraw.")

    cluster.credits_paid = max(int(cluster.credits_paid or 0) - refund, 0)
    statuses = [u.status for u in units]
    if all(s == STATUS_CANCELLED for s in statuses):
        cluster.status = STATUS_CANCELLED
        cluster.finished_at = datetime.datetime.utcnow()
        db.session.commit()
    else:
        db.session.commit()
        roll_up(cluster)
    return refund


# ---------------------------------------------------------------------------
# What the background drainer picks up
# ---------------------------------------------------------------------------

def pending_clusters(limit=10, now=None):
    """Clusters needing a pass, most deserving first.

    Ordered by the SAME rule as the rental queue — paid priority plus one step
    per few minutes waited — by handing the cluster row to
    compute_rental.effective_priority, which only reads `priority` and
    `created_at`. Reused rather than reimplemented: two orderings that were
    meant to be the same and drifted is how a queue quietly starts starving.

    "Needing a pass" is broader than "queued": a cluster left RUNNING by a
    restart, with units still queued or with every unit finished, needs one too
    — the first to be dispatched, the second to reach `done` instead of sitting
    at `running` forever.
    """
    from model.ComputeCluster import ComputeCluster
    from model.ComputeRental import STATUS_QUEUED as UNIT_QUEUED, units_for_cluster
    from services.compute_rental import effective_priority

    now = now or datetime.datetime.utcnow()
    rows = (db.session.query(ComputeCluster)
            .filter(ComputeCluster.status.in_((STATUS_QUEUED, STATUS_RUNNING)))
            .order_by(ComputeCluster.created_at.asc())
            .all())

    out = []
    for cluster in rows:
        units = units_for_cluster(cluster.id)
        if not units:
            continue
        statuses = [u.status for u in units]
        if any(s == UNIT_QUEUED for s in statuses):
            out.append(cluster)
        elif rollup_status(statuses) != cluster.status:
            out.append(cluster)

    out.sort(key=lambda c: (-effective_priority(c, now),
                            c.created_at or now, c.id))
    return out[:max(1, int(limit or 1))]


def next_pending_cluster(now=None):
    """The one cluster the drainer should work on next, or None."""
    found = pending_clusters(limit=1, now=now)
    return found[0] if found else None
