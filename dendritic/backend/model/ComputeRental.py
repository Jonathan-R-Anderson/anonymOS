"""Rented compute: a user's own program, queued and run on OUR machines.

WHERE THIS RUNS, AND WHY THAT IS THE WHOLE DESIGN
--------------------------------------------------
On operator infrastructure — the sandboxed `code-runner` pod — and never on a
volunteer's machine.

That is not an implementation detail, it is the security model. roadmap/
gpgpu-roadmap.md forbids arbitrary submitted code on volunteer hardware in as
many words: a submitter picks a runtime image from a signed catalogue and
supplies DATA, because nearly every sandbox escape starts from attacker-chosen
code. This feature is the exact opposite — somebody's own program, which is the
point of renting compute.

Both can be true because they are different machines. A volunteer lends a
machine on the promise that only catalogue software runs on it; the operator
runs a pod they own, on hardware they own, and eats the consequences of a
break-out themselves. Nobody's desktop is on the other side of it.

So if this is ever pointed at the volunteer pool, it stops being this feature
and becomes the catalogue one. Worth writing down here rather than discovering
it in a config change.

PRIORITY THAT DOES NOT BECOME A CLOSED SHOP
--------------------------------------------
Paid priority has an obvious failure: whoever pays most is always at the front,
so an unpaid job at the back never runs at all while anybody is paying. A queue
that can starve is not a queue, it is an auction with a waiting room attached.

So the ordering key is `priority + age`, not `priority` (see
services/compute_rental.effective_priority). Paying moves you forward now;
waiting moves you forward eventually. A free job's position is bounded rather
than hopeful, and that bound is a number this file can state.
"""

import datetime as _datetime

from shared import db

# Queue states. A job is only ever in one of these, and the transitions are
# one-way apart from queued -> running -> queued on a retry.
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

TERMINAL = (STATUS_DONE, STATUS_FAILED, STATUS_CANCELLED)

# What a boost costs, in AXONCoins, and what it is worth in queue positions.
#
# Deliberately coarse and cheap. The point is to let somebody who is blocked
# jump a queue, not to build a market where the price of going first rises with
# demand — that is the mechanism that turns a shared resource into one only the
# well-funded can use.
PRIORITY_TIERS = (
    (0, 0, "Normal"),
    (5, 10, "Priority"),
    (20, 25, "Express"),
)

MAX_FILES = 40
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024

# How much of a retrieved output file we are willing to keep on the row.
# Advisory: the service that fetches /work/output.jsonl does the truncating.
# Stated here because the column it lands in is declared here, and a limit that
# lives only in the caller is a limit that the next caller will not know about.
MAX_OUTPUT_TEXT_BYTES = 512 * 1024


def _entrypoint_default(context):
    """The old default for a language job, and nothing for a workload unit.

    A catalogue workload ships its own entry point inside the signed image; the
    submitter sends DATA, so there is no file of theirs to run. A flat
    "main.py" default would write a filename that does not exist into every
    cluster unit, and the first person to read one would reasonably conclude
    the unit was misconfigured.

    Conditional rather than removed, because dropping the default outright
    would change what a language job with no explicit entry point does — and
    that is the path everything before M10 takes. The fallback below is
    "main.py" for the same reason: if the parameters cannot be read, the safe
    guess is the behaviour that already exists.
    """
    try:
        params = context.get_current_parameters()
    except Exception:
        return "main.py"
    return None if params.get("workload") else "main.py"


class ComputeRental(db.Model):
    """One submitted program, and where it has got to.

    Also one UNIT of a cluster (see model/ComputeCluster.py). A cluster is N of
    these rows plus a parent row, deliberately rather than a second job table:
    a unit that is an ordinary rental inherits placement, the node bridge,
    verification and provider payment without any of them learning a new shape.
    """

    __tablename__ = "compute_rental"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)

    name = db.Column(db.String(120), nullable=False, default="")
    language = db.Column(db.String(16), nullable=False, default="python")

    # WHICH CATALOGUE WORKLOAD THIS IS, or null for a language job as today.
    #
    # Separate from `language` on purpose, and it is worth saying why because
    # one column would obviously be shorter. "embed" is not a language. The two
    # answer different questions: `language` says which interpreter the
    # submitter's OWN code needs, `workload` says which signed catalogue image
    # runs over the submitter's DATA — and in the second case there is no code
    # of theirs at all.
    #
    # Collapsing them would make the UI lie about what it offers. The language
    # picker would grow an "embed" entry that is not a language and cannot run
    # a main.py, and the workload picker would inherit python/c/go entries that
    # are not workloads and have no corpus to read. Whichever way round, the
    # form would be offering a combination the runner cannot honour.
    workload = db.Column(db.String(32), nullable=True, index=True)

    # Which file to run. Stored rather than guessed: a program with several
    # files has no obvious entry point, and guessing "main.py" wrongly wastes a
    # queue slot to produce a confusing error.
    #
    # Nullable since M10: a data-only workload has no entry point of the
    # submitter's to name. Language jobs still default to "main.py" — see
    # _entrypoint_default above for why that default has to be conditional.
    entrypoint = db.Column(db.String(255), nullable=True, default=_entrypoint_default)
    stdin_text = db.Column(db.Text, nullable=False, default="")

    # Which cluster this unit belongs to, and which shard of the corpus it was
    # handed. Null for a job somebody submitted on its own, which is every job
    # that existed before M10.
    #
    # CASCADE because a unit outliving its cluster is not a job, it is a row
    # whose inputs and meaning have both been deleted.
    cluster_id = db.Column(db.Integer,
                           db.ForeignKey("compute_cluster.id", ondelete="CASCADE"),
                           nullable=True, index=True)
    # The shard's position, so results can be reassembled in the order the
    # corpus was split. Without it the concatenated output is in whatever order
    # N nodes happened to finish, which is not the order the user sent.
    shard_index = db.Column(db.Integer, nullable=True)

    # "cpu" or "gpu". GPU is accepted and queued separately even before there is
    # GPU capacity, because a queue that refuses the request outright tells the
    # operator nothing about demand.
    device = db.Column(db.String(8), nullable=False, default="cpu", index=True)

    # How this job must be isolated, and whether the submitter sent CODE or only
    # data for a signed catalogue image.
    #
    # These are two questions, not one. "Arbitrary" is what decides whether a
    # container is an acceptable boundary — the gpgpu roadmap forbids arbitrary
    # payloads on volunteer hardware precisely because a container is not one.
    # A microVM is, which is the single place that rule may be relaxed, so the
    # requirement travels with the job rather than being inferred at dispatch.
    #
    # A job marked arbitrary may ONLY be placed on a node reporting microVM
    # isolation. A node that quietly ran it in a container would look identical
    # to a working node until somebody submitted something hostile.
    arbitrary = db.Column(db.Boolean, nullable=False, default=False,
                          server_default="false", index=True)

    # What was ASKED FOR. The market prices against these, and demand() sums
    # them — without a real figure it counted one core per job regardless, so a
    # request for 32 cores and one for 1 moved the price identically.
    cores = db.Column(db.Integer, nullable=False, default=1, server_default="1")
    # Requested wall-clock ceiling. A ceiling rather than an estimate: a job is
    # killed at it, so pricing against anything softer would charge for time the
    # network never agreed to provide.
    seconds = db.Column(db.Integer, nullable=False, default=60, server_default="60")

    # Where it ran, recorded once placed. Null while queued.
    #
    # The node id rather than an operator name: what matters for a dispute is
    # which machine produced the result, and operator labels are self-declared.
    worker_node_id = db.Column(db.String(80), nullable=True, index=True)

    # "container" or "microvm", recorded so a result carries the boundary it ran
    # behind. Without it, a result from a hardened container and one from a VM
    # are indistinguishable afterwards — and they are not the same claim.
    isolation = db.Column(db.String(16), nullable=True)

    # Whether the network CHECKED this result, and who agreed.
    #
    # Recorded rather than inferred, because "agreed", "unverified" and
    # "insufficient" are three different claims and a missing value would read
    # as the weakest of them. A GPU result is unverified by construction; a CPU
    # result with no second node available is insufficient, which is a statement
    # about the network rather than about the work.
    verdict = db.Column(db.String(16), nullable=True, index=True)
    verified_by = db.Column(db.String(200), nullable=True)

    status = db.Column(db.String(16), nullable=False, default=STATUS_QUEUED, index=True)
    priority = db.Column(db.Integer, nullable=False, default=0, index=True)
    credits_paid = db.Column(db.Integer, nullable=False, default=0)

    stdout = db.Column(db.Text, nullable=False, default="")
    stderr = db.Column(db.Text, nullable=False, default="")
    exit_code = db.Column(db.Integer, nullable=True)
    runtime_ms = db.Column(db.Integer, nullable=True)

    # The file the workload PRODUCED, retrieved from /work/output.jsonl.
    #
    # Separate from stdout because they are verified differently and must not
    # be confused: stdout is what compute_verify hashes (the embed image prints
    # `embed-digest sha256:<hex> count:<n>` there precisely so the vectors can
    # be checked without shipping them twice), while this is the payload the
    # user came for. Truncated by the retrieving service to
    # MAX_OUTPUT_TEXT_BYTES; a job that returns a gigabyte should degrade to a
    # partial result rather than to an unreadable row.
    output_text = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    files = db.relationship("ComputeRentalFile", backref="rental",
                            cascade="all, delete-orphan", lazy="select")

    @property
    def finished(self):
        return self.status in TERMINAL

    @property
    def editable(self):
        """Files may be corrected while the job is still waiting.

        Not while it is running: the runner has already been handed a copy, so
        an edit would silently not be what ran, and the output would belong to
        code the user can no longer see.
        """
        return self.status == STATUS_QUEUED


class ComputeRentalFile(db.Model):
    """One file of a submitted program.

    Stored in rows rather than as a blob so the inline editor can save a single
    file without rewriting the rest, and so a diff of what changed between
    attempts is possible later.
    """

    __tablename__ = "compute_rental_file"
    __table_args__ = (
        db.UniqueConstraint("rental_id", "path", name="uq_rental_file_path"),
    )

    id = db.Column(db.Integer, primary_key=True)
    rental_id = db.Column(db.Integer, db.ForeignKey("compute_rental.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    path = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False, default="")
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow,
                           onupdate=_datetime.datetime.utcnow)


def queued_jobs(device=None):
    """Everything still waiting, oldest first within a priority.

    Everything, INCLUDING cluster units. Deliberately: this is the honest
    answer to "what is queued", and a wait estimate that silently ignored half
    the queue would be wrong in the reassuring direction. The serial per-device
    drainer must not pick units up, but that is a scheduling decision and it
    lives with the scheduler — see services/compute_rental.ordered_queue.
    """
    query = db.session.query(ComputeRental).filter(
        ComputeRental.status == STATUS_QUEUED)
    if device:
        query = query.filter(ComputeRental.device == device)
    return query.order_by(ComputeRental.created_at.asc()).all()


def units_for_cluster(cluster_id):
    """A cluster's units, in corpus order.

    Ordered by shard_index rather than by id or completion time: reassembling
    the output means putting shard 0 first, and "whichever node answered first"
    is not that. id order happens to agree today because units are created in
    one loop, but that is an accident of the writer, not a guarantee the reader
    should depend on.
    """
    return (
        db.session.query(ComputeRental)
        .filter(ComputeRental.cluster_id == cluster_id)
        .order_by(ComputeRental.shard_index.asc(), ComputeRental.id.asc())
        .all()
    )


def jobs_for_slip(slip_id, limit=50):
    return (
        db.session.query(ComputeRental)
        .filter(ComputeRental.slip_id == slip_id)
        .order_by(ComputeRental.created_at.desc())
        .limit(limit)
        .all()
    )


def recent_durations(device="cpu", limit=40):
    """How long finished jobs actually took, for the wait estimate.

    Measured rather than assumed. A fixed per-job estimate is wrong within a day
    of anybody using the service, and wrong in the direction that matters: it
    tells people a queue is short when it is not.
    """
    rows = (
        db.session.query(ComputeRental.runtime_ms)
        .filter(ComputeRental.device == device,
                ComputeRental.status == STATUS_DONE,
                ComputeRental.runtime_ms.isnot(None))
        .order_by(ComputeRental.finished_at.desc())
        .limit(limit)
        .all()
    )
    return [r[0] for r in rows if r[0]]
