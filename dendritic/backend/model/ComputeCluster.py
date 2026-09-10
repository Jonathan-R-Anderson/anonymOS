"""An AI compute cluster: N volunteer machines running one catalogue workload.

WHAT A CLUSTER IS, IN ONE SENTENCE
-----------------------------------
A parent row here, plus N ComputeRental UNIT rows carrying (cluster_id,
shard_index, workload, one shard of the corpus as an input file).

WHY THE UNITS ARE RENTALS AND NOT A SECOND JOB TABLE
-----------------------------------------------------
Because everything that has to happen to a unit already happens to a rental.
compute_placement.place() picks a node for it, compute_bridge ships it,
compute_verify.compare() checks it, compute_earnings.credit_provider() pays for
it. A parallel `compute_cluster_unit` table would need all four taught a second
row shape, and the day one of them was taught and another was not, units would
run and never pay — or pay and never verify.

So the only thing this table holds is what is true of the CLUSTER and not of
any one unit: what was asked for, how far along the whole thing is, and what it
cost in total. Anything per-machine belongs on the unit, where the machinery
that already exists can see it.

WHY VERIFICATION DEFAULTS HIGHER HERE
--------------------------------------
An ordinary rental samples verification at 0.25 because replication is another
node's electricity and the point is to make lying unprofitable, not impossible.
A slice-1 workload is different: embeddings are bit-exact, the digest is a
32-byte line of stdout, and the second run is the same cheap work. Verifying
all of it costs little and means the user's vectors are not one anonymous
machine's word. `verify_rate` is per cluster rather than a constant because
slices 2-5 will not be bit-exact and will have to sample.
"""

import datetime as _datetime

from shared import db

# Mirrors model/ComputeRental's states, and the values are the same STRINGS on
# purpose: a page rendering a cluster and its units side by side compares them,
# and two vocabularies that mean the same thing would need a translation table
# nobody would remember to update.
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

TERMINAL = (STATUS_DONE, STATUS_FAILED, STATUS_CANCELLED)

# The verification rate a cluster gets unless it asks for another. 1.0, not the
# rental default of 0.25 — see the module docstring.
DEFAULT_VERIFY_RATE = 1.0


class ComputeCluster(db.Model):
    """One request for N machines, and where the whole request has got to."""

    __tablename__ = "compute_cluster"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)

    name = db.Column(db.String(120), nullable=False, default="")

    # Which catalogue workload every unit runs. Not a language: a cluster runs
    # signed images over the submitter's data, never the submitter's code. See
    # the comment on ComputeRental.workload for why the two are separate.
    workload = db.Column(db.String(32), nullable=False, default="embed")

    # "cpu" or "gpu", copied onto every unit. One device per cluster rather
    # than per unit: a run split across both would produce results verified two
    # different ways (GPU results are unverified by construction), and a single
    # output file assembled from shards with different verification strength is
    # a claim nobody can state accurately afterwards.
    device = db.Column(db.String(8), nullable=False, default="cpu")

    # HOW MANY MACHINES WERE ASKED FOR. Kept even after the units exist, and
    # not derived by counting them, because those are different facts: if the
    # network could only place 6 of 8, the difference between "asked for 8" and
    # "6 units exist" is the entire explanation of what happened.
    node_count = db.Column(db.Integer, nullable=False, default=1, server_default="1")

    # Per-unit ceilings, same meaning as on a rental: a wall-clock kill time and
    # a core count the market prices against.
    seconds = db.Column(db.Integer, nullable=False, default=120, server_default="120")
    cores = db.Column(db.Integer, nullable=False, default=1, server_default="1")
    priority = db.Column(db.Integer, nullable=False, default=0)

    # Indexed because the cluster drainer scans it on every pass. device and
    # priority above are not: this table gets one row per cluster, so an index
    # on a two-value column would be read past rather than used.
    status = db.Column(db.String(16), nullable=False, default=STATUS_QUEUED,
                       server_default=STATUS_QUEUED, index=True)

    # What fraction of units get run twice on independent nodes. Per cluster
    # because bit-exact workloads can afford 1.0 and tolerance-checked ones
    # cannot; a constant would force one answer on both.
    verify_rate = db.Column(db.Float, nullable=False, default=DEFAULT_VERIFY_RATE,
                            server_default="1.0")

    # Total charged for the whole cluster, in AXONCoins. Stored on the parent
    # rather than summed from the units at read time: the user was quoted and
    # charged ONE number for N machines, and a total recomputed later from rows
    # that may have been retried would stop matching the receipt.
    credits_paid = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    # How many lines of corpus were split across the units. The size of the job
    # in the only unit the user supplied it in; bytes would not let anyone check
    # that the reassembled output has one vector per input line.
    corpus_lines = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    @property
    def finished(self):
        return self.status in TERMINAL


def clusters_for_slip(slip_id, limit=50):
    """A user's clusters, newest first."""
    return (
        db.session.query(ComputeCluster)
        .filter(ComputeCluster.slip_id == slip_id)
        .order_by(ComputeCluster.created_at.desc())
        .limit(limit)
        .all()
    )
