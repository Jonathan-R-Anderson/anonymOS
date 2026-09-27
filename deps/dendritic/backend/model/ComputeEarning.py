"""What a node earned for running one job.

Append-only. There is no edit path and no soft delete: an earning that could be
altered afterwards is not a record of anything, and a provider who saw a number
and then saw a different one would be right to stop trusting the ledger.
Corrections, if ever needed, are a second row in the other direction.
"""

import datetime

from shared import db


class ComputeEarning(db.Model):
    __tablename__ = "compute_earning"

    id = db.Column(db.Integer, primary_key=True)
    rental_id = db.Column(db.Integer, db.ForeignKey("compute_rental.id"),
                          nullable=False, index=True)
    # The node, not the operator. What matters for a dispute is which machine
    # produced the result; operator labels are self-declared.
    node_id = db.Column(db.String(80), nullable=False, index=True)
    amount = db.Column(db.BigInteger, nullable=False)
    device = db.Column(db.String(8), nullable=False, default="cpu")
    # Recorded because a failed job earns a different rate, and a ledger that
    # showed only the amount could not explain why two similar jobs paid
    # differently.
    succeeded = db.Column(db.Boolean, nullable=False, default=True,
                          server_default="true")
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.datetime.utcnow, index=True)

    __table_args__ = (
        # One earning per (job, node). The database enforces the idempotency the
        # service also checks, because a retried completion callback is an
        # ordinary event and paying twice for it is not recoverable.
        db.UniqueConstraint("rental_id", "node_id", name="uq_earning_job_node"),
    )
