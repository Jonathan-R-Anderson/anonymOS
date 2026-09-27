"""Acting on the retention schedule. The part that actually deletes.

`model.PublicInterestReport` decides WHEN a submission expires; this decides what
happens when it does. Separating them is not ceremony -- a policy nothing
enforces is a promise made to complainants on the confirmation page and quietly
broken, and an enforcer with the policy inlined cannot be tested without a
database.

WHAT "DELETED" HAS TO MEAN
--------------------------
The encrypted payload has to go, not just the row pointing at it. Removing the
index row alone would leave ciphertext on volunteer disks that nobody can find
and nobody will ever remove -- the worst of both outcomes, because the data
survives while the ability to act on it does not.

So the order is: delete the stored object, then clear the pointer, then record
what happened. If the object deletion fails, the row is KEPT and the sweep tries
again next pass. A row whose payload is still out there must not look expired.

WHAT SURVIVES DELETION, AND WHY
-------------------------------
The index row is not deleted -- it is emptied. `content_hash`, `dht_key` and
`stored_at` are cleared, `status` becomes ARCHIVED... no: it becomes EXPIRED-in-
effect by having no payload, and the row remains as a tombstone carrying the
reference code, the dates and the audit trail.

That is deliberate. A submitter who quotes their reference code after expiry
should be told "this was deleted on schedule", not "no such report" -- those are
different facts, and the second one reads as though they imagined filing it. The
tombstone holds no personal information: everything identifying was in the
payload that has just been destroyed.

WHY THE AUDIT ROW MATTERS MOST HERE
-----------------------------------
A record disappearing on schedule and a record somebody deleted look identical
afterwards unless one of them was written down. The expiry pass records itself
with the service name as the actor, so a scheduled deletion can never be mistaken
for a human one -- or the reverse, which is the direction that matters if anyone
ever asks why a report is gone.
"""

import datetime

from shared import app, db

from model.PublicInterestReport import PublicInterestReport
from model import PublicInterestReportAudit as audit
from services import report_dht


# A single pass is bounded so one sweep cannot hold a worker or the database for
# an unbounded time. Whatever is left is picked up on the next pass; retention is
# a schedule, not a deadline measured in seconds.
BATCH_SIZE = 200


def due(now=None, limit=BATCH_SIZE):
    """Submissions whose retention has run out.

    Pinned and story-source rows are excluded HERE as well as in the schedule
    that set `expires_at`. Belt and braces on purpose: `expires_at` is a stored
    value, so a row pinned after its expiry was computed would still carry an
    old date, and the pin has to win at the moment of deletion rather than at
    the moment of calculation.
    """
    now = now or datetime.datetime.utcnow()
    return (db.session.query(PublicInterestReport)
            .filter(PublicInterestReport.expires_at.isnot(None))
            .filter(PublicInterestReport.expires_at <= now)
            .filter(PublicInterestReport.pinned.is_(False))
            .filter(PublicInterestReport.story_source.is_(False))
            .order_by(PublicInterestReport.expires_at.asc())
            .limit(limit).all())


def expire_one(report, actor="retention-sweep", client=None):
    """Destroy one submission's payload and leave a tombstone.

    Returns True when the payload is gone. Returns False -- and changes
    nothing -- when the storage layer would not delete it, so the row stays
    expired-but-present and the next pass tries again.
    """
    versions_removed = []
    if report.dht_key or report.stored_at:
        try:
            versions_removed = report_dht.delete(report.report_id, client=client)
        except Exception:
            app.logger.exception("retention: could not delete stored object for %s",
                                 report.report_id)
            return False

        if not versions_removed:
            # Nothing was removed. Either it was already gone or the gateway
            # refused every key; the two are indistinguishable from here, and
            # guessing "already gone" would clear the pointer to data that may
            # still exist. Leave it and retry.
            app.logger.warning(
                "retention: %s expired but no stored object was removed; "
                "leaving the row for the next pass", report.report_id)
            return False

    previous_status = report.status
    report.content_hash = None
    report.dht_key = None
    report.stored_at = None
    report.expires_at = None
    report.updated_at = datetime.datetime.utcnow()

    audit.record(report.report_id, audit.ACTION_EXPIRED, actor,
                 previous_status=previous_status,
                 new_status=previous_status,
                 detail={"versions_removed": versions_removed,
                         "scheduled": True})
    return True


def sweep(now=None, limit=BATCH_SIZE, actor="retention-sweep", client=None):
    """One pass. Returns a summary dict; never raises into the caller."""
    rows = due(now=now, limit=limit)
    expired, deferred = 0, 0

    for report in rows:
        try:
            if expire_one(report, actor=actor, client=client):
                expired += 1
            else:
                deferred += 1
        except Exception:
            app.logger.exception("retention: expiring %s failed", report.report_id)
            deferred += 1

    if expired or deferred:
        db.session.commit()

    return {"due": len(rows), "expired": expired, "deferred": deferred}
