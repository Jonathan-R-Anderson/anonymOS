"""Who did what to a submission, when. Append-only.

Modelled on `model.DhtPurgeAudit`, whose docstring makes the case: nothing else
in this codebase records an admin ACTION, and the question worth answering later
is "who did this, and what did they see before they clicked".

THREE THINGS CARRIED OVER FROM THAT TABLE
-----------------------------------------
1. **The row is written even when nothing changed.** An attempted action, a
   refused one, and a status set to the value it already had are all somebody
   reaching for the control. A log that records only successful mutations cannot
   be used to reconstruct what happened.
2. **The detail is stored verbatim as JSON**, not collapsed into columns. An
   action touches things that are true in different ways -- what the retention
   clock became, whether the DHT object was actually deleted, which fields a
   reviewer saw -- and flattening that into a boolean turns the one fact worth
   keeping into "ok: true".
3. **There is no update or delete path.** Not enforced by the database (this
   deployment builds its schema with create_all() and would need a trigger), but
   by there being no code that writes one. An audit trail with an edit path is a
   record of what somebody was last willing to admit.

READS ARE RECORDED, NOT ONLY WRITES
-----------------------------------
Unusual, and deliberate. For most admin surfaces the sensitive act is the change.
Here the sensitive act is *looking*: these payloads hold a complainant's name,
address and account of being harmed, and "who read this report" is exactly the
question that matters after a leak. So ACTION_VIEWED exists and the decrypt path
writes one.
"""

import datetime as _datetime
import json as _json

from shared import db


ACTION_SUBMITTED = "submitted"
ACTION_STORE_FAILED = "store_failed"
ACTION_VIEWED = "viewed"
ACTION_STATUS_CHANGED = "status_changed"
ACTION_NOTE_ADDED = "note_added"
ACTION_INFO_REQUESTED = "info_requested"
ACTION_PINNED = "pinned"
ACTION_UNPINNED = "unpinned"
ACTION_EXPIRED = "expired"
ACTION_DELETED = "deleted"


class PublicInterestReportAudit(db.Model):
    __tablename__ = "public_interest_report_audit"

    id = db.Column(db.Integer, primary_key=True)

    report_id = db.Column(db.String(32), nullable=False, index=True)

    action = db.Column(db.String(48), nullable=False, index=True)

    # The authenticated reviewer, as a string rather than an FK to a slip.
    #
    # Two reasons. Admin access here is a wallet signature, not necessarily a
    # slip, so there is not always a row to point at. And an FK would let the
    # identity be deleted out from under the audit trail -- the whole value of
    # this table is that it still answers "who" after the account is gone.
    #
    # For an automated expiry pass this is the service name, so a scheduled
    # deletion and a human one are never confused for each other.
    actor = db.Column(db.String(128), nullable=False)

    previous_status = db.Column(db.String(32), nullable=True)
    new_status = db.Column(db.String(32), nullable=True)

    # Verbatim JSON. See point 2 in the module docstring.
    detail_json = db.Column(db.Text, nullable=False, default="{}")

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)

    @property
    def detail(self):
        try:
            return _json.loads(self.detail_json or "{}")
        except (ValueError, TypeError):
            # A trail that cannot be parsed must still be readable as SOMETHING.
            # Returning the raw string beats raising inside an audit view and
            # making the whole page fail because one old row is malformed.
            return {"unparsed": self.detail_json}


def record(report_id, action, actor, previous_status=None, new_status=None,
           detail=None, commit=False):
    """Append one audit row.

    Deliberately does not commit by default: an audit row must land in the SAME
    transaction as the thing it describes, or a crash between the two produces
    either an action nobody recorded or a record of something that never
    happened. Callers that own the transaction pass commit=False (the default)
    and commit once.
    """
    # Assignment rather than the constructor, for the same reason as the report
    # row itself: it works identically under SQLAlchemy's declarative base and
    # under the plain-object stub the tests use, so the audit trail can be
    # asserted on without a live database.
    row = PublicInterestReportAudit()
    row.report_id = report_id
    row.action = action
    row.actor = actor or "unknown"
    row.previous_status = previous_status
    row.new_status = new_status
    row.detail_json = _json.dumps(detail or {}, sort_keys=True, default=str)
    db.session.add(row)
    if commit:
        db.session.commit()
    return row
