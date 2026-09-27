"""Reviewer notes. A separate table so "keep them out of the submission" is
structural rather than a habit.

WHY NOT A COLUMN ON THE REPORT
------------------------------
Because the report row gets serialised, exported and -- in the DHT design --
partially mirrored, and every one of those paths would have to remember to strip
a notes column. A separate table cannot be leaked by forgetting.

WHY NOTES NEVER ENTER THE PAYLOAD
---------------------------------
The encrypted payload is the submitter's account of what happened. A reviewer's
working assessment of it ("caller seemed confused about dates", "second report
from this address") is a different document with a different audience, and
merging the two would mean the complainant's own record contains somebody's
opinion of them. It also means a payload re-encrypted after a note was added
would change its content hash, breaking the integrity check on the thing the
submitter actually sent.

So: notes live here, they are never written to the DHT, and they never travel
into a news story (see the report-to-story wall in the roadmap).
"""

import datetime as _datetime

from shared import db


class PublicInterestReportNote(db.Model):
    __tablename__ = "public_interest_report_note"

    id = db.Column(db.Integer, primary_key=True)

    # By report_id rather than the surrogate key, so a note survives the row
    # being rebuilt from the DHT and cannot be silently reattached to a
    # different report by an id collision after a restore.
    report_id = db.Column(db.String(32), nullable=False, index=True)

    # The reviewer identity, as authenticated. See the audit table for why this
    # is a string and not an FK.
    author = db.Column(db.String(128), nullable=False)

    body = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)
