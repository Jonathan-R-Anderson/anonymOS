"""Who did what to a story, when. Append-only.

Modelled on `model.PublicInterestReportAudit`, and the three properties that
matter are carried over unchanged:

1. **The row is written even when the action changed nothing.** A refused
   promotion, an approval clicked twice, a status set to the value it already
   held -- each is somebody reaching for the control. A trail that records only
   successful mutations cannot reconstruct what happened, which is the only
   thing it is for.
2. **The detail is stored verbatim as JSON**, not flattened into columns. The
   things an editorial action touches are true in different ways -- which fields
   a reviewer changed, what the requested changes said, which version was
   published, why a tier moved -- and collapsing that into a boolean turns the
   one fact worth keeping into "ok: true".
3. **There is no update or delete path.** Not enforced by the database (this
   deployment builds its schema with create_all() and would need a trigger) but
   by there being no code that writes one. An audit trail with an edit path is a
   record of what somebody was last willing to admit.

READS ARE RECORDED, NOT ONLY WRITES
-----------------------------------
`ACTION_VIEWED_UNPUBLISHED` exists for the same reason `ACTION_VIEWED` does on
the report trail. An unpublished story is the one that names a person who has
not been called yet, whose lawyer has not been called yet, and whose employer
would very much like to read it early. "Who opened this before it ran" is
exactly the question asked after a story leaks, and it can only be answered by a
system that was already writing it down.

WHY THE ACTOR IS A STRING AND NOT AN FK
---------------------------------------
Editorial access can be a wallet signature rather than a slip, so there is not
always a row to point at -- and an FK would let the identity be deleted out from
under the trail. The whole value of this table is that it still answers "who"
after the account is gone. For an automated pass this is the service name, so a
scheduled archival and a human one are never confused for each other.
"""

import datetime as _datetime
import json as _json

from shared import db


ACTION_CREATED = "created"
ACTION_SUBMITTED = "submitted"
ACTION_REVIEW_STARTED = "review_started"
ACTION_CHANGES_REQUESTED = "changes_requested"
ACTION_APPROVED = "approved"
ACTION_PUBLISHED = "published"
ACTION_CORRECTED = "corrected"
ACTION_RETRACTED = "retracted"
ACTION_ARCHIVED = "archived"
ACTION_TIER_CHANGED = "tier_changed"
ACTION_SUSPENDED = "suspended"
ACTION_PEN_NAME_APPROVED = "pen_name_approved"
ACTION_VIEWED_UNPUBLISHED = "viewed_unpublished"


class EditorialAction(db.Model):
    __tablename__ = "editorial_action"

    id = db.Column(db.Integer, primary_key=True)

    # Not an FK, and nullable: some of these actions are about a PERSON rather
    # than a story (a tier change, a suspension, a pen name approved), and a
    # trail that could only describe stories would simply not record them.
    story_id = db.Column(db.Integer, nullable=True, index=True)

    action = db.Column(db.String(48), nullable=False, index=True)

    # The editor, as a string rather than an FK. See the module docstring.
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


def record(story_id, action, actor, previous_status=None, new_status=None,
           detail=None, commit=False):
    """Append one editorial audit row.

    Deliberately does not commit by default: an audit row must land in the SAME
    transaction as the thing it describes, or a crash between the two produces
    either an action nobody recorded or a record of something that never
    happened. Callers that own the transaction pass commit=False (the default)
    and commit once.

    Called for attempts and refusals as well as for changes -- see point 1 in
    the module docstring.
    """
    # Assignment rather than the constructor, so the row builds identically
    # under SQLAlchemy's declarative base and under the plain-object stub the
    # tests use, and the trail can be asserted on without a live database.
    row = EditorialAction()
    row.story_id = story_id
    row.action = action
    row.actor = actor or "unknown"
    row.previous_status = previous_status
    row.new_status = new_status
    row.detail_json = _json.dumps(detail or {}, sort_keys=True, default=str)
    db.session.add(row)
    if commit:
        db.session.commit()
    return row
