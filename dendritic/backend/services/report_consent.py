"""Asking for permission to publish, and refusing to publish without it.

The model holds the record; this holds the transitions and the gate. Kept apart
so the gate can be tested without a database and so there is exactly one
function a publish path has to call.

WHAT THE GATE ACTUALLY GUARDS
-----------------------------
A story that CITES a submission. Not every story -- most of the newsroom will
never touch a report -- and the link is recorded on the story rather than
inferred, because inferring it means guessing, and guessing wrong in the
permissive direction publishes somebody's account without their permission.

`NewsStory.source_report_id` is that link. It is internal: it appears on no
public surface, and `services/bylines.py` never sees it. A reader learns nothing
about which stories came from the intake queue, which matters because that set
is small enough that knowing a story came from a report narrows who filed it.

WHY THE WALL STILL STANDS
-------------------------
This does not create a path from a report to a draft. There is still no button
that turns a submission into a story, no pre-filled fields, and no copy of a
payload into story tables -- a reviewer opens a blank draft and writes. All this
adds is a record of permission and a refusal to publish without one. The
friction the wall exists for is untouched.
"""

import datetime

from shared import app, db

from model.ReportConsent import (
    LEVEL_NAMED, LEVEL_NONE, LEVELS, PUBLISHABLE_LEVELS, ReportConsent,
    current_for, generate_request_token,
)
from model import PublicInterestReportAudit as audit


class ConsentError(Exception):
    """Refused. The message is safe to show a reviewer."""


def _now():
    return datetime.datetime.utcnow()


def request_consent(report_id, scope, actor):
    """Record that permission was asked for, and mint the link to answer with.

    Returns the new row. The token is on it; delivering the link is NOT this
    function's job and deliberately never will be -- see the note in
    `blueprints/report_review.request_more_info` for the same reasoning. A
    reviewer contacts the person by whatever means that person said was safe,
    and a button here that appeared to send an email would leave a reviewer
    believing somebody had been contacted.
    """
    scope = (scope or "").strip()
    if not scope:
        raise ConsentError(
            "Describe what you would publish before asking for permission. A "
            "yes to an unrecorded question is not consent.")

    row = ReportConsent()
    row.report_id = report_id
    row.level = LEVEL_NONE
    row.scope = scope[:20000]
    row.request_token = generate_request_token()
    row.requested_by = actor
    row.requested_at = _now()
    row.created_at = _now()
    db.session.add(row)

    audit.record(report_id, "consent_requested", actor,
                 detail={"scope_length": len(scope)})
    db.session.commit()
    return row


def answer(report_id, level, answered_by, note=None, token=None):
    """Record an answer. A withdrawal is an answer of NONE.

    Appends rather than edits: "consented, then withdrew" and "never consented"
    are different facts, and only one of them means somebody made a mistake.
    """
    if level not in LEVELS:
        raise ConsentError("That is not a permission level this system uses.")

    pending = current_for(report_id)

    # A token, when supplied, must match the OUTSTANDING request. Answering with
    # a link from a superseded request would let an older, broader scope be
    # accepted after a reviewer had narrowed it.
    if token is not None:
        if pending is None or not pending.request_token:
            raise ConsentError("That link is no longer valid.")
        import hmac
        if not hmac.compare_digest(str(token), str(pending.request_token)):
            raise ConsentError("That link is no longer valid.")

    row = ReportConsent()
    row.report_id = report_id
    row.level = level
    # Carried forward so the record says what THIS answer was given against.
    row.scope = (pending.scope if pending is not None else "")
    row.request_token = None
    row.answered_by = answered_by
    row.answered_at = _now()
    row.note = (note or "").strip()[:5000] or None
    row.created_at = _now()
    db.session.add(row)

    audit.record(report_id, "consent_answered", answered_by,
                 detail={"level": level, "by_token": token is not None})
    db.session.commit()
    return row


def by_token(token):
    """The submission an answer-link belongs to, or None.

    Constant-time compared and bounded: the token is a bearer credential, so a
    lookup that leaked its validity through timing would let it be guessed a
    character at a time.
    """
    if not token:
        return None
    row = (db.session.query(ReportConsent)
           .filter(ReportConsent.request_token == token)
           .order_by(ReportConsent.created_at.desc())
           .first())
    return row


def check_story(story):
    """(allowed, reason). The gate a publish path calls. Never raises.

    A story with no `source_report_id` is allowed: most of the newsroom has
    nothing to do with the intake queue, and requiring consent from a submission
    that does not exist would make the gate meaningless by making it universal.

    A story that DOES cite one is refused unless the newest consent row permits
    publication. Absence of a record is a refusal -- see model.may_publish for
    why that default is not negotiable.
    """
    report_id = getattr(story, "source_report_id", None)
    if not report_id:
        return True, None

    consent = current_for(report_id)
    if consent is None:
        return False, (
            "This story cites submission %s and there is no record that the "
            "person who sent it agreed to anything being published. Ask them "
            "first." % report_id)
    if consent.level not in PUBLISHABLE_LEVELS:
        return False, (
            "The person who sent submission %s has not given permission to "
            "publish, or has withdrawn it." % report_id)
    return True, None


def naming_allowed(story):
    """Whether the complainant may be NAMED in this story.

    Separate from `check_story` because they are different questions and the
    common answer differs: most people who agree to publication do not agree to
    being named, and a gate that ran them together would force that choice into
    a single yes or no.

    Advisory rather than enforced -- nothing can inspect prose and decide
    whether it identifies somebody. The editor console shows it beside the
    story so the decision is in front of whoever approves it.
    """
    report_id = getattr(story, "source_report_id", None)
    if not report_id:
        return None
    consent = current_for(report_id)
    return bool(consent and consent.level == LEVEL_NAMED)
