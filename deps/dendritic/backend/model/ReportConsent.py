"""Permission to publish something a person told us in confidence.

FILING IS NOT CONSENT TO PUBLISH
--------------------------------
Somebody who reports being assaulted by police is asking for help. They are not
offering their account to a newsroom, and they are certainly not offering their
name. Consent to be helped and consent to be named are different permissions,
and a system that treats the first as implying the second will eventually put
somebody's legal name in an article because a field was populated.

So publishing anything derived from a submission needs its own record, and this
is it: separate, explicit, revocable up to publication, and tied to the
reference code rather than to an account, because the person may not have one.

WHY IT IS NOT A CHECKBOX ON THE INTAKE FORM
-------------------------------------------
Because at intake there is nothing to consent TO. Nobody knows yet whether there
is a story, what it would say, or what would be attributed to them -- and a
blanket permission collected before any of that is known is the kind that gets
waved at afterwards rather than the kind somebody actually gave.

Consent is therefore ASKED FOR by a reviewer who can describe the specific
thing, and granted against that description. `scope` records what was described,
verbatim, so a later reader can see what the person was actually agreeing to
rather than inferring it from what was eventually published.

THE THREE LEVELS, AND WHY NOT TWO
---------------------------------
    NONE        no permission. The default, and what a withdrawal returns to.
    ANONYMOUS   the account may be used; the person may not be identified.
    NAMED       the person may be named.

The middle level is the one that matters. Most people who want something
published do not want their name on it, and a two-level permission forces them
to choose between silence and exposure -- so they pick silence, and the thing
that happened to them goes unreported.

WITHDRAWAL IS A NEW ROW, NOT AN EDIT
------------------------------------
The history has to survive. "They consented, then withdrew it" and "they never
consented" are different facts and only one of them means somebody made a
mistake; an edit-in-place turns the first into the second. The current position
is the newest row, and `current_for()` is the only thing that should decide it.
"""

import datetime as _datetime
import secrets

from shared import db


LEVEL_NONE = "NONE"
LEVEL_ANONYMOUS = "ANONYMOUS"
LEVEL_NAMED = "NAMED"

LEVELS = (LEVEL_NONE, LEVEL_ANONYMOUS, LEVEL_NAMED)

# Levels that permit publication at all.
PUBLISHABLE_LEVELS = (LEVEL_ANONYMOUS, LEVEL_NAMED)


def generate_request_token():
    """The token a complainant follows to answer. Unguessable.

    A bearer token: whoever holds it can answer on that submission's behalf. It
    is therefore as strong as the reference code and separate from it, so a
    reference code overheard once does not also carry the ability to grant
    permission to publish.
    """
    return secrets.token_urlsafe(24)


class ReportConsent(db.Model):
    __tablename__ = "report_consent"

    id = db.Column(db.Integer, primary_key=True)

    # By reference code, not by row id: the code is what the person holds, and
    # the index row can be rebuilt.
    report_id = db.Column(db.String(32), nullable=False, index=True)

    level = db.Column(db.String(16), nullable=False, default=LEVEL_NONE)

    # What they were told they would be agreeing to, verbatim. Written by the
    # reviewer who asked. Without it a granted consent is a yes to a question
    # nobody recorded.
    scope = db.Column(db.Text, nullable=False, default="")

    # The token the request was sent with. Retained so a second request cannot
    # be answered with an older link, and cleared once answered.
    request_token = db.Column(db.String(64), nullable=True, index=True)
    requested_by = db.Column(db.String(128), nullable=True)
    requested_at = db.Column(db.DateTime, nullable=True)

    # Who recorded the answer. "complainant" when they answered themselves
    # through their reference code; a reviewer identity when it arrived by some
    # other means and was entered by hand -- which is worth being able to tell
    # apart later.
    answered_by = db.Column(db.String(128), nullable=True)
    answered_at = db.Column(db.DateTime, nullable=True)

    # Free text from the person, if they left any.
    note = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)

    @property
    def permits_publication(self):
        return self.level in PUBLISHABLE_LEVELS

    @property
    def permits_naming(self):
        return self.level == LEVEL_NAMED


def current_for(report_id):
    """The newest consent row for a submission, or None.

    The ONLY thing that should decide the current position. Rows accumulate --
    a withdrawal is a new row rather than an edit, so the history survives --
    and reading any row but the newest gives an answer that was true once.
    """
    if not report_id:
        return None
    return (db.session.query(ReportConsent)
            .filter(ReportConsent.report_id == report_id)
            .order_by(ReportConsent.created_at.desc(), ReportConsent.id.desc())
            .first())


def may_publish(report_id):
    """(allowed, level). Absence of a record is a NO, never a maybe.

    The default has to be refusal. A submission with no consent row is the
    ordinary case -- almost every report will never be written about -- so a
    system that treated "no record" as "not yet decided" and let a draft through
    would fail open on the one gate that must not.
    """
    consent = current_for(report_id)
    if consent is None:
        return False, LEVEL_NONE
    return consent.permits_publication, consent.level
