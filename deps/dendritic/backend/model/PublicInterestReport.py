"""The queryable half of a public-interest submission. Deliberately no PII.

A submission is stored in two places, and the split is the whole privacy design:

    encrypted payload  -> the DHT, unreadable by the nodes holding it
    this row           -> the site's database, so reviewers can find it

Everything a person typed about themselves -- name, email, phone, street, the
description, the city -- lives ONLY in the payload. This row carries what a queue
needs to sort and filter, and nothing that identifies anybody.

WHY THAT SPLIT AND NOT "PUT IT ALL IN THE DHT"
----------------------------------------------
The DHT is content-addressed put/get. It has no query, no index and no filter, so
"show me new reports in Ohio" cannot be answered by it at any price. A reviewer
interface needs an index, and an index is a database. Keeping the index free of
PII is what makes it safe to have one.

WHY THE INDEX IS THE PART THAT LEAKS
------------------------------------
The payload is encrypted and the index is not, so every column added here is a
column somebody can read with database access. That is why `city` is absent while
`state` is present: "excessive force, 2026-03-04, Barstow" identifies a person to
anyone who was there, and the filter a reviewer actually needs is jurisdictional.
A test asserts the absence of PII columns so that a later, well-meant addition
trips something instead of quietly widening this.

ONE TABLE, SEVERAL KINDS
------------------------
A civil-rights report and a newsroom tip are the same lifecycle -- arrive,
triage, act, retain, expire -- over different payload schemas, so they are one
table keyed by `kind` rather than two stacks. `model.Report` already uses this
pattern for post reports and board messages. The kinds differ in what the FORM
requires, not in what happens afterwards: a civil-rights report asks for contact
details because somebody wants their case worked; a tip must be submittable with
nothing at all.

The name is `PublicInterestReport` and not `Report` because `model.Report` is
taken -- it is user reports OF POSTS, surfaced to board moderators. Reusing it
would drop civil-rights submissions into the moderator queue and the report bell.
`Tip` is likewise taken, by AXONCoin tipping.
"""

import datetime as _datetime
import secrets

from shared import db


# --- kinds -----------------------------------------------------------------

KIND_CIVIL_RIGHTS = "civil_rights"
KIND_NEWS_TIP = "news_tip"

KINDS = (KIND_CIVIL_RIGHTS, KIND_NEWS_TIP)


# --- statuses --------------------------------------------------------------

STATUS_NEW = "NEW"
STATUS_UNDER_REVIEW = "UNDER_REVIEW"
STATUS_MORE_INFO_REQUESTED = "MORE_INFO_REQUESTED"
STATUS_VERIFIED = "VERIFIED"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_REFERRED = "REFERRED"
STATUS_CLOSED = "CLOSED"
STATUS_ARCHIVED = "ARCHIVED"

STATUSES = (
    STATUS_NEW,
    STATUS_UNDER_REVIEW,
    STATUS_MORE_INFO_REQUESTED,
    STATUS_VERIFIED,
    STATUS_UNVERIFIED,
    STATUS_REFERRED,
    STATUS_CLOSED,
    STATUS_ARCHIVED,
)

# States in which the submission is live work. A retention clock here would
# delete an open case while somebody was still working it.
OPEN_STATUSES = (STATUS_NEW, STATUS_UNDER_REVIEW, STATUS_MORE_INFO_REQUESTED)


# --- reference codes -------------------------------------------------------

# Crockford base32: no I, L, O or U, so it survives being read aloud, written on
# paper and typed back in by somebody who is upset. That is not a stylistic
# choice -- for a source, this code may be the only way back to their own
# submission, and a transcription error is a lost report.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# 12 characters ~= 60 bits. The code is a bearer token: whoever holds it can read
# the status of that submission, so guessing one must be hopeless.
_CODE_LENGTH = 12

# One prefix for every kind, on purpose. A kind-specific prefix would mean a code
# found written down announces that its holder sent a press tip, and the database
# already knows the kind -- so encoding it in the token buys nothing and tells
# anyone who finds it something about the person who wrote it.
_PREFIX = "SR"


def generate_report_id():
    """An unguessable public reference, e.g. ``SR-8F3K2QD7NRVX``.

    Random rather than sequential. A sequence would publish how many submissions
    exist and in what order, which is itself information about who reported what
    and when -- and it would let anyone holding one code walk to its neighbours.
    """
    body = "".join(secrets.choice(_ALPHABET) for _ in range(_CODE_LENGTH))
    return "%s-%s" % (_PREFIX, body)


# --- retention -------------------------------------------------------------

_DAY = 86400

# How long a submission lives once it is in a given state, in seconds.
# None means "no expiry while it stays in this state".
#
# Per status rather than one global TTL, because the two failure directions need
# opposite answers: a report that vanishes destroys the complainant's record of
# what they filed, and a report kept forever is a subpoena target and a breach
# waiting to age into one.
RETENTION_SECONDS = {
    KIND_CIVIL_RIGHTS: {
        STATUS_NEW: None,
        STATUS_UNDER_REVIEW: None,
        STATUS_MORE_INFO_REQUESTED: None,
        # Brackets the limitation period on common civil-rights claims, so the
        # record outlives the window in which the complainant might need it.
        STATUS_VERIFIED: 3 * 365 * _DAY,
        STATUS_REFERRED: 3 * 365 * _DAY,
        # Not substantiated. The shortest defensible life: keeping an
        # unsubstantiated allegation about a named person is the case where
        # retention does the most harm and the least good.
        STATUS_UNVERIFIED: 365 * _DAY,
        STATUS_CLOSED: 365 * _DAY,
        # The deliberate keep, chosen by a reviewer rather than defaulted into.
        STATUS_ARCHIVED: 7 * 365 * _DAY,
    },
    KIND_NEWS_TIP: {
        # An old tip nobody pursued has no advocate: no complainant is waiting on
        # it, and it is a stranger's sensitive documents sitting in storage.
        STATUS_NEW: 90 * _DAY,
        STATUS_UNDER_REVIEW: None,
        STATUS_MORE_INFO_REQUESTED: None,
        STATUS_VERIFIED: 3 * 365 * _DAY,
        STATUS_REFERRED: 3 * 365 * _DAY,
        STATUS_UNVERIFIED: 90 * _DAY,
        STATUS_CLOSED: 30 * _DAY,
        STATUS_ARCHIVED: 7 * 365 * _DAY,
    },
}


def retention_seconds(kind, status, pinned=False, story_source=False):
    """How long this submission may live in `status`, or None for indefinitely.

    Two overrides beat the table, and both mean "something is actively relying on
    this":

    * `pinned` -- a live investigation owns its source material, and a clock that
      deletes it mid-investigation is the failure this whole table exists to
      avoid in the other direction.
    * `story_source` -- it substantiates something already published, so it must
      outlive the story. Deleting the basis of a published allegation leaves the
      allegation standing with nothing behind it.
    """
    if pinned or story_source:
        return None
    return RETENTION_SECONDS.get(kind, {}).get(status)


class PublicInterestReport(db.Model):
    """The index row. See the module docstring for what may and may not go here."""

    __tablename__ = "public_interest_report"

    id = db.Column(db.Integer, primary_key=True)

    # The submitter-facing reference. Unique and unguessable; this is what a
    # person quotes back to us, and the only handle a source without an email
    # address has on their own submission.
    report_id = db.Column(db.String(32), nullable=False, unique=True, index=True)

    kind = db.Column(db.String(32), nullable=False, default=KIND_CIVIL_RIGHTS,
                     index=True)

    # Which payload schema the ciphertext follows. Old payloads must stay
    # decodable after the form changes, and the only way to know how to read one
    # is to have recorded how it was written.
    schema_version = db.Column(db.Integer, nullable=False, default=1)

    status = db.Column(db.String(32), nullable=False, default=STATUS_NEW,
                       index=True)

    # sha256 of the CIPHERTEXT as stored. Proves the bytes fetched back from the
    # DHT are the bytes we put there -- the AEAD tag proves a payload decrypts to
    # something we sealed, this proves it is the one sealed for THIS report.
    content_hash = db.Column(db.String(64), nullable=True, index=True)

    # Where it lives: civil-rights-reports/<report-id>/v<n>. Carries no date, no
    # category and no jurisdiction, because a DHT key is visible to every node
    # that routes for it.
    dht_key = db.Column(db.String(255), nullable=True)
    dht_version = db.Column(db.Integer, nullable=False, default=1)

    # Set ONLY after the object has been read back and verified. This column is
    # what makes "do not tell the user it was submitted when storage failed" an
    # invariant rather than a promise: a row with stored_at NULL is a failed
    # submission by construction, and the confirmation page reads this rather
    # than a function's return value.
    stored_at = db.Column(db.DateTime, nullable=True)

    # Classification tags, comma-separated. Not PII, and the primary filter a
    # reviewer works by.
    categories = db.Column(db.Text, nullable=False, default="")

    # COARSE jurisdiction only. `city` is deliberately absent -- see the module
    # docstring. Country and state are what scope a referral.
    country = db.Column(db.String(64), nullable=True, index=True)
    state = db.Column(db.String(64), nullable=True, index=True)

    # Retention bookkeeping. `status_changed_at` is separate from `updated_at`
    # because the retention clock restarts on a STATUS transition and not on an
    # edit -- adding a note must not extend how long a report is kept.
    status_changed_at = db.Column(db.DateTime, nullable=False,
                                  default=_datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)

    # Overrides on the retention table. Both mean "something is relying on this".
    pinned = db.Column(db.Boolean, nullable=False, default=False)
    story_source = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow,
                           onupdate=_datetime.datetime.utcnow)

    @property
    def category_list(self):
        return [c for c in (self.categories or "").split(",") if c]

    @property
    def is_stored(self):
        """Whether this submission actually reached the DHT and read back.

        Every surface that reports success to a human must consult this and not
        the absence of an exception.
        """
        return self.stored_at is not None

    def recompute_expiry(self, now=None):
        """Set `expires_at` from the retention table for the current status.

        Called on every status transition. Returns the new value so a caller can
        record it in the audit row: a record disappearing on schedule and a
        record somebody deleted must be distinguishable afterwards.
        """
        now = now or _datetime.datetime.utcnow()
        seconds = retention_seconds(self.kind, self.status,
                                    pinned=self.pinned,
                                    story_source=self.story_source)
        self.expires_at = None if seconds is None \
            else self.status_changed_at + _datetime.timedelta(seconds=seconds)
        return self.expires_at
