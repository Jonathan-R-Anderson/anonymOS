"""A story, its byline mode, and the approval that is bound to its bytes.

BYLINE MODES
------------
    SLIP        the contributor's own name, linked to their profile
    PEN_NAME    a persistent pseudonym with its own author page
    ANONYMOUS   no byline, no author page, no thread between stories

The mode is chosen per story. `slip_id` is recorded in EVERY mode -- editors must
know who filed -- so anonymity here is from READERS, not from the newsroom. The
contributor-facing UI has to say that in those words, because a writer who
believes otherwise will take risks on a guarantee nobody made.

Only unmasking is retroactive. ANONYMOUS -> SLIP is the author's to make at any
time. SLIP -> ANONYMOUS is not, and must never be offered as though it were: the
byline has already been in the feed, in caches, in archives and in scrapers --
and this site scrapes other sites for a living, so it of all places knows that
published is published.

AN APPROVAL IS A DECISION ABOUT AN ARTIFACT
--------------------------------------------
A one-time approval is a one-time key to publish WHAT WAS SUBMITTED -- the exact
text the editor read. Edit the story and the thing that was approved no longer
exists, so the approval refers to nothing.

That is enforced mechanically rather than by convention: `approved_hash` records
the content hash of the version an editor approved, and `is_displayable` compares
the live content against it. The difference matters. Under a rule, "editing
re-queues it" is a line somebody must remember to write on every path that can
modify a story -- the edit form, an admin correction, a bulk operation, a feature
nobody has thought of yet. Under the mechanism, a story whose hash does not match
its approval is not displayable by construction, and the path that forgot to
re-queue it fails closed.

CORRECTIONS AND RETRACTIONS ARE NOT OPTIONAL
---------------------------------------------
This will carry allegations about named people. A correction is additive and
visible; a retraction leaves the URL live with a notice rather than 404ing,
because the link is already in other people's citations and a story that vanishes
reads as one somebody made go away.
"""

import datetime as _datetime
import hashlib

from shared import db


# -- byline modes -----------------------------------------------------------

BYLINE_SLIP = "SLIP"
BYLINE_PEN_NAME = "PEN_NAME"
BYLINE_ANONYMOUS = "ANONYMOUS"

BYLINE_MODES = (BYLINE_SLIP, BYLINE_PEN_NAME, BYLINE_ANONYMOUS)

# Modes that appear on an author surface. ANONYMOUS is absent by construction,
# and services/bylines.py is the only module that should consult this.
ATTRIBUTED_MODES = (BYLINE_SLIP, BYLINE_PEN_NAME)


# -- workflow ---------------------------------------------------------------

STATUS_DRAFT = "DRAFT"
STATUS_SUBMITTED = "SUBMITTED"
STATUS_IN_REVIEW = "IN_REVIEW"
STATUS_CHANGES_REQUESTED = "CHANGES_REQUESTED"
STATUS_APPROVED = "APPROVED"
STATUS_PUBLISHED = "PUBLISHED"
STATUS_CORRECTED = "CORRECTED"
STATUS_RETRACTED = "RETRACTED"
STATUS_ARCHIVED = "ARCHIVED"

STATUSES = (STATUS_DRAFT, STATUS_SUBMITTED, STATUS_IN_REVIEW,
            STATUS_CHANGES_REQUESTED, STATUS_APPROVED, STATUS_PUBLISHED,
            STATUS_CORRECTED, STATUS_RETRACTED, STATUS_ARCHIVED)

# Statuses whose content is meant to be readable by the public. RETRACTED is
# here on purpose: the URL keeps serving, with a notice instead of the story.
PUBLIC_STATUSES = (STATUS_PUBLISHED, STATUS_CORRECTED, STATUS_RETRACTED)


def content_hash(headline, standfirst, body):
    """The identity of one version of a story.

    Over exactly the fields an editor reads. A change to any of them is a
    different artifact and invalidates the approval; a change to a tag or a
    category does not, because nobody approves a story on the strength of its
    tags.
    """
    digest = hashlib.sha256()
    for field in (headline or "", standfirst or "", body or ""):
        digest.update(field.encode("utf-8"))
        digest.update(b"\x00")      # separator, so a||b and ab differ
    return digest.hexdigest()


class NewsStory(db.Model):
    __tablename__ = "news_story"

    id = db.Column(db.Integer, primary_key=True)

    slug = db.Column(db.String(160), nullable=False, index=True)
    headline = db.Column(db.String(300), nullable=False)
    standfirst = db.Column(db.Text, nullable=False, default="")
    body = db.Column(db.Text, nullable=False, default="")

    # Who actually filed it, in EVERY mode. See the module docstring.
    #
    # NULLABLE, and only for one reason: account deletion. The column exists so
    # an editor can hold a filer accountable, and that is a property about a
    # LIVING account -- once the account is gone there is nobody to hold, and
    # insisting on an answer would mean deleting the published record to get
    # one. It was NOT NULL, and blueprints/admin._delete_slip deletes every row
    # with a non-nullable slip_id, so removing an author took their published
    # and RETRACTED stories with them: URLs already in other people's citations
    # started 404ing, and the retraction notice an editor wrote was destroyed
    # along with the story it was about.
    #
    # Nothing may create a story without it. `newsroom.draft_story` always sets
    # it and the leak tests assert every mode records it; this nullability is
    # the tombstone case, not a licence.
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True,
                        index=True)
    byline_mode = db.Column(db.String(16), nullable=False, default=BYLINE_SLIP)
    pen_name_id = db.Column(db.Integer, db.ForeignKey("pen_name.id"),
                            nullable=True, index=True)

    status = db.Column(db.String(24), nullable=False, default=STATUS_DRAFT,
                       index=True)

    section = db.Column(db.String(64), nullable=True, index=True)
    tags = db.Column(db.Text, nullable=False, default="")
    hero_media_id = db.Column(db.Integer, db.ForeignKey("media.id"),
                              nullable=True)

    # The approval, bound to the bytes it was granted for.
    approved_hash = db.Column(db.String(64), nullable=True)
    approved_by = db.Column(db.String(128), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)

    published_at = db.Column(db.DateTime, nullable=True, index=True)
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow,
                           onupdate=_datetime.datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow, index=True)

    # Shown ON the story, dated, saying what changed. Not a silent edit: silent
    # edits are the fastest way for a publication to lose the credibility this
    # whole feature is trying to build.
    correction_notice = db.Column(db.Text, nullable=True)
    corrected_at = db.Column(db.DateTime, nullable=True)

    retraction_notice = db.Column(db.Text, nullable=True)
    retracted_at = db.Column(db.DateTime, nullable=True)

    # The submission this story came from, if any. INTERNAL.
    #
    # It appears on no public surface and services/bylines.py never sees it. The
    # set of stories drawn from the intake queue is small, so knowing a story
    # came from a report narrows who could have filed it -- which is exactly the
    # inference the encryption exists to prevent.
    #
    # Recorded rather than inferred because services/report_consent.check_story
    # gates publication on it, and inferring the link means guessing; guessing
    # wrong in the permissive direction publishes somebody's account without
    # their permission.
    source_report_id = db.Column(db.String(32), nullable=True, index=True)

    # Recorded so it cannot be forgotten as a habit: was a named party offered a
    # chance to respond, and what did they say. A field, because a practice that
    # lives only in someone's head is one that lapses under deadline.
    reply_offered_at = db.Column(db.DateTime, nullable=True)
    reply_text = db.Column(db.Text, nullable=True)

    # Denormalised score for the front-page rail. Recomputed by a background
    # pass -- the front page must never COUNT() votes per request.
    score = db.Column(db.Integer, nullable=False, default=0)
    vote_count = db.Column(db.Integer, nullable=False, default=0)

    # -- identity ----------------------------------------------------------

    @property
    def current_hash(self):
        return content_hash(self.headline, self.standfirst, self.body)

    @property
    def approval_matches_content(self):
        """Whether the approval still refers to what is actually stored."""
        return bool(self.approved_hash) and self.approved_hash == self.current_hash

    @property
    def is_displayable(self):
        """The single gate every public surface must pass through.

        Both halves are required. A public status alone would let an edited
        story keep serving on an approval granted for different words; a
        matching hash alone would publish a draft nobody approved.
        """
        return self.status in PUBLIC_STATUSES and self.approval_matches_content

    @property
    def is_retracted(self):
        return self.status == STATUS_RETRACTED

    @property
    def tag_list(self):
        return [t for t in (self.tags or "").split(",") if t]

    def approve(self, actor, now=None):
        """Bind an approval to the current content."""
        self.approved_hash = self.current_hash
        self.approved_by = actor
        self.approved_at = now or _datetime.datetime.utcnow()
        self.status = STATUS_APPROVED
        return self.approved_hash

    def invalidate_approval(self):
        """Called wherever content changes. Belt to `is_displayable`'s braces.

        Not the mechanism -- `is_displayable` is, and it holds even when nobody
        calls this. This exists so a story that has drifted also *looks* wrong
        in the queue, rather than only failing silently at render time.
        """
        self.approved_hash = None
        self.approved_by = None
        self.approved_at = None
