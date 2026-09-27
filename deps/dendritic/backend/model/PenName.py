"""A persistent pseudonym: reputation without a real byline.

WHY THIS EXISTS AT ALL
----------------------
The obvious design offers two choices -- your name or nothing -- and that
quietly punishes the people most likely to need cover. A reporter covering their
own employer, their own police department or their own town cannot use their
slip, and with only "anonymous" left they lose everything reputational: a reader
cannot tell the regular housing-court correspondent from a stranger's first post,
and the writer can never build a body of work.

A pen name is the middle: a stable name a reader can follow and hold to account,
with no public link to the slip behind it. `ANONYMOUS` then means what it should
-- the story that must leave no thread at all -- rather than being the only way
to write unattributed.

WHY ONE OWNER, NEVER TRANSFERRED, NEVER REUSED
-----------------------------------------------
Two people writing under one name is a credibility problem (the name's track
record stops meaning anything) and a deanonymisation vector (each of them can
infer things about the other's work). Release is therefore permanent: `retired`
rather than deleted, so the slug can never be claimed again by someone who would
inherit the previous holder's readers.

THE SLUG NAMESPACE IS SHARED WITH PROFILES, DELIBERATELY
---------------------------------------------------------
Author pages live at one path whether the author is a slip or a pen name, so a
pen name that duplicated an existing `Profile.slug` would shadow somebody's
profile URL. `slug_is_available()` checks both, and it is the only correct place
to ask -- a uniqueness constraint on this table alone would pass and still
collide.
"""

import datetime as _datetime
import re

from shared import db


SLUG_PATTERN = re.compile(r"[^a-z0-9]+")

# Long enough to be a real name, short enough for a URL and a byline line.
MAX_DISPLAY = 60
MAX_SLUG = 64


def normalise_slug(value):
    return SLUG_PATTERN.sub("-", (value or "").strip().lower()).strip("-")[:MAX_SLUG]


def slug_is_available(slug):
    """True when no profile AND no pen name holds this slug.

    Checks BOTH namespaces. See the module docstring: asking only this table is
    the mistake that lets a pen name shadow a profile URL.

    Retired pen names still count as taken -- a released name is never reissued.
    """
    slug = normalise_slug(slug)
    if not slug:
        return False

    from model.Profile import Profile

    if db.session.query(Profile.id).filter(Profile.slug == slug).first():
        return False
    if db.session.query(PenName.id).filter(PenName.slug == slug).first():
        return False
    return True


class PenName(db.Model):
    __tablename__ = "pen_name"

    id = db.Column(db.Integer, primary_key=True)

    slug = db.Column(db.String(MAX_SLUG), nullable=False, unique=True, index=True)
    display_name = db.Column(db.String(MAX_DISPLAY), nullable=False)

    # The link this whole table exists to keep private.
    #
    # NULLABLE for account deletion only -- see NewsStory.slip_id for the same
    # reasoning. A pen name whose owner is gone is RETIRED rather than deleted:
    # its slug stays claimed forever so nobody inherits its readers, and the
    # stories it signed keep their byline. Indexed because the
    # newsroom needs "which pen names does this slip hold", and NEVER exposed by
    # any public surface -- see services/bylines.py, which is the only module
    # allowed to decide what a reader sees.
    owner_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"),
                              nullable=True, index=True)

    bio = db.Column(db.Text, nullable=False, default="")

    # Approved by an editor before it can carry a byline. Unmoderated, somebody
    # registers a real journalist's name, or "Syndichan Editorial", and every
    # story under it inherits credibility it was never granted.
    approved = db.Column(db.Boolean, nullable=False, default=False)
    approved_by = db.Column(db.String(128), nullable=True)

    # Released, not deleted. The slug stays claimed forever; see the docstring.
    retired = db.Column(db.Boolean, nullable=False, default=False)
    retired_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow)

    @property
    def usable(self):
        """Whether a new story may be filed under this name."""
        return bool(self.approved) and not self.retired

    def retire(self, now=None):
        """Release the name. Existing stories keep it; nobody else may have it."""
        self.retired = True
        self.retired_at = now or _datetime.datetime.utcnow()
