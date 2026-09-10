"""A slip that writes. The newsroom's record of a person, not a second account.

WHY THIS IS NOT AN ACCOUNT SYSTEM
---------------------------------
`Slip` already has registration, password/wallet auth and sessions, and `Profile`
already has a public slug, an avatar and a bio surface. A contributor is a slip
with a tier and a beat, so that is all this table holds. Building a parallel
identity would mean two names, two logins and two places to ban somebody from.

TIERS, AND WHAT EACH ONE BUYS
-----------------------------
Anyone with a slip may write and submit. What a tier changes is what happens
after they press submit:

    READER       drafts and submits. Everything they file is reviewed.
    CONTRIBUTOR  same, plus may propose corrections to their published work.
    TRUSTED      publishes directly; review happens after the fact.
    EDITOR       publishes, promotes others, and retracts.

The jump that matters is TRUSTED, because it is the first tier where words reach
the public without anyone else reading them first. It is granted by an editor and
never earned automatically -- a story count is a measure of persistence, not of
judgement, and the risk being managed here is a defamation claim rather than
spam.

EDITOR IS AN APPOINTMENT, NOT A TIER YOU REACH
-----------------------------------------------
`Slip.is_mod` already exists and is set by an admin. Editor is deliberately NOT
that flag: moderating a board is removing spam and abuse, while approving an
article that names a private individual is a publishing decision with legal
consequences. One person may hold both, but they are different grants, so they
are different columns.
"""

import datetime as _datetime

from shared import db


TIER_READER = "READER"
TIER_CONTRIBUTOR = "CONTRIBUTOR"
TIER_TRUSTED = "TRUSTED"
TIER_EDITOR = "EDITOR"

TIERS = (TIER_READER, TIER_CONTRIBUTOR, TIER_TRUSTED, TIER_EDITOR)

# Ordered, so "at least CONTRIBUTOR" is a comparison rather than a set of ors
# that some caller will get subtly wrong.
_TIER_RANK = {tier: index for index, tier in enumerate(TIERS)}

# How many approved stories before CONTRIBUTOR is offered. Promotion past that
# is a human decision; see the module docstring.
CONTRIBUTOR_THRESHOLD = 3


def tier_at_least(tier, minimum):
    return _TIER_RANK.get(tier or "", -1) >= _TIER_RANK.get(minimum, 99)


class Contributor(db.Model):
    """One slip's standing in the newsroom."""

    __tablename__ = "contributor"

    id = db.Column(db.Integer, primary_key=True)

    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), unique=True,
                        nullable=False, index=True)

    tier = db.Column(db.String(16), nullable=False, default=TIER_READER,
                     index=True)

    # Shown on the author page. Distinct from the profile bio: a newsroom bio is
    # "covers housing court in the East Bay", which is a claim about what they
    # write rather than about who they are.
    byline_name = db.Column(db.String(80), nullable=True)
    bio = db.Column(db.Text, nullable=False, default="")
    beat = db.Column(db.String(120), nullable=True)

    # Counted rather than derived on read: an author page and the promotion
    # check both want it, and neither should scan every story to get it.
    published_count = db.Column(db.Integer, nullable=False, default=0)

    # An editor can stop somebody publishing without deleting their work or
    # their slip. Separate from a site ban, which is a different judgement made
    # by different people for different reasons.
    suspended = db.Column(db.Boolean, nullable=False, default=False)
    suspended_reason = db.Column(db.String(500), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow,
                           onupdate=_datetime.datetime.utcnow)

    # -- capabilities ------------------------------------------------------

    @property
    def may_submit(self):
        """Anyone not suspended may write. The floor is deliberately low."""
        return not self.suspended

    @property
    def may_publish_directly(self):
        """TRUSTED and above skip pre-publication review.

        Suspension beats tier: an editor who suspends somebody expects that to
        take effect immediately, not to be overridden by a rank they were given
        last year.
        """
        return not self.suspended and tier_at_least(self.tier, TIER_TRUSTED)

    @property
    def may_edit_others(self):
        return not self.suspended and tier_at_least(self.tier, TIER_EDITOR)

    @property
    def eligible_for_promotion(self):
        """Whether the threshold has been met. NOT whether to promote.

        Deliberately advisory. Promotion is an editor pressing a button, because
        a story count measures persistence and the thing being judged is
        judgement.
        """
        return (self.tier == TIER_READER
                and self.published_count >= CONTRIBUTOR_THRESHOLD)
