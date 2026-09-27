"""Every PUBLISHED version of a story, kept so a correction can be additive.

WHY A VERSION HAS TO SURVIVE BEING SUPERSEDED
----------------------------------------------
`NewsStory` holds one set of live bytes. Fix a factual error in place and the
sentence that was wrong stops existing -- which is exactly the sentence a
correction notice is about. "An earlier version of this story said the council
voted unanimously" is unverifiable if the earlier version is gone, and a
publication that can only assert what it used to say is asking to be taken on
trust at the moment it has just admitted being wrong.

So a correction here is additive: the previous wording is superseded, never
overwritten, and both the notice and `model.EditorialAction` can point at a row
that still exists.

ONLY PUBLISHED VERSIONS, NOT EVERY KEYSTROKE
---------------------------------------------
A row is written when a version reaches the public, not when a draft is saved.
A full draft history would be a record of a reporter's thinking -- who they
suspected before they had it, what they cut after a call from a lawyer -- and
that is a file worth subpoenaing. What is owed to readers is that everything
which was PUBLISHED can be recovered. Nothing more is stored, so nothing more
can be demanded.

`content_hash` is copied onto the row rather than recomputed on read, so a
revision stays matched to the approval that authorised it even after the story's
own `approved_hash` has moved on to a later version.

`editor` is a string and not an FK, for the same reason as
`model.EditorialAction.actor`: the point of the record is that it still answers
"who signed this off" after the account is gone.
"""

import datetime as _datetime

from shared import db


# The digest NewsStory.content_hash() produces: hex sha256.
CONTENT_HASH_LENGTH = 64


class StoryRevision(db.Model):
    __tablename__ = "story_revision"

    id = db.Column(db.Integer, primary_key=True)

    story_id = db.Column(db.Integer, db.ForeignKey("news_story.id"),
                         nullable=False, index=True)

    # 1 for the first published version, then upwards. Per story, not global, so
    # "version 2 of this story" means something to a reader.
    version = db.Column(db.Integer, nullable=False, default=1)

    # The bytes as published. The same three fields NewsStory.content_hash()
    # covers, because those are the ones an editor actually read.
    headline = db.Column(db.String(300), nullable=False, default="")
    standfirst = db.Column(db.Text, nullable=False, default="")
    body = db.Column(db.Text, nullable=False, default="")

    content_hash = db.Column(db.String(CONTENT_HASH_LENGTH), nullable=True)

    # Who approved THIS version. See the module docstring on why it is a string.
    editor = db.Column(db.String(128), nullable=True)

    # What changed, in the words shown to readers -- this is the correction
    # notice for this revision, not an internal changelog. Nullable because the
    # first published version corrects nothing.
    note = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow)


def next_version(story_id):
    """The version number the next published revision should carry.

    Derived from the stored rows rather than from a counter on the story, so a
    revision that failed to write cannot leave the sequence with a hole that
    later reads as a version somebody deleted.
    """
    highest = (
        db.session.query(db.func.max(StoryRevision.version))
        .filter(StoryRevision.story_id == story_id)
        .scalar()
    )
    return int(highest or 0) + 1


def record_revision(story, editor=None, note=None, version=None, commit=False):
    """Append the story's CURRENT bytes as a published version.

    Does not commit by default, for the reason spelled out in
    model.EditorialAction.record: the revision and the status change that
    produced it must land in one transaction, or a crash between them leaves
    either a published story with no recoverable text or a version of something
    that was never published.
    """
    # Attribute assignment rather than constructor kwargs, so this builds
    # identically under SQLAlchemy's declarative base and under the plain-object
    # stub the tests use.
    row = StoryRevision()
    row.story_id = story.id
    row.version = next_version(story.id) if version is None else version
    row.headline = story.headline or ""
    row.standfirst = story.standfirst or ""
    row.body = story.body or ""
    row.content_hash = story.current_hash
    row.editor = editor or story.approved_by
    row.note = note
    db.session.add(row)
    if commit:
        db.session.commit()
    return row
