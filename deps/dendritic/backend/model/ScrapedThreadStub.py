"""What survives when a scraped thread's content is purged.

A stub is the IDENTITY of a thread we used to carry, with none of its content:
the source triple, when we last saw a post in it, and how big it was. It exists
for one reason -- when a purged thread comes back (a bumped thread, a re-crawled
board), we can tell "we already had this and deliberately dropped it" apart from
"this is new", without keeping a single post or image.

Sized to be cheap on purpose. Thirty days of stubs is kilobytes; thirty days of
the content they describe is what filled the data node's disk.

See services/scraped_retention.py for the two clocks and why they differ.
"""
import datetime as _datetime

from shared import db


class ScrapedThreadStub(db.Model):
    __tablename__ = "scraped_thread_stub"

    id = db.Column(db.Integer, primary_key=True)
    # The source triple -- the same identity Thread carries, so a re-import can
    # be matched before any content is fetched.
    source_type = db.Column(db.String(128), nullable=False)
    source_name = db.Column(db.String(64), nullable=True)
    source_thread_id = db.Column(db.String(128), nullable=False)
    # Which local board it had been imported into, so a re-import lands back in
    # the same place. Not a FK: the board may be deleted independently and that
    # must not cascade away our memory of the thread.
    board_id = db.Column(db.Integer, nullable=True)

    # The newest post we ever saw. This is the clock the purge decision used,
    # and the one the metadata-retention sweep measures against.
    last_post_at = db.Column(db.DateTime, nullable=True, index=True)
    purged_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    # Cheap provenance for the admin view: how much we dropped.
    post_count = db.Column(db.Integer, nullable=False, default=0)
    media_count = db.Column(db.Integer, nullable=False, default=0)
    reason = db.Column(db.String(64), nullable=False, default="out_of_window")

    __table_args__ = (
        db.UniqueConstraint(
            "source_type", "source_name", "source_thread_id",
            name="uq_scraped_stub_source",
        ),
        db.Index("ix_scraped_stub_purged_at", "purged_at"),
    )


def stub_for(source_type, source_name, source_thread_id):
    """The stub for a remote thread, or None. Used by the importer to recognise
    a thread we purged rather than treating it as new."""
    if not source_type or source_thread_id is None:
        return None
    query = db.session.query(ScrapedThreadStub).filter(
        ScrapedThreadStub.source_type == source_type,
        ScrapedThreadStub.source_thread_id == str(source_thread_id),
    )
    if source_name is None:
        query = query.filter(ScrapedThreadStub.source_name.is_(None))
    else:
        query = query.filter(ScrapedThreadStub.source_name == source_name)
    return query.one_or_none()


def record_stub(thread, post_count=0, media_count=0, reason="out_of_window"):
    """Remember a thread we are about to purge. Caller commits.

    Upserts: a thread that comes back and is purged again updates the existing
    stub rather than tripping the unique constraint.
    """
    existing = stub_for(thread.source_type, thread.source_name, thread.source_thread_id)
    now = _datetime.datetime.utcnow()
    if existing is None:
        existing = ScrapedThreadStub(
            source_type=thread.source_type,
            source_name=thread.source_name,
            source_thread_id=str(thread.source_thread_id),
        )
        db.session.add(existing)
    existing.board_id = thread.board
    existing.last_post_at = thread.last_updated
    existing.purged_at = now
    existing.post_count = int(post_count or 0)
    existing.media_count = int(media_count or 0)
    existing.reason = reason
    return existing
