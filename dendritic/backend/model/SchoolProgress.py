"""Which chapters a slip has marked as read.

One row per (slip, subject, chapter), and the unique constraint is the feature:
marking a chapter read twice — a double click, a page refresh on a POST — must
not produce two rows, because the progress bar counts rows.

Deliberately NOT a percentage stored on the slip. A stored total drifts the
moment a chapter is added or removed from the curriculum; counting the rows that
still match chapters in the book cannot.
"""

import datetime as _datetime

from shared import db


class SchoolProgress(db.Model):
    __tablename__ = "school_progress"
    __table_args__ = (
        db.UniqueConstraint("slip_id", "subject_slug", "chapter_slug",
                            name="uq_school_progress_once"),
    )

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)
    # Slugs rather than foreign keys: the curriculum lives in source, not in the
    # database, so there is no row to point at. A chapter that is renamed leaves
    # an orphan row, which reads as "not yet read" — the harmless direction.
    subject_slug = db.Column(db.String(64), nullable=False, index=True)
    chapter_slug = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def counts_for_slip(slip_id):
    """{subject_slug: chapters read} — one query for the whole school index."""
    if not slip_id:
        return {}
    rows = (
        db.session.query(SchoolProgress.subject_slug, db.func.count(SchoolProgress.id))
        .filter(SchoolProgress.slip_id == slip_id)
        .group_by(SchoolProgress.subject_slug)
        .all()
    )
    return {slug: int(count) for slug, count in rows}
