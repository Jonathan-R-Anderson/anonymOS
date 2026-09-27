import datetime as _datetime

from shared import db


class ImportedMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    thread_id = db.Column(
        db.Integer,
        db.ForeignKey("thread.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_post_id = db.Column(db.String(128), nullable=False)
    media_id = db.Column(
        db.Integer,
        db.ForeignKey("media.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    image_path = db.Column(db.String, nullable=True)
    external_media_url = db.Column(db.String, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=_datetime.datetime.utcnow,
        onupdate=_datetime.datetime.utcnow,
    )

    __table_args__ = (
        db.UniqueConstraint("thread_id", "source_post_id", name="uq_imported_media_thread_source_post"),
    )
