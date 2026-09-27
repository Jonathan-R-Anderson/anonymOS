import hashlib
import secrets

from sqlalchemy import and_
from sqlalchemy.orm import relationship

from model.Post import Post
from model.Poster import Poster
from model.Slip import Slip, slip_from_id
from shared import db

tags = db.Table('tags',
                db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True),
                db.Column('thread_id', db.Integer, db.ForeignKey('thread.id'), primary_key=True)
                )


class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(
        db.String(64), nullable=False, unique=True, index=True,
        default=lambda: hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
    )
    board = db.Column(db.Integer, db.ForeignKey("board.id"), nullable=False)
    views = db.Column(db.Integer, nullable=False)
    posts = relationship("Post", order_by=Post.datetime)
    last_updated = db.Column(db.DateTime)
    # Last time the thread PAGE was directly opened (distinct from last_updated,
    # which tracks post/bump activity). Drives the unviewed-thread flush.
    last_viewed_at = db.Column(db.DateTime, nullable=True)
    source_type = db.Column(db.String(128), nullable=False, default="local")
    source_name = db.Column(db.String(64), nullable=True)
    source_thread_id = db.Column(db.String(128), nullable=True)
    source_url = db.Column(db.String, nullable=True)
    # Keep tag loading on-demand; subquery eager loading has been producing
    # broken row mappings on plain Thread fetches in production.
    tags = relationship("Tag", secondary=tags, lazy='select',
                        backref=db.backref('threads', lazy='select'))

    def num_media(self):
        return db.session.query(Post.id).filter(
            and_(
                Post.thread == self.id,
                Post.media.isnot(None)
            )
        ).count()

    def admin_is_op(self):
        if not self.posts:
            return False
        poster_id = self.posts[0].poster
        if poster_id is None:
            return False
        slip_id = db.session.query(Poster).filter(Poster.id == poster_id).one().slip
        if slip_id is None:
            return False
        slip = slip_from_id(slip_id)
        return slip is not None and slip.is_admin
