"""Dedup + provenance ledger for imported NNTPChan articles.

Every overchan article we have processed gets one row here keyed by its
Message-ID, so re-pulling a newsgroup never double-imports. It also records the
local Thread/Post the article became (or NULL when we deliberately dropped it —
address-blocked or hash-blocked), and the thread root Message-ID so a reply can
find the local thread its OP created.
"""
import datetime as _datetime

from shared import db


class NntpArticle(db.Model):
    __tablename__ = "nntp_article"

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(250), nullable=False, unique=True, index=True)
    newsgroup = db.Column(db.String(255), nullable=True)
    thread_root = db.Column(db.String(250), nullable=True, index=True)
    local_thread_id = db.Column(db.Integer, nullable=True)
    local_post_id = db.Column(db.Integer, nullable=True)
    is_op = db.Column(db.Boolean, nullable=False, default=False)
    imported_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


def is_message_seen(message_id):
    if not message_id:
        return False
    return (
        db.session.query(NntpArticle.id)
        .filter(NntpArticle.message_id == message_id)
        .first()
        is not None
    )


def record_article(message_id, newsgroup, thread_root, local_thread_id, local_post_id, is_op):
    row = NntpArticle(
        message_id=message_id,
        newsgroup=newsgroup,
        thread_root=thread_root,
        local_thread_id=local_thread_id,
        local_post_id=local_post_id,
        is_op=bool(is_op),
    )
    db.session.add(row)
    return row


def thread_for_root(root_message_id):
    """Local thread id created by the OP whose Message-ID == root_message_id."""
    if not root_message_id:
        return None
    row = (
        db.session.query(NntpArticle)
        .filter(
            NntpArticle.message_id == root_message_id,
            NntpArticle.local_thread_id.isnot(None),
        )
        .first()
    )
    return row.local_thread_id if row is not None else None
