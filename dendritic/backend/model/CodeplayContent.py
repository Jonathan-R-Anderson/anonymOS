"""Editable, DHT-published codeplay content.

Codeplay's questions/problems used to be static JSON baked into the image
(backend/data/codeplay/*.json, converted from the upstream project). That made
them un-editable and tied to a redeploy. This table is the editable source of
truth: one row per item, keyed by (collection, item_id), so an admin can add or
change questions/answers for every aspect (mcq, coding problems, flashcards,
bug-hunter, daily) at runtime. The bundled JSON becomes the initial seed; a
content-addressed snapshot of each collection is published to the DHT so the
durable copy lives on the network, not just the server image.

`collection` is the SAME name services.codeplay.load() asks for -- mcq /
problems / flashcards / bughunter / daily -- so the loader can build its
list (or, for daily, its {difficulty: [...]} dict) straight from these rows.
`payload` is the full item as JSON; `category`/`difficulty` are lifted out for
filtering (pick_questions) and, for daily, for bucketing.
"""
import datetime as _datetime
import json as _json

from shared import db

COLLECTIONS = ("mcq", "problems", "flashcards", "bughunter", "daily")


class CodeplayContent(db.Model):
    __tablename__ = "codeplay_content"
    __table_args__ = (
        db.UniqueConstraint("collection", "item_id", name="uq_codeplay_content_collection_item"),
    )

    id = db.Column(db.Integer, primary_key=True)
    collection = db.Column(db.String(24), nullable=False, index=True)
    item_id = db.Column(db.String(64), nullable=False)
    category = db.Column(db.String(64), nullable=False, default="", server_default="")
    difficulty = db.Column(db.String(16), nullable=False, default="", server_default="")
    payload = db.Column(db.Text, nullable=False, default="{}")
    position = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    active = db.Column(db.Boolean, nullable=False, default=True, server_default="1")
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow,
                           onupdate=_datetime.datetime.utcnow)

    def item(self):
        """The stored item as a dict, with its id guaranteed present."""
        try:
            data = _json.loads(self.payload) if self.payload else {}
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("id", self.item_id)
        return data


def has_any():
    return db.session.query(CodeplayContent.id).first() is not None


def collection_rows(collection, active_only=True):
    query = db.session.query(CodeplayContent).filter(CodeplayContent.collection == collection)
    if active_only:
        query = query.filter(CodeplayContent.active.is_(True))
    return query.order_by(CodeplayContent.position.asc(), CodeplayContent.id.asc()).all()


def build_collection(collection, active_only=True):
    """Reassemble the structure services.codeplay expects: a list for every
    collection except `daily`, which is a {Easy/Medium/Hard: [...]} dict."""
    rows = collection_rows(collection, active_only=active_only)
    if collection == "daily":
        buckets = {}
        for row in rows:
            buckets.setdefault(row.difficulty or "Easy", []).append(row.item())
        return buckets
    return [row.item() for row in rows]


def collection_counts():
    from sqlalchemy import func
    rows = (
        db.session.query(CodeplayContent.collection, func.count(CodeplayContent.id))
        .group_by(CodeplayContent.collection)
        .all()
    )
    return {c: n for c, n in rows}


def item_by_id(row_id):
    return db.session.query(CodeplayContent).filter(CodeplayContent.id == row_id).one_or_none()
