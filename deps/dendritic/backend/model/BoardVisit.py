import datetime

from shared import db


class BoardVisit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id"), nullable=False)
    page_id = db.Column(db.String(64), nullable=False, unique=True)
    visitor_token = db.Column(db.String(64), nullable=False)
    path = db.Column(db.String(255), nullable=True)
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    ended_at = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Integer, nullable=False, default=0)
    page_views = db.Column(db.Integer, nullable=False, default=1)
