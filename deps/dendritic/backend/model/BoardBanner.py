import datetime as _datetime

from model.Media import storage
from shared import db


class BoardBanner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id"), nullable=False, index=True)
    media_id = db.Column(db.Integer, db.ForeignKey("media.id"), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    media = db.relationship("Media")

    @property
    def media_url(self):
        if self.media is None:
            return None
        return storage.get_media_url(self.media.id, self.media.ext)

    @property
    def thumb_url(self):
        if self.media is None:
            return None
        return storage.get_thumb_url(self.media.id)


def board_banner_urls(board):
    urls = []
    for banner in getattr(board, "banners", []) or []:
        banner_url = banner.media_url
        if banner_url:
            urls.append(banner_url)
    return urls
