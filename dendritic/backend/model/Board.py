import datetime as _datetime

from sqlalchemy import desc
from sqlalchemy.orm import backref, relationship

from model.BoardSource import BoardSource
from model.Thread import Thread
from shared import db


class Board(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False)
    display_name = db.Column(db.String(96), nullable=True)
    rules = db.Column(db.String, nullable=True)
    threads = relationship("Thread", order_by=desc(Thread.last_updated))
    max_threads = db.Column(db.Integer, default=50)
    mimetypes = db.Column(db.String, nullable=False)
    owner_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)
    is_private = db.Column(db.Boolean, nullable=False, default=False)
    # When set, posters' country flags (geolocated from their IP) are shown
    # next to their per-board poster ID.
    show_country_flags = db.Column(db.Boolean, nullable=False, default=False, server_default="0")
    # When set, this board accepts posts ONLY through the authenticated bot API
    # (POST /api/v1/bot/post) — web-form posting (new threads AND replies) and the
    # generic JSON post API are blocked. See blueprints/bot_api.py + the FAQ.
    api_only = db.Column(db.Boolean, nullable=False, default=False, server_default="0")
    # Bot-facing description of what content belongs on this board, surfaced to
    # bots via GET /api/v1/bot/boards (falls back to `rules`). See bot_api.py.
    api_description = db.Column(db.Text, nullable=True)
    # Reject images the NSFW classifier scores at or above the site threshold
    # (Yahoo open_nsfw, see services/nsfw.py + the nsfw-classifier sidecar).
    # ON by default for every new board. USER-created boards cannot turn it off —
    # blueprints/boards.py forces it on for any non-sysop board form — only an
    # admin-created board can (admin.create_board / the admin board form).
    nsfw_filter = db.Column(db.Boolean, nullable=False, default=True, server_default="1")
    # Board creation time; used as the inactivity baseline before any posts
    # exist. See services/board_cleanup.py.
    created_at = db.Column(db.DateTime, nullable=True, default=_datetime.datetime.utcnow, server_default=db.func.now())
    # Owner-customizable CSS applied to the board's catalog page (MySpace-style).
    custom_css = db.Column(db.Text, nullable=True)
    # Owner-customizable JavaScript run on the board's catalog page. Arbitrary
    # code (not sanitized) — runs for every visitor of the board.
    custom_js = db.Column(db.Text, nullable=True)
    # Owner-customizable HTML injected at the top of the board's catalog page.
    custom_html = db.Column(db.Text, nullable=True)
    board_type = db.Column(db.String(24), nullable=False, default="standard")
    geo_strategy = db.Column(db.String(24), nullable=True)
    geo_parent_id = db.Column(db.Integer, db.ForeignKey("board.id"), nullable=True)
    geo_key = db.Column(db.String(128), nullable=True)
    geo_label = db.Column(db.String(128), nullable=True)
    geo_latitude = db.Column(db.Float, nullable=True)
    geo_longitude = db.Column(db.Float, nullable=True)
    geo_radius_miles = db.Column(db.Integer, nullable=True)
    sources = relationship("BoardSource", cascade="all, delete-orphan", lazy="subquery")
    banners = relationship("BoardBanner", cascade="all, delete-orphan", lazy="select")
    geo_parent = relationship(
        "Board",
        remote_side=[id],
        backref=backref("geo_children", lazy="select"),
    )

    @property
    def title(self):
        return (self.display_name or self.name or "").strip()

    @property
    def is_geo_root(self):
        return self.board_type == "geo-root"

    @property
    def is_geo_generated(self):
        return self.board_type == "geo-generated"

    @property
    def geo_scope_label(self):
        if self.geo_strategy == "city":
            return "city"
        if self.geo_strategy == "radius":
            radius = self.geo_radius_miles or 50
            return "within %d miles" % radius
        return "standard"
