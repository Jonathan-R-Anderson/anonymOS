import datetime as _datetime

from shared import db


class BoardSource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    board_id = db.Column(db.Integer, db.ForeignKey("board.id", ondelete="CASCADE"), nullable=False)
    # For the built-in scrapers this is "4chan"/"8chan"/"7chan"/"reddit". For a
    # site monitored from the aggregated-chan list it is that site's HOST, which
    # is what keeps thread identity — (source_type, source_thread_id) — unique
    # across sites whose thread-id sequences overlap.
    source_type = db.Column(db.String(128), nullable=False)
    source_name = db.Column(db.String(64), nullable=False)
    source_thread_id = db.Column(db.String(128), nullable=False)
    # Full base URL of the remote site for generic (aggregated-chan) sources, so
    # the scraper can be told which site to crawl. Null for the built-in scrapers,
    # whose base URL is fixed by their container's env.
    source_site = db.Column(db.String(500), nullable=True)
    # When this source was submitted — the staleness baseline for a thread that
    # never produces any content (i.e. was already dead when it was added).
    created_at = db.Column(db.DateTime, nullable=True, default=_datetime.datetime.utcnow, server_default=db.func.now())
    # Set once the source thread is deemed dead (no new content within the
    # configured window): monitoring stops — it is skipped by sync and
    # unregistered from the scraper. See services/scraped_thread_retire.py.
    retired = db.Column(db.Boolean, nullable=False, default=False, server_default="0")

    __table_args__ = (
        db.UniqueConstraint(
            "board_id", "source_type", "source_name", "source_thread_id",
            name="uq_board_source",
        ),
    )
