"""Daily time-lapse snapshots for the per-profile graffiti walls.

A background thread re-saves each enabled profile's canvas under today's date
(YYYY-MM-DD) roughly hourly, so the current day's frame tracks the latest state
and past days freeze at their end-of-day state. Snapshots older than the
profile's configured window (`place_timelapse_days`) are pruned."""
import datetime as _datetime

import shared
from shared import db
from model.Profile import Profile
from services import place as _place

DEFAULT_TIMELAPSE_DAYS = 7
_INTERVAL_SECONDS = 3600


def run_place_snapshots():
    today = _datetime.datetime.utcnow().strftime("%Y-%m-%d")
    profiles = db.session.query(Profile).filter(Profile.enable_place.is_(True)).all()
    count = 0
    for profile in profiles:
        try:
            _place.save_snapshot(profile.slug, today)
            days = getattr(profile, "place_timelapse_days", None) or DEFAULT_TIMELAPSE_DAYS
            _place.prune_snapshots(profile.slug, days)
            count += 1
        except Exception:
            # A single bad profile must not stop the sweep.
            pass
    return count


def start_place_snapshots(flask_app):
    def _loop():
        import time as _time
        _time.sleep(60)
        while True:
            try:
                with flask_app.app_context():
                    run_place_snapshots()
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("Place snapshot sweep failed")
            _time.sleep(_INTERVAL_SECONDS)

    shared.spawn_native_thread(target=_loop, name="place-snapshots", daemon=True)
