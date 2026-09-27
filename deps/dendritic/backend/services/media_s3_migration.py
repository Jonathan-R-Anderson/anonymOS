"""Run the one-time folder->S3 media migration WITHOUT blocking startup.

This used to run synchronously in ensure_runtime.py, before uwsgi was started.
migrate_to_s3.find_uploads_dir() os.walk()s the whole of /maniwani -- including
anime-captcha/node_modules -- and then /data, hunting for loose .jpg/.png/.svg
files. On this deployment that takes ~6m15s and ends with "NO MEDIA FOUND",
because the migration finished months ago and there is nothing left to move.

The cost was six minutes of hard downtime on every restart. The backend is
replicas:1, so until uwsgi answers /health the pod is not Ready and nginx serves
its "Just a moment..." holding page. Every deploy, every crash, every config
change paid it.

Two changes here:

  1. It runs in a background thread inside the app, so serving starts first and
     the migration proceeds behind it. (A thread in ensure_runtime.py would not
     survive -- that is a separate process which exits before uwsgi starts.)

  2. It records completion in a SiteSetting, so the filesystem walk happens at
     most ONCE. A migration that has already reported "nothing to move" has no
     reason to re-scan a node_modules tree on every boot forever.

Leader-gated like the other sweeps: four uwsgi workers must not run the same
migration concurrently.
"""
import datetime as _datetime

from model.SiteSetting import get_setting, set_setting
from shared import db


DONE_SETTING = "media_s3_migration_completed_at"
# Long enough that startup is well clear, short enough that a real pending
# migration still happens promptly on the first boot after an upgrade.
_START_DELAY_SECONDS = 120


def already_done():
    return bool((get_setting(DONE_SETTING, "") or "").strip())


def mark_done(note=""):
    stamp = _datetime.datetime.utcnow().isoformat() + "Z"
    set_setting(DONE_SETTING, ("%s %s" % (stamp, note)).strip())
    db.session.commit()


def run_once(flask_app, force=False):
    """Run the migration if it has never completed. Returns True if it ran."""
    if not force and already_done():
        flask_app.logger.debug("media S3 migration already completed; skipping the scan")
        return False
    try:
        import migrate_to_s3

        migrate_to_s3.migrate()
        flask_app.logger.info("Media migration completed.")
        mark_done("ok")
        return True
    except Exception:
        # Deliberately NOT marked done: a failed migration must be retried on
        # the next boot rather than silently recorded as finished.
        db.session.rollback()
        flask_app.logger.exception("Media migration failed")
        return False


def start_media_s3_migration(flask_app):
    def _loop():
        import time as _time

        _time.sleep(_START_DELAY_SECONDS)
        try:
            with flask_app.app_context():
                from services.singleton_worker import is_maintenance_leader

                if is_maintenance_leader():
                    run_once(flask_app)
        except Exception:
            try:
                with flask_app.app_context():
                    db.session.rollback()
            except Exception:
                pass
            flask_app.logger.exception("media S3 migration thread failed")

    import shared as _shared

    _shared.spawn_native_thread(
        target=_loop, name="media-s3-migration", daemon=True
    )
