"""Re-scan stored media against the NSFW classifier and ClamAV.

WHY A SECOND PASS
-----------------
Everything is scanned once, at upload/import. That single check is not enough:

  * ClamAV signatures change daily — a file that was clean when stored can be a
    known-bad sample a week later.
  * The NSFW classifier, its threshold, and the scanning code itself change. This
    codebase alone gained video frame extraction after ~5000 files had already
    been imported unscored, and shipped for hours with an unsized threshold.
  * A scan can be SKIPPED at store time without anything looking wrong: the
    classifier being briefly unreachable leaves `nsfw_score` NULL with
    `nsfw_fail_closed` off.

So this samples stored media and checks it again.

WHAT A HIT DOES — two different actions on purpose
--------------------------------------------------
  * VIRUS -> the sha256 goes on the hash blocklist, which makes every serving
    route answer 410 for EVERYONE (`is_media_hash_blocked` in blueprints/upload.py).
    Not overlay-blocking: overlay-blocking still shows the file to signed-in
    viewers, which is wrong for malware. The bytes are deliberately NOT deleted —
    an operator may need the sample, and the blocklist already stops it being
    served or re-stored.
  * NSFW over threshold -> `overlay_blocked` plus both hashes (exact + perceptual).
    The file survives and stays visible to signed-in viewers, which is the
    documented intent of overlay-blocking, and the hashes stop re-import.

SELECTION
---------
Least-recently-scanned first, randomised within that: `rescanned_at NULLS FIRST,
random()`. Never-scanned files (the pre-feature backlog) drain first, and the
random tiebreak stops a permanently-failing row from being retried forever at the
head of every pass. `rescanned_at` is stamped even when a scan is inconclusive —
the same "record the attempt, not the success" rule the monitored-board scheduler
needs, and for the same reason.

RESOURCE DISCIPLINE
-------------------
Every file means a storage read plus up to two HTTP calls to sidecars. The 2026-07-26
connection-pool outage was caused by exactly this shape of work holding a DB
connection across network calls, so:
  * the sweep runs through the capped scrape queue (services/scrape_queue.py);
  * bytes are read and scanned with NO open transaction, and the DB is touched
    only afterwards, inside `db_budget()`;
  * it is leader-gated, so four uWSGI workers do not each scan the same files.
"""
import datetime as _datetime
import os
import threading

from model.Media import Media
from shared import app, db

QUEUE_NAME = "media-rescan"

# Files per sweep. Small on purpose: each one is a storage read plus up to two
# sidecar round-trips, and the sweep is background work with no deadline.
DEFAULT_BATCH = int(os.getenv("MEDIA_RESCAN_BATCH", "10") or 10)
_SWEEP_INTERVAL_SECONDS = int(os.getenv("MEDIA_RESCAN_LOOP_SECONDS", "900") or 900)
# Do not re-scan something already checked recently, however idle the sweep is.
MIN_AGE_DAYS = int(os.getenv("MEDIA_RESCAN_MIN_AGE_DAYS", "7") or 7)
SETTING_KEY = "media_rescan_enabled"

_thread = None
_lock = threading.Lock()
_stop = threading.Event()

_stats = {
    "passes": 0, "scanned": 0, "nsfw_hits": 0, "virus_hits": 0,
    "unavailable": 0, "missing": 0, "last_run": None,
}


def rescan_enabled():
    from model.SiteSetting import get_setting

    raw = (get_setting(SETTING_KEY, "") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def stats():
    return dict(_stats)


def _candidates(limit):
    """(id, ext, mimetype, sha256) for the least-recently-scanned media."""
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=MIN_AGE_DAYS)
    rows = (
        db.session.query(Media.id, Media.ext, Media.mimetype, Media.sha256)
        .filter(db.or_(Media.rescanned_at.is_(None), Media.rescanned_at < cutoff))
        .order_by(Media.rescanned_at.asc().nullsfirst(), db.func.random())
        .limit(max(1, int(limit)))
        .all()
    )
    # Plain tuples: the caller drops the session before doing any network work, so
    # nothing may stay attached to it.
    return [(r[0], r[1], r[2], r[3]) for r in rows]


def _stamp_scanned(media_id, nsfw_score=None):
    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if media is None:
        return None
    media.rescanned_at = _datetime.datetime.utcnow()
    if nsfw_score is not None:
        media.nsfw_score = nsfw_score
    db.session.add(media)
    return media


def _act_on_virus(media_id, sha256, detail):
    """Block the hash so no route serves it to anyone. Does not delete the bytes."""
    from model.BlockedMediaHash import block_media_hash

    app.logger.warning(
        "media rescan: VIRUS on media %s (%s) - blocking hash %s",
        media_id, detail, (sha256 or "")[:12],
    )
    if sha256:
        block_media_hash(sha256, reason="antivirus (re-scan): %s" % (detail or "infected")[:180])
    _stats["virus_hits"] += 1


def _act_on_nsfw(media_id, sha256, score, data):
    """Hide already-stored legacy media without creating an automatic ban.

    New uploads are rejected before persistence. Re-scan operates on historical
    files, so it retains the existing overlay behavior to avoid breaking rows
    that reference the media, but exact/perceptual bans remain manual-only.
    """
    from services.media_overlay import set_media_overlay_blocked

    reason = "nsfw:%.4f (re-scan)" % score
    app.logger.warning(
        "media rescan: media %s scores %.4f - overlay-blocking it", media_id, score
    )
    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if media is not None:
        set_media_overlay_blocked(media, True)
    _stats["nsfw_hits"] += 1


def rescan_one(media_id, ext, mimetype, sha256):
    """Re-scan a single file. Returns a short outcome string."""
    from model.Media import MissingAttachmentError, storage
    from services import nsfw as nsfw_service
    from services.scrape_queue import db_budget
    from services.upload_security import UnsafeUploadError, scan_bytes_with_clamav

    # ---- phase 1: read the bytes. No transaction is held open here.
    try:
        data = storage.read_attachment_bytes(media_id, ext)
    except MissingAttachmentError:
        with db_budget():
            _stamp_scanned(media_id)
            db.session.commit()
        _stats["missing"] += 1
        return "missing"
    except Exception as exc:
        app.logger.warning("media rescan: could not read media %s (%s)", media_id, exc)
        return "unreadable"
    if not data:
        return "empty"

    # ---- phase 2: the network scans, still with no open transaction.
    virus_detail = None
    try:
        scan_bytes_with_clamav(data, filename="rescan-%s.%s" % (media_id, ext or "bin"))
    except UnsafeUploadError as exc:
        # Distinguish an actual detection from "could not scan" — with
        # CLAMAV_FAIL_CLOSED on, the same exception means the scanner was down, and
        # treating that as a detection would blocklist clean files en masse.
        text = str(exc).lower()
        if "could not be virus-scanned" in text:
            _stats["unavailable"] += 1
        else:
            virus_detail = str(exc)[:200]
    except Exception as exc:
        app.logger.debug("media rescan: clamav error on %s (%s)", media_id, exc)

    nsfw_score = None
    if virus_detail is None:
        try:
            nsfw_score = nsfw_service.classify_bytes(data, mimetype)
        except nsfw_service.NsfwUnavailable as exc:
            # Never fail-closed here: fail_closed exists to stop NEW uploads, and
            # applying it to a re-scan would block already-stored media just
            # because a sidecar was briefly down.
            app.logger.debug("media rescan: classifier unavailable for %s (%s)", media_id, exc)
            _stats["unavailable"] += 1

    # ---- phase 3: the DB work, bounded by the scrape queue's connection budget.
    with db_budget():
        try:
            if virus_detail is not None:
                _act_on_virus(media_id, sha256, virus_detail)
                _stamp_scanned(media_id)
                db.session.commit()
                return "virus"
            blocks = (
                nsfw_score is not None
                and nsfw_service.score_blocks(nsfw_score, None)
            )
            if blocks:
                _act_on_nsfw(media_id, sha256, nsfw_score, data)
                _stamp_scanned(media_id, nsfw_score=nsfw_score)
                db.session.commit()
                return "nsfw"
            _stamp_scanned(media_id, nsfw_score=nsfw_score)
            db.session.commit()
            return "clean"
        except Exception:
            db.session.rollback()
            app.logger.exception("media rescan: could not record the result for %s", media_id)
            return "error"


def run_media_rescan(limit=None, force=False):
    """One sweep. Returns the number of files scanned."""
    if not force and not rescan_enabled():
        return 0
    from services.scrape_queue import db_budget, submit

    with db_budget():
        try:
            candidates = _candidates(limit or DEFAULT_BATCH)
        except Exception:
            db.session.rollback()
            app.logger.exception("media rescan: could not select candidates")
            return 0
        finally:
            # Explicitly give the connection back before any network work: the
            # candidate list is plain tuples and needs no session.
            db.session.commit()

    if not candidates:
        return 0

    queued = 0
    for media_id, ext, mimetype, sha256 in candidates:
        def _job(mid=media_id, e=ext, mt=mimetype, sh=sha256):
            outcome = rescan_one(mid, e, mt, sh)
            _stats["scanned"] += 1
            app.logger.debug("media rescan: media %s -> %s", mid, outcome)

        if submit(QUEUE_NAME, "media-rescan:%s" % media_id, _job, label="media %s" % media_id):
            queued += 1
    _stats["passes"] += 1
    _stats["last_run"] = _datetime.datetime.utcnow().isoformat()
    if queued:
        app.logger.info("media rescan: queued %d file(s) for re-scan", queued)
    return queued


def _loop(flask_app):
    # Let the sidecars finish booting before the first pass.
    _stop.wait(timeout=120)
    while not _stop.is_set():
        try:
            with flask_app.app_context():
                from services.singleton_worker import is_maintenance_leader

                # Leader-gated: `lazy-apps` + 4 processes would otherwise run four
                # copies, quadrupling the sidecar load and racing on the same rows.
                if is_maintenance_leader():
                    run_media_rescan()
        except Exception:
            flask_app.logger.exception("media rescan sweep failed")
        finally:
            try:
                with flask_app.app_context():
                    db.session.remove()
            except Exception:
                pass
        _stop.wait(timeout=max(60, _SWEEP_INTERVAL_SECONDS))


def start_media_rescan(flask_app):
    """Start the periodic re-scan sweep once per process."""
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="media-rescan", daemon=True
        )
        _thread.start()
        return True


__all__ = [
    "DEFAULT_BATCH", "MIN_AGE_DAYS", "QUEUE_NAME", "SETTING_KEY", "rescan_enabled",
    "rescan_one", "run_media_rescan", "start_media_rescan", "stats",
]
