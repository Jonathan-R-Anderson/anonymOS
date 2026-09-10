import os
import time

import requests
from sqlalchemy.exc import IntegrityError, OperationalError

from shared import app, db, is_retryable_session_error, reset_sqlalchemy_session, spawn_native_thread
from services.torrent_media import public_magnet_url, torrent_display_name


def _seedbox_base_url():
    return (app.config.get("SEEDBOX_SEED_URL") or "http://seedbox:8781").rstrip("/")


def _seedbox_seed_url():
    return _seedbox_base_url() + "/seed"


def _seedbox_media_base_url():
    configured = (
        app.config.get("SEEDBOX_MEDIA_BASE_URL")
        or os.environ.get("SEEDBOX_MEDIA_BASE_URL")
        or "http://maniwani:3032"
    )
    return str(configured).rstrip("/")


def _seedbox_media_source_url(media_id, fallback_url):
    if media_id:
        return "%s/upload/%d/fetch" % (_seedbox_media_base_url(), media_id)
    return fallback_url


def _seed_request_metadata(
    media_id,
    fallback_url,
    media_ext=None,
    expected_info_hash=None,
    piece_length=None,
):
    source_url = _seedbox_media_source_url(media_id, fallback_url)
    metadata = {
        "media_id": media_id,
        "source_url": source_url,
        "ext": media_ext,
        "expected_info_hash": expected_info_hash,
        "piece_length": piece_length,
        "display_name": torrent_display_name(media_id, media_ext) if media_id and media_ext else None,
    }

    payload = {"url": source_url}
    if media_id:
        payload["mediaId"] = int(media_id)
    if metadata["display_name"]:
        payload["name"] = metadata["display_name"]
    if metadata["piece_length"]:
        payload["pieceLength"] = int(metadata["piece_length"])
    if metadata["expected_info_hash"]:
        payload["expectedInfoHash"] = str(metadata["expected_info_hash"])

    if not media_id or (metadata["ext"] and metadata["expected_info_hash"] and metadata["piece_length"]):
        return payload, metadata

    from model.Media import Media

    media = (
        db.session.query(
            Media.id,
            Media.ext,
            Media.torrent_info_hash,
            Media.torrent_piece_length,
        )
        .filter(Media.id == media_id)
        .one_or_none()
    )
    if media is None:
        return payload, metadata

    metadata["ext"] = metadata["ext"] or media.ext
    metadata["expected_info_hash"] = metadata["expected_info_hash"] or media.torrent_info_hash
    metadata["piece_length"] = metadata["piece_length"] or media.torrent_piece_length
    metadata["display_name"] = metadata["display_name"] or torrent_display_name(media.id, media.ext)

    if metadata["display_name"]:
        payload["name"] = metadata["display_name"]
    if media_id:
        payload["mediaId"] = int(media_id)
    if metadata["piece_length"]:
        payload["pieceLength"] = int(metadata["piece_length"])
    if metadata["expected_info_hash"]:
        payload["expectedInfoHash"] = str(metadata["expected_info_hash"])
    return payload, metadata


def _background_sleep(seconds):
    try:
        import gevent
        gevent.sleep(seconds)
    except ImportError:
        time.sleep(seconds)


def _invalidate_media_caches(media_id):
    from model.ImportedMedia import ImportedMedia
    from model.Post import Post
    from model.Thread import Thread
    from services.aggregator_sync.media import invalidate_post_render_cache, invalidate_thread_cache
    from thread import invalidate_board_cache

    board_ids = set()
    post_ids = set()
    thread_ids = set()

    for thread_id, board_id in (
        db.session.query(ImportedMedia.thread_id, Thread.board)
        .join(Thread, Thread.id == ImportedMedia.thread_id)
        .filter(ImportedMedia.media_id == media_id)
        .all()
    ):
        thread_ids.add(thread_id)
        board_ids.add(board_id)

    for post_id, thread_id, board_id in (
        db.session.query(Post.id, Post.thread, Thread.board)
        .join(Thread, Thread.id == Post.thread)
        .filter(Post.media == media_id)
        .all()
    ):
        post_ids.add(post_id)
        thread_ids.add(thread_id)
        board_ids.add(board_id)

    for post_id in post_ids:
        invalidate_post_render_cache(post_id)
    for thread_id in thread_ids:
        invalidate_thread_cache(thread_id)
    for board_id in board_ids:
        invalidate_board_cache(board_id)


def _store_magnet(media_id, magnet_url):
    from model.Media import Media
    from model.ImageMagnet import sync_image_magnet_url

    attempts = 5
    for attempt in range(attempts):
        try:
            media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
            if media is None:
                raise LookupError("media %s is not committed yet" % media_id)

            _resolved_url, changed = sync_image_magnet_url(media, magnet_url)
            if changed:
                db.session.add(media)
                db.session.commit()
                try:
                    _invalidate_media_caches(media_id)
                except Exception as exc:
                    app.logger.warning("seedbox: failed to invalidate caches for media %s: %s", media_id, exc)
            else:
                db.session.rollback()
            return changed
        except Exception as exc:
            db.session.rollback()
            retryable = (
                isinstance(exc, (IntegrityError, OperationalError, LookupError))
                or is_retryable_session_error(exc)
            )
            if retryable is False or attempt + 1 >= attempts:
                raise
            app.logger.warning(
                "seedbox: retrying magnet store %s/%s for media %s after %s",
                attempt + 1,
                attempts,
                media_id,
                exc,
            )
            reset_sqlalchemy_session(dispose_engine=True)
            _background_sleep(1 + attempt)


def seed_media_background(
    media_id,
    object_url,
    media_ext=None,
    expected_info_hash=None,
    piece_length=None,
):
    """Fire-and-forget: call the seedbox, then persist the returned magnet URL."""
    def _run():
        try:
            with app.app_context():
                request_payload, metadata = _seed_request_metadata(
                    media_id,
                    object_url,
                    media_ext=media_ext,
                    expected_info_hash=expected_info_hash,
                    piece_length=piece_length,
                )

            source_url = request_payload["url"]
            attempts = 5
            for attempt in range(attempts):
                resp = requests.post(_seedbox_seed_url(), json=request_payload, timeout=60)
                if resp.ok:
                    response_payload = resp.json() or {}
                    seeded_info_hash = str(response_payload.get("infoHash") or "").strip().lower() or None
                    expected_hash = str(metadata.get("expected_info_hash") or "").strip().lower() or None
                    if expected_hash and seeded_info_hash and seeded_info_hash != expected_hash:
                        app.logger.warning(
                            "seedbox: info hash mismatch for media %s via %s: expected %s got %s",
                            media_id,
                            source_url,
                            expected_hash,
                            seeded_info_hash,
                        )
                        return
                    confirmed_info_hash = seeded_info_hash or expected_hash
                    magnet_url = (response_payload.get("magnetUrl") or "").strip() or None
                    if not magnet_url and confirmed_info_hash and metadata.get("ext"):
                        magnet_url = public_magnet_url(
                            media_id,
                            metadata["ext"],
                            confirmed_info_hash,
                            include_torrent_url=False,
                        )
                    if not magnet_url:
                        return
                    with app.app_context():
                        changed = _store_magnet(media_id, magnet_url)
                        if changed:
                            app.logger.info("seedbox: stored magnet for media %s", media_id)
                    return

                detail = None
                try:
                    detail = (resp.json() or {}).get("error")
                except Exception:
                    detail = resp.text
                if attempt + 1 >= attempts:
                    app.logger.warning(
                        "seedbox seed failed for media %s via %s: HTTP %s %s",
                        media_id,
                        source_url,
                        resp.status_code,
                        detail or "",
                    )
                    return
                app.logger.warning(
                    "seedbox seed retry %s/%s for media %s via %s after HTTP %s %s",
                    attempt + 1,
                    attempts,
                    media_id,
                    source_url,
                    resp.status_code,
                    detail or "",
                )
                _background_sleep(2 + attempt)
        except Exception as exc:
            app.logger.warning("seedbox: seed_media_background failed for media %s: %s", media_id, exc)

    try:
        import gevent
        gevent.spawn(_run)
    except ImportError:
        spawn_native_thread(target=_run, daemon=True)


# ---------------------------------------------------------------------------
# Phase 2 offload controller helpers (unseed / reacquire / status).
# These are synchronous, tolerant, and safe to call from the offload loop.
# ---------------------------------------------------------------------------


def seedbox_status(timeout=5):
    """GET the seedbox /status and return the parsed dict, or None if the
    seedbox is unreachable. The controller uses this to learn each info hash's
    numPeers and whether the server is still seeding it. Returning None (rather
    than an empty payload) lets the caller distinguish "seedbox down" from
    "seedbox up but seeding nothing" and refuse to offload on the former."""
    url = "%s/status" % _seedbox_base_url()
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        app.logger.warning("seedbox: seedbox_status unavailable: %s", exc)
        return None
    if not isinstance(payload, dict):
        app.logger.warning("seedbox: seedbox_status returned a non-object payload")
        return None
    payload.setdefault("items", [])
    return payload


def unseed_media(info_hash, timeout=15):
    """Stop seeding *info_hash* and delete its seedbox cache file (DELETE
    /seed/:infoHash). Tolerant of every failure; returns a dict with an ``ok``
    flag so the offload path can log (but never crash) when the seedbox does not
    confirm. A 404 means the seedbox already was not seeding it, which is the
    desired end state, so that is reported as ok too."""
    normalized = str(info_hash or "").strip().lower()
    if not normalized:
        return {"ok": False, "error": "missing info_hash"}
    url = "%s/seed/%s" % (_seedbox_base_url(), normalized)
    try:
        resp = requests.delete(url, timeout=timeout)
    except Exception as exc:
        app.logger.warning("seedbox: unseed_media failed for %s: %s", normalized, exc)
        return {"ok": False, "error": str(exc)}
    try:
        payload = resp.json() or {}
    except Exception:
        payload = {}
    payload["status_code"] = resp.status_code
    # 200 => stopped + cache unlinked; 404 => was not seeding (already gone).
    payload["ok"] = bool(resp.ok) or resp.status_code == 404
    if not payload["ok"]:
        app.logger.warning(
            "seedbox: unseed_media for %s returned HTTP %s %s",
            normalized,
            resp.status_code,
            payload.get("error") or "",
        )
    return payload


def reacquire_media(media_id, magnet_url, expected_info_hash, restore_url, timeout=120):
    """Ask the seedbox to re-download *expected_info_hash* from the still-present
    browser swarm (POST /reacquire), re-seed it, and POST the recovered bytes to
    *restore_url* so the backend can rebuild the deleted origin object.

    Returns the seedbox JSON ({infoHash, restored}) on an HTTP 200, else None.
    Logs loudly on every failure — the caller keeps the video flagged offloaded
    and retries on the next tick, so a transient failure never loses data."""
    base = _seedbox_base_url()
    payload = {
        "mediaId": int(media_id) if media_id else None,
        "magnet": magnet_url,
        "expectedInfoHash": str(expected_info_hash or "").strip().lower() or None,
        "restoreUrl": restore_url,
    }
    try:
        resp = requests.post("%s/reacquire" % base, json=payload, timeout=timeout)
    except Exception as exc:
        app.logger.error(
            "seedbox: reacquire_media network failure for media %s (%s): %s",
            media_id,
            expected_info_hash,
            exc,
        )
        return None
    try:
        data = resp.json() or {}
    except Exception:
        data = {}
    if not resp.ok:
        detail = data.get("error") if isinstance(data, dict) else None
        app.logger.error(
            "seedbox: reacquire_media FAILED for media %s (%s): HTTP %s %s",
            media_id,
            expected_info_hash,
            resp.status_code,
            detail or (resp.text or "")[:200],
        )
        return None
    return data if isinstance(data, dict) else None
