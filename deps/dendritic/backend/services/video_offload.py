"""Viewer-count-driven seed-offload controller for the /videos feature (Phase 2).

The server hosts every video torrent by default. Once a video is popular enough
that the browser swarm can carry it, the server LITERALLY deletes both of its
copies (the seedbox cache file and the origin object) and stops seeding,
letting the peers carry it. When viewers thin out again, the server re-acquires
the file from the still-present browser peers, re-stores the origin, and resumes
seeding.

State machine (evaluated by the elected leader worker every tick):

    seeding  --(viewers >= HIGH held for GRACE_TICKS ticks AND swarm peers >= K)-->  offloaded
                 [delete seedbox cache + delete origin object]
    offloaded --(viewers <= LOW, eager, no debounce)-->  seeding
                 [re-download from swarm, re-seed, restore origin]

Safety principles baked into the transitions:
  * Leader election (a Postgres advisory lock, distinct from the aggregator's)
    so only ONE of the 4 uWSGI workers ever acts.
  * The server keeps its copy until the swarm can demonstrably carry it:
    HIGH viewers must hold for GRACE_TICKS consecutive ticks AND the seedbox
    must actually see >= MIN_PEERS connected peers before any deletion.
  * A Redis outage is never read as "0 viewers" -- if Redis is unreachable the
    whole tick is skipped, so we never offload on an unknown viewer state.
  * The seedbox must be reachable (status readable) before any deletion, so we
    never delete when we cannot verify the swarm.
  * Re-acquisition is EAGER (no debounce) so we pull the file back while the
    last few peers still hold it. A failed re-acquire is logged loudly and the
    video stays flagged offloaded so the next tick retries -- data is never
    dropped on a transient failure.
  * offloaded=True is committed BEFORE the destructive deletes, so a crash
    mid-delete can only ever leave "data still present but flagged offloaded"
    (self-heals) -- never "flagged present but actually deleted".
"""

import os
import time as _time

import shared
from shared import app, db

# Reuse the aggregator's battle-tested autonomous-connection helpers for the
# advisory-lock bookkeeping (they are generic; only the lock id below differs).
from services.aggregator_sync.state import (
    _close_raw_connection,
    _open_background_sync_connection,
    _set_connection_autocommit,
)


# ---------------------------------------------------------------------------
# Config (defaults per the product owner; every value overridable via app.config
# or an identically named environment variable -- see shared.py registration).
# ---------------------------------------------------------------------------

_CONFIG_DEFAULTS = {
    "VIDEO_OFFLOAD_ENABLED": True,
    "VIDEO_OFFLOAD_HIGH": 5,
    "VIDEO_OFFLOAD_LOW": 4,
    "VIDEO_OFFLOAD_GRACE_TICKS": 3,
    "VIDEO_OFFLOAD_TICK_SECONDS": 7,
    "VIDEO_OFFLOAD_ADVISORY_LOCK_ID": 741312,
    "VIDEO_OFFLOAD_MIN_PEERS": 2,
}


def _cfg_int(key):
    default = _CONFIG_DEFAULTS[key]
    value = app.config.get(key, default)
    if value is None:
        value = os.getenv(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _cfg_bool(key):
    default = _CONFIG_DEFAULTS[key]
    value = app.config.get(key)
    if value is None:
        value = os.getenv(key)
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in ("", "0", "false", "no", "off")


def offload_advisory_lock_id():
    """The dedicated advisory lock id for the offload leader election. MUST
    differ from the aggregator's (741311) so the two subsystems each elect their
    own single leader instead of contending for one lock."""
    return _cfg_int("VIDEO_OFFLOAD_ADVISORY_LOCK_ID")


# ---------------------------------------------------------------------------
# Controller state (in-memory, per worker; only the leader's copy is consulted).
# ---------------------------------------------------------------------------

# video_id -> consecutive ticks with viewers >= HIGH while seeding (the debounce
# behind the retain-until-peers safeguard on the destructive direction).
_high_streak = {}
# video_ids whose re-acquire is running in a background worker (so we do not
# stack duplicate reacquire requests for the same video).
_reacquire_inflight = set()
_disabled_logged = False


# ---------------------------------------------------------------------------
# Leader election (own advisory lock + own autonomous connection). Mirrors
# aggregator_sync.state._background_sync_should_run but with a distinct lock id.
# ---------------------------------------------------------------------------

_lock_connection = None
_lock_owner = None
_db_down_logged = False


def _drop_lock_connection():
    global _lock_connection, _lock_owner
    connection = _lock_connection
    _lock_connection = None
    _lock_owner = None
    if connection is None:
        return
    try:
        _close_raw_connection(connection)
    except Exception:
        pass


def _offload_should_run():
    """True only in the single worker that holds the offload advisory lock."""
    global _lock_connection, _lock_owner, _db_down_logged

    backend = db.engine.url.get_backend_name()
    if backend not in ("postgresql", "postgres"):
        # SQLite/dev: a single process, so it is always the leader.
        return True

    if _lock_connection is not None:
        try:
            cursor = _lock_connection.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            _db_down_logged = False
            return True
        except Exception:
            _drop_lock_connection()

    raw_connection = None
    try:
        raw_connection = _open_background_sync_connection()
        _set_connection_autocommit(raw_connection, True)
        cursor = raw_connection.cursor()
        cursor.execute("SELECT pg_try_advisory_lock(%s)", (offload_advisory_lock_id(),))
        row = cursor.fetchone()
        cursor.close()
        acquired = bool(row and row[0])
    except Exception:
        if raw_connection is not None:
            try:
                _close_raw_connection(raw_connection)
            except Exception:
                pass
        _drop_lock_connection()
        if _db_down_logged is False:
            app.logger.warning("video_offload: database unavailable for leader election; will retry")
            _db_down_logged = True
        return False

    if acquired:
        _lock_connection = raw_connection
        _db_down_logged = False
        owner = "pid-%s" % os.getpid()
        if _lock_owner != owner:
            _lock_owner = owner
            app.logger.info(
                "video_offload: worker %s acquired the offload advisory lock (%s)",
                owner,
                offload_advisory_lock_id(),
            )
        return True

    _close_raw_connection(raw_connection)
    _db_down_logged = False
    return False


# ---------------------------------------------------------------------------
# Tick helpers
# ---------------------------------------------------------------------------


def _cleanup_after_error(exc):
    if shared.is_retryable_session_error(exc):
        shared.reset_sqlalchemy_session(dispose_engine=True)
        return
    try:
        db.session.rollback()
    except Exception:
        pass
    try:
        db.session.remove()
    except Exception:
        pass


def _status_by_hash(status):
    """Map info_hash (lowercase) -> seedbox status item."""
    result = {}
    if not status:
        return result
    for item in status.get("items", []) or []:
        info_hash = str(item.get("infoHash") or "").strip().lower()
        if info_hash:
            result[info_hash] = item
    return result


def _candidate_video_ids(redis_client, status_by_hash):
    """Videos worth evaluating this tick: those actively watched (Redis
    ``video:active``) UNION those the server is currently seeding (matched back
    from the seedbox status by torrent info-hash) UNION every already-offloaded
    video (so the safe re-onboard direction is always re-evaluated even if the
    active set was flushed or the app restarted)."""
    from model.Media import Media
    from model.Video import Video

    ids = set()

    if redis_client is not None:
        try:
            for raw in redis_client.smembers("video:active") or []:
                try:
                    ids.add(int(raw))
                except (TypeError, ValueError):
                    continue
        except Exception:
            pass

    hashes = [h for h in status_by_hash.keys() if h]
    if hashes:
        rows = (
            db.session.query(Video.id)
            .join(Media, Media.id == Video.media_id)
            .filter(db.func.lower(Media.torrent_info_hash).in_(hashes))
            .all()
        )
        for (video_id,) in rows:
            ids.add(video_id)

    for (video_id,) in db.session.query(Video.id).filter(Video.offloaded.is_(True)).all():
        ids.add(video_id)

    return ids


def _offload(video, media, info_hash, viewers, num_peers):
    """Destructive transition: the swarm can carry this video, so free both
    server copies and stop seeding. Ordered so a crash never deletes data the DB
    still believes is present."""
    from model.Media import storage
    from services.seedbox import unseed_media

    media_id = media.id
    media_ext = media.ext

    # 1) Commit the flag FIRST. If we crash after this, the worst state is
    #    "offloaded=True but copies still present" -- safe and self-healing.
    video.offloaded = True
    db.session.add(video)
    db.session.commit()
    app.logger.warning(
        "video_offload: OFFLOADING video %s (media %s) viewers=%s peers=%s -- deleting seedbox cache + origin; swarm carries it now",
        video.id,
        media_id,
        viewers,
        num_peers,
    )

    # 2) Stop seeding and unlink the seedbox cache file.
    unseed_result = unseed_media(info_hash)
    if not (unseed_result or {}).get("ok"):
        app.logger.error(
            "video_offload: unseed did not confirm for media %s info_hash %s: %s",
            media_id,
            info_hash,
            unseed_result,
        )

    # 3) Delete the origin object (attachment only; the thumbnail is preserved so
    #    the listing still renders while the video lives on the swarm).
    try:
        storage.delete_attachment_object(media_id, media_ext)
        app.logger.warning("video_offload: deleted origin object for media %s", media_id)
    except Exception:
        # Benign: the copy simply remains (extra safety, minor storage use).
        app.logger.exception(
            "video_offload: failed deleting origin object for media %s (kept -- data still present)",
            media_id,
        )

    _high_streak.pop(video.id, None)


def _spawn_reacquire(video_id, media_id, media_ext, info_hash):
    """Safe transition: re-download the offloaded video from the swarm, re-seed
    it, and restore the origin. Runs in a background thread so a slow swarm never
    stalls the leader tick. Only one re-acquire per video runs at a time."""
    if video_id in _reacquire_inflight:
        return
    from services.seedbox import _seedbox_media_base_url
    from services.torrent_media import public_magnet_url

    magnet = public_magnet_url(media_id, media_ext, info_hash, include_torrent_url=False)
    restore_url = "%s/videos/internal/restore/%d" % (_seedbox_media_base_url(), media_id)
    _reacquire_inflight.add(video_id)

    def _run():
        try:
            with app.app_context():
                from model.Video import Video
                from services.seedbox import reacquire_media

                result = reacquire_media(media_id, magnet, info_hash, restore_url)
                recovered = bool(
                    result
                    and str(result.get("infoHash") or "").strip().lower() == info_hash
                )
                restored = bool(result and result.get("restored"))
                if recovered and restored:
                    _clear_offloaded_flag(video_id)
                    app.logger.warning(
                        "video_offload: RE-ONBOARDED video %s (media %s) from swarm -- origin restored, seeding resumed",
                        video_id,
                        media_id,
                    )
                elif recovered and not restored:
                    # Swarm data recovered and re-seeding, but the origin restore
                    # POST did not confirm. No data lost (seedbox holds it); leave
                    # offloaded=True so the next tick retries and completes it.
                    app.logger.error(
                        "video_offload: reacquire of video %s (media %s) recovered the file but origin restore did not confirm (%s); will retry",
                        video_id,
                        media_id,
                        result,
                    )
                else:
                    app.logger.error(
                        "video_offload: reacquire FAILED for video %s (media %s) info_hash %s result=%s; leaving offloaded=True to retry",
                        video_id,
                        media_id,
                        info_hash,
                        result,
                    )
        except Exception:
            app.logger.exception(
                "video_offload: reacquire worker crashed for video %s (media %s)",
                video_id,
                media_id,
            )
            try:
                db.session.rollback()
            except Exception:
                pass
        finally:
            _reacquire_inflight.discard(video_id)

    shared.spawn_native_thread(
        target=_run,
        name="video-offload-reacquire-%s" % video_id,
        daemon=True,
    )


def _clear_offloaded_flag(video_id):
    from model.Video import Video

    for attempt in range(3):
        try:
            video = db.session.query(Video).filter(Video.id == video_id).one_or_none()
            if video is not None and video.offloaded:
                video.offloaded = False
                db.session.add(video)
                db.session.commit()
            else:
                db.session.rollback()
            return
        except Exception as exc:
            try:
                db.session.rollback()
            except Exception:
                pass
            if attempt == 2 or not shared.is_retryable_session_error(exc):
                raise
            shared.reset_sqlalchemy_session(dispose_engine=True)


def _run_tick():
    global _disabled_logged

    # Kill switch: the thread stays alive but does nothing while disabled.
    if _cfg_bool("VIDEO_OFFLOAD_ENABLED") is False:
        if _disabled_logged is False:
            app.logger.info("video_offload: disabled via VIDEO_OFFLOAD_ENABLED; controller idle")
            _disabled_logged = True
        return
    _disabled_logged = False

    from blueprints.videos import _redis, video_viewer_count
    from model.Video import Video
    from services.seedbox import seedbox_status

    # --- Redis liveness gate: never interpret an outage as "no viewers" ---
    redis_client = _redis()
    redis_up = False
    if redis_client is not None:
        try:
            redis_client.ping()
            redis_up = True
        except Exception:
            redis_up = False
    if redis_up is False:
        app.logger.warning(
            "video_offload: Redis unreachable -- skipping tick (viewer state UNKNOWN, never offloading on unknown)"
        )
        return

    # --- Seedbox gate: we must see the swarm before any deletion ---
    status = seedbox_status()
    if status is None:
        app.logger.warning("video_offload: seedbox status unreachable -- skipping tick (cannot verify swarm)")
        return
    status_by_hash = _status_by_hash(status)

    candidate_ids = _candidate_video_ids(redis_client, status_by_hash)
    if not candidate_ids:
        return

    high = _cfg_int("VIDEO_OFFLOAD_HIGH")
    low = _cfg_int("VIDEO_OFFLOAD_LOW")
    grace = _cfg_int("VIDEO_OFFLOAD_GRACE_TICKS")
    min_peers = _cfg_int("VIDEO_OFFLOAD_MIN_PEERS")

    for video_id in candidate_ids:
        video = db.session.query(Video).filter(Video.id == video_id).one_or_none()
        if video is None:
            _high_streak.pop(video_id, None)
            continue
        media = video.media
        info_hash = str(getattr(media, "torrent_info_hash", "") or "").strip().lower()
        if not info_hash:
            continue

        # Redis is confirmed up above; a spurious 0 here would only ever delay an
        # offload or trigger a (safe) re-onboard, so every failure mode is safe.
        viewers = video_viewer_count(video.id)
        entry = status_by_hash.get(info_hash)
        is_seeding = entry is not None
        num_peers = int(entry.get("numPeers") or 0) if entry else 0

        if video.offloaded:
            # SAFE direction, eager (no debounce): pull the file back while the
            # thinning swarm still holds it.
            if viewers <= low:
                _spawn_reacquire(video.id, media.id, media.ext, info_hash)
            _high_streak.pop(video.id, None)
            continue

        # DANGEROUS direction. Only offload something we are actually seeding.
        if is_seeding is False:
            _high_streak.pop(video.id, None)
            continue

        if viewers >= high:
            streak = _high_streak.get(video.id, 0) + 1
            _high_streak[video.id] = streak
            # retain-until-peers: HIGH must hold GRACE_TICKS ticks AND the
            # seedbox must actually see >= MIN_PEERS connected peers.
            if streak >= grace and num_peers >= min_peers:
                _offload(video, media, info_hash, viewers, num_peers)
        else:
            _high_streak.pop(video.id, None)

    # Forget streaks for videos that dropped out of the candidate set.
    for stale in list(_high_streak.keys()):
        if stale not in candidate_ids:
            _high_streak.pop(stale, None)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def start_offload_controller(flask_app):
    """Spawn the offload controller daemon thread. Non-fatal on failure; the
    thread starts even when VIDEO_OFFLOAD_ENABLED is False (it then idles) so the
    flag can be flipped at runtime without a restart."""

    def _loop():
        _time.sleep(12)  # let startup (aggregator/news) settle first
        while True:
            tick_seconds = _CONFIG_DEFAULTS["VIDEO_OFFLOAD_TICK_SECONDS"]
            try:
                with flask_app.app_context():
                    tick_seconds = _cfg_int("VIDEO_OFFLOAD_TICK_SECONDS")
                    try:
                        if _offload_should_run():
                            _run_tick()
                    except Exception as exc:
                        _cleanup_after_error(exc)
                        flask_app.logger.exception("video_offload: tick failed")
            except Exception:
                flask_app.logger.exception("video_offload: unexpected loop error")
            _time.sleep(max(1, tick_seconds))

    shared.spawn_native_thread(target=_loop, name="video-offload-controller", daemon=True)
    flask_app.logger.info(
        "video_offload: controller thread started (advisory lock id %s, tick %ss)",
        offload_advisory_lock_id(),
        _cfg_int("VIDEO_OFFLOAD_TICK_SECONDS"),
    )
