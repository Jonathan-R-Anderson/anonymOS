"""Where a given media object's bytes come from.

Once an object has been offloaded, the DHT is its SOURCE OF TRUTH and the local
store is not consulted. That is deliberate and was asked for explicitly: the
point of the exercise is to stop paying for the data server, and a silent
fallback would mask exactly the failure you need to see -- an object that is
supposed to be in the network but is not retrievable from it. A read that
should succeed and does not is a bug to fix, not something to paper over by
quietly serving the copy we are trying to stop keeping.

WHAT IS AND IS NOT OFFLOADED
----------------------------
Only USER-GENERATED media is ever offloaded: attachments, their thumbnails and
their hover previews, and only after clearing the banned-hash and NSFW gates
(services/storage_offload.py).

Everything else stays exactly where it is and is never published to volunteers:

  * the `static` bucket -- site assets, never touched by the offload query;
  * source watermarks, board banners, overlay/replacement images;
  * /aggregator-assets/** and /image-proxy -- remote bytes we mirror or proxy
    but do not own;
  * /nntp-watermark/** -- served straight from the database.

So this module is not "DHT with a fallback". It is a router: offloaded objects
come from the DHT, everything else comes from where it always came from.
"""
from shared import app, db


def _offloaded_ids(media_ids):
    """The subset of these ids marked offloaded. One query, not one per id."""
    from model.Media import Media
    from shared import db

    ids = [int(i) for i in media_ids if i is not None]
    if not ids:
        return set()
    try:
        rows = (
            db.session.query(Media.id)
            .filter(Media.id.in_(ids), Media.dht_offloaded_at.isnot(None))
            .all()
        )
        return {row[0] for row in rows}
    except Exception:
        db.session.rollback()
        app.logger.exception("media read: offload lookup failed")
        # Unknown -> treat as NOT offloaded, so a database hiccup degrades to
        # "serve from the local store" rather than "serve nothing".
        return set()


def is_offloaded(media_id):
    return int(media_id) in _offloaded_ids([media_id])


def attachment_bytes(media_id, media_ext, recent=False):
    """Attachment bytes, from the DHT when the object has been offloaded.

    Once local shard copies are pruned a miss is an I2P round trip, so the read
    goes through the W-TinyLFU cache and is collapsed by single-flight. `recent`
    marks content from an active thread, which is admitted without having to win
    a frequency comparison it could not yet win (services/media_cache.py).
    """
    from model.Media import storage as primary

    if not is_offloaded(media_id):
        return primary.read_attachment_bytes(media_id, media_ext)

    from services.media_cache import cache, single_flight
    from services.storage_offload import _DHTStorage, dht_enabled

    if not dht_enabled():
        # Marked offloaded but no DHT configured: that is a misconfiguration,
        # not a routing decision. Say so rather than silently reading local.
        app.logger.error(
            "media %s is marked offloaded but DHT_S3_ENDPOINT is unset", media_id
        )
        return None

    store = cache()
    key = "attachment:%s" % media_id
    hit = store.get(key)
    if hit is not None:
        return hit
    if store.is_unavailable(key):
        # Known-missing recently. Returning early is the point: without it one
        # unreachable object becomes a per-request I2P fetch storm.
        return None

    def _fetch():
        return _DHTStorage.get().read_attachment_bytes(media_id, media_ext)

    try:
        data = single_flight().do(key, _fetch)
    except Exception:
        store.mark_unavailable(key)
        app.logger.info("media read: DHT attachment miss for %s", media_id,
                        exc_info=True)
        return None
    if not data:
        store.mark_unavailable(key)
        return None
    store.put(key, data, recent=recent)
    return data


_PREFETCH_LIMIT = 40


def prefetch_thread(thread_id):
    """Warm the cache for every offloaded attachment in one thread.

    Prefetching per THREAD rather than per image is the whole point: I2P cost is
    dominated by round trips, so fetching a thread's twenty images one at a time
    as the browser asks for them costs twenty serial round trips. Issuing them
    together overlaps that latency.

    Runs in the background and never raises into the request -- a page must not
    get slower because a prefetch failed. Single-flight means a prefetch racing
    the real request for the same object collapses into one fetch rather than
    doubling the work.
    """
    from model.Post import Post

    try:
        rows = (
            db.session.query(Post.media)
            .filter(Post.thread == thread_id, Post.media.isnot(None))
            .limit(_PREFETCH_LIMIT)
            .all()
        )
    except Exception:
        db.session.rollback()
        return 0
    media_ids = [row[0] for row in rows if row[0]]
    if not media_ids:
        return 0
    offloaded = _offloaded_ids(media_ids)
    if not offloaded:
        # Nothing offloaded: reads are local and prefetching would only burn
        # time re-reading what the request path is about to read anyway.
        return 0

    from model.Media import Media

    try:
        targets = (
            db.session.query(Media.id, Media.ext)
            .filter(Media.id.in_(sorted(offloaded)))
            .all()
        )
    except Exception:
        db.session.rollback()
        return 0

    def _warm():
        with app.app_context():
            for media_id, media_ext in targets:
                try:
                    # recent=True: a thread being opened right now is exactly the
                    # content that should be admitted without first having to win
                    # a frequency comparison against the established hot set.
                    attachment_bytes(media_id, media_ext, recent=True)
                except Exception:
                    continue

    try:
        import shared as _shared

        _shared.spawn_native_thread(
            target=_warm, name="media-prefetch-%s" % thread_id, daemon=True
        )
    except Exception:
        app.logger.exception("media prefetch: could not start for thread %s", thread_id)
        return 0
    return len(targets)


def thumbnail_bytes(media_id):
    """Thumbnail bytes. Regenerable, so a DHT miss falls back to REGENERATING
    from the attachment (which itself comes from the DHT) rather than to the
    local copy -- the attachment is the thing that must be authoritative."""
    from model.Media import storage as primary

    if not is_offloaded(media_id):
        return primary.read_thumbnail_bytes(media_id)

    from services.storage_offload import _DHTStorage, dht_enabled

    if not dht_enabled():
        app.logger.error("media %s marked offloaded but DHT is unset", media_id)
        return None
    try:
        data = _DHTStorage.get().read_thumbnail_bytes(media_id)
        if data:
            return data
    except Exception:
        app.logger.info("media read: DHT thumb miss for %s", media_id, exc_info=True)
    return None


def video_preview_bytes(media_id):
    from model.Media import storage as primary

    if not is_offloaded(media_id):
        return primary.read_video_preview_bytes(media_id)

    from services.storage_offload import _DHTStorage, dht_enabled

    if not dht_enabled():
        app.logger.error("media %s marked offloaded but DHT is unset", media_id)
        return None
    try:
        return _DHTStorage.get().read_video_preview_bytes(media_id)
    except Exception:
        app.logger.info("media read: DHT preview miss for %s", media_id, exc_info=True)
        return None
