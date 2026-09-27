"""Overlay-blocking: hide a file behind an operator-uploaded image.

A middle ground between "leave it up" and "delete it". A media row flagged
`overlay_blocked` is still stored and still visible to anyone signed into a slip
account; everyone else gets a single operator-uploaded overlay image instead.

THE GATE LIVES IN THE SERVING ROUTES. NOT IN TEMPLATES.
-------------------------------------------------------
Hiding a thumbnail in a template changes what the page shows, not what the server
sends: the real URL (/upload/<id>/fetch, /upload/thumb/<id>, /image-proxy,
/aggregator-assets/...) stays directly fetchable by anyone who reads the HTML,
guesses an id, or has an old link. So every route that returns bytes calls
`should_substitute()` and, when it is true, returns `overlay_response()` instead.
`/upload/<id>` is gated too even though it only returns a MAGNET link — a magnet
is a way to fetch the real bytes.

CACHING IS THE FOOT-GUN
-----------------------
The response now depends on the viewer's cookie, so a shared cache must never
reuse one viewer's copy for another. Every gated response — the overlay AND the
real bytes served to a signed-in viewer — gets `Cache-Control: private, no-store`
plus `Vary: Cookie` via `harden_response()`. Without that, one signed-in view
could populate a cache that then serves the real image to everyone.

COST
----
`get_slip()` costs TWO DB queries (model/Slip.py) — a Session lookup then a Slip
lookup — and a catalog page fetches dozens of images. So the slip check runs ONLY
after `media.overlay_blocked` is found true, which is rare. Unflagged media pays
nothing beyond a boolean read on a row already loaded.
"""
import io
import threading

from flask import g, has_request_context, make_response

from model.SiteSetting import get_setting, set_setting
from shared import app, db

# SiteSetting holding the Media id of the overlay image, mirroring the
# source-watermark convention in source_watermarks.py.
OVERLAY_SETTING = "overlay_block_media_id"

# The overlay is served on every blocked-image request, so its bytes are cached in
# process rather than re-read from the object store each time. Keyed by media id so
# uploading a new overlay invalidates it implicitly.
_overlay_cache_lock = threading.Lock()
_overlay_cache = {"media_id": None, "payload": None}


def overlay_media_id():
    raw = (get_setting(OVERLAY_SETTING, "") or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def set_overlay_media_id(media_id):
    """Point the overlay at a Media row (or clear it with None). Does NOT commit."""
    set_setting(OVERLAY_SETTING, "" if media_id is None else str(int(media_id)))
    with _overlay_cache_lock:
        _overlay_cache["media_id"] = None
        _overlay_cache["payload"] = None
    return media_id


def overlay_summary():
    """Admin-panel view of the configured overlay image."""
    from model.Media import Media, storage

    media_id = overlay_media_id()
    if media_id is None:
        return {"media_id": None, "image_url": None, "thumb_url": None}
    row = db.session.query(Media.ext).filter(Media.id == media_id).one_or_none()
    if row is None:
        return {"media_id": media_id, "image_url": None, "thumb_url": None, "missing": True}
    return {
        "media_id": media_id,
        "image_url": storage.get_media_url(media_id, row.ext),
        "thumb_url": storage.get_thumb_url(media_id),
    }


def _generated_placeholder():
    """Fallback when no overlay image has been uploaded yet.

    Deliberately NOT the real bytes: a flag that silently stops working because
    the operator has not uploaded an image yet would be the worst outcome. Reuses
    the storage provider's labelled placeholder so this needs no new asset.
    """
    from model.Media import storage

    try:
        buffer, _is_animated = storage._placeholder_thumbnail("BLOCKED")
        return buffer.getvalue(), "image/jpeg"
    except Exception:
        app.logger.exception("overlay: could not build the fallback placeholder")
        # A 1x1 GIF, so the route can still answer with an image rather than 500.
        return (
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
            b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
            b"\x00\x02\x02D\x01\x00;",
            "image/gif",
        )


def overlay_payload():
    """(bytes, mimetype) for the overlay image. Never None."""
    from model.Media import Media, storage

    media_id = overlay_media_id()
    if media_id is None:
        return _generated_placeholder()

    with _overlay_cache_lock:
        if _overlay_cache["media_id"] == media_id and _overlay_cache["payload"]:
            return _overlay_cache["payload"]

    row = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if row is None:
        app.logger.warning("overlay: configured media %s no longer exists", media_id)
        return _generated_placeholder()
    try:
        data = storage.read_attachment_bytes(row.id, row.ext)
    except Exception as exc:
        # Includes MissingAttachmentError: whatever the reason, falling back to the
        # generated placeholder is always safer than serving the real bytes.
        app.logger.warning("overlay: could not read media %s (%s)", media_id, exc)
        return _generated_placeholder()

    payload = (data, row.mimetype or "image/png")
    with _overlay_cache_lock:
        _overlay_cache["media_id"] = media_id
        _overlay_cache["payload"] = payload
    return payload


def viewer_may_see_real_media():
    """True when the request carries a valid slip session.

    Cached per request on flask.g: one image request can consult this more than
    once (thumbnail + magnet), and each miss costs two DB queries.
    """
    if not has_request_context():
        # Background work (the re-scan sweep, imports) is not a viewer. Treat it as
        # NOT privileged so nothing accidentally leaks real bytes through a code
        # path that assumes a request.
        return False
    cached = getattr(g, "_overlay_viewer_signed_in", None)
    if cached is not None:
        return cached
    value = False
    try:
        from model.Slip import get_slip

        value = get_slip() is not None
    except Exception:
        db.session.rollback()
        app.logger.exception("overlay: could not resolve the viewer's slip")
        value = False
    g._overlay_viewer_signed_in = value
    return value


# Automated NSFW blocks write a reason of "nsfw:<score>" — see
# aggregator_sync/media._persist_nsfw_refusal and services/media_rescan. That
# prefix is how a serving route tells an NSFW rejection from a manual ban or an
# antivirus hit, which are shown differently.
NSFW_REASON_PREFIX = "nsfw:"


def reason_is_nsfw(reason):
    return str(reason or "").strip().lower().startswith(NSFW_REASON_PREFIX)


def replacement_response(sha256=None, reason=None):
    """The operator-uploaded image, served in place of NSFW-blocked content.

    Used when the AUTOMATED filter rejected an image. Unlike the overlay gate this
    is NOT slip-gated: for auto-blocked content the original bytes were usually
    never stored at all (save_attachment raises before the Media row is created),
    so there is nothing to reveal to a signed-in viewer — and an image the filter
    judged NSFW should not be shown on the strength of being logged in.
    """
    data, mimetype = overlay_payload()
    response = make_response(data)
    response.headers["Content-Type"] = mimetype or "image/png"
    response.headers["Content-Disposition"] = "inline"
    response.headers["X-Media-Replaced"] = "nsfw"
    if sha256:
        response.headers["X-Media-Hash"] = str(sha256)[:12]
    # Cacheable by the VIEWER but not by shared caches: the substitution does not
    # depend on the cookie, but keeping it private avoids any interaction with the
    # slip-gated overlay responses on the same routes.
    return harden_response(response)


def blocked_hash_replacement(sha256):
    """Replacement response when this hash was blocked BY THE NSFW FILTER.

    Returns None when the hash is not blocked, or was blocked for some other
    reason (manual ban, antivirus) — those keep their existing handling.
    """
    if not sha256:
        return None
    from model.BlockedMediaHash import get_blocked_media_hash

    try:
        blocked = get_blocked_media_hash(sha256)
    except Exception:
        db.session.rollback()
        app.logger.exception("overlay: blocked-hash lookup failed")
        return None
    if blocked is None or not reason_is_nsfw(getattr(blocked, "reason", None)):
        return None
    return replacement_response(sha256=sha256, reason=getattr(blocked, "reason", None))


def media_is_overlay_blocked(media):
    return bool(media is not None and getattr(media, "overlay_blocked", False))


def should_substitute(media):
    """Whether THIS request must be served the overlay instead of `media`."""
    if not media_is_overlay_blocked(media):
        return False
    return not viewer_may_see_real_media()


# Whether ANY media is overlay-blocked. Cached briefly so the sha256 lookup in
# media_for_sha256() can be skipped entirely on sites with none — otherwise every
# proxied/aggregator image would pay for a query to learn there is nothing to find.
# 30s matches the BannedImageFingerprint cache convention.
_EXISTS_TTL_SECONDS = 30
_exists_cache = {"at": 0.0, "value": False}


def any_overlay_blocked():
    import time

    from model.Media import Media

    now = time.time()
    if now - _exists_cache["at"] < _EXISTS_TTL_SECONDS:
        return _exists_cache["value"]
    try:
        value = (
            db.session.query(Media.id).filter(Media.overlay_blocked.is_(True)).first()
            is not None
        )
    except Exception:
        db.session.rollback()
        app.logger.exception("overlay: existence check failed")
        # Fail toward DOING the per-image lookup: a false "nothing is blocked"
        # would serve real bytes for a flagged file.
        return True
    _exists_cache["at"] = now
    _exists_cache["value"] = value
    return value


def invalidate_exists_cache():
    _exists_cache["at"] = 0.0
    _exists_cache["value"] = False


def media_for_sha256(sha256):
    """The Media row for these bytes, for routes that serve files, not ids.

    /aggregator-assets and /image-proxy serve bytes addressed by path or URL, so
    they have no media id to check. A mirrored copy shares the same sha256, so the
    flag can still be found. Returns None when nothing matches.
    """
    if not sha256:
        return None
    from model.Media import Media

    try:
        return (
            db.session.query(Media)
            .filter(Media.sha256 == sha256, Media.overlay_blocked.is_(True))
            .first()
        )
    except Exception:
        db.session.rollback()
        app.logger.exception("overlay: sha256 lookup failed")
        return None


def harden_response(response):
    """Mark a response as viewer-specific so no shared cache reuses it."""
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    existing_vary = response.headers.get("Vary")
    response.headers["Vary"] = ("%s, Cookie" % existing_vary) if existing_vary else "Cookie"
    return response


def overlay_response(media=None):
    """The overlay image as a Flask response, safe to return from any route."""
    data, mimetype = overlay_payload()
    response = make_response(data)
    response.headers["Content-Type"] = mimetype or "image/png"
    response.headers["Content-Disposition"] = "inline"
    # So an operator can confirm the gate fired without reading the logs.
    response.headers["X-Media-Overlay"] = "blocked"
    if media is not None and getattr(media, "id", None):
        response.headers["X-Media-Id"] = str(media.id)
    return harden_response(response)


def overlay_bytes_io():
    """The overlay as a BytesIO, for callers that need a stream (send_file)."""
    data, mimetype = overlay_payload()
    return io.BytesIO(data), mimetype


def set_media_overlay_blocked(media, blocked=True):
    """Flag/unflag one Media row. Caller commits."""
    if media is None:
        return False
    media.overlay_blocked = bool(blocked)
    db.session.add(media)
    invalidate_exists_cache()
    return True


__all__ = [
    "NSFW_REASON_PREFIX", "OVERLAY_SETTING", "any_overlay_blocked",
    "blocked_hash_replacement", "harden_response", "invalidate_exists_cache",
    "media_for_sha256", "reason_is_nsfw", "replacement_response",
    "media_is_overlay_blocked", "overlay_bytes_io", "overlay_media_id", "overlay_payload",
    "overlay_response", "overlay_summary", "set_media_overlay_blocked",
    "set_overlay_media_id", "should_substitute", "viewer_may_see_real_media",
]
