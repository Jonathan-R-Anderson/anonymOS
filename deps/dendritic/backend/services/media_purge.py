"""Search for and PURGE specific media (explicit content) from the DHT store and
the database, blocklisting the content hash so it cannot be re-uploaded.

A purge is the strong form of deletion:
  1. blocklist the content sha256 (BlockedMediaHash) so re-upload is refused;
  2. delete the object (attachment + thumbnail + preview) from BOTH object
     stores -- the site's primary store and the storage node's DHT gateway;
  3. delete every row that references the media (videos, then posts) and the
     Media row itself.

WHAT STEP 2 DOES NOT DO -- this was wrong here for a while and is worth stating.
`Media.delete_attachment()` calls `model.Media.storage`, which is the PRIMARY
store. Once media is offloaded, reads come from the DHT gateway instead
(services/media_read.py), so deleting only the primary left the purged bytes
live on the node and still fetchable by key. Both stores are now deleted from.

Even with both gone, shards of an offloaded object that were already placed on
OTHER PEERS are not deleted and cannot be: the peer protocol has no delete
operation. See services/dht_object_purge.py, which reports that per layer
instead of hiding it behind one word. This module remains the bulk moderation
tool; use that page when what matters is knowing exactly how far a purge got.

Search is deliberately over the metadata the server still holds (sha256,
nsfw_score, extension, and post body/subject/board), which is exactly what an
admin needs to find "explicit segments of data" to purge -- the bytes themselves
never have to be pulled back from the DHT to locate them.
"""
from shared import app, db
from model.Media import Media, storage
from model.Post import Post
from model.Thread import Thread
from model.Board import Board
from model.BlockedMediaHash import block_media_hash

_IMAGE_EXTS = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "avif"]
_VIDEO_EXTS = ["mp4", "webm", "mov", "mkv", "m4v", "ogg"]


def _context_for(media_id):
    """Posts / threads / boards that embed this media (for the results table)."""
    try:
        rows = (
            db.session.query(Post.id, Post.thread, Post.body, Board.name, Board.uri)
            .join(Thread, Post.thread == Thread.id)
            .join(Board, Thread.board == Board.id)
            .filter(Post.media == media_id)
            .limit(5).all()
        )
    except Exception:
        db.session.rollback()
        return []
    return [{"post_id": r[0], "thread_id": r[1], "excerpt": (r[2] or "")[:120],
             "board": r[3] or r[4] or ""} for r in rows]


def search(text=None, sha256=None, media_id=None, min_nsfw=None, kind=None, limit=100):
    """Find media matching any combination of: exact sha256, exact media id, a
    minimum NSFW score, a kind (image|video), and a keyword in post body/subject."""
    query = db.session.query(Media)
    if sha256:
        query = query.filter(Media.sha256 == sha256.strip().lower())
    if media_id:
        try:
            query = query.filter(Media.id == int(media_id))
        except (TypeError, ValueError):
            pass
    if min_nsfw not in (None, ""):
        try:
            query = query.filter(Media.nsfw_score.isnot(None), Media.nsfw_score >= float(min_nsfw))
        except (TypeError, ValueError):
            pass
    if kind == "image":
        query = query.filter(Media.ext.in_(_IMAGE_EXTS))
    elif kind == "video":
        query = query.filter(Media.ext.in_(_VIDEO_EXTS))
    if text:
        like = "%" + text.strip() + "%"
        media_ids = {
            m for (m,) in db.session.query(Post.media).filter(
                Post.media.isnot(None),
                db.or_(Post.body.ilike(like), Post.subject.ilike(like)),
            ).distinct()
        }
        if not media_ids:
            return []
        query = query.filter(Media.id.in_(media_ids))

    rows = query.order_by(Media.id.desc()).limit(min(int(limit or 100), 500)).all()
    results = []
    for media in rows:
        thumb = None
        try:
            thumb = storage.get_thumb_url(media.id)
        except Exception:
            pass
        results.append({
            "id": media.id, "ext": media.ext, "sha256": media.sha256,
            "nsfw_score": media.nsfw_score, "thumb_url": thumb,
            "context": _context_for(media.id),
        })
    return results


def purge_media_id(media_id, reason=None, acting_slip_id=None):
    """Purge one media object: blocklist its hash, delete it from the DHT gateway,
    and delete every referencing row + the Media row. Returns a per-item result."""
    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if media is None:
        return {"media_id": media_id, "ok": False, "error": "not found"}
    sha = media.sha256
    result = {"media_id": media_id, "sha256": sha, "posts_deleted": 0, "videos_deleted": 0}

    if sha:
        try:
            block_media_hash(sha, reason=(reason or "admin purge"), created_by_slip_id=acting_slip_id)
        except Exception:
            app.logger.exception("media_purge: blocklist failed for media %s", media_id)

    media_ext = media.ext
    try:
        media.delete_attachment()
        result["primary_deleted"] = True
    except Exception:
        result["primary_deleted"] = False
        app.logger.exception("media_purge: primary delete_attachment failed for media %s", media_id)

    # The DHT gateway is a DIFFERENT endpoint and needs its own delete. Skipping
    # it is what left offloaded media serving happily after a "purge".
    result["dht_deleted"] = None
    try:
        from services.storage_offload import _DHTStorage, dht_write_enabled

        if dht_write_enabled():
            _DHTStorage.get().delete_attachment(media_id, media_ext)
            result["dht_deleted"] = True
    except Exception:
        result["dht_deleted"] = False
        app.logger.exception("media_purge: DHT delete failed for media %s", media_id)

    # Otherwise this worker keeps serving the bytes out of RAM: media_read
    # consults the cache before anything else.
    try:
        from services.media_cache import cache

        cache().drop("attachment:%d" % media_id)
        cache().mark_unavailable("attachment:%d" % media_id)
    except Exception:
        app.logger.exception("media_purge: cache eviction failed for media %s", media_id)

    try:
        # Videos reference media without ON DELETE CASCADE, so remove them first.
        from model.Video import Video
        result["videos_deleted"] = db.session.query(Video).filter(
            Video.media_id == media_id
        ).delete(synchronize_session=False)
    except Exception:
        app.logger.exception("media_purge: video delete failed for media %s", media_id)

    result["posts_deleted"] = db.session.query(Post).filter(
        Post.media == media_id
    ).delete(synchronize_session=False)
    db.session.query(Media).filter(Media.id == media_id).delete(synchronize_session=False)
    db.session.commit()
    result["ok"] = True
    return result


def purge_media_ids(ids, reason=None, acting_slip_id=None):
    out = []
    for raw in ids:
        try:
            out.append(purge_media_id(int(raw), reason=reason, acting_slip_id=acting_slip_id))
        except Exception as exc:
            db.session.rollback()
            out.append({"media_id": raw, "ok": False, "error": str(exc)})
    return out
