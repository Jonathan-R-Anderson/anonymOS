import io
import mimetypes
import os
import threading
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import cache
import requests
from model.ImageMagnet import magnet_needs_seedbox_seed
from model.Media import BlockedMediaError, Media, MissingAttachmentError, storage
from model.PostPresentation import media_row_payload
from model.Post import CONTEXT_CATALOG, CONTEXT_THREAD, Post, post_render_cache_key
from model.PostRemoval import PostRemoval
from model.Reply import Reply, REPLY_REGEXP
from model.Thread import Thread
from shared import app, db

from services.seedbox import seed_media_background

from .config import (
    FALLBACK_IMAGE_PATH,
    MAX_IMPORTED_SOURCE_ID_LENGTH,
    MAX_IMPORTED_BODY_LENGTH,
    mirror_inline_sleep_budget_seconds,
    mirror_max_retries,
    mirror_request_delay_seconds,
    mirror_retry_backoff_seconds,
    mirror_user_agent,
)
from .assets import imported_media_payload
from .scraper_db import aggregator_db_path, scraper_data_dir
from .state import _sync_log
from .text import (
    _clip_imported_text,
    _translated_imported_body,
    normalize_external_media_url,
    normalize_source_url,
    row_value,
)


_mirror_rate_lock = threading.Lock()
_mirror_next_request_at: Dict[str, float] = {}
_imported_media_repair_lock = threading.Lock()
_pending_imported_media_repairs = set()
_GENERIC_IMPORT_MIMETYPES = {
    "",
    "application/octet-stream",
    "binary/octet-stream",
    "application/unknown",
    "unknown/unknown",
}


def _magnet_needs_seedbox_seed(magnet_url: Optional[str]) -> bool:
    return magnet_needs_seedbox_seed(magnet_url)


def _queue_seedbox_for_media(media) -> bool:
    if media is None or getattr(media, "id", None) is None:
        return False
    mimetype = str(getattr(media, "mimetype", "") or "").lower()
    if mimetype.startswith("image/") is False:
        return False
    try:
        seed_media_background(
            media.id,
            storage.get_attachment_fetch_url(media.id, media.ext),
            media_ext=media.ext,
            expected_info_hash=getattr(media, "torrent_info_hash", None),
            piece_length=getattr(media, "torrent_piece_length", None),
        )
        return True
    except Exception as exc:
        _sync_log("Failed to queue seedbox seeding for media %s: %s" % (media.id, exc))
        return False


# Wrap mirrored bytes in a file-like object for attachment storage.
class _MirrorFile:
    # Initialize the in-memory mirrored file wrapper.
    def __init__(self, filename, content_type, data, source_url=None):
        self.filename = filename
        self.content_type = content_type
        self.data = data
        self.source_url = source_url
        self._pos = 0

    # Read bytes from the mirrored file buffer.
    def read(self, size=-1):
        if size == -1:
            res = self.data[self._pos:]
            self._pos = len(self.data)
            return res
        else:
            res = self.data[self._pos:self._pos+size]
            self._pos += len(res)
            return res

    # Move the read cursor within the mirrored file buffer.
    def seek(self, pos, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self._pos = pos
        elif whence == io.SEEK_CUR:
            self._pos += pos
        elif whence == io.SEEK_END:
            self._pos = len(self.data) + pos
        return self._pos

    # Report the current read cursor offset.
    def tell(self):
        return self._pos


# Resolve a scraper-managed local asset path if it exists inside the data directory.
def _scraper_asset_path(source_type: str, row) -> Optional[str]:
    image_path = row_value(row, "image_path")
    if not image_path:
        return None
    # scraper_data_dir(), not dirname(db): a generic site's DB is one level
    # below its DATA_DIR, so dirname(db) missed every generic asset.
    data_dir = scraper_data_dir(source_type)
    candidate = os.path.abspath(os.path.join(data_dir, str(image_path)))
    if candidate.startswith(data_dir + os.sep) is False and candidate != data_dir:
        return None
    if os.path.exists(candidate) is False:
        return None
    return candidate


# Import already-downloaded scraper media into Maniwani storage.
def _mirror_local_media(
    file_path: str, source_url: Optional[str] = None, nsfw_board=None,
    source_type=None, source_locator=None,
) -> Optional[Media]:
    try:
        file_size = os.path.getsize(file_path)
        if file_size > app.config.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024):
            _sync_log("Skipping too-large local media: %s (%s bytes)" % (file_path, file_size))
            return None
        filename = os.path.basename(file_path)
        content_type = mimetypes.guess_type(source_url or filename)[0] or "application/octet-stream"
        if not _is_mirrorable_media(content_type):
            _sync_log(
                "Skipped local scraper media %s: %s is not image/video/audio"
                % (file_path, content_type)
            )
            return None
        with open(file_path, "rb") as fh:
            data = fh.read()
        media = storage.save_attachment(
            _MirrorFile(filename, content_type, data, source_url=source_url),
            nsfw_board=nsfw_board,
        )
        if media is not None:
            _queue_seedbox_for_media(media)
        return media
    except BlockedMediaError as exc:
        _sync_log(_blocked_media_reason("local scraper media %s" % file_path, exc))
        if getattr(exc, "nsfw_score", None) is not None and source_type:
            from model.RejectedImportedAsset import reject_imported_asset
            reject_imported_asset(
                source_type, source_locator, source_url,
                reason="nsfw:%.4f" % exc.nsfw_score,
            )
            try:
                os.remove(file_path)
            except OSError:
                pass
        return None
    except Exception as exc:
        _sync_log("Failed to import local scraper media %s: %s" % (file_path, exc))
        return None


def _persist_nsfw_refusal(exc, data=None, source_url=None):
    """Compatibility no-op for workers still calling the old helper.

    Automated classifier failures are transient moderation decisions, not
    permanent bans. ``save_attachment`` rejects before creating a Media row or
    writing object bytes. Exact and perceptual hashes are reserved for explicit
    moderator bans.
    """
    return False


# Rate-limit outbound media mirror requests per host.
def _throttle_mirror_request(host: str) -> None:
    request_delay_seconds = mirror_request_delay_seconds()
    if request_delay_seconds <= 0:
        return
    with _mirror_rate_lock:
        now = time.monotonic()
        next_allowed = _mirror_next_request_at.get(host, now)
        sleep_for = max(0.0, next_allowed - now)
        _mirror_next_request_at[host] = max(next_allowed, now) + request_delay_seconds
    if sleep_for > 0:
        time.sleep(sleep_for)


# Compute the next retry delay for a rate-limited mirror response.
def _retry_after_seconds(response, attempt: int) -> float:
    retry_backoff_seconds = mirror_retry_backoff_seconds()
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return max(float(retry_after), retry_backoff_seconds)
        except ValueError:
            pass
    return retry_backoff_seconds * (attempt + 1)




def _nsfw_board_for_thread(thread) -> Optional[object]:
    """Destination Board for imported media, so its NSFW toggle is honoured.

    Query.get() rather than a filter so repeat lookups within one sync pass are
    served from SQLAlchemy's identity map instead of re-querying per media row.
    Returns None on any failure, which falls back to the site-wide NSFW policy --
    i.e. failing toward MORE filtering, never less.
    """
    try:
        from model.Board import Board
        board_id = getattr(thread, "board", None)
        return db.session.query(Board).get(board_id) if board_id else None
    except Exception:
        return None


def _nsfw_board_for_post(post) -> Optional[object]:
    try:
        from model.Thread import Thread
        thread_id = getattr(post, "thread", None)
        thread = db.session.query(Thread).get(thread_id) if thread_id else None
        return _nsfw_board_for_thread(thread) if thread is not None else None
    except Exception:
        return None



# Content types that can legitimately be a post attachment. Anything else is not
# media, whatever the source claimed.
_MIRRORABLE_PREFIXES = ("image/", "video/", "audio/")


def _is_mirrorable_media(content_type) -> bool:
    """Whether fetched bytes may be stored as an imported post's attachment.

    A defence independent of the crawler: when the scraper mis-identifies a body
    link as an attachment (a mediafire/tumblr URL, say), the fetch returns an HTML
    download PAGE. Storing that produced a `.bin` with mimetype text/html which the
    board then rendered as the post's "image" — a white page of markup. Refuse it
    here so a scraper bug can never put non-media in a post again.
    """
    value = (content_type or "").split(";", 1)[0].strip().lower()
    if not value:
        return False
    return value.startswith(_MIRRORABLE_PREFIXES)


def _blocked_media_reason(label: str, exc) -> str:
    """One log line for a rejected import, naming WHICH gate rejected it.

    Without this an NSFW rejection and a banned-hash block read identically, which
    makes "why did this image not import" unanswerable from the log.
    """
    score = getattr(exc, "nsfw_score", None)
    if score is not None:
        return "Skipped %s: NSFW filter (score %.2f)" % (label, float(score))
    # Include the reason: FOUR different gates raise BlockedMediaError without a
    # score (banned hash, perceptual fingerprint, magic-byte signature mismatch,
    # ClamAV), and logging only the sha256 made "why was this skipped?"
    # unanswerable — the hash is not on any list when the signature/AV gate fired.
    reason = (getattr(exc, "reason", None) or "").strip()
    return "Skipped blocked %s (%s%s)" % (
        label,
        getattr(exc, "sha256", "?"),
        "; %s" % reason[:120] if reason else "; no reason recorded",
    )


# Mirror imported media from a local scraper file or external URL.
def _mirror_imported_asset(source_type: str, row, nsfw_board=None) -> Optional[Media]:
    desired_media_url = normalize_external_media_url(row_value(row, "image_url"))
    local_path = _scraper_asset_path(source_type, row)
    from model.RejectedImportedAsset import imported_asset_is_rejected
    if imported_asset_is_rejected(source_type, local_path, desired_media_url):
        return None
    if local_path:
        _sync_log("Importing scraper-downloaded media from %s" % local_path)
        mirrored = _mirror_local_media(
            local_path, desired_media_url, nsfw_board=nsfw_board,
            source_type=source_type, source_locator=row_value(row, "image_path"),
        )
        if mirrored is not None:
            return mirrored
    if desired_media_url:
        return _mirror_external_media(
            desired_media_url,
            referer=normalize_source_url(row_value(row, "permalink") or row_value(row, "url")),
            nsfw_board=nsfw_board,
            source_type=source_type,
        )
    return None


# Keep a post's mirrored media fields in sync with imported source data.
def _sync_imported_media(post: Post, source_type: str, row, replace_existing: bool = False) -> bool:
    desired_media_url = normalize_external_media_url(row_value(row, "image_url"))
    updated = False

    if post.external_media_url != desired_media_url:
        post.external_media_url = desired_media_url
        updated = True

    if desired_media_url is None:
        return updated

    if post.media is not None and replace_existing is False:
        return updated

    if replace_existing:
        _sync_log("Refreshing mirrored media from %s" % desired_media_url)
    else:
        _sync_log("Mirroring media from %s" % desired_media_url)

    previous_media_id = post.media
    mirrored = _mirror_imported_asset(
        source_type, row, nsfw_board=_nsfw_board_for_post(post)
    )
    if mirrored is None:
        if replace_existing and previous_media_id is not None:
            post.media = None
            _delete_media_by_id(previous_media_id)
            updated = True
        return updated

    if post.media != mirrored.id:
        post.media = mirrored.id
        updated = True
    if previous_media_id is not None and previous_media_id != mirrored.id:
        _delete_media_by_id(previous_media_id)
    return updated


# Delete a mirrored media record and its stored attachment.
def _delete_media_by_id(media_id: Optional[int]) -> None:
    if media_id is None:
        return
    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if media is None:
        return
    try:
        media.delete_attachment()
    except Exception as exc:
        _sync_log("Failed to delete mirrored media %s: %s" % (media_id, exc))
    db.session.delete(media)


def _imported_source_post_id(row) -> Optional[str]:
    return _clip_imported_text(
        row_value(row, "source_post_id") or row_value(row, "post_id"),
        MAX_IMPORTED_SOURCE_ID_LENGTH,
    )


def _imported_media_source_fields(row):
    image_path = row_value(row, "image_path")
    normalized_image_path = None
    if image_path is not None:
        normalized_image_path = str(image_path).strip().replace("\\", "/") or None
    desired_media_url = normalize_external_media_url(row_value(row, "image_url"))
    return normalized_image_path, desired_media_url


def _has_specific_import_mimetype(value: Optional[str]) -> bool:
    normalized = (value or "").split(";", 1)[0].strip().lower()
    return normalized not in _GENERIC_IMPORT_MIMETYPES


def _imported_media_mapping_has_live_media(mapping) -> Tuple[bool, bool]:
    media_id = getattr(mapping, "media_id", None)
    if not media_id:
        return False, False
    from model.ImageMagnet import ImageMagnet
    media = (
        db.session.query(
            Media.id,
            Media.ext,
            Media.mimetype,
            Media.torrent_info_hash,
            ImageMagnet.magnet_url.label("image_magnet_url"),
        )
        .outerjoin(ImageMagnet, ImageMagnet.media_id == Media.id)
        .filter(Media.id == media_id)
        .one_or_none()
    )
    if media is None:
        return False, False
    if _has_specific_import_mimetype(media.mimetype) is False:
        return False, False

    needs_magnet = False
    is_image = str(media.mimetype or "").lower().startswith("image/")
    if is_image and (
        not media.torrent_info_hash
        or not media.image_magnet_url
        or _magnet_needs_seedbox_seed(media.image_magnet_url)
    ):
        needs_magnet = True

    # We no longer verify S3/disk presence synchronously inside the sync loop because it
    # drastically slows down the transaction and holds SQLite write locks. Orphaned media
    # verification is now delegated to `purge_orphaned_media.py`.
    return True, needs_magnet


def _schedule_imported_media_repair(thread, row) -> None:
    if thread is None or not getattr(thread, "id", None):
        return
    source_post_id = _imported_source_post_id(row)
    if not source_post_id:
        return
    normalized_image_path, desired_media_url = _imported_media_source_fields(row)
    if not normalized_image_path and not desired_media_url:
        return

    repair_key = (thread.id, source_post_id)
    with _imported_media_repair_lock:
        if repair_key in _pending_imported_media_repairs:
            return
        _pending_imported_media_repairs.add(repair_key)

    thread_id = thread.id
    source_type = thread.source_type
    row_copy = dict(row) if isinstance(row, dict) else dict(row.items()) if hasattr(row, "items") else row

    def _run():
        try:
            import gevent
            gevent.sleep(0)
        except Exception:
            pass

        try:
            from model.ImportedMedia import ImportedMedia
            from model.Thread import Thread
            from thread import invalidate_board_cache

            with app.app_context():
                current_thread = (
                    db.session.query(Thread)
                    .filter(Thread.id == thread_id)
                    .one_or_none()
                )
                if current_thread is None:
                    return

                mapping = (
                    db.session.query(ImportedMedia)
                    .filter(
                        ImportedMedia.thread_id == thread_id,
                        ImportedMedia.source_post_id == source_post_id,
                    )
                    .one_or_none()
                )

                changed = False
                if (
                    mapping is not None
                    and mapping.image_path == normalized_image_path
                    and mapping.external_media_url == desired_media_url
                ):
                    has_live_media, needs_magnet = _imported_media_mapping_has_live_media(mapping)
                    if has_live_media:
                        if needs_magnet:
                            changed, missing_attachment = _ensure_magnet_for_mapping(mapping)
                            if missing_attachment:
                                _delete_imported_media_mapping(mapping)
                                changed = True
                        if changed:
                            db.session.commit()
                            invalidate_board_cache(current_thread.board)
                            invalidate_thread_cache(current_thread.id)
                        return

                _mapping, row_changed = _sync_imported_thread_media_row(
                    current_thread,
                    source_type,
                    row_copy,
                    mapping,
                )
                if row_changed:
                    db.session.commit()
                    invalidate_board_cache(current_thread.board)
                    invalidate_thread_cache(current_thread.id)
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            app.logger.exception(
                "Failed lazy imported media repair for thread %s source post %s",
                thread_id,
                source_post_id,
            )
        finally:
            try:
                db.session.remove()
            except Exception:
                pass
            with _imported_media_repair_lock:
                _pending_imported_media_repairs.discard(repair_key)

    # Through the CAPPED QUEUE, not a bare gevent.spawn(). This is called from the
    # render path — imported_thread_media_payload() runs it per imported post, and
    # model/ThreadPosts.py calls that per post — so an unbounded spawn here turned
    # every page view into another greenlet that checks out a DB connection and
    # then blocks on _global_sync_lock. That is how a traffic burst emptied a
    # 15-connection pool and produced 60-second requests.
    #
    # A small cap is not a compromise: the work serializes behind
    # _global_sync_lock anyway, so extra workers would only wait on the mutex
    # while each holds a connection. Bounding it is strictly better.
    from services.scrape_queue import submit as _submit_scrape

    if not _submit_scrape(
        "media-repair",
        "media-repair:%s:%s" % (thread_id, source_post_id),
        _run,
        label="thread %s post %s" % (thread_id, source_post_id),
    ):
        # Shed or already queued. Release our in-flight marker so a later render
        # can re-propose it; leaving the key set would disable repair for this
        # (thread, post) for the lifetime of the process.
        with _imported_media_repair_lock:
            _pending_imported_media_repairs.discard(repair_key)


def _ensure_magnet_for_mapping(mapping) -> Tuple[bool, bool]:
    """Returns (changed, missing_attachment)"""
    media_id = getattr(mapping, "media_id", None)
    if not media_id:
        return False, False
    media = db.session.query(Media).filter(Media.id == media_id).one_or_none()
    if media is None:
        return False, True
    from model.ImageMagnet import media_supports_image_magnets
    if not media_supports_image_magnets(media):
        return False, False

    changed = False
    if not (media.torrent_info_hash and media.torrent_piece_length):
        try:
            attachment_bytes = storage.read_attachment_bytes(media.id, media.ext)
            from services.torrent_media import torrent_info_hash_for_bytes
            torrent_info_hash, torrent_piece_length = torrent_info_hash_for_bytes(
                attachment_bytes,
                media_id=media.id,
                media_ext=media.ext,
            )
            media.torrent_info_hash = torrent_info_hash
            media.torrent_piece_length = torrent_piece_length
            changed = True
        except MissingAttachmentError:
            return False, True
        except Exception as exc:
            _sync_log("Failed to generate torrent info for media %s: %s" % (media_id, exc))
            return False, False

    from services.torrent_media import resolved_media_torrent_payload
    payload, magnet_changed = resolved_media_torrent_payload(media)
    if _magnet_needs_seedbox_seed((payload or {}).get("magnet_url")):
        _queue_seedbox_for_media(media)
    if changed or magnet_changed:
        db.session.add(media)
        _sync_log("Retrofit existing mirrored media %s with magnet URL" % media_id)
        return True, False
    return False, False


def _delete_imported_media_mapping(mapping) -> None:
    if mapping is None:
        return
    previous_media_id = getattr(mapping, "media_id", None)
    db.session.delete(mapping)
    if previous_media_id is not None:
        _delete_media_by_id(previous_media_id)


def _sync_imported_thread_media_row(thread, source_type: str, row, mapping):
    from model.ImportedMedia import ImportedMedia

    source_post_id = _imported_source_post_id(row)
    if not source_post_id:
        return None, False

    normalized_image_path, desired_media_url = _imported_media_source_fields(row)
    if not normalized_image_path and not desired_media_url:
        if mapping is not None:
            _delete_imported_media_mapping(mapping)
            return None, True
        return None, False

    has_live_media = False
    needs_magnet = False
    if mapping is not None and mapping.image_path == normalized_image_path and mapping.external_media_url == desired_media_url:
        has_live_media, needs_magnet = _imported_media_mapping_has_live_media(mapping)

    if has_live_media:
        if needs_magnet:
            changed, missing = _ensure_magnet_for_mapping(mapping)
            if missing:
                _delete_imported_media_mapping(mapping)
                return None, True
            if changed:
                return mapping, True
        return mapping, False

    mirrored = _mirror_imported_asset(
        source_type, row, nsfw_board=_nsfw_board_for_thread(thread)
    )
    if mirrored is None:
        from model.RejectedImportedAsset import imported_asset_is_rejected
        rejected = imported_asset_is_rejected(
            source_type, row_value(row, "image_path"), desired_media_url
        )
        if mapping is not None:
            _delete_imported_media_mapping(mapping)
            return None, True
        return None, rejected

    previous_media_id = getattr(mapping, "media_id", None)
    if mapping is None:
        mapping = ImportedMedia(
            thread_id=thread.id,
            source_post_id=source_post_id,
            media_id=mirrored.id,
            image_path=normalized_image_path,
            external_media_url=desired_media_url,
        )
    else:
        mapping.media_id = mirrored.id
        mapping.image_path = normalized_image_path
        mapping.external_media_url = desired_media_url
    db.session.add(mapping)
    if previous_media_id is not None and previous_media_id != mirrored.id:
        _delete_media_by_id(previous_media_id)
    return mapping, True


def sync_imported_thread_media(thread, source_type: str, rows) -> bool:
    from model.ImportedMedia import ImportedMedia

    if thread is None or not getattr(thread, "id", None):
        return False

    existing_mappings = {
        mapping.source_post_id: mapping
        for mapping in (
            db.session.query(ImportedMedia)
            .filter(ImportedMedia.thread_id == thread.id)
            .all()
        )
    }
    seen_source_post_ids = set()
    changed = False

    for row in rows or []:
        source_post_id = _imported_source_post_id(row)
        if not source_post_id:
            continue
        seen_source_post_ids.add(source_post_id)
        mapping, row_changed = _sync_imported_thread_media_row(
            thread,
            source_type,
            row,
            existing_mappings.get(source_post_id),
        )
        if row_changed:
            changed = True
        if mapping is None:
            existing_mappings.pop(source_post_id, None)
        else:
            existing_mappings[source_post_id] = mapping

    for source_post_id, mapping in list(existing_mappings.items()):
        if source_post_id in seen_source_post_ids:
            continue
        _delete_imported_media_mapping(mapping)
        changed = True

    return changed


def repair_imported_media_for_media_id(media_id: int) -> bool:
    from model.ImportedMedia import ImportedMedia
    from model.Thread import Thread
    from thread import invalidate_board_cache

    if not media_id:
        return False

    mapping_row = (
        db.session.query(ImportedMedia, Thread)
        .join(Thread, Thread.id == ImportedMedia.thread_id)
        .filter(ImportedMedia.media_id == media_id)
        .one_or_none()
    )
    if mapping_row is None:
        return False

    mapping, thread = mapping_row
    if thread is None or thread.source_type == "local" or not thread.source_thread_id:
        return False

    try:
        from services.aggregator_sync.api import _row_source_post_id, _thread_rows_from_conn
        from services.aggregator_sync.scraper_db import _read_scraper_db

        db_path = aggregator_db_path(thread.source_type)
        if os.path.exists(db_path) is False:
            return False

        source_post_id = getattr(mapping, "source_post_id", None)
        if not source_post_id:
            return False

        def _reader(connection):
            _thread_row, post_rows = _thread_rows_from_conn(
                connection,
                thread.source_type,
                thread.source_name,
                thread.source_thread_id,
            )
            for row in post_rows:
                if _row_source_post_id(row) == source_post_id:
                    return row
            return None

        row = _read_scraper_db(db_path, _reader)
        if row is None:
            return False

        _mapping, changed = _sync_imported_thread_media_row(thread, thread.source_type, row, mapping)
        if changed:
            db.session.commit()
            invalidate_thread_cache(thread.id)
            invalidate_board_cache(thread.board)
            return True
        return False
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass
        app.logger.exception("Failed repairing imported media %s from scraper source", media_id)
        return False


def imported_thread_media_rows(thread_id: int, source_post_ids=None) -> Dict[str, object]:
    from model.ImageMagnet import ImageMagnet
    from model.ImportedMedia import ImportedMedia

    if not thread_id:
        return {}

    query = (
        db.session.query(
            ImportedMedia.source_post_id.label("source_post_id"),
            Media.id,
            Media.ext,
            Media.mimetype,
            Media.is_animated,
            Media.torrent_info_hash,
            Media.torrent_piece_length,
            ImageMagnet.magnet_url.label("image_magnet_url"),
        )
        .join(Media, Media.id == ImportedMedia.media_id)
        .outerjoin(ImageMagnet, ImageMagnet.media_id == Media.id)
        .filter(ImportedMedia.thread_id == thread_id)
    )
    normalized_source_post_ids = [value for value in (source_post_ids or []) if value]
    if normalized_source_post_ids:
        query = query.filter(ImportedMedia.source_post_id.in_(normalized_source_post_ids))
    return {
        row.source_post_id: row
        for row in query.all()
    }


def imported_thread_media_payload(thread, row, keyed_media_rows: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    source_post_id = _imported_source_post_id(row)
    media_row = keyed_media_rows.get(source_post_id) if keyed_media_rows is not None and source_post_id else None
    if media_row is None and source_post_id and thread is not None and getattr(thread, "id", None):
        media_row = imported_thread_media_rows(thread.id, [source_post_id]).get(source_post_id)
    if media_row is not None:
        mimetype = str(getattr(media_row, "mimetype", "") or "").lower()
        if (
            mimetype.startswith("image/")
            and (
                not getattr(media_row, "torrent_info_hash", None)
                or not getattr(media_row, "image_magnet_url", None)
                or _magnet_needs_seedbox_seed(getattr(media_row, "image_magnet_url", None))
            )
        ):
            _schedule_imported_media_repair(thread, row)
        return media_row_payload(media_row.id, media_row)
    from model.RejectedImportedAsset import imported_asset_is_rejected
    if imported_asset_is_rejected(
        thread.source_type, row_value(row, "image_path"), row_value(row, "image_url")
    ):
        return {"media": None}
    _schedule_imported_media_repair(thread, row)
    return imported_media_payload(thread.source_type, row)


# Download and store external media with retry and fallback handling.
def _mirror_external_media(url: str, referer: Optional[str] = None, nsfw_board=None, source_type=None) -> Optional[Media]:
    parsed = urlparse(url)
    max_retries = mirror_max_retries()
    retry_backoff_seconds = mirror_retry_backoff_seconds()
    # Budget for sleeping while a transaction is open. See
    # mirror_inline_sleep_budget_seconds() for why this exists.
    sleep_budget = mirror_inline_sleep_budget_seconds()
    slept_seconds = 0.0
    headers = {"User-Agent": mirror_user_agent()}
    if referer:
        headers["Referer"] = referer
    for attempt in range(max_retries):
        try:
            _throttle_mirror_request(parsed.netloc or "default")
            resp = requests.get(url, timeout=10, stream=True, headers=headers)
            if resp.status_code == 429:
                delay = _retry_after_seconds(resp, attempt)
                # _retry_after_seconds honours the remote's Retry-After with no
                # cap, so a hostile or misconfigured site could otherwise pin this
                # connection for as long as it liked.
                if slept_seconds + delay > sleep_budget:
                    _sync_log(
                        "Mirror rate limited for %s; wants %.1fs which exceeds the "
                        "%.1fs in-transaction sleep budget. Deferring to the media "
                        "repair sweep." % (url, delay, sleep_budget)
                    )
                    return None
                _sync_log("Mirror rate limited for %s; backing off %.1fs" % (url, delay))
                time.sleep(delay)
                slept_seconds += delay
                continue
            resp.raise_for_status()

            cl = resp.headers.get("Content-Length")
            if cl and int(cl) > app.config.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024):
                _sync_log("Skipping too-large media: %s (%s bytes)" % (url, cl))
                return None

            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            filename = parsed.path.split("/")[-1] or "image"
            if "." not in filename:
                ext = mimetypes.guess_extension(content_type) or ".bin"
                filename += ext

            data = resp.content
            if not _is_mirrorable_media(content_type):
                _sync_log(
                    "Skipped %s: served %s, which is not image/video/audio "
                    "(a link in the post body, not an attachment)"
                    % (url, content_type or "an unknown type")
                )
                return None
            file_obj = _MirrorFile(filename, content_type, data, source_url=url)
            media = storage.save_attachment(file_obj, nsfw_board=nsfw_board)
            if media is not None:
                _queue_seedbox_for_media(media)
            return media
        except BlockedMediaError as exc:
            # Not retried: a blocked image is a decision, not a transient failure.
            _sync_log(_blocked_media_reason("mirrored media %s" % url, exc))
            if getattr(exc, "nsfw_score", None) is not None and source_type:
                from model.RejectedImportedAsset import reject_imported_asset
                reject_imported_asset(
                    source_type, url, reason="nsfw:%.4f" % exc.nsfw_score
                )
            return None
        except Exception as exc:
            if attempt + 1 >= max_retries:
                _sync_log("Failed to mirror %s: %s" % (url, exc))
                return None
            delay = retry_backoff_seconds * (attempt + 1)
            if slept_seconds + delay > sleep_budget:
                # Give up THIS pass rather than sleep on a held connection.
                # imported_media_repair retries later, outside the transaction.
                _sync_log(
                    "Mirror attempt %d failed for %s: %s. Next retry wants %.1fs, "
                    "over the %.1fs in-transaction sleep budget — deferring to the "
                    "media repair sweep." % (attempt + 1, url, exc, delay, sleep_budget)
                )
                return None
            _sync_log("Mirror attempt %d failed for %s: %s; retrying in %.1fs" % (attempt + 1, url, exc, delay))
            time.sleep(delay)
            slept_seconds += delay
    
    # All attempts failed, try to use fallback image
    if FALLBACK_IMAGE_PATH and os.path.exists(FALLBACK_IMAGE_PATH):
        try:
            _sync_log("All attempts failed for %s; using fallback image" % url)
            with open(FALLBACK_IMAGE_PATH, "rb") as fh:
                data = fh.read()
            filename = os.path.basename(FALLBACK_IMAGE_PATH)
            content_type = mimetypes.guess_type(filename)[0] or "image/png"
            # nsfw_enforce=False: this is our own bundled placeholder, so there is
            # nothing to moderate and no reason to spend a classifier call on it.
            media = storage.save_attachment(
                _MirrorFile(filename, content_type, data, source_url=url),
                nsfw_enforce=False,
            )
            if media is not None:
                _queue_seedbox_for_media(media)
            return media
        except BlockedMediaError as exc:
            _sync_log(_blocked_media_reason("fallback media for %s" % url, exc))
            return None
        except Exception as exc:
            _sync_log("Failed to use fallback image: %s" % exc)
    
    return None


# Derive reply edges for an imported post from its parent and translated body.
def imported_replies(post: Post, row, source_post_id_map: Dict[str, int]):
    reply_targets = set()
    parent_post_id = _clip_imported_text(row_value(row, "parent_post_id"), 128)
    if parent_post_id:
        local_parent_post_id = source_post_id_map.get(parent_post_id)
        if local_parent_post_id:
            reply_targets.add(local_parent_post_id)

    import re
    translated_body = _translated_imported_body(row, source_post_id_map)
    for match in re.finditer(REPLY_REGEXP, translated_body):
        reply_targets.add(int(match.group(2)))

    return [Reply(reply_from=post.id, reply_to=reply_to) for reply_to in reply_targets if reply_to != post.id]


# Invalidate cached rendered fragments for a single imported post.
def invalidate_post_render_cache(post_id: int) -> None:
    cache_connection = cache.Cache()
    cache_connection.invalidate(post_render_cache_key(CONTEXT_CATALOG, post_id))
    cache_connection.invalidate(post_render_cache_key(CONTEXT_THREAD, post_id))


# Invalidate cached rendered fragments for every post in a thread.
def invalidate_thread_cache(thread_id: int) -> None:
    from model.ThreadPosts import thread_posts_cache_key
    from thread import invalidate_thread_render_cache

    cache_connection = cache.Cache()
    cache_connection.invalidate(thread_posts_cache_key(thread_id))
    invalidate_thread_render_cache(thread_id)


# Delete an imported thread along with its posts, replies, and mirrored media.
def delete_thread(thread: Thread) -> None:
    from model.ImportedMedia import ImportedMedia

    for mapping in (
        db.session.query(ImportedMedia)
        .filter(ImportedMedia.thread_id == thread.id)
        .all()
    ):
        _delete_imported_media_mapping(mapping)

    for post in list(thread.posts):
        db.session.query(Reply).filter(
            (Reply.reply_from == post.id) |
            (Reply.reply_to == post.id)
        ).delete(synchronize_session=False)

        PostRemoval().delete_impl(post.id)

    db.session.delete(thread)
