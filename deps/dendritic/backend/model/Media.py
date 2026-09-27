import datetime
import io
import json
import mimetypes
import logging
import os
import shutil
import subprocess
import tempfile
import threading
from flask import has_request_context, redirect, request, send_from_directory, session, url_for
from PIL import Image, ImageDraw
from model.BlockedMediaHash import get_blocked_media_hash, media_sha256_bytes
from model.ImageMagnet import ImageMagnet
from services.torrent_media import absolute_upload_url, resolved_media_torrent_payload, torrent_info_hash_for_bytes
from shared import db, app


_GENERIC_CONTENT_TYPES = {
    "",
    "application/octet-stream",
    "binary/octet-stream",
    "application/unknown",
    "unknown/unknown",
}
_EXTENSION_OVERRIDES = {
    "image/jpeg": "jpg",
    "text/plain": "txt",
}


def _normalized_content_type(value):
    return (value or "").split(";", 1)[0].strip().lower()


def _attachment_stream(attachment_file):
    return getattr(attachment_file, "stream", attachment_file)


def _peek_attachment_bytes(attachment_file, size=512):
    stream = _attachment_stream(attachment_file)
    position = None
    try:
        position = stream.tell()
    except Exception:
        position = None
    try:
        if hasattr(stream, "seek"):
            stream.seek(0)
        data = stream.read(size) or b""
    finally:
        try:
            if hasattr(stream, "seek"):
                stream.seek(position if position is not None else 0)
        except Exception:
            pass
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def _read_attachment_bytes(attachment_file):
    stream = _attachment_stream(attachment_file)
    try:
        if hasattr(stream, "seek"):
            stream.seek(0)
        data = stream.read() or b""
    finally:
        try:
            if hasattr(stream, "seek"):
                stream.seek(0)
        except Exception:
            pass
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def _looks_like_text_bytes(data):
    if not data or b"\x00" in data:
        return False
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    control_chars = 0
    for char in decoded:
        if char.isprintable() or char.isspace():
            continue
        control_chars += 1
    return control_chars == 0


def _sniff_attachment_mimetype(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[4:8] == b"ftyp":
        return "video/mp4"
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return "video/webm"
    if _looks_like_text_bytes(data):
        return "text/plain"
    return None


def resolve_attachment_content_type(attachment_file):
    explicit = _normalized_content_type(getattr(attachment_file, "content_type", None))
    if not explicit:
        explicit = _normalized_content_type(getattr(attachment_file, "mimetype", None))
    if explicit and explicit not in _GENERIC_CONTENT_TYPES:
        return explicit
    sniffed = _sniff_attachment_mimetype(_peek_attachment_bytes(attachment_file))
    if sniffed:
        return sniffed
    guessed, _encoding = mimetypes.guess_type(getattr(attachment_file, "filename", "") or "")
    guessed = _normalized_content_type(guessed)
    if guessed:
        return guessed
    return "application/octet-stream"


def attachment_extension(attachment_file, mimetype=None):
    filename = os.path.basename(getattr(attachment_file, "filename", "") or "")
    if "." in filename:
        detected_ext = filename.rsplit(".", 1)[1].lower()
        if detected_ext == "jpeg":
            return "jpg"
        if len(detected_ext) <= 4:
            return detected_ext
    normalized_type = _normalized_content_type(mimetype)
    if normalized_type in _EXTENSION_OVERRIDES:
        return _EXTENSION_OVERRIDES[normalized_type]
    guessed_ext = mimetypes.guess_extension(normalized_type or "") or ""
    guessed_ext = guessed_ext.lstrip(".").lower()
    if guessed_ext == "jpe":
        return "jpg"
    if guessed_ext:
        return guessed_ext[:4]
    return "bin"


class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ext = db.Column(db.String(4), nullable=False)
    mimetype = db.Column(db.String(255), nullable=False)
    is_animated = db.Column(db.Boolean, nullable=False)
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    # Perceptual fingerprint (services/perceptual.py) for distance-based banning
    # and NNTP banlist federation. Null for non-images / when Pillow can't decode.
    fingerprint = db.Column(db.String(1024), nullable=True)
    # NSFW probability from the open_nsfw classifier, 0..1. Scored once at upload
    # (see services/nsfw.py). Null for non-images, when the filter is off, or when
    # the classifier was unavailable. Stored so per-board enforcement can run
    # later at post time — the browser pre-uploads media before choosing a board.
    nsfw_score = db.Column(db.Float, nullable=True)
    # Serve an operator-uploaded overlay image instead of these bytes to anyone who
    # is not signed into a slip account. A softer alternative to deleting media:
    # the file is kept and stays visible to authenticated users. Enforced in the
    # SERVING routes (blueprints/upload.py, blueprints/image_proxy.py), never in a
    # template — a template-only gate leaves the real URL directly fetchable.
    overlay_blocked = db.Column(db.Boolean, nullable=False, default=False, server_default="false")
    # Last time the random re-scan sweep re-checked this file against the NSFW
    # classifier and ClamAV. NULL = never re-scanned, which the sweep prefers.
    rescanned_at = db.Column(db.DateTime, nullable=True)
    # Set once this object has been written into the storage DHT AND read back
    # byte-identically. NOT a claim that the primary can be freed -- offload and
    # reclaim are separate steps on purpose (services/storage_offload.py).
    dht_offloaded_at = db.Column(db.DateTime, nullable=True, index=True)
    # Failed offload attempts. Without this the sweep re-selects the same
    # lowest-id rows every pass (ORDER BY id ASC + LIMIT) and never advances
    # past media whose object was pruned from the store years ago -- it would
    # spin on the same dead rows forever and offload nothing.
    dht_offload_attempts = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    torrent_info_hash = db.Column(db.String(40), nullable=True, index=True)
    torrent_piece_length = db.Column(db.Integer, nullable=True)
    image_magnet = db.relationship(
        "ImageMagnet",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def delete_attachment(self):
        storage.delete_attachment(self.id, self.ext)


class BlockedMediaError(Exception):
    def __init__(self, sha256, reason=None, nsfw_score=None):
        self.sha256 = sha256
        # Set when the NSFW classifier is what rejected this, so callers can tell
        # an NSFW rejection from a banned-hash / fingerprint / AV block instead of
        # string-matching the reason. Importers log the two differently.
        self.nsfw_score = nsfw_score
        self.reason = (reason or "").strip() or None
        super().__init__(self.__str__())

    def __str__(self):
        message = "This file matches a blocked media hash and cannot be stored."
        if self.reason:
            return "%s Reason: %s" % (message, self.reason)
        return message


class MissingAttachmentError(FileNotFoundError):
    def __init__(self, media_id, media_ext, storage_key=None, original_error=None):
        self.media_id = media_id
        self.media_ext = media_ext
        self.storage_key = (storage_key or "").strip() or None
        self.original_error = original_error
        message = "Attachment for media %s.%s is missing." % (media_id, media_ext)
        if self.storage_key:
            message = "%s Storage key: %s" % (message, self.storage_key)
        super().__init__(message)


def _is_missing_storage_error(exc):
    if isinstance(exc, FileNotFoundError):
        return True
    exc_type = str(type(exc))
    if "NoSuchKey" in exc_type or "NoSuchBucket" in exc_type:
        return True
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error") or {}
        if str(error.get("Code") or "").strip() in ("404", "NoSuchKey", "NoSuchBucket", "NotFound"):
            return True
    if "NoSuchKey" in str(exc) or "NoSuchBucket" in str(exc):
        return True
    return False


def _request_ip_address():
    if has_request_context() is False:
        return None
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.environ.get("REMOTE_ADDR")


def _log_blocked_media_attempt(sha256, reason=None, filename=None, source_url=None):
    app.logger.warning(
        "FAIL2BAN blocked-media hash=%s ip=%s filename=%s source_url=%s reason=%s",
        sha256,
        _request_ip_address(),
        filename or "",
        source_url or "",
        reason or "",
    )

class StorageBase:
    _FFMPEG_FLAGS = "-i pipe:0 -f mjpeg -frames:v 1 -vf scale=w=500:h=500:force_original_aspect_ratio=decrease pipe:1"
    # Hover-preview clip for the "recently uploaded" marquee: first ~2.5s, muted
    # (-an), downscaled to 360px wide, H.264. Uses a FRAGMENTED mp4
    # (frag_keyframe+empty_moov+default_base_moof) instead of +faststart so the
    # muxer never needs to seek the output and a plain stdout pipe works — mirrors
    # how the thumbnail is piped in/out. -nostdin keeps ffmpeg from ever reading
    # stdin for interactive keypresses. The input itself is written to a
    # temporary seekable file because many MP4 uploads keep their sample index
    # at the end and cannot be decoded reliably from a non-seekable pipe.
    _VIDEO_PREVIEW_FLAGS = (
        "-t 2.5 -an -vf scale=360:-2 "
        "-c:v libx264 -preset veryfast -crf 30 -pix_fmt yuv420p "
        "-movflags frag_keyframe+empty_moov+default_base_moof -f mp4 pipe:1"
    )

    # =========================
    # CORE SAVE LOGIC
    # =========================
    def save_attachment(
        self, attachment_file, content_type=None, nsfw_board=None, nsfw_enforce=True
    ):
        """Store an attachment, running every upload gate first.

        nsfw_board -- the Board this media is destined for, so the NSFW filter can
            honour that board's toggle. None means "no board context", which
            applies the global threshold (avatars, banners, watermarks, video).
        nsfw_enforce -- pass False to score-and-store WITHOUT blocking, for the
            pre-upload path (/upload/media) where the board is not known yet;
            post.get_media_id then enforces per-board using the stored score.
            Scoring always happens regardless, so the deferred check has a value
            to work from.
        """
        attachment_mimetype = _normalized_content_type(content_type)

        if not attachment_mimetype or attachment_mimetype in _GENERIC_CONTENT_TYPES:
            attachment_mimetype = resolve_attachment_content_type(attachment_file)

        attachment_bytes = _read_attachment_bytes(attachment_file)
        attachment_hash = media_sha256_bytes(attachment_bytes)

        blocked = get_blocked_media_hash(attachment_hash)
        if blocked is not None:
            _log_blocked_media_attempt(
                attachment_hash,
                reason=blocked.reason,
                filename=getattr(attachment_file, "filename", None),
                source_url=getattr(attachment_file, "source_url", None),
            )
            raise BlockedMediaError(attachment_hash, blocked.reason)

        # Additive upload security (ported from gh0stgrid): reject content whose
        # magic bytes contradict its declared type, and virus-scan the payload.
        from services.upload_security import (
            UnsafeUploadError,
            content_signature_matches,
            scan_bytes_with_clamav,
        )

        if not content_signature_matches(attachment_mimetype, attachment_bytes):
            app.logger.warning(
                "Rejected upload %s: content does not match declared type %s",
                getattr(attachment_file, "filename", None),
                attachment_mimetype,
            )
            raise BlockedMediaError(
                attachment_hash,
                "File contents do not match the declared %s type." % attachment_mimetype,
            )
        try:
            scan_bytes_with_clamav(
                attachment_bytes,
                filename=getattr(attachment_file, "filename", None) or "upload",
            )
        except UnsafeUploadError as exc:
            raise BlockedMediaError(attachment_hash, str(exc))

        # Distance-based (perceptual) image ban. Blocks near-duplicates of any
        # banned fingerprint — local OR federated in from an NNTPChan peer — and
        # records this image's fingerprint so it can be banned-by-distance later
        # and broadcast. Additive + guarded: an empty banlist or a Pillow failure
        # never blocks a legitimate upload (exact-hash + AV still apply).
        fingerprint_hex = None
        if attachment_mimetype.startswith("image/"):
            try:
                from services.perceptual import compute_fingerprint, decode_vector
                from model.BannedImageFingerprint import match_vector
                fp = compute_fingerprint(attachment_bytes)
                if fp is not None:
                    fingerprint_hex = fp[2]
                    match = match_vector(decode_vector(fingerprint_hex))
                    if match is not None:
                        _log_blocked_media_attempt(
                            attachment_hash,
                            reason="image-distance:%s" % (match[1] or "banned fingerprint"),
                            filename=getattr(attachment_file, "filename", None),
                            source_url=getattr(attachment_file, "source_url", None),
                        )
                        raise BlockedMediaError(
                            attachment_hash,
                            "Image matches a banned fingerprint (distance %.1f)." % match[2],
                        )
            except BlockedMediaError:
                raise
            except Exception:
                app.logger.exception("perceptual fingerprint check failed")

        # NSFW classification (Yahoo open_nsfw via the nsfw-classifier sidecar).
        # Always SCORES here; only BLOCKS here when the caller has no board to
        # apply per-board policy to. The post path passes nsfw_board (or defers
        # entirely) because the browser pre-uploads media via /upload/media before
        # a board is known — see services/nsfw.py for the full rationale.
        nsfw_score = None
        if attachment_mimetype:
            from services import nsfw as nsfw_service
            try:
                nsfw_score = nsfw_service.classify_bytes(attachment_bytes, attachment_mimetype)
            except nsfw_service.NsfwUnavailable as exc:
                # Fail-closed applies even on the deferred path: if we cannot score
                # it now, no later per-board check can either.
                if nsfw_service.fail_closed():
                    app.logger.warning("nsfw: rejecting upload, classifier down (%s)", exc)
                    raise BlockedMediaError(
                        attachment_hash,
                        "The NSFW filter is unavailable, so uploads are paused. Try again shortly.",
                    )
                app.logger.warning("nsfw: allowing upload, classifier down (%s)", exc)
            if nsfw_enforce and nsfw_score is not None and nsfw_service.score_blocks(nsfw_score, nsfw_board):
                _log_blocked_media_attempt(
                    attachment_hash,
                    reason="nsfw:%.4f" % nsfw_score,
                    filename=getattr(attachment_file, "filename", None),
                    source_url=getattr(attachment_file, "source_url", None),
                )
                raise BlockedMediaError(
                    attachment_hash,
                    nsfw_service.rejection_message(nsfw_score),
                    nsfw_score=nsfw_score,
                )

        file_ext = attachment_extension(attachment_file, attachment_mimetype)

        media = Media(
            ext=file_ext,
            mimetype=attachment_mimetype,
            is_animated=False,
            sha256=attachment_hash,
            fingerprint=fingerprint_hex,
            nsfw_score=nsfw_score,
        )

        db.session.add(media)
        db.session.flush()

        media_id = media.id

        # Generate torrent metadata
        torrent_info_hash, torrent_piece_length = torrent_info_hash_for_bytes(
            attachment_bytes,
            media_id=media_id,
            media_ext=file_ext,
        )

        media.torrent_info_hash = torrent_info_hash
        media.torrent_piece_length = torrent_piece_length

        # Store torrent payload (important for WebTorrent / P2P)
        resolved_media_torrent_payload(media)

        # Store file locally (fallback / seeding source)
        attachment_buffer = io.BytesIO(attachment_bytes)
        self._write_attachment(attachment_buffer, media_id, file_ext)

        # Generate thumbnail
        thumbnail, is_animated = self._make_thumbnail(
            io.BytesIO(attachment_bytes),
            media_id,
            attachment_mimetype,
            file_ext,
        )

        media.is_animated = is_animated
        # ONE COPY OF AN IMAGE IN THE DATABASE. Images are no longer stored a
        # second time at thumbnail size; the original is served and displayed
        # small by CSS (see upload.thumb). _make_thumbnail still runs above
        # because it is also what detects is_animated, which the listing needs.
        #
        # Videos are the exception and must keep a generated still: there is no
        # image to serve in place of an .mp4, so this is a derived poster frame
        # rather than a duplicate of anything.
        if attachment_mimetype.startswith("video/"):
            self._write_thumbnail(thumbnail, media_id)

        # Hover-preview clip for videos, generated right after the thumbnail and
        # stored under its own key. BEST-EFFORT: any ffmpeg/storage failure just
        # means no preview (the marquee falls back to the static thumbnail) and
        # must never break the upload.
        if attachment_mimetype.startswith("video/"):
            try:
                preview_bytes = self._make_video_preview(io.BytesIO(attachment_bytes))
                if preview_bytes:
                    self._write_video_preview(io.BytesIO(preview_bytes), media_id)
            except Exception:
                app.logger.exception("Hover-preview generation failed for media %s", media_id)

        return media

    # =========================
    # MAGNET GENERATION
    # =========================
    def _build_magnet(self, media):
        if not media or not media.torrent_info_hash:
            return None

        # Minimal magnet (can add trackers later)
        return (
            f"magnet:?xt=urn:btih:{media.torrent_info_hash}"
            f"&dn={media.id}.{media.ext}"
        )

    def _get_media(self, media_id):
        return Media.query.get(media_id)

    # =========================
    # URL GENERATION (FIXED)
    # =========================
    def get_media_url(self, media_id, media_ext):
        return url_for("upload.raw_attachment", media_id=media_id)

    def get_direct_media_url(self, media_id, media_ext):
        return url_for("upload.fetch_attachment", media_id=media_id)

    def get_attachment_fetch_url(self, media_id, media_ext):
        return absolute_upload_url("/upload/%d/fetch" % media_id)

    def get_thumb_url(self, media_id):
        return url_for("upload.thumb", media_id=media_id)

    def get_video_preview_url(self, media_id):
        return url_for("upload.preview", media_id=media_id, v=2)

    # =========================
    # STORAGE INTERFACE
    # =========================
    def attachment_exists(self, media_id, media_ext):
        raise NotImplementedError

    def read_attachment_bytes(self, media_id, media_ext):
        raise NotImplementedError

    def read_attachment_range(self, media_id, media_ext, start, end):
        """Bytes [start, end] INCLUSIVE, as HTTP Range counts them.

        Exists for stream archives. Those are the only objects the site serves
        that a viewer seeks around inside, and once the local copy is deleted
        after DHT offload there is no nginx on the path to satisfy a Range for
        us. Reading a multi-hour recording whole, per seek, is not viable.
        """
        raise NotImplementedError

    def read_thumbnail_bytes(self, media_id):
        raise NotImplementedError

    def read_video_preview_bytes(self, media_id):
        raise NotImplementedError

    def _write_attachment(self, attachment_file, media_id, media_ext):
        raise NotImplementedError

    def _write_thumbnail(self, thumbnail_bytes, media_id):
        raise NotImplementedError

    def _write_video_preview(self, preview_bytes, media_id):
        raise NotImplementedError

    def delete_attachment_object(self, media_id, media_ext):
        """Delete ONLY the attachment/origin object, leaving the thumbnail AND
        the hover-preview clip.

        The Phase 2 video-offload controller deletes an origin once the swarm can
        carry the video, but keeps the (small) thumbnail so the listing still
        renders and the (small) preview so the marquee hover still plays.
        ``delete_attachment`` removes all of them; this removes just the origin
        file — it must never touch the thumbnail or the preview.
        """
        raise NotImplementedError

    def write_attachment_bytes(self, media_id, media_ext, data):
        """Re-store an attachment's raw bytes under an existing media id.

        Used to rebuild an origin object a prior offload deleted, from the bytes
        the seedbox recovered off the swarm. Reuses the same low-level writer
        ``save_attachment`` uses, so S3/Folder behave identically.
        """
        self._write_attachment(io.BytesIO(bytes(data)), media_id, media_ext)

    def ensure_thumbnail_bytes(self, media):
        media_obj = media if hasattr(media, "id") else self._get_media(media)
        media_id = getattr(media_obj, "id", media)
        # Route both reads through media_read: for an OFFLOADED object the DHT
        # is the source of truth, and reading the local copy here would keep
        # the data server load-bearing for media we have already moved.
        # A thumbnail is regenerable, so a DHT thumb miss falls through to
        # regenerating from the attachment -- which also comes from the DHT.
        from services import media_read

        try:
            existing = media_read.thumbnail_bytes(media_id)
            if existing:
                return existing
        except MissingAttachmentError:
            pass

        if media_obj is None:
            raise MissingAttachmentError(media_id, "jpg")

        attachment_bytes = media_read.attachment_bytes(media_obj.id, media_obj.ext)
        if not attachment_bytes:
            raise MissingAttachmentError(media_obj.id, media_obj.ext)
        thumbnail_bytes, _is_animated = self._make_thumbnail(
            io.BytesIO(attachment_bytes),
            media_obj.id,
            media_obj.mimetype,
            media_obj.ext,
        )
        raw_thumbnail = thumbnail_bytes.read() if hasattr(thumbnail_bytes, "read") else bytes(thumbnail_bytes)
        self._write_thumbnail(io.BytesIO(raw_thumbnail), media_obj.id)
        return raw_thumbnail

    def ensure_video_preview_bytes(self, media):
        """Return the hover-preview clip bytes, LAZILY generating + storing it on
        first request for videos uploaded before previews existed.

        Unlike ``ensure_thumbnail_bytes`` this never raises for a missing source:
        a Phase-2-offloaded video whose origin is already gone and which has no
        stored preview simply returns None, so the route 404s and the marquee
        falls back to the static thumbnail. A stored preview is ALWAYS kept
        through offload, so offloaded videos that already have one still preview.
        """
        media_obj = media if hasattr(media, "id") else self._get_media(media)
        media_id = getattr(media_obj, "id", media)
        # Same routing as the thumbnail path: the DHT is authoritative for
        # offloaded objects (services/media_read.py).
        from services import media_read

        try:
            existing = media_read.video_preview_bytes(media_id)
            if existing:
                return existing
        except MissingAttachmentError:
            pass

        if media_obj is None:
            return None

        mimetype = str(getattr(media_obj, "mimetype", "") or "")
        if not mimetype.startswith("video/"):
            return None

        try:
            attachment_bytes = media_read.attachment_bytes(media_obj.id, media_obj.ext)
        except MissingAttachmentError:
            # Origin offloaded and no stored preview: nothing to serve.
            return None

        preview_bytes = self._make_video_preview(io.BytesIO(attachment_bytes))
        if not preview_bytes:
            return None
        try:
            self._write_video_preview(io.BytesIO(preview_bytes), media_obj.id)
        except Exception:
            app.logger.exception("Failed to persist lazy hover-preview for media %s", media_obj.id)
        return preview_bytes

    # =========================
    # THUMBNAIL GENERATION
    # =========================
    def _placeholder_thumbnail(self, label):
        """A 500x500 labelled placeholder for media with no extractable frame
        (audio, unknown types, or ffmpeg failures). Always returns
        (BytesIO, is_animated) so callers never crash on a None thumbnail."""
        thumb = Image.new("RGB", (500, 500), (28, 30, 38))
        draw = ImageDraw.Draw(thumb)
        text = (str(label) if label else "FILE").strip().upper()[:12] or "FILE"
        try:
            font = draw.getfont()
        except Exception:
            font = None
        try:
            bbox = draw.textbbox((0, 0), text, font=font)
            tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        except Exception:
            tw, th = len(text) * 6, 11
        draw.text(((500 - tw) / 2, (500 - th) / 2), text, fill=(226, 226, 232), font=font)
        buffer = io.BytesIO()
        thumb.save(buffer, "JPEG")
        return io.BytesIO(buffer.getvalue()), False

    def _make_thumbnail(self, attachment, media_id, mimetype, file_ext):
        if mimetype.startswith("image"):
            attachment.seek(0)
            try:
                thumb = Image.open(attachment)
            except Exception:
                # PIL cannot decode this despite an image/* type. SVG is the case
                # that actually bit us: image/svg+xml is vector XML, so Image.open
                # raises UnidentifiedImageError, which escaped as a 500 from
                # /upload/thumb/<id> — and the front page and catalogs render every
                # tile through that route, so a handful of SVGs broke the page's
                # images. Eight of the thirty newest media were SVGs.
                #
                # A placeholder, not an exception: a thumbnail is decoration, and
                # failing to make one must never turn into a server error. The
                # original file is still served fine by /upload/<id>/fetch.
                #
                # Deliberately NOT rasterizing the SVG: that needs a vector
                # renderer we do not ship, and rendering untrusted SVG (which can
                # carry script and external references) is its own risk.
                app.logger.warning(
                    "thumbnail: %s is not decodable by PIL (media %s); using a placeholder",
                    mimetype, media_id,
                )
                return self._placeholder_thumbnail(
                    (file_ext or mimetype.split("/")[-1] or "IMAGE")
                )

            is_animated = False
            try:
                is_animated = thumb.is_animated
            except AttributeError:
                pass

            if thumb.mode in ("RGBA", "LA"):
                mode = "RGB" if thumb.mode == "RGBA" else "L"
                color = (255, 255, 255) if mode == "RGB" else 255
                background = Image.new(mode, thumb.size, color)
                background.paste(thumb, thumb.split()[-1])
                thumb = background

            size = thumb.size

            if size[0] > size[1]:
                scale_factor = 500 / size[0]
            else:
                scale_factor = 500 / size[1]

            new_width = int(thumb.width * scale_factor)
            new_height = int(thumb.height * scale_factor)

            thumb = thumb.resize((new_width, new_height), Image.LANCZOS)
            thumb = thumb.convert("RGB")

            temp_buffer = io.BytesIO()
            thumb.save(temp_buffer, "JPEG")

            return io.BytesIO(temp_buffer.getvalue()), is_animated

        elif mimetype.startswith("text"):
            thumb = Image.new("RGB", (500, 500), (255, 255, 255))
            draw = ImageDraw.Draw(thumb)
            font = draw.getfont()

            attachment.seek(0)
            text = attachment.read()

            if isinstance(text, bytes):
                text = text.decode("utf-8", errors="replace")

            draw.multiline_text((0, 0), text, font=font, fill=(0, 0, 0))

            temp_buffer = io.BytesIO()
            thumb.save(temp_buffer, "JPEG")

            return io.BytesIO(temp_buffer.getvalue()), False

        elif mimetype.startswith("video"):
            attachment.seek(0)
            try:
                ffmpeg_result = subprocess.run(
                    (f"{self._get_ffmpeg_path()} {self._FFMPEG_FLAGS}").split(),
                    input=attachment.read(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=25,
                )
            except (subprocess.TimeoutExpired, OSError):
                app.logger.warning("ffmpeg thumbnail timed out/failed for media %s", media_id)
                return self._placeholder_thumbnail("VIDEO")
            if ffmpeg_result.returncode != 0 or not ffmpeg_result.stdout:
                return self._placeholder_thumbnail("VIDEO")
            return io.BytesIO(ffmpeg_result.stdout), True

        # Audio (and any other type with no visual frame) gets a labelled
        # placeholder. Previously audio fell through to `return None`, which
        # crashed save_attachment on unpacking — and an mp3 mis-sniffed as
        # video/mpeg hit the timeout-less ffmpeg above and hung the whole upload.
        elif mimetype.startswith("audio"):
            return self._placeholder_thumbnail("AUDIO")

        return self._placeholder_thumbnail(file_ext or "FILE")

    # =========================
    # HOVER-PREVIEW GENERATION
    # =========================
    def _make_video_preview(self, source):
        """Produce a short, muted, downscaled hover-preview clip for a video.

        The source is placed in a temporary seekable file so MP4 inputs with a
        trailing ``moov`` atom can be decoded. The fragmented-mp4 clip is read
        from stdout (pipe:1). Tolerates any ffmpeg problem (missing binary,
        unsupported codec, non-zero exit) by returning None so a bad video never
        blocks an upload or a preview request.
        """
        if hasattr(source, "read"):
            try:
                source.seek(0)
            except Exception:
                pass
            source_bytes = source.read()
        else:
            source_bytes = source
        if isinstance(source_bytes, str):
            source_bytes = source_bytes.encode("utf-8")
        source_bytes = bytes(source_bytes or b"")
        if not source_bytes:
            return None

        try:
            with tempfile.NamedTemporaryFile(prefix="maniwani-preview-") as source_file:
                source_file.write(source_bytes)
                source_file.flush()
                ffmpeg_commandline = (
                    f"{self._get_ffmpeg_path()} -nostdin -i {source_file.name} "
                    f"{self._VIDEO_PREVIEW_FLAGS}"
                ).split()
                ffmpeg_result = subprocess.run(
                    ffmpeg_commandline,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=40,
                )
        except Exception:
            app.logger.exception("ffmpeg hover-preview invocation failed")
            return None
        if ffmpeg_result.returncode != 0 or not ffmpeg_result.stdout:
            stderr_tail = (ffmpeg_result.stderr or b"").decode("utf-8", errors="replace")[-1000:]
            app.logger.warning(
                "ffmpeg hover-preview produced no output (returncode=%s, detail=%s)",
                ffmpeg_result.returncode,
                stderr_tail,
            )
            return None
        return ffmpeg_result.stdout

    # =========================
    # LIFECYCLE / CONFIG
    # =========================
    def bootstrap(self):
        pass

    def update(self):
        pass

    def reload_config(self):
        pass

    def wipe_all(self):
        raise NotImplementedError

    def static_resource(self, path):
        raise NotImplementedError

    def _get_ffmpeg_path(self):
        return app.config.get("FFMPEG_PATH") or "ffmpeg"


class FolderStorage(StorageBase):
    _ATTACHMENT_FILENAME = "%d.%s"
    _THUMBNAIL_FILENAME = "%d.jpg"
    # Version the derived clip so previews produced before browser-compatible
    # pixel-format enforcement are lazily regenerated from the origin.
    _PREVIEW_FILENAME = "%d-v2.mp4"
    def __init__(self):
        super().__init__()
        self.reload_config()
    def get_attachment(self, media_id):
        media = db.session.query(Media).filter(Media.id == media_id).one()
        return send_from_directory(self._upload_folder,
                                   self._attachment_name(media.id, media.ext),
                                   last_modified=datetime.datetime.now())
    def get_thumbnail(self, media_id):
        return send_from_directory(self._thumb_folder,
                                   self._thumbnail_name(media_id),
                                   last_modified=datetime.datetime.now())
    def delete_attachment(self, media_id, media_ext):
        os.remove(os.path.join(self._upload_folder,
                               self._attachment_name(media_id, media_ext)))
        os.remove(os.path.join(self._thumb_folder,
                               self._thumbnail_name(media_id)))
        # Best-effort: previews only exist for videos (and only since this
        # feature landed), so a missing one is normal — never fail the delete.
        try:
            os.remove(os.path.join(self._preview_folder,
                                   self._preview_name(media_id)))
        except FileNotFoundError:
            pass
    def delete_attachment_object(self, media_id, media_ext):
        # Offload path: remove ONLY the origin file. The thumbnail and the
        # hover-preview clip are intentionally left in place.
        try:
            os.remove(os.path.join(self._upload_folder,
                                   self._attachment_name(media_id, media_ext)))
        except FileNotFoundError:
            pass
    def attachment_exists(self, media_id, media_ext):
        full_path = os.path.join(self._upload_folder, self._attachment_name(media_id, media_ext))
        return os.path.isfile(full_path)

    def read_attachment_bytes(self, media_id, media_ext):
        full_path = os.path.join(self._upload_folder, self._attachment_name(media_id, media_ext))
        try:
            return open(full_path, "rb").read()
        except FileNotFoundError as exc:
            raise MissingAttachmentError(
                media_id,
                media_ext,
                storage_key=full_path,
                original_error=exc,
            ) from exc

    def read_attachment_range(self, media_id, media_ext, start, end):
        full_path = os.path.join(self._upload_folder, self._attachment_name(media_id, media_ext))
        try:
            with open(full_path, "rb") as handle:
                handle.seek(start)
                return handle.read(end - start + 1)
        except FileNotFoundError as exc:
            raise MissingAttachmentError(
                media_id,
                media_ext,
                storage_key=full_path,
                original_error=exc,
            ) from exc

    def read_thumbnail_bytes(self, media_id):
        full_path = os.path.join(self._thumb_folder, self._thumbnail_name(media_id))
        try:
            return open(full_path, "rb").read()
        except FileNotFoundError as exc:
            raise MissingAttachmentError(
                media_id,
                "jpg",
                storage_key=full_path,
                original_error=exc,
            ) from exc
    def read_video_preview_bytes(self, media_id):
        full_path = os.path.join(self._preview_folder, self._preview_name(media_id))
        try:
            return open(full_path, "rb").read()
        except FileNotFoundError as exc:
            raise MissingAttachmentError(
                media_id,
                "mp4",
                storage_key=full_path,
                original_error=exc,
            ) from exc
    def bootstrap(self):
        os.makedirs(self._upload_folder, exist_ok=True)
        os.makedirs(self._thumb_folder, exist_ok=True)
        os.makedirs(self._preview_folder, exist_ok=True)
    def reload_config(self):
        self._upload_folder = app.config["UPLOAD_FOLDER"]
        self._thumb_folder = app.config["THUMB_FOLDER"]
        # Derived hover-preview clips live alongside the thumbnails (defaults to
        # UPLOAD_FOLDER/previews) so no new env/config is required to deploy.
        self._preview_folder = app.config.get("PREVIEW_FOLDER") or os.path.join(
            self._upload_folder, "previews"
        )
    def wipe_all(self):
        for folder_path in (self._upload_folder, self._thumb_folder, self._preview_folder):
            if os.path.isdir(folder_path):
                for item_name in os.listdir(folder_path):
                    item_path = os.path.join(folder_path, item_name)
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
            else:
                os.makedirs(folder_path, exist_ok=True)
    def get_attachment_fetch_url(self, media_id, media_ext):
        return absolute_upload_url("/upload/%d/raw" % media_id)
    def _attachment_name(self, media_id, media_ext):
        return self._ATTACHMENT_FILENAME % (media_id, media_ext)
    def _thumbnail_name(self, media_id):
        return self._THUMBNAIL_FILENAME % media_id
    def _preview_name(self, media_id):
        return self._PREVIEW_FILENAME % media_id
    def _write_attachment(self, attachment_bytes, media_id, media_ext):
        full_path = os.path.join(self._upload_folder,
                                 self._attachment_name(media_id, media_ext))
        open(full_path, "wb").write(attachment_bytes.getvalue())
    def _write_thumbnail(self, thumbnail_bytes, media_id):
        full_path = os.path.join(self._thumb_folder,
                                 self._thumbnail_name(media_id))
        open(full_path, "wb").write(thumbnail_bytes.getvalue())
    def _write_video_preview(self, preview_bytes, media_id):
        # Lazy generation may run before bootstrap on a fresh volume, so ensure
        # the folder exists rather than relying on bootstrap having created it.
        os.makedirs(self._preview_folder, exist_ok=True)
        full_path = os.path.join(self._preview_folder,
                                 self._preview_name(media_id))
        open(full_path, "wb").write(preview_bytes.getvalue())


class S3Storage(StorageBase):
    _ATTACHMENT_KEY = "%d.%s"
    _ATTACHMENT_BUCKET = "attachments"
    _THUMBNAIL_KEY = "%d.jpg"
    _THUMBNAIL_BUCKET = "thumbs"
    _PREVIEW_KEY = "%d-v2.mp4"
    _PREVIEW_BUCKET = "previews"
    _STATIC_DIR = "static"
    _CUSTOM_STATIC_DIR = "deploy-configs/custom-static"
    _STATIC_BUCKET = "static"
    _PUBLIC_READ_POLICY = json.dumps({"Version":"2012-10-17",
                                      "Statement":[
                                          {
                                              "Sid":"allpublic",
                                              "Effect":"Allow",
                                              "Principal": "*",
                                              "Action": "s3:GetObject",
                                              "Resource": "arn:aws:s3:::%s/*"
                                          }
                                      ]})
    
    def __init__(self):
        self.reload_config()

    def reload_config(self):
        import boto3
        self._endpoint = app.config["S3_ENDPOINT"]
        self._access_key = app.config["S3_ACCESS_KEY"]
        self._secret_key = app.config["S3_SECRET_KEY"]
        self._bucket_uuid = app.config.get("S3_UUID_PREFIX") or ""
        self._bucket_check_lock = threading.Lock()
        self._verified_buckets = set()
        from botocore.config import Config
        ca_bundle = (app.config.get("S3_CA_BUNDLE") or "").strip()
        insecure = str(app.config.get("S3_INSECURE_TLS") or "").strip().lower()
        if insecure in ("1", "true", "yes"):
            verify = False
        elif ca_bundle:
            verify = ca_bundle
        else:
            verify = None
        extra = {}
        try:
            Config(request_checksum_calculation="when_required")
            extra["request_checksum_calculation"] = "when_required"
            extra["response_checksum_validation"] = "when_required"
        except Exception:
            pass
        # Bound every S3 call. Without explicit timeouts botocore waits 60s per
        # read with unbounded legacy retries, so a single stalled S3 write
        # freezes the *open post transaction* around it (get_media_id runs inside
        # create_post's transaction) — leaving a session "idle in transaction"
        # that holds locks on poster/profile and cascades into a site-wide lock
        # pileup (ALTER TABLE and every profile SELECT queue behind it -> 504s).
        # Fail fast instead: worst case ~2*(5+20)=50s < nginx's 60s upstream
        # timeout, so the request errors cleanly and the transaction rolls back.
        self._s3_client = boto3.resource("s3",
                                         endpoint_url=self._endpoint,
                                         aws_access_key_id=self._access_key,
                                         aws_secret_access_key=self._secret_key,
                                         verify=verify,
                                         config=Config(
                                             **extra,
                                             s3={'addressing_style': 'path'},
                                             connect_timeout=5,
                                             read_timeout=20,
                                             retries={'max_attempts': 2, 'mode': 'standard'},
                                         ))

    def get_attachment(self, media_id):
        media = db.session.query(Media).filter(Media.id == media_id).one()
        media_ext = media.ext
        return redirect(self.get_media_url(media_id, media_ext))
    def get_thumbnail(self, media_id):
        return redirect(self.get_thumb_url(media_id))
    def get_media_url(self, media_id, media_ext):
        # An OFFLOADED object must not be handed out as an /s3/ URL. That URL is
        # proxied by nginx straight to the data server, bypassing Python
        # entirely -- so it would keep serving the very copy the offload exists
        # to stop keeping, and would break outright once that copy is reclaimed.
        # Route those through the app instead, which reads from the DHT
        # (services/media_read.py). Everything not offloaded -- static assets,
        # watermarks, banners, anything we mirror rather than own -- keeps the
        # direct /s3/ URL and its performance.
        try:
            from services.media_read import is_offloaded

            if is_offloaded(media_id):
                return absolute_upload_url("/upload/%d/fetch" % media_id)
        except Exception:
            app.logger.exception("get_media_url: offload check failed for %s", media_id)
        s3_key = self._s3_attachment_key(media_id, media_ext)
        return self._format_url(self._ATTACHMENT_BUCKET, s3_key)
    def get_attachment_fetch_url(self, media_id, media_ext):
        return absolute_upload_url("/upload/%d/fetch" % media_id)
    def get_thumb_url(self, media_id):
        return url_for("upload.thumb", media_id=media_id)
    def delete_attachment(self, media_id, media_ext):
        s3_attach_key = self._s3_attachment_key(media_id, media_ext)
        self._s3_remove_key(self._ATTACHMENT_BUCKET, s3_attach_key)
        s3_thumb_key = self._s3_thumbnail_key(media_id)
        self._s3_remove_key(self._THUMBNAIL_BUCKET, s3_thumb_key)
        # Best-effort: the previews bucket only exists once a video has been
        # uploaded, so tolerate a missing bucket/key when fully deleting media.
        try:
            self._s3_remove_key(self._PREVIEW_BUCKET, self._s3_preview_key(media_id))
        except Exception as exc:
            if not _is_missing_storage_error(exc):
                raise
    def delete_attachment_object(self, media_id, media_ext):
        # Offload path: remove ONLY the origin object. The thumbnail and the
        # hover-preview clip are intentionally left in place.
        s3_attach_key = self._s3_attachment_key(media_id, media_ext)
        self._s3_remove_key(self._ATTACHMENT_BUCKET, s3_attach_key)
    def attachment_exists(self, media_id, media_ext):
        s3_key = self._s3_attachment_key(media_id, media_ext)
        bucket = self._get_bucket(self._ATTACHMENT_BUCKET)
        try:
            bucket.Object(s3_key).load()
            return True
        except Exception as exc:
            if _is_missing_storage_error(exc):
                return False
            raise

    def read_attachment_bytes(self, media_id, media_ext):
        s3_key = self._s3_attachment_key(media_id, media_ext)
        bucket = self._get_bucket(self._ATTACHMENT_BUCKET)
        try:
            return bucket.Object(s3_key).get()["Body"].read()
        except Exception as exc:
            if _is_missing_storage_error(exc):
                raise MissingAttachmentError(
                    media_id,
                    media_ext,
                    storage_key=s3_key,
                    original_error=exc,
                ) from exc
            raise

    def read_attachment_range(self, media_id, media_ext, start, end):
        s3_key = self._s3_attachment_key(media_id, media_ext)
        bucket = self._get_bucket(self._ATTACHMENT_BUCKET)
        try:
            data = bucket.Object(s3_key).get(
                Range="bytes=%d-%d" % (start, end)
            )["Body"].read()
        except Exception as exc:
            if _is_missing_storage_error(exc):
                raise MissingAttachmentError(
                    media_id,
                    media_ext,
                    storage_key=s3_key,
                    original_error=exc,
                ) from exc
            raise
        # A gateway that does not implement Range answers with the WHOLE object.
        # Returning that under a 206 would hand the browser bytes from offset 0
        # while it believes it received the range it asked for -- a corrupt seek
        # that looks like a corrupt file. Detect it by length and slice here.
        if len(data) > (end - start + 1):
            data = data[start:end + 1]
        return data

    def read_thumbnail_bytes(self, media_id):
        s3_key = self._s3_thumbnail_key(media_id)
        bucket = self._get_bucket(self._THUMBNAIL_BUCKET)
        try:
            return bucket.Object(s3_key).get()["Body"].read()
        except Exception as exc:
            if _is_missing_storage_error(exc):
                raise MissingAttachmentError(
                    media_id,
                    "jpg",
                    storage_key=s3_key,
                    original_error=exc,
                ) from exc
            raise
    def read_video_preview_bytes(self, media_id):
        s3_key = self._s3_preview_key(media_id)
        bucket = self._get_bucket(self._PREVIEW_BUCKET)
        try:
            return bucket.Object(s3_key).get()["Body"].read()
        except Exception as exc:
            if _is_missing_storage_error(exc):
                raise MissingAttachmentError(
                    media_id,
                    "mp4",
                    storage_key=s3_key,
                    original_error=exc,
                ) from exc
            raise
    def bootstrap(self):
        app.logger.info("S3Storage bootstrap: ensuring buckets and syncing static files")
        self._ensure_buckets()
        # The static-file sync PUTs each object into the DHT store, which blocks
        # until DurableRemoteHolders(6,3)=7 distinct peers hold shards. On a small
        # or cold network that quorum may not exist yet, so this must not gate app
        # startup: run it in the background with an app context. The site serves
        # immediately; static assets disperse as storage nodes come online.
        import threading
        def _bg_static_sync():
            with app.app_context():
                try:
                    self.update()
                    app.logger.info("S3Storage bootstrap: background static sync complete")
                except Exception:
                    app.logger.exception("S3Storage bootstrap: background static sync failed")
        threading.Thread(target=_bg_static_sync, name="s3-static-sync", daemon=True).start()
        app.logger.info("S3Storage bootstrap: complete (static sync backgrounded)")
    def wipe_all(self):
        for bucket_name in (self._ATTACHMENT_BUCKET, self._THUMBNAIL_BUCKET, self._PREVIEW_BUCKET, self._STATIC_BUCKET):
            try:
                bucket = self._get_bucket(bucket_name)
                bucket.objects.all().delete()
            except Exception as exc:
                if _is_missing_storage_error(exc):
                    continue
                response = getattr(exc, "response", None)
                error = response.get("Error") if isinstance(response, dict) else {}
                if str((error or {}).get("Code") or "").strip() in ("404", "NoSuchBucket", "NotFound"):
                    continue
                raise
    def _create_bucket(self, bucket_name):
        app.logger.info("S3Storage _create_bucket: creating bucket=%s", bucket_name)
        try:
            self._s3_client.create_bucket(Bucket=bucket_name, ACL='public-read')
            app.logger.info("S3Storage _create_bucket: created bucket=%s", bucket_name)
        except Exception as exc:
            if self._is_bucket_already_owned_error(exc):
                app.logger.info("S3Storage _create_bucket: bucket already owned, setting ACL bucket=%s", bucket_name)
                try:
                    self._s3_client.Bucket(bucket_name).Acl().put(ACL='public-read')
                except Exception:
                    pass
                return
            app.logger.exception("S3Storage _create_bucket: FAILED bucket=%s", bucket_name)
            raise
    def _ensure_buckets(self, bucket_suffixes=None, force=False):
        suffixes = bucket_suffixes or (
            self._ATTACHMENT_BUCKET,
            self._THUMBNAIL_BUCKET,
            self._PREVIEW_BUCKET,
            self._STATIC_BUCKET,
        )
        for bucket_suffix in suffixes:
            bucket_name = self._bucket_uuid + bucket_suffix
            if force is False and bucket_name in self._verified_buckets:
                continue
            with self._bucket_check_lock:
                if force is False and bucket_name in self._verified_buckets:
                    continue
                try:
                    self._s3_client.meta.client.head_bucket(Bucket=bucket_name)
                    app.logger.info("S3Storage _ensure_buckets: bucket exists bucket=%s", bucket_name)
                except Exception as exc:
                    app.logger.warning("S3Storage _ensure_buckets: bucket missing, creating bucket=%s err=%s", bucket_name, exc)
                    self._create_bucket(bucket_name)
                self._verified_buckets.add(bucket_name)
    def _is_bucket_already_owned_error(self, exc):
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            error = response.get("Error") or {}
            if error.get("Code") == "BucketAlreadyOwnedByYou":
                return True
        return "BucketAlreadyOwnedByYou" in str(exc)

    def update(self):
        self._ensure_buckets()
        static_bucket = self._get_bucket(self._STATIC_BUCKET)
        # copy over all static files
        static_dirs = [self._STATIC_DIR]
        # check for custom static directory
        if os.path.exists(self._CUSTOM_STATIC_DIR):
            static_dirs.append(self._CUSTOM_STATIC_DIR)
        # Only upload what is actually missing or changed.
        #
        # This used to put_object() every static file on every boot. Against a
        # local object store that was merely wasteful; against the DHT store it
        # is thousands of erasure-coded dispersals, each placed across nine
        # holders, re-done on every restart -- which made startup take minutes,
        # and startup blocks uwsgi, so every deploy was a multi-minute outage.
        #
        # Comparing size is enough here: these are build artifacts, so a changed
        # file is a different file. A same-size edit is possible in principle,
        # and FORCE_STATIC_SYNC=1 exists for that case.
        force = os.environ.get("FORCE_STATIC_SYNC", "").lower() in ("1", "true", "yes")
        try:
            existing = {
                obj.key: obj.size
                for obj in static_bucket.objects.all()
            }
        except Exception:
            # A store that cannot be listed is not a reason to skip the upload;
            # fall back to the old unconditional behaviour.
            existing = {}
        uploaded = skipped = 0
        for static_dir in static_dirs:
            for base, _, filenames in os.walk(static_dir):
                for filename in filenames:
                    # strip the unecessary part of the path (static or deploy-configs/custom-static)
                    s3_key = "/".join([base[len(static_dir + "/"):], filename])
                    # correctly handle files at the root of the directory
                    if s3_key.startswith("/"):
                        s3_key = s3_key[1:]
                    full_path = os.path.join(static_dir, s3_key)
                    if not force and existing.get(s3_key) == os.path.getsize(full_path):
                        skipped += 1
                        continue
                    mimetype = self._get_mimetype(s3_key)
                    with open(full_path, "rb") as static_file:
                        static_bucket.put_object(
                            Key=s3_key,
                            Body=static_file,
                            ContentType=mimetype,
                            ACL="public-read",
                        )
                    uploaded += 1
        logging.getLogger(__name__).info(
            "static sync: %d uploaded, %d already present", uploaded, skipped
        )
        for bucket_name in (self._ATTACHMENT_BUCKET, self._THUMBNAIL_BUCKET, self._PREVIEW_BUCKET, self._STATIC_BUCKET):
            bucket = self._get_bucket(bucket_name)
            bucket.Policy().put(Policy=self._PUBLIC_READ_POLICY % bucket.name)
            bucket.Policy().reload()
    def static_resource(self, path):
        return self._format_url(self._STATIC_BUCKET, path)
    def _format_url(self, bucket, path):
        if app.config.get("CDN_REWRITE"):
            args = {
                "ENDPOINT": self._endpoint,
                "BUCKET_UUID": self._bucket_uuid,
                "BUCKET": bucket,
                "PATH": path}
            return app.config["CDN_REWRITE"].format(**args)
        else:
            return "%s/%s%s/%s" % (self._endpoint, self._bucket_uuid, bucket, path)
    def _get_bucket(self, bucket):
        return self._s3_client.Bucket(self._bucket_uuid + bucket)
    # Above this, an object is uploaded in parts instead of one request.
    #
    # WHY: a single PUT of a stream recording -- hundreds of megabytes -- is
    # closed by the DHT gateway partway through the body (ConnectionClosedError
    # on prod, every attempt, four for four). The same gateway accepts the same
    # bytes as a multipart upload, which was verified against it directly before
    # this was written rather than assumed. Multipart also means a failure costs
    # one part instead of the whole transfer.
    #
    # The threshold is well above any image or thumbnail, so ordinary uploads
    # keep taking the single-request path and pay nothing for this.
    # 5MB, MEASURED against the gateway rather than chosen for tidiness. Parts
    # of 5MB and below are accepted; 6MB and above close the connection, and a
    # 64MB object uploads fine in 5MB parts -- so the constraint is per-REQUEST
    # body size, not total object size, and the single-PUT path hits the same
    # wall (a 24MB PUT fails). Hence the threshold sits at the part size: past
    # it, everything must go in parts.
    #
    # 5MB is also S3's own minimum part size, so this stays valid if the gateway
    # is ever swapped for a standards-compliant implementation. Do not raise it
    # without re-measuring; the failure is a mid-body connection close that
    # looks like a network fault rather than a limit.
    _MULTIPART_THRESHOLD = 5 * 1024 * 1024
    _MULTIPART_CHUNKSIZE = 5 * 1024 * 1024

    def _transfer_config(self):
        from boto3.s3.transfer import TransferConfig

        return TransferConfig(
            multipart_threshold=self._MULTIPART_THRESHOLD,
            multipart_chunksize=self._MULTIPART_CHUNKSIZE,
            # Deliberately modest. The gateway is a single node that is also
            # serving the site; ten parallel part uploads of a 400MB object is a
            # way to turn one slow archive into a site-wide stall.
            max_concurrency=4,
            use_threads=True,
        )

    def _put_object(self, bucket, key, body, mimetype):
        if len(body) >= self._MULTIPART_THRESHOLD:
            bucket.upload_fileobj(
                io.BytesIO(body),
                key,
                ExtraArgs={"ContentType": mimetype, "ACL": "public-read"},
                Config=self._transfer_config(),
            )
            return
        bucket.put_object(
            Key=key,
            Body=body,
            ContentType=mimetype,
            ACL="public-read",
        )
    def _write_attachment(self, attachment_file, media_id, media_ext):
        s3_key = self._s3_attachment_key(media_id, media_ext)
        bucket = self._get_bucket(self._ATTACHMENT_BUCKET)
        mimetype = self._get_mimetype(s3_key)
        raw = attachment_file.getvalue() if hasattr(attachment_file, "getvalue") else attachment_file.read()
        app.logger.info("S3 _write_attachment: bucket=%s key=%s mimetype=%s", bucket.name, s3_key, mimetype)
        try:
            self._put_object(bucket, s3_key, raw, mimetype)
            app.logger.info("S3 _write_attachment: SUCCESS bucket=%s key=%s", bucket.name, s3_key)
        except Exception as exc:
            if "NoSuchBucket" in str(exc) or "404" in str(exc):
                app.logger.warning("S3 _write_attachment: Bucket missing! Creating buckets and retrying...")
                self._ensure_buckets((self._ATTACHMENT_BUCKET,), force=True)
                try:
                    self._put_object(bucket, s3_key, raw, mimetype)
                    app.logger.info("S3 _write_attachment: SUCCESS on retry bucket=%s key=%s", bucket.name, s3_key)
                    return
                except Exception as retry_exc:
                    app.logger.exception("S3 _write_attachment: FAILED on retry bucket=%s key=%s", bucket.name, s3_key)
                    raise retry_exc
            app.logger.exception("S3 _write_attachment: FAILED bucket=%s key=%s", bucket.name, s3_key)
            raise
    def _write_thumbnail(self, thumbnail_bytes, media_id):
        s3_key = self._s3_thumbnail_key(media_id)
        bucket = self._get_bucket(self._THUMBNAIL_BUCKET)
        mimetype = self._get_mimetype(s3_key)
        # Read bytes upfront — upload_fileobj closes the stream on failure,
        # so we need the raw bytes to reconstruct a fresh stream for the retry.
        raw = thumbnail_bytes.read() if not getattr(thumbnail_bytes, "closed", False) else b""
        app.logger.info("S3 _write_thumbnail: bucket=%s key=%s", bucket.name, s3_key)
        try:
            self._put_object(bucket, s3_key, raw, mimetype)
            app.logger.info("S3 _write_thumbnail: SUCCESS bucket=%s key=%s", bucket.name, s3_key)
        except Exception as exc:
            if "NoSuchBucket" in str(exc) or "404" in str(exc):
                app.logger.warning("S3 _write_thumbnail: Bucket missing! Creating buckets and retrying...")
                self._ensure_buckets((self._THUMBNAIL_BUCKET,), force=True)
                try:
                    self._put_object(bucket, s3_key, raw, mimetype)
                    app.logger.info("S3 _write_thumbnail: SUCCESS on retry bucket=%s key=%s", bucket.name, s3_key)
                    return
                except Exception as retry_exc:
                    app.logger.exception("S3 _write_thumbnail: FAILED on retry bucket=%s key=%s", bucket.name, s3_key)
                    raise retry_exc
            app.logger.exception("S3 _write_thumbnail: FAILED bucket=%s key=%s", bucket.name, s3_key)
            raise
    def _write_video_preview(self, preview_bytes, media_id):
        s3_key = self._s3_preview_key(media_id)
        bucket = self._get_bucket(self._PREVIEW_BUCKET)
        mimetype = self._get_mimetype(s3_key)
        # Read bytes upfront — upload_fileobj closes the stream on failure, so we
        # need the raw bytes to reconstruct a fresh stream for the retry.
        raw = preview_bytes.read() if not getattr(preview_bytes, "closed", False) else b""
        app.logger.info("S3 _write_video_preview: bucket=%s key=%s", bucket.name, s3_key)
        try:
            self._put_object(bucket, s3_key, raw, mimetype)
            app.logger.info("S3 _write_video_preview: SUCCESS bucket=%s key=%s", bucket.name, s3_key)
        except Exception as exc:
            if "NoSuchBucket" in str(exc) or "404" in str(exc):
                app.logger.warning("S3 _write_video_preview: Bucket missing! Creating buckets and retrying...")
                self._ensure_buckets((self._PREVIEW_BUCKET,), force=True)
                try:
                    self._put_object(bucket, s3_key, raw, mimetype)
                    app.logger.info("S3 _write_video_preview: SUCCESS on retry bucket=%s key=%s", bucket.name, s3_key)
                    return
                except Exception as retry_exc:
                    app.logger.exception("S3 _write_video_preview: FAILED on retry bucket=%s key=%s", bucket.name, s3_key)
                    raise retry_exc
            app.logger.exception("S3 _write_video_preview: FAILED bucket=%s key=%s", bucket.name, s3_key)
            raise
    def _s3_remove_key(self, bucket_name, key):
        bucket = self._get_bucket(bucket_name)
        bucket.delete_objects(Delete={"Objects": [{"Key": key}]})
    def _s3_attachment_key(self, media_id, media_ext):
        return self._ATTACHMENT_KEY % (media_id, media_ext)
    def _s3_thumbnail_key(self, media_id):
        return self._THUMBNAIL_KEY % (media_id)
    def _s3_preview_key(self, media_id):
        return self._PREVIEW_KEY % (media_id)
    def _get_mimetype(self, path):
        mimetype, _ = mimetypes.guess_type(path)
        return mimetype or "application/octet-stream"


def get_storage_provider():
    if app.config.get("STORAGE_PROVIDER") is None:
        return FolderStorage()
    if app.config["STORAGE_PROVIDER"] == "S3":
        # prevent non-s3 installations from needing to pull in boto3
        global boto3
        boto3 = __import__("boto3")
        return S3Storage()
    elif app.config["STORAGE_PROVIDER"] == "FOLDER":
        return FolderStorage()
    # TODO: proper error-handling on unknown key value
storage = get_storage_provider()


@app.context_processor
def static_handler():
    def static_resource(path):
        normalized_path = path.lstrip("/")
        static_url_base = app.config.get("STATIC_URL_BASE")
        if static_url_base:
            return "%s/%s" % (static_url_base.rstrip("/"), normalized_path)
        resource_url = url_for("serve_static", path=normalized_path)
        absolute_path = os.path.join(app.static_folder, normalized_path)
        if os.path.isfile(absolute_path):
            version = int(os.path.getmtime(absolute_path))
            separator = "&" if "?" in resource_url else "?"
            return "%s%sv=%d" % (resource_url, separator, version)
        return resource_url
    def get_current_theme():
        # Saved preference: persistent cookie first, then session, then default
        # (resolver lives in the theme blueprint; imported lazily to avoid a
        # circular import at module load).
        from blueprints.theme import resolve_current_theme
        return resolve_current_theme()
    def get_current_theme_path():
        theme_name = get_current_theme()
        theme_template = "css/{THEME_NAME}/theme-{THEME_NAME}.css"
        return static_resource(theme_template.format(THEME_NAME=theme_name))
    def get_themes():
        return app.config.get("THEME_LIST") or ("stock", "harajuku", "wildride", "711chan", "cyberpunk", "midnight")
    return dict(static_resource=static_resource,
                get_current_theme=get_current_theme,
                get_current_theme_path=get_current_theme_path,
                get_themes=get_themes)


@app.context_processor
def upload_size():
    def max_upload_size():
        upload_byte_size = app.config["MAX_CONTENT_LENGTH"]
        megabyte_size = upload_byte_size / (1024 ** 2)
        return "%.1fMB" % megabyte_size
    return dict(max_upload_size=max_upload_size)


@app.context_processor
def upload_urls():
    return dict(get_media_url=storage.get_media_url, get_thumb_url=storage.get_thumb_url)
