from typing import Dict, Optional

from flask import url_for

from board_sources import source_label
from model.ImageMagnet import ImageMagnet, magnet_needs_seedbox_seed
from model.Media import Media, storage
from model.Slip import slip_from_id
from services.torrent_media import resolved_media_torrent_payload
from source_watermarks import source_watermark_image_url
from shared import db


def _queue_seedbox_repair(media, torrent_payload) -> None:
    if media is None or torrent_payload is None:
        return
    if magnet_needs_seedbox_seed(torrent_payload.get("magnet_url")) is False:
        return
    mimetype = str(getattr(media, "mimetype", "") or "").lower()
    if mimetype.startswith("image/") is False:
        return
    media_id = getattr(media, "id", None)
    media_ext = getattr(media, "ext", None)
    if not media_id or not media_ext:
        return
    try:
        from services.seedbox import seed_media_background

        seed_media_background(
            media_id,
            storage.get_attachment_fetch_url(media_id, media_ext),
            media_ext=media_ext,
            expected_info_hash=getattr(media, "torrent_info_hash", None),
            piece_length=getattr(media, "torrent_piece_length", None),
        )
    except Exception:
        return


def media_row_payload(media_id, media=None) -> Dict[str, object]:
    if not media_id:
        return {"media": None}
    if media is None:
        media = (
            db.session.query(
                Media.id,
                Media.ext,
                Media.mimetype,
                Media.is_animated,
                Media.torrent_info_hash,
                Media.torrent_piece_length,
                ImageMagnet.magnet_url.label("image_magnet_url"),
            )
            .outerjoin(ImageMagnet, ImageMagnet.media_id == Media.id)
            .filter(Media.id == media_id)
            .one_or_none()
        )
    if media is None:
        return {"media": None}
    media_ext = media.ext
    mimetype = media.mimetype
    is_animated = media.is_animated
    public_media_url = storage.get_media_url(media_id, media_ext)
    direct_media_url = public_media_url
    torrent_payload, _magnet_changed = resolved_media_torrent_payload(media)
    magnet_media_url = None
    if torrent_payload is not None:
        torrent_payload["mimetype"] = mimetype
        if isinstance(mimetype, str) and mimetype.startswith("image/"):
            direct_media_url = storage.get_direct_media_url(media_id, media_ext)
            magnet_media_url = torrent_payload.get("magnet_url")
            _queue_seedbox_repair(media, torrent_payload)
    resolved_media_url = public_media_url
    if magnet_media_url:
        resolved_media_url = magnet_media_url
    return {
        "media": media_id,
        "media_ext": media_ext,
        "mimetype": mimetype,
        "is_animated": is_animated,
        "thumb_url": url_for("upload.thumb", media_id=media_id),
        "media_url": resolved_media_url,
        "direct_media_url": direct_media_url if magnet_media_url else public_media_url,
        "magnet_media_url": magnet_media_url,
        "torrent": torrent_payload,
    }


def media_payload(post, keyed_media: Optional[Dict[int, object]] = None) -> Dict[str, object]:
    if post.media:
        media = keyed_media.get(post.media) if keyed_media is not None else None
        return media_row_payload(post.media, media)

    return {"media": None}


def post_display_name(post, poster=None, slip=None) -> str:
    if slip is None and poster is not None and getattr(poster, "slip", None):
        slip = slip_from_id(poster.slip)
    if slip is not None and getattr(slip, "is_admin", False):
        return "sysop"
    if post.author_name:
        return post.author_name
    return "Anonymous"


def post_tripcode(post, poster=None, slip=None) -> Optional[str]:
    if slip is None and poster is not None and getattr(poster, "slip", None):
        slip = slip_from_id(poster.slip)
    if slip is not None and getattr(slip, "is_admin", False):
        return None
    return getattr(post, "tripcode", None)


def poster_display_id(poster) -> Optional[str]:
    if poster is None:
        return None
    return getattr(poster, "hex_string", None)


def source_metadata(source_type: str, source_name: Optional[str], source_url: Optional[str],
                    watermark_url: Optional[str] = None,
                    watermark_label: Optional[str] = None) -> Dict[str, object]:
    is_imported = source_type != "local"
    watermark_image_url = source_watermark_image_url(source_type) if is_imported else None
    label = source_label(source_type, source_name) if is_imported and source_name else source_type
    # Federated (NNTP) posts are stored with source_type "local" so they render
    # through the normal post-row path, but they carry a per-post source
    # watermark (e.g. the origin site's favicon) + label so viewers can still
    # tell where the post came from. A custom watermark_url drives the frontend's
    # source-watermarked--custom styling.
    if watermark_url or watermark_label:
        is_imported = True
        if watermark_url:
            watermark_image_url = watermark_url
        if watermark_label:
            label = watermark_label
    return {
        "source_type": source_type,
        "source_name": source_name,
        "source_url": source_url,
        "source_label": label,
        "is_imported": is_imported,
        "watermark_image_url": watermark_image_url,
    }
