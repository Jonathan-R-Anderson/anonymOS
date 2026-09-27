from typing import Dict, Optional

from flask import g, has_request_context

from board_sources import SUPPORTED_SOURCE_TYPES
from model.Media import Media, storage
from model.SiteSetting import get_setting, set_setting
from shared import db


SOURCE_WATERMARK_SETTING_TEMPLATE = "source-watermark-media-id:%s"
SOURCE_DISPLAY_NAMES = {
    "4chan": "4chan",
    "8chan": "8chan",
    "7chan": "7chan",
    "reddit": "Reddit",
}


def source_watermark_setting_key(source_type: str) -> str:
    return SOURCE_WATERMARK_SETTING_TEMPLATE % source_type


def source_display_name(source_type: str) -> str:
    return SOURCE_DISPLAY_NAMES.get(source_type, source_type)


def source_watermark_media_id(source_type: str) -> Optional[int]:
    if source_type not in SUPPORTED_SOURCE_TYPES:
        return None
    raw_value = (get_setting(source_watermark_setting_key(source_type), "") or "").strip()
    if raw_value == "":
        return None
    try:
        return int(raw_value)
    except (TypeError, ValueError):
        return None


def source_watermark_summary(source_type: str) -> Dict[str, object]:
    summary_cache = _request_cache()
    if summary_cache is not None and source_type in summary_cache:
        return summary_cache[source_type]

    media_id = source_watermark_media_id(source_type)
    image_url = None
    thumb_url = None
    if media_id is not None:
        media = (
            db.session.query(Media.ext)
            .filter(Media.id == media_id)
            .one_or_none()
        )
        if media is not None:
            image_url = storage.get_media_url(media_id, media.ext)
            thumb_url = storage.get_thumb_url(media_id)

    summary = {
        "source_type": source_type,
        "display_name": source_display_name(source_type),
        "media_id": media_id,
        "image_url": image_url,
        "thumb_url": thumb_url,
    }
    if summary_cache is not None:
        summary_cache[source_type] = summary
    return summary


def source_watermark_image_url(source_type: str) -> Optional[str]:
    return source_watermark_summary(source_type).get("image_url")


def replace_source_watermark(source_type: str, media_id: int) -> Optional[int]:
    previous_media_id = source_watermark_media_id(source_type)
    set_setting(source_watermark_setting_key(source_type), str(media_id))
    _clear_request_cache(source_type)
    return previous_media_id


def clear_source_watermark(source_type: str) -> Optional[int]:
    previous_media_id = source_watermark_media_id(source_type)
    set_setting(source_watermark_setting_key(source_type), "")
    _clear_request_cache(source_type)
    return previous_media_id


def _request_cache():
    if has_request_context() is False:
        return None
    if getattr(g, "_source_watermark_cache", None) is None:
        g._source_watermark_cache = {}
    return g._source_watermark_cache


def _clear_request_cache(source_type: str) -> None:
    summary_cache = _request_cache()
    if summary_cache is not None:
        summary_cache.pop(source_type, None)
