import mimetypes
import os
from typing import Dict, Optional, Tuple
from urllib.parse import quote

from .scraper_db import scraper_data_dir
from .text import normalize_external_media_url, row_value


# Resolve a scraper-owned asset path to its on-disk location.
def resolve_scraper_asset_path(source_type: str, asset_path) -> Optional[Tuple[str, str, str]]:
    if not asset_path:
        return None
    try:
        # scraper_data_dir(), not dirname(db): a generic site's DB lives one level
        # below its DATA_DIR, so dirname(db) missed every generic asset.
        data_dir = scraper_data_dir(source_type)
    except ValueError:
        return None

    relative_path = os.path.normpath(str(asset_path).replace("\\", "/").lstrip("/")).replace("\\", "/")
    if relative_path in ("", "."):
        return None

    absolute_path = os.path.abspath(os.path.join(data_dir, relative_path))
    if absolute_path.startswith(data_dir + os.sep) is False:
        return None

    return data_dir, relative_path, absolute_path


# Return the Maniwani-served URL for a cached scraper asset when it exists.
def scraper_asset_url(source_type: str, asset_path) -> Optional[str]:
    resolved = resolve_scraper_asset_path(source_type, asset_path)
    if resolved is None:
        return None

    _, relative_path, absolute_path = resolved
    if os.path.isfile(absolute_path) is False:
        return None

    return "/aggregator-assets/%s/%s" % (
        quote(str(source_type), safe=""),
        quote(relative_path, safe="/"),
    )


# Prefer locally cached scraper media over the original remote URL.
def imported_image_display_url(source_type: str, row) -> Optional[str]:
    from model.RejectedImportedAsset import imported_asset_is_rejected

    if imported_asset_is_rejected(
        source_type, row_value(row, "image_path"), row_value(row, "image_url")
    ):
        return None
    local_url = scraper_asset_url(source_type, row_value(row, "image_path"))
    if local_url:
        return local_url
    remote_url = normalize_external_media_url(row_value(row, "image_url"))
    if not remote_url:
        return None
    # THROUGH THE PROXY, never a bare hotlink.
    #
    # This used to return the remote URL directly, which meant the browser fetched
    # the image straight from the source chan — bypassing every gate we have. An
    # image the NSFW filter had rejected still displayed, because nothing we control
    # was in the request path. It also handed each viewer's IP to the remote site.
    #
    # /image-proxy applies the hash blocklist, the NSFW replacement image and the
    # overlay gate, and falls back to a placeholder if the fetch fails — so a
    # broken proxy fetch degrades to a placeholder rather than to an ungated image.
    return "/image-proxy?url=%s" % quote(remote_url, safe="")


def imported_media_payload(source_type: str, row) -> Dict[str, object]:
    preview_url = imported_image_display_url(source_type, row)
    target_url = normalize_external_media_url(row_value(row, "url"))
    permalink = normalize_external_media_url(row_value(row, "permalink"))
    post_type = (row_value(row, "post_type") or "").strip().lower()

    if post_type == "video" and target_url:
        return {
            "media": preview_url or target_url,
            "thumb_url": preview_url or target_url,
            "media_url": target_url,
            "media_ext": None,
            "mimetype": _guess_imported_mimetype(target_url, "video/mp4"),
            "is_animated": False,
        }

    if preview_url:
        media_url = preview_url
        if post_type == "link" and target_url:
            media_url = target_url
        elif post_type == "comment" and target_url and target_url != permalink:
            media_url = target_url
        return {
            "media": preview_url,
            "thumb_url": preview_url,
            "media_url": media_url,
            "media_ext": None,
            "mimetype": _guess_imported_mimetype(preview_url, "image/jpeg"),
            "is_animated": _looks_animated_image(preview_url),
        }

    return {"media": None}


def _guess_imported_mimetype(url: Optional[str], default: str) -> str:
    guessed = mimetypes.guess_type(url or "")[0]
    return guessed or default


def _looks_animated_image(url: Optional[str]) -> bool:
    mimetype = _guess_imported_mimetype(url, "")
    return mimetype == "image/gif"
