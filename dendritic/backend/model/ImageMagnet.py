import datetime as _datetime
from urllib.parse import parse_qs, urlsplit

from shared import db


class ImageMagnet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    media_id = db.Column(
        db.Integer,
        db.ForeignKey("media.id"),
        nullable=False,
        unique=True,
    )
    magnet_url = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=_datetime.datetime.utcnow,
        onupdate=_datetime.datetime.utcnow,
    )


def current_image_magnet_url(media):
    direct_value = getattr(media, "image_magnet_url", None)
    if direct_value:
        return direct_value
    relation = getattr(media, "image_magnet", None)
    if relation is None:
        return None
    return getattr(relation, "magnet_url", None)


def media_supports_image_magnets(media):
    mimetype = (getattr(media, "mimetype", "") or "").strip().lower()
    return mimetype.startswith("image/")


def _magnet_info_hash(value):
    normalized = str(value or "").strip()
    if normalized.startswith("magnet:?") is False:
        return None
    query = parse_qs(urlsplit(normalized).query)
    xt_values = query.get("xt") or []
    for value in xt_values:
        marker = "urn:btih:"
        if value.startswith(marker):
            return value[len(marker):].strip().lower() or None
    return None


def _magnet_has_xs(value):
    normalized = str(value or "").strip()
    return normalized.startswith("magnet:?") and "xs=" in normalized


def _magnet_uses_internal_tracker(value):
    normalized = str(value or "").strip().lower()
    if normalized.startswith("magnet:?") is False:
        return False
    # Hosts that mean "this magnet points back at us". "ceph" used to be here
    # and was removed rather than renamed: there is no such service, so the test
    # could never match, and a dead branch that looks like a rule is worse than
    # no rule — somebody eventually maintains it.
    return (
        "://tracker:" in normalized
        or "://maniwani:" in normalized
        or "://syndichan-node:" in normalized
    )


def magnet_needs_seedbox_seed(value):
    normalized = str(value or "").strip()
    if normalized.startswith("magnet:?") is False:
        return True
    return _magnet_has_xs(normalized) or _magnet_uses_internal_tracker(normalized)


def _should_replace_existing_magnet(existing_value, replacement_value):
    normalized_existing = str(existing_value or "").strip()
    normalized_replacement = str(replacement_value or "").strip()
    if not normalized_existing:
        return True
    if normalized_existing.startswith("magnet:?") is False:
        return True
    if _magnet_uses_internal_tracker(normalized_existing):
        return True

    existing_hash = _magnet_info_hash(normalized_existing)
    replacement_hash = _magnet_info_hash(normalized_replacement)
    if existing_hash and replacement_hash and existing_hash != replacement_hash:
        return True

    if _magnet_has_xs(normalized_existing) and not _magnet_has_xs(normalized_replacement):
        return True
    return False


def sync_image_magnet_url(media, magnet_url):
    if media is None or not getattr(media, "id", None) or not magnet_url:
        return magnet_url, False
    if media_supports_image_magnets(media) is False:
        return magnet_url, False

    current_value = current_image_magnet_url(media)
    if current_value and _should_replace_existing_magnet(current_value, magnet_url) is False:
        return current_value, False

    image_magnet = (
        db.session.query(ImageMagnet)
        .filter(ImageMagnet.media_id == media.id)
        .one_or_none()
    )
    if image_magnet is None:
        image_magnet = ImageMagnet(media_id=media.id, magnet_url=magnet_url)
        db.session.add(image_magnet)
        return image_magnet.magnet_url, True
    if image_magnet.magnet_url and _should_replace_existing_magnet(image_magnet.magnet_url, magnet_url) is False:
        return image_magnet.magnet_url, False
    image_magnet.magnet_url = magnet_url
    db.session.add(image_magnet)
    return image_magnet.magnet_url, True
