import hashlib
import math
import re
import time
from dataclasses import dataclass
from typing import Optional

import requests
from flask import has_request_context, session

from model.Board import Board
from shared import app, db


VIEWER_GEO_SESSION_KEY = "viewer-geo"
VIEWER_GEO_TTL_SECONDS = 60 * 60 * 12
DEFAULT_GEO_RADIUS_MILES = 50
STANDARD_BOARD_TYPE = "standard"
GEO_ROOT_BOARD_TYPE = "geo-root"
GEO_GENERATED_BOARD_TYPE = "geo-generated"
CITY_GEO_STRATEGY = "city"
RADIUS_GEO_STRATEGY = "radius"
REVERSE_GEOCODE_URL = "https://nominatim.openstreetmap.org/reverse"


@dataclass
class ViewerLocation:
    latitude: float
    longitude: float
    stored_at: float
    city_key: Optional[str] = None
    city_label: Optional[str] = None


def slugify_board_name(value: Optional[str]) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return slug[:32]


def normalize_geo_strategy(raw_value: Optional[str]) -> str:
    value = (raw_value or "").strip().lower()
    if value == CITY_GEO_STRATEGY:
        return CITY_GEO_STRATEGY
    if value == RADIUS_GEO_STRATEGY:
        return RADIUS_GEO_STRATEGY
    raise ValueError("Geo boards must use either city or radius matching.")


def parse_geo_radius_miles(raw_value: Optional[str], default: int = DEFAULT_GEO_RADIUS_MILES) -> int:
    value = (raw_value or "").strip()
    if not value:
        return default
    if value.isdigit() is False:
        raise ValueError("Geo radius must be a positive integer.")
    miles = int(value)
    if miles <= 0:
        raise ValueError("Geo radius must be a positive integer.")
    return miles


def viewer_location() -> Optional[ViewerLocation]:
    if has_request_context() is False:
        return None
    raw_value = session.get(VIEWER_GEO_SESSION_KEY)
    if not isinstance(raw_value, dict):
        return None
    try:
        latitude = float(raw_value.get("latitude"))
        longitude = float(raw_value.get("longitude"))
        stored_at = float(raw_value.get("stored_at") or 0)
    except (TypeError, ValueError):
        return None
    if (time.time() - stored_at) > VIEWER_GEO_TTL_SECONDS:
        session.pop(VIEWER_GEO_SESSION_KEY, None)
        return None
    return ViewerLocation(
        latitude=latitude,
        longitude=longitude,
        stored_at=stored_at,
        city_key=(raw_value.get("city_key") or None),
        city_label=(raw_value.get("city_label") or None),
    )


def store_viewer_location(latitude: float, longitude: float, city_key: Optional[str] = None, city_label: Optional[str] = None) -> ViewerLocation:
    location = ViewerLocation(
        latitude=float(latitude),
        longitude=float(longitude),
        stored_at=time.time(),
        city_key=city_key,
        city_label=city_label,
    )
    if has_request_context():
        session[VIEWER_GEO_SESSION_KEY] = {
            "latitude": location.latitude,
            "longitude": location.longitude,
            "stored_at": location.stored_at,
            "city_key": location.city_key,
            "city_label": location.city_label,
        }
    return location


def haversine_miles(latitude_a: float, longitude_a: float, latitude_b: float, longitude_b: float) -> float:
    earth_radius_miles = 3958.7613
    lat_a = math.radians(latitude_a)
    lon_a = math.radians(longitude_a)
    lat_b = math.radians(latitude_b)
    lon_b = math.radians(longitude_b)
    delta_lat = lat_b - lat_a
    delta_lon = lon_b - lon_a
    a = (
        math.sin(delta_lat / 2.0) ** 2
        + math.cos(lat_a) * math.cos(lat_b) * (math.sin(delta_lon / 2.0) ** 2)
    )
    return earth_radius_miles * 2.0 * math.asin(min(1.0, math.sqrt(a)))


def reverse_geocode_city(latitude: float, longitude: float) -> Optional[dict]:
    try:
        response = requests.get(
            app.config.get("GEO_REVERSE_GEOCODE_URL") or REVERSE_GEOCODE_URL,
            params={
                "format": "jsonv2",
                "lat": "%.6f" % latitude,
                "lon": "%.6f" % longitude,
                "zoom": 10,
                "addressdetails": 1,
            },
            headers={
                "User-Agent": app.config.get("GEO_USER_AGENT") or "maniwani/geo-boards",
            },
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json() or {}
    except Exception:
        app.logger.exception("Reverse geocoding failed for %.6f, %.6f", latitude, longitude)
        return None

    address = payload.get("address") or {}
    locality = (
        address.get("city")
        or address.get("town")
        or address.get("village")
        or address.get("municipality")
        or address.get("hamlet")
        or address.get("county")
    )
    if not locality:
        return None
    region = address.get("state") or address.get("region") or address.get("state_district")
    country_code = (address.get("country_code") or "").upper()
    label_bits = [locality]
    if region:
        label_bits.append(region)
    elif country_code:
        label_bits.append(country_code)
    label = ", ".join([bit for bit in label_bits if bit])
    key_bits = [slugify_board_name(locality)]
    if region:
        key_bits.append(slugify_board_name(region))
    elif country_code:
        key_bits.append(country_code.lower())
    key = "-".join([bit for bit in key_bits if bit]).strip("-")
    if not key:
        return None
    return {
        "city_key": key,
        "city_label": label,
        "latitude": latitude,
        "longitude": longitude,
    }


def board_requires_location(board: Optional[Board]) -> bool:
    return board is not None and (board.is_geo_root or board.is_geo_generated)


def viewer_can_access_geo_board(board: Optional[Board], location: Optional[ViewerLocation] = None) -> bool:
    if board is None or board.is_geo_generated is False:
        return False
    location = location or viewer_location()
    if location is None:
        return False
    if board.geo_strategy == CITY_GEO_STRATEGY:
        return bool(location.city_key and board.geo_key and location.city_key == board.geo_key)
    if board.geo_strategy == RADIUS_GEO_STRATEGY:
        if board.geo_latitude is None or board.geo_longitude is None:
            return False
        radius = board.geo_radius_miles or DEFAULT_GEO_RADIUS_MILES
        return haversine_miles(location.latitude, location.longitude, board.geo_latitude, board.geo_longitude) <= radius
    return False


def resolve_geo_board(board: Board, latitude: float, longitude: float) -> Board:
    if board.is_geo_root:
        return _resolve_geo_root_board(board, latitude, longitude)

    area = reverse_geocode_city(latitude, longitude)
    location = store_viewer_location(
        latitude,
        longitude,
        city_key=area.get("city_key") if area else None,
        city_label=area.get("city_label") if area else None,
    )
    if board.is_geo_generated and viewer_can_access_geo_board(board, location):
        return board
    if board.geo_parent is not None and board.geo_parent.is_geo_root:
        return _resolve_geo_root_board(board.geo_parent, latitude, longitude)
    return board


def describe_geo_target(board: Board) -> str:
    if board.geo_strategy == CITY_GEO_STRATEGY:
        return "your city"
    radius = board.geo_radius_miles or DEFAULT_GEO_RADIUS_MILES
    return "people within %d miles" % radius


def _resolve_geo_root_board(board: Board, latitude: float, longitude: float) -> Board:
    strategy = board.geo_strategy or CITY_GEO_STRATEGY
    radius = board.geo_radius_miles or DEFAULT_GEO_RADIUS_MILES
    area = reverse_geocode_city(latitude, longitude)
    location = store_viewer_location(
        latitude,
        longitude,
        city_key=area.get("city_key") if area else None,
        city_label=area.get("city_label") if area else None,
    )
    if strategy == CITY_GEO_STRATEGY:
        geo_key = location.city_key or _coordinate_key(latitude, longitude)
        geo_label = location.city_label or _coordinate_label(latitude, longitude)
        child = (
            db.session.query(Board)
            .filter(
                Board.geo_parent_id == board.id,
                Board.board_type == GEO_GENERATED_BOARD_TYPE,
                Board.geo_strategy == CITY_GEO_STRATEGY,
                Board.geo_key == geo_key,
            )
            .one_or_none()
        )
        if child is not None:
            return child
        return _create_geo_child_board(
            board,
            geo_key=geo_key,
            geo_label=geo_label,
            latitude=latitude,
            longitude=longitude,
            radius_miles=radius,
        )

    existing = _nearest_radius_board(board.id, latitude, longitude, radius)
    if existing is not None:
        return existing
    geo_label = _radius_label(location.city_label, radius, latitude, longitude)
    geo_key = _coordinate_key(latitude, longitude)
    return _create_geo_child_board(
        board,
        geo_key=geo_key,
        geo_label=geo_label,
        latitude=latitude,
        longitude=longitude,
        radius_miles=radius,
    )


def _nearest_radius_board(parent_id: int, latitude: float, longitude: float, radius_miles: int) -> Optional[Board]:
    candidates = (
        db.session.query(Board)
        .filter(
            Board.geo_parent_id == parent_id,
            Board.board_type == GEO_GENERATED_BOARD_TYPE,
            Board.geo_strategy == RADIUS_GEO_STRATEGY,
            Board.geo_latitude.isnot(None),
            Board.geo_longitude.isnot(None),
        )
        .all()
    )
    nearest_distance = None
    nearest_board = None
    for candidate in candidates:
        distance = haversine_miles(latitude, longitude, candidate.geo_latitude, candidate.geo_longitude)
        if distance > radius_miles:
            continue
        if nearest_distance is None or distance < nearest_distance:
            nearest_distance = distance
            nearest_board = candidate
    return nearest_board


def _create_geo_child_board(template_board: Board, geo_key: str, geo_label: str, latitude: float, longitude: float, radius_miles: int) -> Board:
    child = Board(
        name=_generated_board_slug(template_board, geo_key),
        display_name=_generated_board_title(template_board, geo_label),
        rules=template_board.rules,
        max_threads=template_board.max_threads,
        mimetypes=template_board.mimetypes,
        owner_slip_id=template_board.owner_slip_id,
        is_private=False,
        board_type=GEO_GENERATED_BOARD_TYPE,
        geo_strategy=template_board.geo_strategy,
        geo_parent_id=template_board.id,
        geo_key=geo_key,
        geo_label=geo_label,
        geo_latitude=latitude,
        geo_longitude=longitude,
        geo_radius_miles=radius_miles,
    )
    db.session.add(child)
    db.session.commit()
    return child


def _generated_board_slug(template_board: Board, geo_key: str) -> str:
    prefix = slugify_board_name(template_board.name)[:12] or "geo"
    digest = hashlib.sha1(("%s:%s" % (template_board.id, geo_key)).encode("utf-8")).hexdigest()[:12]
    candidates = [
        ("%s-%s" % (prefix, digest))[:32],
        digest[:32],
    ]
    for candidate in candidates:
        if _board_slug_available(candidate):
            return candidate
    suffix = 2
    while True:
        candidate = ("%s-%s-%d" % (prefix, digest[:8], suffix))[:32]
        if _board_slug_available(candidate):
            return candidate
        suffix += 1


def _board_slug_available(slug: str) -> bool:
    return db.session.query(Board.id).filter(Board.name == slug).one_or_none() is None


def _generated_board_title(template_board: Board, geo_label: str) -> str:
    base = template_board.title or template_board.name
    label = (geo_label or "").strip()
    if not label:
        return base
    return ("%s · %s" % (base, label))[:96]


def _coordinate_key(latitude: float, longitude: float) -> str:
    return hashlib.sha1(("%.4f:%.4f" % (latitude, longitude)).encode("utf-8")).hexdigest()[:16]


def _coordinate_label(latitude: float, longitude: float) -> str:
    return "Near %.2f, %.2f" % (latitude, longitude)


def _radius_label(city_label: Optional[str], radius_miles: int, latitude: float, longitude: float) -> str:
    if city_label:
        return "%s area" % city_label
    return "Within %d miles of %.2f, %.2f" % (radius_miles, latitude, longitude)
