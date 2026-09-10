"""Real-time visitor presence for the admin live world map.

Public pages heartbeat their IP to record_presence() (from base.html); the admin
composition monitor polls active_visitors() a few times a second to draw a single
pulsing dot per current visitor, geolocated to their country (services/geoip.py).

Everything lives in Redis with a short TTL, so a visitor's dot vanishes seconds
after they close the tab / stop heartbeating. Scope is the operator's own site
only -- the site's own pages feeding the site's own admin panel. Best-effort:
nothing here ever raises into a request.
"""
import json
import time

import keystore
from services.geoip import latlon_for_ip

_TTL = 60          # seconds a visitor's geo record lives without a heartbeat
_WINDOW = 45       # a visitor counts as "present" for this long after their last ping
_MAX = 2000        # safety cap on dots returned to the panel

_INDEX = "presence:index"
_GEO_PREFIX = "presence:geo:"

_client = None


def _redis():
    global _client
    if _client is None:
        _client = keystore.make_redis()
    return _client


def record_presence(ip, page=None):
    """Mark one visitor (by IP) as present right now, caching their resolved
    coordinates and the page they are on so the admin poll doesn't re-geolocate
    every IP every tick. `page` is untrusted visitor input: we only store a short
    sanitized string; the admin UI must still render it as text, never HTML."""
    ip = (ip or "").strip()[:64]
    if not ip or ip == "?":
        return
    try:
        now = time.time()
        lat, lon, cc = latlon_for_ip(ip)
        page = (page or "").replace("\r", "").replace("\n", " ").strip()[:200]
        payload = json.dumps({"lat": lat, "lon": lon, "cc": cc, "page": page})
        r = _redis()
        pipe = r.pipeline()
        pipe.setex(_GEO_PREFIX + ip, _TTL, payload)
        pipe.zadd(_INDEX, {ip: now})
        pipe.zremrangebyscore(_INDEX, 0, now - _WINDOW)
        pipe.execute()
    except Exception:
        pass


def active_visitors(window_seconds=_WINDOW):
    """Every visitor seen within the window that we could geolocate, newest first,
    as [{"ip", "lat", "lon", "cc"}] for the world map. IPs we cannot place on the
    map (unknown country / no centroid) are omitted from the dots."""
    try:
        r = _redis()
        now = time.time()
        r.zremrangebyscore(_INDEX, 0, now - window_seconds)
        ips = r.zrevrangebyscore(_INDEX, now, now - window_seconds, start=0, num=_MAX)
    except Exception:
        return []
    out = []
    for ip in ips:
        try:
            raw = r.get(_GEO_PREFIX + ip)
        except Exception:
            raw = None
        if not raw:
            continue
        try:
            geo = json.loads(raw)
        except Exception:
            continue
        lat = geo.get("lat")
        lon = geo.get("lon")
        if lat is None or lon is None:
            continue
        out.append({"ip": ip, "lat": lat, "lon": lon, "cc": geo.get("cc"), "page": geo.get("page") or ""})
    return out


def visitor_count(window_seconds=_WINDOW):
    """Total present visitors (including ones we couldn't geolocate)."""
    try:
        r = _redis()
        now = time.time()
        r.zremrangebyscore(_INDEX, 0, now - window_seconds)
        return int(r.zcount(_INDEX, now - window_seconds, now))
    except Exception:
        return 0
