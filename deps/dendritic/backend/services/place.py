"""Per-profile collaborative pixel wall ("graffiti") — a native r/place-style
canvas rendered as the profile-page background.

Each pixel is full RGBA, stored as 8 hex chars (RRGGBBAA) so painters can pick
any colour / shade / opacity. Redis layout (per profile slug):
  place:<slug>            (W*H*8)-char hex string, RRGGBBAA per pixel ("00000000" = clear)
  place:<slug>:v          integer version, bumped on every placement
  place:<slug>:recent     capped list "v|x|y|rrggbbaa|ts" (newest first) for the live/blink feed
  place:<slug>:cool:<ip>  short per-visitor cooldown key (TTL)
  place:<slug>:snap:<day> full-grid snapshot for a YYYY-MM-DD (time-lapse frame)
  place:<slug>:days       sorted set of snapshot days
The string is mostly zeros, so it gzips to almost nothing on the wire; Redis
holds it uncompressed (~512 KB at 256x256 — the sysop can shrink W/H if needed)."""
import re as _re
import time as _time

import keystore

PLACE_W = 256
PLACE_H = 256
PLACE_COOLDOWN_SECONDS = 1
RECENT_MAX = 1000
_PX = 8                      # hex chars per pixel (RRGGBBAA)
_CELLS = PLACE_W * PLACE_H
_LEN = _CELLS * _PX
_BLANK = "0" * _LEN
_COLOR_RE = _re.compile(r"^[0-9a-fA-F]{8}$")

# Optional quick-pick swatches shown next to the colour wheel (client may ignore).
PLACE_SWATCHES = [
    "000000ff", "ffffffff", "e50000ff", "e59500ff", "e5d900ff", "02be01ff",
    "00d3ddff", "0083c7ff", "0000eaff", "820080ff", "ffa7d1ff", "a06a42ff",
]

_client = None


def _r():
    global _client
    if _client is None:
        _client = keystore.make_redis()
    return _client


def _key(slug):
    return "place:%s" % slug


def _ver_key(slug):
    return "place:%s:v" % slug


def _recent_key(slug):
    return "place:%s:recent" % slug


def _cool_key(slug, ip):
    return "place:%s:cool:%s" % (slug, ip or "?")


def _snap_key(slug, day):
    return "place:%s:snap:%s" % (slug, day)


def _days_key(slug):
    return "place:%s:days" % slug


def _ensure(r, slug):
    if r.strlen(_key(slug)) != _LEN:
        r.set(_key(slug), _BLANK)


def _normalize_color(value):
    """Return a lowercase 8-hex RRGGBBAA string, or None if invalid.
    Accepts an optional leading '#' and expands 6-hex (RGB) to full alpha."""
    if not value:
        return None
    v = str(value).strip().lstrip("#").lower()
    if len(v) == 6 and _re.match(r"^[0-9a-f]{6}$", v):
        v = v + "ff"
    return v if _COLOR_RE.match(v) else None


def get_canvas(slug):
    r = _r()
    _ensure(r, slug)
    return {
        "w": PLACE_W,
        "h": PLACE_H,
        "swatches": PLACE_SWATCHES,
        "pixels": r.get(_key(slug)) or _BLANK,
        "version": int(r.get(_ver_key(slug)) or "0"),
        "cooldown": PLACE_COOLDOWN_SECONDS,
    }


def canvas_version(slug):
    try:
        return int(_r().get(_ver_key(slug)) or "0")
    except Exception:
        return 0


def recent_since(slug, since_version):
    r = _r()
    try:
        raw = r.lrange(_recent_key(slug), 0, RECENT_MAX - 1)
    except Exception:
        return []
    now = int(_time.time())
    out = []
    for entry in raw:
        parts = entry.split("|")
        if len(parts) != 5:
            continue
        try:
            v = int(parts[0]); x = int(parts[1]); y = int(parts[2]); ts = int(parts[4])
        except ValueError:
            continue
        color = _normalize_color(parts[3])
        if color is None or v <= since_version:
            continue
        out.append({"x": x, "y": y, "color": color, "v": v, "age": max(0, now - ts)})
    out.sort(key=lambda item: item["v"])
    return out


def place_pixel(slug, x, y, color, ip):
    try:
        x = int(x); y = int(y)
    except (TypeError, ValueError):
        raise ValueError("coordinates must be integers")
    if not (0 <= x < PLACE_W and 0 <= y < PLACE_H):
        raise ValueError("pixel out of bounds")
    color = _normalize_color(color)
    if color is None:
        raise ValueError("colour must be RRGGBB or RRGGBBAA hex")

    r = _r()
    cool_key = _cool_key(slug, ip)
    if r.get(cool_key):
        ttl = r.ttl(cool_key)
        return {"ok": False, "cooldown": ttl if ttl and ttl > 0 else PLACE_COOLDOWN_SECONDS}

    _ensure(r, slug)
    r.setrange(_key(slug), (y * PLACE_W + x) * _PX, color)
    version = int(r.incr(_ver_key(slug)))
    r.lpush(_recent_key(slug), "%d|%d|%d|%s|%d" % (version, x, y, color, int(_time.time())))
    r.ltrim(_recent_key(slug), 0, RECENT_MAX - 1)
    if PLACE_COOLDOWN_SECONDS > 0:
        r.setex(cool_key, PLACE_COOLDOWN_SECONDS, "1")
    return {"ok": True, "x": x, "y": y, "color": color, "version": version}


def clear_canvas(slug):
    r = _r()
    r.set(_key(slug), _BLANK)
    r.delete(_recent_key(slug))
    return int(r.incr(_ver_key(slug)))


# --- Time-lapse snapshots ---------------------------------------------------

def save_snapshot(slug, day):
    r = _r()
    _ensure(r, slug)
    r.set(_snap_key(slug, day), r.get(_key(slug)) or _BLANK)
    try:
        r.zadd(_days_key(slug), {day: int(day.replace("-", ""))})
    except Exception:
        pass


def prune_snapshots(slug, keep_days):
    r = _r()
    keep_days = max(1, int(keep_days))
    days = r.zrange(_days_key(slug), 0, -1)
    if len(days) <= keep_days:
        return 0
    drop = days[:len(days) - keep_days]
    for day in drop:
        r.delete(_snap_key(slug, day))
        r.zrem(_days_key(slug), day)
    return len(drop)


def snapshot_days(slug, limit=30):
    r = _r()
    try:
        days = r.zrange(_days_key(slug), 0, -1)
    except Exception:
        return []
    if limit and len(days) > limit:
        days = days[len(days) - limit:]
    return days


def get_snapshot(slug, day):
    r = _r()
    data = r.get(_snap_key(slug, day))
    if not data:
        return None
    return {"w": PLACE_W, "h": PLACE_H, "day": day, "pixels": data}
