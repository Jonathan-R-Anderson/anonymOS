"""Lightweight offline IP -> ISO-3166 country lookup.

Reads the CC0 country database downloaded at build time (build-helpers/
geoip_bootstrap.py) into sorted range tables and binary-searches them. No
third-party dependency, no network at runtime. If the data files are missing
(download failed / not provisioned) every lookup returns None and the country
flag feature is simply inactive.
"""
import bisect
import hashlib
import ipaddress
import os
import threading

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IPV4_CSV = os.path.join(_BASE, "resources", "geoip", "country-ipv4.csv")
_IPV6_CSV = os.path.join(_BASE, "resources", "geoip", "country-ipv6.csv")

_lock = threading.Lock()
_tables = None  # {"v4": (starts, ends, codes), "v6": (...)} once loaded


def _load_csv(path):
    starts, ends, codes = [], [], []
    if not os.path.isfile(path):
        return starts, ends, codes
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                parts = line.strip().split(",")
                if len(parts) < 3:
                    continue
                try:
                    start = int(ipaddress.ip_address(parts[0]))
                    end = int(ipaddress.ip_address(parts[1]))
                except ValueError:
                    continue
                code = parts[2].strip().upper()
                if len(code) != 2:
                    continue
                starts.append(start)
                ends.append(end)
                codes.append(code)
    except OSError:
        return [], [], []
    # The published DB is already sorted by start address; the bisect lookup
    # relies on that, so we do not re-sort a ~400k row table on every boot.
    return starts, ends, codes


def _tables_loaded():
    global _tables
    if _tables is not None:
        return _tables
    with _lock:
        if _tables is None:
            _tables = {
                "v4": _load_csv(_IPV4_CSV),
                "v6": _load_csv(_IPV6_CSV),
            }
    return _tables


def country_for_ip(ip_string):
    """Return the uppercase ISO-3166 alpha-2 country code for an IP, or None."""
    if not ip_string:
        return None
    try:
        address = ipaddress.ip_address(str(ip_string).strip())
    except ValueError:
        return None
    key = "v6" if address.version == 6 else "v4"
    starts, ends, codes = _tables_loaded()[key]
    if not starts:
        return None
    value = int(address)
    # Rightmost range whose start <= value; then confirm value <= its end.
    index = bisect.bisect_right(starts, value) - 1
    if 0 <= index < len(ends) and value <= ends[index]:
        return codes[index]
    return None


def flag_emoji(country_code):
    """Convert an alpha-2 country code to its regional-indicator flag emoji."""
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return None
    return "".join(chr(0x1F1E6 + (ord(char) - ord("A"))) for char in code)


def flag_for_ip(ip_string):
    """Convenience: IP -> (country_code, flag_emoji) or (None, None)."""
    code = country_for_ip(ip_string)
    if not code:
        return None, None
    return code, flag_emoji(code)


def _ip_jitter(ip_string):
    """Deterministic small lat/lon offset per IP so multiple visitors in the same
    country spread into a little cluster instead of stacking on one pixel, and a
    given IP's dot stays put across polls (seeded by the IP, so it never jumps)."""
    digest = hashlib.md5((ip_string or "").encode("utf-8", "ignore")).digest()
    a = int.from_bytes(digest[0:4], "big") / 4294967296.0
    b = int.from_bytes(digest[4:8], "big") / 4294967296.0
    return (a - 0.5) * 7.0, (b - 0.5) * 9.0  # +/-3.5 deg lat, +/-4.5 deg lon


def latlon_for_ip(ip_string):
    """IP -> (lat, lon, country_code), or (None, None, code_or_None) when unknown.

    Country-level only (see module docstring): we resolve the country, take its
    centroid, and add a small deterministic jitter. That's precise enough to drop
    a visitor's dot on the right region of a world map, without any city database.
    """
    code = country_for_ip(ip_string)
    if not code:
        return None, None, None
    try:
        from services.country_centroids import CENTROIDS
    except Exception:
        return None, None, code
    base = CENTROIDS.get(code)
    if not base:
        return None, None, code
    dlat, dlon = _ip_jitter(str(ip_string))
    lat = max(-85.0, min(85.0, base[0] + dlat))
    lon = max(-179.0, min(179.0, base[1] + dlon))
    return round(lat, 4), round(lon, 4), code
