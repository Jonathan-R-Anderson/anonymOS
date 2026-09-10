"""Non-reversible poster-IP tokens for board-level moderators.

Board owners and their appointed moderators must be able to recognize and ban a
poster without ever seeing the raw IP address. A plain hash of an IP is trivially
reversible (the IPv4 space is tiny), so tokens are keyed with the app secret via
HMAC-SHA256 — stable per IP, groupable across a poster's posts, but not
brute-forceable without the server key. Global site admins still see raw IPs.
"""

import hashlib
import hmac

from model.Slip import slip_is_admin
from shared import app


def _secret_bytes() -> bytes:
    secret = app.config.get("SECRET_KEY") or getattr(app, "secret_key", None) or "maniwani-ip-hash"
    if isinstance(secret, str):
        return secret.encode("utf-8")
    return bytes(secret)


def poster_ip_token(ip) -> str:
    """Return a stable, non-reversible token for an IP (e.g. ``ip-3f9a1c2b7d0e``)."""
    if not ip:
        return None
    digest = hmac.new(_secret_bytes(), str(ip).encode("utf-8"), hashlib.sha256).hexdigest()
    return "ip-" + digest[:12]


def viewer_may_see_raw_ip(slip=None) -> bool:
    """Only global site admins may see raw poster IPs."""
    return slip_is_admin(slip)


def poster_ip_display(ip, reveal: bool = False):
    """Raw IP when ``reveal`` (global admin), otherwise the hashed token."""
    if not ip:
        return None
    return ip if reveal else poster_ip_token(ip)
