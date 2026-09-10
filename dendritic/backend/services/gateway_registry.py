"""Read the authoritative healthy-gateway registry for the admin map.

Dedicated gateways do not send storage heartbeats, so they cannot be derived
from ``storage_node``.  The gateway controller is the authority for whether a
node passed independent verification, remains healthy, and is currently
published.  Cache briefly because the admin map polls every three seconds.
"""

import os
import threading
import time

import requests

from services.geoip import latlon_for_ip


DEFAULT_URL = (
    "http://gateway-controller.maniwani.svc.cluster.local:8080"
    "/api/v1/gateways"
)
_CACHE_SECONDS = 10.0
_lock = threading.Lock()
_cache = {"expires": 0.0, "gateways": [], "error": None}


def _registry_url():
    return os.environ.get("GATEWAY_CONTROLLER_URL", DEFAULT_URL).strip()


def _normalize_gateway(value):
    if not isinstance(value, dict):
        return None
    hostname = str(value.get("hostname") or "").strip().lower().rstrip(".")
    address = str(value.get("ip") or "").strip()
    node_id = str(value.get("node_id") or "").strip()
    if not hostname or not address:
        return None
    # Controllers deployed before the detailed status response returned only
    # hostname/IP/latency. The list itself has always contained exclusively
    # healthy, verified, TLS-valid gateways, so retain map compatibility while
    # a rolling controller upgrade is in progress.
    node_id = node_id or ("gateway:" + hostname)
    lat, lon, country = latlon_for_ip(address)
    if lat is None or lon is None:
        return None
    return {
        "id": node_id[:12],
        "node_id": node_id,
        "ip": address,
        "hostname": hostname,
        "lat": lat,
        "lon": lon,
        "country": country,
        "capacity_bytes": 0,
        "platform": "gateway",
        "kind": "gateway",
        "storage": False,
        "gateway": True,
        "healthy": bool(value.get("healthy", True)),
        "verified": bool(value.get("verified", True)),
        "tls_valid": bool(value.get("tls_valid", True)),
        "latency_ms": value.get("latency"),
        "last_seen": value.get("last_seen"),
        "expires_at": value.get("registration_expires_at"),
        "status_url": "https://%s/readyz" % hostname,
    }


def active_gateways(now=None):
    """Return ``(gateways, error)`` from a short-lived process-local cache."""
    clock = time.monotonic() if now is None else float(now)
    with _lock:
        if clock < _cache["expires"]:
            return list(_cache["gateways"]), _cache["error"]

        try:
            response = requests.get(
                _registry_url(),
                timeout=(1.0, 3.0),
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Syndichan-Admin-Gateway-Monitor/1.0",
                },
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                raise ValueError("gateway registry did not return a list")
            gateways = []
            for item in payload[:1000]:
                gateway = _normalize_gateway(item)
                if gateway is not None:
                    gateways.append(gateway)
            error = None
        except Exception as exc:
            # Preserve the last known markers during a brief controller restart,
            # but tell the UI they are stale rather than silently claiming zero.
            gateways = list(_cache["gateways"])
            error = str(exc)[:240]

        _cache.update(
            expires=clock + _CACHE_SECONDS,
            gateways=gateways,
            error=error,
        )
        return list(gateways), error


def registered_identities():
    """``(peer_ids, current)`` for gateways the controller publishes as healthy.

    Used to tell an observation about a real gateway from one about a name
    somebody invented. ``current`` is False when the controller could not be
    reached, and the distinction matters: an outage must not be read as "no
    gateway is registered", or every honest gateway would be marked unknown for
    as long as the controller was down.

    Registration is checked at the moment of observation rather than looked up
    afterwards, because a gateway that misbehaves and then unregisters would
    otherwise read as one that never existed — and the report against it would
    quietly evaporate along with the record of who it was.
    """
    gateways, error = active_gateways()
    return {str(entry.get("node_id") or "") for entry in gateways}, error is None


def reset_cache():
    """Test helper; also useful after changing the controller URL in-process."""
    with _lock:
        _cache.update(expires=0.0, gateways=[], error=None)
