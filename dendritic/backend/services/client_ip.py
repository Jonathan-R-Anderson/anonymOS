"""Resolve the client IP without trusting visitor-supplied proxy headers."""

import ipaddress

def _address(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def _networks(values):
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",") if item.strip()]
    result = []
    for value in values or ():
        try:
            result.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            continue
    return result


def _is_trusted(address, networks):
    return address is not None and any(address in network for network in networks)


def resolve_client_ip(remote_addr, forwarded_for=None, trusted_proxy_cidrs=()):
    """Return a normalized address, honoring XFF only from configured proxies."""

    peer = _address(remote_addr)
    if peer is None:
        return str(remote_addr or "")

    trusted = _networks(trusted_proxy_cidrs)
    if not _is_trusted(peer, trusted) or not forwarded_for:
        return str(peer)

    forwarded = []
    for item in str(forwarded_for).split(","):
        parsed = _address(item)
        if parsed is None:
            return str(peer)
        forwarded.append(parsed)

    # X-Forwarded-For is client-first. Walk back from our immediate peer and
    # discard only explicitly trusted proxy hops.
    chain = forwarded + [peer]
    for address in reversed(chain):
        if _is_trusted(address, trusted):
            continue
        return str(address)
    return str(forwarded[0] if forwarded else peer)


def get_client_ip():
    from flask import request
    from shared import app

    remote_addr = request.remote_addr or request.environ.get("REMOTE_ADDR") or ""
    return resolve_client_ip(
        remote_addr,
        request.headers.get("X-Forwarded-For"),
        app.config.get("TRUSTED_PROXY_CIDRS") or (),
    )
