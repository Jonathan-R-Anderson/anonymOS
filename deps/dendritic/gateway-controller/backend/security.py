from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from datetime import UTC, datetime, timedelta

import base58
from fastapi import HTTPException, Request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings
from .models import UsedNonce
from .schemas import IdentityRequest, RegistrationRequest

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise HTTPException(403, "source is not an IP address") from error
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or (
            address.version == 4
            and address in ipaddress.ip_network("100.64.0.0/10")
        )
    ):
        raise HTTPException(403, "a globally routable public IP source is required")
    return str(address)

# Compatibility for callers outside this package. New code must use public_ip.
public_ipv4 = public_ip


def source_ip(request: Request, settings: Settings) -> str:
    if request.client is None:
        raise HTTPException(400, "source address unavailable")
    immediate = ipaddress.ip_address(request.client.host)
    trusted = any(
        immediate in ipaddress.ip_network(network, strict=False)
        for network in settings.trusted_proxy_cidrs
    )
    if trusted:
        forwarded = request.headers.get("x-forwarded-for", "")
        candidate = forwarded.split(",", 1)[0].strip()
        if candidate:
            return public_ip(candidate)
    return public_ip(str(immediate))


def validate_managed_hostname(hostname: str, settings: Settings) -> str:
    hostname = hostname.lower().rstrip(".")
    if hostname == settings.public_hostname:
        return hostname
    suffix = "." + settings.domain
    if not hostname.endswith(suffix):
        raise HTTPException(422, "gateway hostname is outside the managed domain")
    host = hostname[: -len(suffix)]
    if not host.startswith(settings.subdomain_prefix + "-") or not _HOST_LABEL.fullmatch(host):
        raise HTTPException(422, "gateway hostname is outside the managed prefix")
    return hostname


def gateway_hostname(node_id: str, settings: Settings) -> str:
    """Return the only hostname a node identity is allowed to reserve."""
    identity_hash = hashlib.sha256(node_id.encode("ascii")).hexdigest()[:24]
    return f"{settings.subdomain_prefix}-{identity_hash}.{settings.domain}"


def _ed25519_key_and_peer_id(public_key_b64: str) -> tuple[bytes, str]:
    try:
        protobuf = base64.b64decode(public_key_b64 + "===")
    except (ValueError, TypeError) as error:
        raise HTTPException(401, "invalid public key encoding") from error
    # libp2p PublicKey protobuf: field 1/type=Ed25519, field 2/data=32 bytes.
    if len(protobuf) != 36 or protobuf[:4] != b"\x08\x01\x12\x20":
        raise HTTPException(401, "only libp2p Ed25519 identities are accepted")
    if len(protobuf) <= 42:
        multihash = b"\x00" + bytes([len(protobuf)]) + protobuf
    else:
        multihash = b"\x12\x20" + hashlib.sha256(protobuf).digest()
    return protobuf[4:], base58.b58encode(multihash).decode("ascii")


async def authenticate_identity(
    raw_body: bytes,
    request: Request,
    body: IdentityRequest,
    session: AsyncSession,
) -> None:
    if request.headers.get("x-syndichan-node") != body.node_id:
        raise HTTPException(401, "node identity header mismatch")
    public_key, expected_node_id = _ed25519_key_and_peer_id(body.public_key)
    if expected_node_id != body.node_id:
        raise HTTPException(401, "public key does not match node ID")
    try:
        signature = base64.b64decode(
            request.headers.get("x-syndichan-signature", "") + "==="
        )
        VerifyKey(public_key).verify(raw_body, signature)
    except (ValueError, BadSignatureError) as error:
        raise HTTPException(401, "invalid request signature") from error
    now = datetime.now(UTC)
    if abs(now.timestamp() - body.timestamp) > 90:
        raise HTTPException(401, "stale registration request")
    await session.execute(delete(UsedNonce).where(UsedNonce.expires_at <= now))
    session.add(
        UsedNonce(
            node_id=body.node_id,
            nonce=body.nonce,
            expires_at=now + timedelta(minutes=5),
        )
    )
    try:
        await session.flush()
    except IntegrityError as error:
        raise HTTPException(409, "registration nonce was already used") from error


async def authenticate_request(
    raw_body: bytes,
    request: Request,
    body: RegistrationRequest,
    session: AsyncSession,
) -> None:
    await authenticate_identity(raw_body, request, body, session)
    if body.port != 443:
        raise HTTPException(422, "only TCP port 443 is accepted")
    if body.registration.get("node_id") != body.node_id:
        raise HTTPException(422, "registration node identity mismatch")
    sequence = body.registration.get("sequence")
    if not isinstance(sequence, int) or sequence < 1:
        raise HTTPException(422, "invalid registration sequence")
