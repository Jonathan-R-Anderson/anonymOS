import base64

import base58
import pytest
from fastapi import HTTPException
from nacl.signing import SigningKey

from backend.config import Settings
from backend.security import (
    _ed25519_key_and_peer_id,
    gateway_hostname,
    public_ip,
    validate_managed_hostname,
)


def test_libp2p_ed25519_identity_binding():
    key = SigningKey.generate()
    protobuf = b"\x08\x01\x12\x20" + bytes(key.verify_key)
    expected = base58.b58encode(b"\x00\x24" + protobuf).decode()
    raw, peer_id = _ed25519_key_and_peer_id(
        base64.b64encode(protobuf).decode().rstrip("=")
    )
    assert raw == bytes(key.verify_key)
    assert peer_id == expected


@pytest.mark.parametrize(
    "value",
    ["127.0.0.1", "10.0.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "::1"],
)
def test_restricted_addresses_are_rejected(value):
    with pytest.raises(HTTPException):
        public_ip(value)


def test_public_sources_accept_both_address_families():
    assert public_ip("8.8.8.8") == "8.8.8.8"
    assert public_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"


def test_only_managed_hostname_prefix_is_accepted():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        domain="syndichan.org",
        subdomain_prefix="gw",
    )
    assert (
        validate_managed_hostname("gw-alpha.syndichan.org", settings)
        == "gw-alpha.syndichan.org"
    )
    assert validate_managed_hostname("syndichan.org", settings) == "syndichan.org"
    with pytest.raises(HTTPException):
        validate_managed_hostname("www.syndichan.org", settings)


def test_gateway_hostname_is_deterministic_and_identity_bound():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        domain="syndichan.org",
        subdomain_prefix="gw",
    )
    first = gateway_hostname("12D3KooWExampleOne", settings)
    assert first == gateway_hostname("12D3KooWExampleOne", settings)
    assert first.startswith("gw-")
    assert first.endswith(".syndichan.org")
    assert first != gateway_hostname("12D3KooWExampleTwo", settings)
