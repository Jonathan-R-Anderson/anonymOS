import asyncio

import pytest

from backend.config import Settings
from backend.verifier import GatewayVerifier


class Reader:
    def __init__(self, response):
        self.response = response

    async def readuntil(self, separator):
        return self.response


class Writer:
    def __init__(self):
        self.request = b""

    def write(self, value):
        self.request += value

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_verifier_requires_200_and_gateway_header(monkeypatch):
    writer = Writer()

    async def connect(**kwargs):
        assert kwargs["host"] == "8.8.8.8"
        assert kwargs["server_hostname"] == "gw-one.syndichan.org"
        return (
            Reader(b"HTTP/1.1 200 OK\r\nX-Gateway-Version: 1.0.0\r\n\r\n"),
            writer,
        )

    monkeypatch.setattr(asyncio, "open_connection", connect)
    verifier = GatewayVerifier(
        Settings(database_url="sqlite+aiosqlite:///:memory:")
    )
    result = await verifier.verify("8.8.8.8", "gw-one.syndichan.org")
    assert result.ok and result.tls_valid
    assert b"Host: gw-one.syndichan.org" in writer.request


@pytest.mark.asyncio
async def test_verifier_rejects_missing_header(monkeypatch):
    async def connect(**kwargs):
        return Reader(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"), Writer()

    monkeypatch.setattr(asyncio, "open_connection", connect)
    verifier = GatewayVerifier(
        Settings(database_url="sqlite+aiosqlite:///:memory:")
    )
    result = await verifier.verify("8.8.8.8", "gw-one.syndichan.org")
    assert not result.ok
    assert result.reason == "gateway header missing"

