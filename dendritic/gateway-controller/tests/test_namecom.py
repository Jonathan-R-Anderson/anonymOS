import httpx
import pytest

from backend.config import Settings
from backend.namecom import (
    DNSRecord,
    NameComClient,
    record_type_for_answer,
    validate_record_answer,
)


def settings():
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        namecom_username="server-only-user",
        namecom_api_token="server-only-token",
        namecom_api_url="https://api.dev.name.com/core/v1",
    )


@pytest.mark.asyncio
async def test_list_records_and_basic_auth():
    async def handler(request):
        assert request.headers["authorization"].startswith("Basic ")
        return httpx.Response(
            200,
            json={
                "records": [
                    {
                        "id": 7,
                        "host": "gw-one",
                        "type": "A",
                        "answer": "8.8.8.8",
                        "ttl": 300,
                    }
                ]
            },
        )

    transport = httpx.MockTransport(handler)
    http = httpx.AsyncClient(
        transport=transport,
        auth=httpx.BasicAuth("server-only-user", "server-only-token"),
    )
    client = NameComClient(settings(), http)
    records = await client.list_records()
    assert records[0].host == "gw-one"
    await http.aclose()


@pytest.mark.asyncio
async def test_create_is_idempotent_when_record_exists():
    methods = []

    async def handler(request):
        methods.append(request.method)
        return httpx.Response(
            200,
            json={
                "records": [
                    {
                        "id": 7,
                        "host": "gw-one",
                        "type": "A",
                        "answer": "8.8.8.8",
                        "ttl": 300,
                    }
                ]
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        auth=httpx.BasicAuth("server-only-user", "server-only-token"),
    )
    client = NameComClient(settings(), http)
    record = await client.create_record("gw-one", "8.8.8.8", 300)
    assert record.id == 7
    assert methods == ["GET"]
    await http.aclose()


def test_record_type_is_derived_from_address_family():
    assert record_type_for_answer("8.8.8.8") == "A"
    assert record_type_for_answer("2606:4700:4700::1111") == "AAAA"
    with pytest.raises(ValueError):
        validate_record_answer("A", "2606:4700:4700::1111")


@pytest.mark.asyncio
async def test_ipv6_create_emits_aaaa():
    requests = []

    async def handler(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"records": []})
        payload = __import__("json").loads(request.content)
        assert payload["type"] == "AAAA"
        return httpx.Response(200, json={"id": 8, **payload})

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        auth=httpx.BasicAuth("server-only-user", "server-only-token"),
    )
    client = NameComClient(settings(), http)
    record = await client.create_record(
        "gw-six", "2606:4700:4700::1111", 300, "AAAA"
    )
    assert record.type == "AAAA"
    assert [request.method for request in requests] == ["GET", "POST"]
    await http.aclose()


def test_dns_record_parse_normalizes_empty_apex_host():
    record = DNSRecord.parse(
        {
            "id": 42,
            "host": "",
            "type": "A",
            "answer": "192.0.2.1",
            "ttl": 300,
        }
    )

    assert record.host == "@"


def test_dns_record_parse_preserves_named_host():
    record = DNSRecord.parse(
        {
            "id": 43,
            "host": "gw-example",
            "type": "AAAA",
            "answer": "2001:db8::1",
            "ttl": 300,
        }
    )

    assert record.host == "gw-example"
