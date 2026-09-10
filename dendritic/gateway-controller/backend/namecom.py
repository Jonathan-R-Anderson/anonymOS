from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from .config import Settings
from .metrics import provider_rate_limits

logger = logging.getLogger(__name__)
RETRYABLE = {429, 500, 502, 504}
RECORD_TYPES = frozenset({"A", "AAAA"})


def record_type_for_answer(answer: str) -> str:
    return "A" if ipaddress.ip_address(answer).version == 4 else "AAAA"


def validate_record_answer(record_type: str, answer: str) -> str:
    record_type = record_type.upper()
    if record_type not in RECORD_TYPES:
        raise ValueError(f"unsupported address record type {record_type}")
    actual = record_type_for_answer(answer)
    if actual != record_type:
        raise ValueError(f"{answer} requires {actual}, not {record_type}")
    return record_type


@dataclass(frozen=True)
class DNSRecord:
    id: int
    host: str
    type: str
    answer: str
    ttl: int

    @classmethod
    def parse(cls, value: dict[str, Any]) -> "DNSRecord":
        # Name.com represents an apex record with an empty host in responses,
        # while its create/update API and our ownership table use "@". Keep a
        # single internal representation so an owned apex record is not
        # mistaken for an unmanaged conflict on every reconciliation.
        host = str(value.get("host") or "@")
        return cls(
            id=int(value["id"]),
            host=host,
            type=str(value["type"]),
            answer=str(value["answer"]),
            ttl=int(value["ttl"]),
        )


class NameComClient:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None):
        username, token = settings.require_namecom_credentials()
        self.domain = settings.domain
        self.base_url = settings.namecom_api_url.rstrip("/")
        self.client = client or httpx.AsyncClient(
            auth=httpx.BasicAuth(username, token),
            timeout=httpx.Timeout(20.0),
            follow_redirects=False,
            headers={"User-Agent": "Syndichan-Gateway-Controller/1.0"},
        )

    @property
    def records_url(self) -> str:
        return f"{self.base_url}/domains/{quote(self.domain, safe='')}/records"

    async def close(self) -> None:
        await self.client.aclose()

    async def _request(
        self, method: str, url: str, *, retry_504: bool = True, **kwargs
    ) -> httpx.Response:
        ambiguous_delete = False
        for attempt in range(5):
            response = await self.client.request(method, url, **kwargs)
            if method == "DELETE" and response.status_code == 404 and ambiguous_delete:
                return response
            retryable = response.status_code in RETRYABLE and (
                response.status_code != 504 or retry_504
            )
            if not retryable:
                response.raise_for_status()
                return response
            # A 429 is a quota signal, not a transient packet loss. Rapid
            # exponential retries consume more quota and can keep the account
            # permanently throttled. Let the scheduled reconciliation or a
            # later signed client retry attempt the operation after the
            # provider window resets.
            if response.status_code == 429:
                provider_rate_limits.inc()
                retry_after = response.headers.get("Retry-After", "60")
                logger.warning(
                    "Name.com %s rate limited; retry after %ss",
                    method,
                    retry_after,
                )
                response.raise_for_status()
            if attempt == 4:
                response.raise_for_status()
            ambiguous_delete = ambiguous_delete or (
                method == "DELETE" and response.status_code == 504
            )
            delay = min(16.0, 2**attempt) + random.uniform(0, 0.25)
            logger.warning(
                "Name.com %s returned %d; retry %d in %.2fs",
                method,
                response.status_code,
                attempt + 1,
                delay,
            )
            await asyncio.sleep(delay)
        raise RuntimeError("unreachable")

    async def list_records(self) -> list[DNSRecord]:
        records: list[DNSRecord] = []
        page = 1
        while True:
            response = await self._request(
                "GET", self.records_url, params={"page": page, "perPage": 1000}
            )
            data = response.json()
            records.extend(DNSRecord.parse(value) for value in data.get("records", []))
            next_page = data.get("nextPage")
            if not next_page:
                return records
            page = int(next_page)

    async def create_record(
        self, host: str, answer: str, ttl: int, record_type: str = "A"
    ) -> DNSRecord:
        record_type = validate_record_answer(record_type, answer)
        existing = await self.find_record(host, record_type, answer)
        if existing is not None:
            if existing.answer == answer and existing.ttl == ttl:
                return existing
            raise RuntimeError(f"refusing to duplicate existing DNS host {host}")
        payload = {"host": host, "type": record_type, "answer": answer, "ttl": ttl}
        for attempt in range(5):
            try:
                response = await self._request(
                    "POST", self.records_url, retry_504=False, json=payload
                )
                return DNSRecord.parse(response.json())
            except httpx.HTTPStatusError as error:
                if error.response.status_code != 504 or attempt == 4:
                    raise
                # A 504 may have committed. Re-list before retrying so an
                # ambiguous response can never create a duplicate.
                existing = await self.find_record(host, record_type, answer)
                if existing is not None:
                    if existing.answer == answer and existing.ttl == ttl:
                        return existing
                    raise RuntimeError(
                        f"ambiguous create found conflicting DNS host {host}"
                    ) from error
                await asyncio.sleep(min(16.0, 2**attempt))
        raise RuntimeError("unreachable")

    async def update_record(
        self,
        record_id: int,
        host: str,
        answer: str,
        ttl: int,
        record_type: str = "A",
    ) -> DNSRecord:
        record_type = validate_record_answer(record_type, answer)
        response = await self._request(
            "PUT",
            f"{self.records_url}/{record_id}",
            json={
                "id": record_id,
                "host": host,
                "type": record_type,
                "answer": answer,
                "ttl": ttl,
            },
        )
        return DNSRecord.parse(response.json())

    async def delete_record(self, record_id: int) -> None:
        await self._request("DELETE", f"{self.records_url}/{record_id}")

    async def list_srv_records(self, host: str) -> list[dict[str, Any]]:
        """SRV records under one host, with their priority/weight/port.

        Separate from list_records because DNSRecord deliberately models only an
        address record: it has no room for the three extra fields an SRV carries,
        and widening it would put four unused columns on every A record the
        reconciler handles.
        """
        response = await self._request("GET", self.records_url)
        found = []
        for value in response.json().get("records") or []:
            if str(value.get("type", "")).upper() != "SRV":
                continue
            if str(value.get("host") or "@") != host:
                continue
            found.append(value)
        return found

    async def create_srv_record(
        self,
        host: str,
        target: str,
        ttl: int,
        priority: int = 10,
        weight: int = 10,
        port: int = 443,
    ) -> dict[str, Any]:
        """Publish one SRV record.

        Not routed through create_record: that validates the answer is an IP
        address, because every record it was written for is an A or AAAA. An SRV
        answer is a hostname, which is the entire reason SRV is used here — a
        joining node needs the gateway's NAME to complete TLS.

        The shape is Name.com's, established by asking it rather than guessing:
        weight, port and target are packed INTO the answer string, and only
        priority is a field of its own. Sending them as separate fields returns

            Answer for SRV records must be "{weight} {port} {target host}"

        which is a 400 with no record created.
        """
        payload = {
            "host": host,
            "type": "SRV",
            "answer": "%d %d %s" % (int(weight), int(port), target.rstrip(".")),
            "ttl": ttl,
            "priority": int(priority),
        }
        response = await self._request(
            "POST", self.records_url, retry_504=False, json=payload
        )
        return response.json()

    async def find_record(
        self, host: str, record_type: str = "A", answer: str | None = None
    ) -> DNSRecord | None:
        record_type = record_type.upper()
        if record_type not in RECORD_TYPES:
            raise ValueError(f"unsupported address record type {record_type}")
        return next(
            (
                record
                for record in await self.list_records()
                if record.type == record_type
                and record.host == host
                and (answer is None or record.answer == answer)
            ),
            None,
        )

    async def record_exists(
        self, host: str, answer: str, record_type: str | None = None
    ) -> bool:
        record_type = record_type or record_type_for_answer(answer)
        return await self.find_record(host, record_type, answer) is not None
