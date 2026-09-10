from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass

from .config import Settings


@dataclass(frozen=True)
class Verification:
    ok: bool
    tls_valid: bool
    latency_ms: float | None
    reason: str | None = None


class GatewayVerifier:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def verify(self, ip: str, hostname: str, port: int = 443) -> Verification:
        started = time.monotonic()
        context = ssl.create_default_context()
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=ip,
                    port=port,
                    ssl=context,
                    server_hostname=hostname,
                    ssl_handshake_timeout=self.settings.gateway_timeout,
                ),
                timeout=self.settings.gateway_timeout,
            )
            request = (
                f"GET {self.settings.expected_gateway_path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                "User-Agent: Syndichan-Gateway-Controller/1.0\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=self.settings.gateway_timeout
            )
            if len(head) > 32 << 10:
                return Verification(False, True, None, "response headers too large")
            lines = head.decode("iso-8859-1").split("\r\n")
            if len(lines) < 2 or not lines[0].startswith("HTTP/1.1 200 "):
                return Verification(False, True, None, "gateway did not return HTTP 200")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip().lower()] = value.strip()
            expected = self.settings.expected_gateway_header.lower()
            if not headers.get(expected):
                return Verification(False, True, None, "gateway header missing")
            return Verification(
                True, True, (time.monotonic() - started) * 1000.0, None
            )
        except ssl.SSLCertVerificationError as error:
            return Verification(False, False, None, f"TLS verification failed: {error}")
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
            return Verification(False, False, None, f"gateway unavailable: {error}")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    pass

