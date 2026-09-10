from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .dns_sync import DNSSynchronizer
from .metrics import gateway_latency, healthy_gateways, verification_failures
from .models import Gateway
from .verifier import GatewayVerifier
from .verifier import Verification

logger = logging.getLogger(__name__)


def apply_health_result(
    gateway: Gateway, result: Verification, now: datetime
) -> None:
    gateway.tls_valid = result.tls_valid
    gateway.updated = now
    if result.ok:
        gateway.healthy = True
        gateway.verified = True
        gateway.failure_count = 0
        gateway.last_seen = now
        gateway.latency = result.latency_ms
        if result.latency_ms is not None:
            gateway_latency.observe(result.latency_ms)
    else:
        gateway.failure_count += 1
        verification_failures.inc()
        if gateway.failure_count >= 3:
            gateway.healthy = False
            gateway.verified = False
    if gateway.registration_expires_at <= now:
        gateway.registered = False
        gateway.healthy = False
        gateway.verified = False


class HealthChecker:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        verifier: GatewayVerifier,
        dns: DNSSynchronizer,
    ):
        self.sessions = sessions
        self.verifier = verifier
        self.dns = dns

    async def run(self) -> None:
        changed = False
        async with self.sessions() as session:
            locked = await session.scalar(
                text(
                    "SELECT pg_try_advisory_xact_lock("
                    "hashtext('syndichan-gateway-health'))"
                )
            )
            if not locked:
                return
            gateways = (
                await session.execute(
                    select(Gateway).where(Gateway.registered.is_(True))
                )
            ).scalars().all()
            results = await asyncio.gather(
                *(self.verifier.verify(item.public_ip, item.hostname, item.port) for item in gateways)
            )
            now = datetime.now(UTC)
            for item, result in zip(gateways, results):
                before = (
                    item.registered,
                    item.verified,
                    item.healthy,
                    item.public_ip,
                    item.hostname,
                )
                apply_health_result(item, result, now)
                after = (
                    item.registered,
                    item.verified,
                    item.healthy,
                    item.public_ip,
                    item.hostname,
                )
                changed = changed or before != after
                if not result.ok:
                    logger.warning(
                        "gateway %s health failure %d/3: %s",
                        item.uuid,
                        item.failure_count,
                        result.reason,
                    )
            healthy_gateways.set(sum(1 for item in gateways if item.healthy and item.verified))
            await session.commit()
        if changed:
            await self.dns.synchronize()
