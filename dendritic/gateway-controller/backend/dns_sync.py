from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .config import Settings
from .metrics import (
    dns_changes,
    dns_desired_records,
    dns_divergence,
    dns_existing_records,
    dns_reconcile_failures,
    managed_dns_records,
)
from .models import Gateway, GatewayReservation, ManagedDNSRecord
from .namecom import DNSRecord, NameComClient, record_type_for_answer

logger = logging.getLogger(__name__)


RecordKey = tuple[str, str, str]  # host, record type, answer


@dataclass(frozen=True)
class DNSPlan:
    create: tuple[RecordKey, ...]
    update: tuple[DNSRecord, ...]
    delete: tuple[DNSRecord, ...]
    conflicts: tuple[RecordKey, ...]


def build_plan(
    desired: set[RecordKey],
    current: dict[RecordKey, DNSRecord],
    owned_record_ids: dict[RecordKey, int],
    ttl: int,
) -> DNSPlan:
    create: list[RecordKey] = []
    update: list[DNSRecord] = []
    delete_records: list[DNSRecord] = []
    conflicts: list[RecordKey] = []
    for key in sorted(desired):
        record = current.get(key)
        owner_id = owned_record_ids.get(key)
        if owner_id is None:
            if record is None:
                create.append(key)
            else:
                conflicts.append(key)
            continue
        if record is None or record.id != owner_id:
            conflicts.append(key)
            continue
        if record.ttl != ttl:
            update.append(record)
    for key, owner_id in sorted(owned_record_ids.items()):
        if key in desired:
            continue
        record = current.get(key)
        if record is not None and record.id == owner_id:
            delete_records.append(record)
        elif record is not None:
            conflicts.append(key)
    return DNSPlan(
        tuple(create),
        tuple(update),
        tuple(delete_records),
        tuple(sorted(set(conflicts))),
    )


def desired_record_keys(
    settings: Settings,
    gateways: list[Gateway],
    reservations: list[GatewayReservation],
) -> set[RecordKey]:
    def relative_host(hostname: str) -> str:
        if hostname == settings.domain:
            return "@"
        suffix = "." + settings.domain
        if not hostname.endswith(suffix):
            raise ValueError("hostname escaped managed domain")
        return hostname[: -len(suffix)]

    desired = {
        (
            relative_host(item.hostname),
            record_type_for_answer(item.public_ip),
            item.public_ip,
        )
        for item in gateways
    }
    desired.update(
        (
            relative_host(item.hostname),
            record_type_for_answer(item.public_ip),
            item.public_ip,
        )
        for item in reservations
    )
    # Certificate names remain one-per-node. The shared browser-facing name is
    # capped and ordered deterministically by measured latency, with unknown
    # latency last, so a large volunteer population cannot create an oversized
    # DNS response.
    ranked = sorted(
        gateways,
        key=lambda item: (
            item.latency is None,
            item.latency if item.latency is not None else float("inf"),
            item.uuid,
        ),
    )
    public_host = relative_host(settings.public_hostname)
    desired.update(
        (
            public_host,
            record_type_for_answer(item.public_ip),
            item.public_ip,
        )
        for item in ranked[: settings.max_answers]
    )
    return desired


class DNSSynchronizer:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        namecom: NameComClient,
    ):
        self.settings = settings
        self.sessions = sessions
        self.namecom = namecom
        self._local_lock = asyncio.Lock()

    def _host(self, hostname: str) -> str:
        if hostname == self.settings.domain:
            return "@"
        suffix = "." + self.settings.domain
        if not hostname.endswith(suffix):
            raise ValueError("hostname escaped managed domain")
        return hostname[: -len(suffix)]

    async def synchronize(self, wait: bool = False) -> None:
        try:
            await self._synchronize(wait)
        except Exception:
            dns_reconcile_failures.inc()
            raise

    async def _synchronize(self, wait: bool = False) -> None:
        if self._local_lock.locked() and not wait:
            return
        async with self._local_lock:
            async with self.sessions() as session:
                now = datetime.now(UTC)
                lock_function = (
                    "pg_advisory_xact_lock" if wait else "pg_try_advisory_xact_lock"
                )
                locked = await session.scalar(
                    text(
                        f"SELECT {lock_function}("
                        "hashtext('syndichan-gateway-dns-sync'))"
                    )
                )
                if not wait and not locked:
                    return
                await session.execute(
                    delete(GatewayReservation).where(
                        GatewayReservation.expires_at <= now
                    )
                )
                # Row locks serialize replicas. The ownership table is also the
                # durable allow-list for deletion after a gateway disappears.
                ownership = (
                    await session.execute(
                        select(ManagedDNSRecord).with_for_update()
                    )
                ).scalars().all()
                desired_gateways = (
                    await session.execute(
                        select(Gateway).where(
                            Gateway.registered.is_(True),
                            Gateway.verified.is_(True),
                            Gateway.healthy.is_(True),
                        )
                    )
                ).scalars().all()
                desired_reservations = (
                    await session.execute(
                        select(GatewayReservation).where(
                            GatewayReservation.expires_at > now
                        )
                    )
                ).scalars().all()
                desired = desired_record_keys(
                    self.settings,
                    list(desired_gateways),
                    list(desired_reservations),
                )
                owned = {
                    (item.hostname, item.record_type, item.answer): item
                    for item in ownership
                }
                current = {
                    (record.host, record.type, record.answer): record
                    for record in await self.namecom.list_records()
                    if record.type in {"A", "AAAA"}
                }
                managed_scope = desired | set(owned)
                existing_managed = set(current) & managed_scope
                dns_desired_records.set(len(desired))
                dns_existing_records.set(len(existing_managed))
                dns_divergence.set(len(desired ^ existing_managed))
                plan = build_plan(
                    desired,
                    current,
                    {host: item.record_id for host, item in owned.items()},
                    self.settings.ttl,
                )
                for host, record_type, answer in plan.conflicts:
                    logger.error(
                        "DNS ownership mismatch for %s %s %s; refusing mutation",
                        host,
                        record_type,
                        answer,
                    )

                for host, record_type, answer in plan.create:
                    record = await self.namecom.create_record(
                        host, answer, self.settings.ttl, record_type
                    )
                    session.add(
                        ManagedDNSRecord(
                            hostname=host,
                            record_type=record_type,
                            record_id=record.id,
                            answer=answer,
                        )
                    )
                    dns_changes.labels("create").inc()

                for record in plan.update:
                    await self.namecom.update_record(
                        record.id,
                        record.host,
                        record.answer,
                        self.settings.ttl,
                        record.type,
                    )
                    dns_changes.labels("update").inc()

                deleted_keys: set[RecordKey] = set()
                for record in plan.delete:
                    await self.namecom.delete_record(record.id)
                    dns_changes.labels("delete").inc()
                    deleted_keys.add((record.host, record.type, record.answer))
                for key, owner in owned.items():
                    if key not in desired and (
                        key in deleted_keys or current.get(key) is None
                    ):
                        await session.delete(owner)
                await session.commit()
                managed_dns_records.set(len(desired))
                # Report the converged state immediately rather than waiting
                # for the next scheduled pass. Ownership conflicts are
                # deliberately not treated as convergence: no mutation was
                # attempted for them and an operator still needs to act.
                desired_conflicts = sum(
                    1 for conflict in plan.conflicts if conflict in desired
                )
                dns_existing_records.set(len(desired) - desired_conflicts)
                dns_divergence.set(len(plan.conflicts))
