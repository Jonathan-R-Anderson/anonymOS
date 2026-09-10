from types import SimpleNamespace

from backend.config import Settings
from backend.dns_sync import build_plan, desired_record_keys
from backend.namecom import DNSRecord
from backend.models import Base, ManagedDNSRecord
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


def record(record_id, host, answer, ttl=300, record_type="A"):
    return DNSRecord(
        id=record_id, host=host, type=record_type, answer=answer, ttl=ttl
    )


def key(item):
    return (item.host, item.type, item.answer)


def test_dns_plan_adds_and_removes_one_answer_among_many():
    keep = record(1, "@", "8.8.8.8")
    remove = record(2, "@", "8.8.4.4")
    current = {key(keep): keep, key(remove): remove}
    desired = {key(keep), ("@", "A", "9.9.9.9")}
    plan = build_plan(
        desired,
        current,
        {key(keep): 1, key(remove): 2},
        300,
    )
    assert plan.create == (("@", "A", "9.9.9.9"),)
    assert plan.update == ()
    assert plan.delete == (remove,)
    assert plan.conflicts == ()


def test_dns_plan_mixed_families_and_ttl_reconciliation():
    ipv4 = record(1, "@", "8.8.8.8", ttl=600)
    ipv6 = record(2, "@", "2606:4700:4700::1111", record_type="AAAA")
    desired = {key(ipv4), key(ipv6)}
    plan = build_plan(
        desired,
        {key(ipv4): ipv4, key(ipv6): ipv6},
        {key(ipv4): 1, key(ipv6): 2},
        300,
    )
    assert plan.create == ()
    assert plan.update == (ipv4,)
    assert plan.delete == ()


def test_dns_plan_noop_reconvergence():
    existing = record(1, "@", "8.8.8.8")
    plan = build_plan(
        {key(existing)}, {key(existing): existing}, {key(existing): 1}, 300
    )
    assert plan.create == plan.update == plan.delete == plan.conflicts == ()


def test_dns_plan_never_adopts_or_deletes_unmanaged_records():
    unmanaged = record(9, "@", "8.8.8.8")
    mismatched = record(10, "gw-owned", "1.1.1.1")
    plan = build_plan(
        {key(unmanaged)},
        {key(unmanaged): unmanaged, key(mismatched): mismatched},
        {key(mismatched): 11},
        300,
    )
    assert plan.create == ()
    assert plan.update == ()
    assert plan.delete == ()
    assert plan.conflicts == (key(unmanaged), key(mismatched))


@pytest.mark.asyncio
async def test_multi_answer_ownership_survives_session_restart():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session:
        session.add_all(
            [
                ManagedDNSRecord(
                    hostname="@",
                    record_type="A",
                    answer="8.8.8.8",
                    record_id=1,
                ),
                ManagedDNSRecord(
                    hostname="@",
                    record_type="A",
                    answer="8.8.4.4",
                    record_id=2,
                ),
            ]
        )
        await session.commit()
    async with sessions() as restarted_session:
        rows = (
            await restarted_session.execute(
                select(ManagedDNSRecord).order_by(ManagedDNSRecord.record_id)
            )
        ).scalars().all()
        assert [(row.hostname, row.record_type, row.answer) for row in rows] == [
            ("@", "A", "8.8.8.8"),
            ("@", "A", "8.8.4.4"),
        ]
    await engine.dispose()


def test_desired_records_keep_node_names_and_cap_shared_public_answers():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        domain="syndichan.org",
        public_hostname="syndichan.org",
        max_answers=2,
    )
    gateways = [
        SimpleNamespace(
            uuid="slow",
            hostname="gw-slow.syndichan.org",
            public_ip="8.8.8.8",
            latency=80.0,
        ),
        SimpleNamespace(
            uuid="fast-v6",
            hostname="gw-fast-v6.syndichan.org",
            public_ip="2606:4700:4700::1111",
            latency=10.0,
        ),
        SimpleNamespace(
            uuid="fast-v4",
            hostname="gw-fast-v4.syndichan.org",
            public_ip="1.1.1.1",
            latency=20.0,
        ),
    ]
    desired = desired_record_keys(settings, gateways, [])
    assert ("gw-slow", "A", "8.8.8.8") in desired
    assert ("gw-fast-v6", "AAAA", "2606:4700:4700::1111") in desired
    assert ("@", "AAAA", "2606:4700:4700::1111") in desired
    assert ("@", "A", "1.1.1.1") in desired
    assert ("@", "A", "8.8.8.8") not in desired


def test_reservations_never_enter_shared_public_answers():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        domain="syndichan.org",
        public_hostname="syndichan.org",
    )
    reservation = SimpleNamespace(
        hostname="gw-candidate.syndichan.org",
        public_ip="9.9.9.9",
    )
    desired = desired_record_keys(settings, [], [reservation])
    assert desired == {("gw-candidate", "A", "9.9.9.9")}
