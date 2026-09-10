from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .database import Session, initialize_database, session_scope
from .dns_sync import DNSSynchronizer
from .health import HealthChecker
from .metrics import (
    failed_registrations,
    gateway_latency,
    healthy_gateways,
    verification_failures,
)
from .models import Gateway, GatewayReservation
from .namecom import NameComClient
from .network_policy import NetworkPolicySynchronizer
from .rate_limit import RateLimiter
from .schemas import GatewayResponse, HostnameReservationRequest, RegistrationRequest
from .scheduler import create_scheduler
from .security import (
    authenticate_request,
    authenticate_identity,
    gateway_hostname,
    source_ip,
    validate_managed_hostname,
)
from .verifier import GatewayVerifier

logger = logging.getLogger(__name__)
@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    await initialize_database()
    namecom = NameComClient(settings)
    verifier = GatewayVerifier(settings)
    dns = DNSSynchronizer(settings, Session, namecom)
    network_policy = NetworkPolicySynchronizer(settings, Session)
    health = HealthChecker(Session, verifier, dns)
    limiter = RateLimiter(limit=5, window=60, redis_url=settings.redis_url)
    scheduler = create_scheduler(settings, health, dns, network_policy)
    app.state.settings = settings
    app.state.verifier = verifier
    app.state.dns = dns
    app.state.limiter = limiter
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)
        await network_policy.close()
        await limiter.close()
        await namecom.close()


app = FastAPI(
    title="Syndichan Gateway Controller",
    version="1.0.0",
    lifespan=lifespan,
)


def _settings(request: Request) -> Settings:
    return getattr(request.app.state, "settings", get_settings())


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/gateways/reserve", status_code=201)
async def reserve_hostname(
    request: Request,
    session: AsyncSession = Depends(session_scope),
) -> dict[str, object]:
    """Reserve and publish the deterministic ACME name for this node.

    The source address is taken from the authenticated network path, never the
    JSON body. The short expiry prevents abandoned ACME attempts from leaving
    permanent DNS records.
    """
    settings = _settings(request)
    ip = source_ip(request, settings)
    await request.app.state.limiter.check(ip)
    raw = await request.body()
    if len(raw) > 64 << 10:
        raise HTTPException(413, "reservation body too large")
    try:
        body = HostnameReservationRequest.model_validate_json(raw)
    except Exception as error:
        raise HTTPException(422, "invalid reservation body") from error
    await authenticate_identity(raw, request, body, session)
    now = datetime.now(UTC)
    await session.execute(
        delete(GatewayReservation).where(GatewayReservation.expires_at <= now)
    )
    hostname = gateway_hostname(body.node_id, settings)
    existing_gateway = (
        await session.execute(select(Gateway).where(Gateway.uuid == body.node_id))
    ).scalar_one_or_none()
    if existing_gateway is not None and existing_gateway.hostname != hostname:
        raise HTTPException(409, "node identity has a conflicting gateway hostname")
    reservation = (
        await session.execute(
            select(GatewayReservation).where(
                GatewayReservation.node_id == body.node_id
            )
        )
    ).scalar_one_or_none()
    if reservation is None:
        active = await session.scalar(
            select(func.count())
            .select_from(GatewayReservation)
            .where(GatewayReservation.expires_at > now)
        )
        if int(active or 0) >= settings.max_gateways:
            raise HTTPException(503, "gateway reservation capacity reached")
        reservation = GatewayReservation(
            node_id=body.node_id,
            public_ip=ip,
            hostname=hostname,
            expires_at=now + timedelta(seconds=settings.reservation_lifetime),
            created=now,
            updated=now,
        )
        session.add(reservation)
    else:
        reservation.public_ip = ip
        reservation.hostname = hostname
        reservation.expires_at = now + timedelta(seconds=settings.reservation_lifetime)
        reservation.updated = now
    await session.commit()
    # ACME cannot begin until the authoritative record exists. Synchronize
    # before returning; the client still confirms recursive DNS propagation.
    try:
        await request.app.state.dns.synchronize(wait=True)
    except httpx.HTTPStatusError as error:
        if error.response.status_code == 429:
            raise HTTPException(
                503,
                "DNS provider rate limited the reservation",
                headers={"Retry-After": error.response.headers.get("Retry-After", "60")},
            ) from error
        raise
    return {
        "hostname": hostname,
        "ip": ip,
        "expires_at": int(reservation.expires_at.timestamp()),
    }


@app.post("/api/v1/gateways/register", status_code=201)
async def register(
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(session_scope),
) -> dict[str, object]:
    settings = _settings(request)
    ip = source_ip(request, settings)
    await request.app.state.limiter.check(ip)
    raw = await request.body()
    if len(raw) > 512 << 10:
        raise HTTPException(413, "registration body too large")
    try:
        body = RegistrationRequest.model_validate_json(raw)
    except Exception as error:
        failed_registrations.inc()
        raise HTTPException(422, "invalid registration body") from error
    await authenticate_request(raw, request, body, session)
    # Commit replay state before performing an expensive external probe. A
    # rejected registration cannot be replayed to turn verification into a
    # resource-exhaustion primitive.
    await session.commit()
    hostname = validate_managed_hostname(body.public_hostname, settings)
    if hostname != gateway_hostname(body.node_id, settings):
        raise HTTPException(422, "gateway hostname does not match node identity")
    existing = (
        await session.execute(select(Gateway).where(Gateway.uuid == body.node_id))
    ).scalar_one_or_none()
    sequence = int(body.registration["sequence"])
    if body.registration.get("health_state") != "healthy":
        raise HTTPException(422, "only healthy registrations may be published")
    if existing is not None and sequence <= existing.sequence:
        raise HTTPException(409, "registration sequence did not increase")
    hostname_owner = (
        await session.execute(select(Gateway).where(Gateway.hostname == hostname))
    ).scalar_one_or_none()
    if hostname_owner is not None and hostname_owner.uuid != body.node_id:
        raise HTTPException(409, "gateway hostname is already assigned")
    count = await session.scalar(
        select(func.count()).select_from(Gateway).where(Gateway.registered.is_(True))
    )
    if existing is None and int(count or 0) >= settings.max_gateways:
        raise HTTPException(503, "gateway capacity reached")

    verification = await request.app.state.verifier.verify(ip, hostname, 443)
    if not verification.ok:
        failed_registrations.inc()
        verification_failures.inc()
        logger.warning("gateway registration rejected node=%s reason=%s", body.node_id, verification.reason)
        raise HTTPException(422, f"gateway verification failed: {verification.reason}")
    now = datetime.now(UTC)
    registration_expiry = min(
        datetime.fromtimestamp(
            int(body.registration.get("expires_at", body.timestamp)), tz=UTC
        ),
        now + timedelta(seconds=settings.registration_lifetime),
    )
    if registration_expiry <= now:
        raise HTTPException(422, "registration is already expired")
    values = dict(
        public_ip=ip,
        hostname=hostname,
        port=443,
        last_seen=now,
        registered=True,
        verified=True,
        healthy=True,
        tls_valid=True,
        latency=verification.latency_ms,
        failure_count=0,
        sequence=sequence,
        registration_expires_at=registration_expiry,
        registration_json=json.dumps(body.registration, separators=(",", ":")),
        updated=now,
    )
    if existing is None:
        session.add(Gateway(uuid=body.node_id, created=now, country=None, **values))
    else:
        for key, value in values.items():
            setattr(existing, key, value)
    await session.execute(
        delete(GatewayReservation).where(GatewayReservation.node_id == body.node_id)
    )
    await session.commit()
    if verification.latency_ms is not None:
        gateway_latency.observe(verification.latency_ms)
    logger.info("gateway registered node=%s hostname=%s ip=%s", body.node_id, hostname, ip)
    # DNS is asynchronous: a transient provider outage must not cause the
    # client to retransmit a registration that is already durable.
    background_tasks.add_task(request.app.state.dns.synchronize)
    return {"registered": True, "hostname": hostname, "ip": ip}


@app.post("/api/v1/gateways/unregister", status_code=204)
async def unregister(
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(session_scope),
) -> Response:
    settings = _settings(request)
    ip = source_ip(request, settings)
    await request.app.state.limiter.check(ip)
    raw = await request.body()
    try:
        body = RegistrationRequest.model_validate_json(raw)
    except Exception as error:
        raise HTTPException(422, "invalid unregister body") from error
    await authenticate_request(raw, request, body, session)
    await session.commit()
    gateway = (
        await session.execute(select(Gateway).where(Gateway.uuid == body.node_id))
    ).scalar_one_or_none()
    if gateway is not None:
        sequence = int(body.registration["sequence"])
        if sequence <= gateway.sequence:
            raise HTTPException(409, "unregister sequence did not increase")
        gateway.registered = False
        gateway.verified = False
        gateway.healthy = False
        gateway.sequence = sequence
        gateway.updated = datetime.now(UTC)
        await session.commit()
        await session.delete(gateway)
        await session.commit()
        background_tasks.add_task(request.app.state.dns.synchronize)
        logger.info("gateway unregistered node=%s", body.node_id)
    return Response(status_code=204)


@app.get("/api/v1/gateways", response_model=list[GatewayResponse])
async def gateways(
    session: AsyncSession = Depends(session_scope),
) -> list[GatewayResponse]:
    values = (
        await session.execute(
            select(Gateway)
            .where(
                Gateway.registered.is_(True),
                Gateway.verified.is_(True),
                Gateway.healthy.is_(True),
            )
            .order_by(Gateway.latency.asc().nullslast())
        )
    ).scalars().all()
    return [
        GatewayResponse(
            node_id=value.uuid,
            hostname=value.hostname,
            ip=value.public_ip,
            port=value.port,
            latency=value.latency,
            healthy=value.healthy,
            verified=value.verified,
            tls_valid=value.tls_valid,
            last_seen=value.last_seen,
            registration_expires_at=value.registration_expires_at,
        )
        for value in values
    ]


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
