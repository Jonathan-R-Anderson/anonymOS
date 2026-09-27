from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Gateway(Base):
    __tablename__ = "gateways"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    public_ip: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    port: Mapped[int] = mapped_column(Integer, default=443)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    registered: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    healthy: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    tls_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    latency: Mapped[float | None] = mapped_column(Float, nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    sequence: Mapped[int] = mapped_column(BigInteger, default=0)
    registration_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    registration_json: Mapped[str] = mapped_column(Text)
    created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ManagedDNSRecord(Base):
    __tablename__ = "managed_dns_records"

    hostname: Mapped[str] = mapped_column(String(253), primary_key=True)
    record_type: Mapped[str] = mapped_column(String(5), primary_key=True, default="A")
    answer: Mapped[str] = mapped_column(String(45), primary_key=True)
    record_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class GatewayReservation(Base):
    __tablename__ = "gateway_hostname_reservations"

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    public_ip: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class UsedNonce(Base):
    __tablename__ = "gateway_registration_nonces"

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
