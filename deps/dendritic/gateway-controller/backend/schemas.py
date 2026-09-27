from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    node_id: str = Field(min_length=8, max_length=128)
    public_key: str = Field(min_length=16, max_length=256)
    timestamp: int
    nonce: str = Field(min_length=16, max_length=128)


class HostnameReservationRequest(IdentityRequest):
    pass


class RegistrationRequest(IdentityRequest):
    public_hostname: str = Field(min_length=1, max_length=253)
    port: int = 443
    registration: dict[str, Any]


class GatewayResponse(BaseModel):
    node_id: str
    hostname: str
    ip: str
    port: int
    latency: float | None
    healthy: bool
    verified: bool
    tls_valid: bool
    last_seen: datetime
    registration_expires_at: datetime
