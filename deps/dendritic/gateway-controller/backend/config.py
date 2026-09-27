from __future__ import annotations

import ipaddress
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, DotEnvSettingsSource, SettingsConfigDict

# First existing path wins. `/secret/.env` is where the deployment mounts the
# stack's shared file; `.env` and `../.env` cover a checkout run in place.
ENV_FILE_CANDIDATES = ("/secret/.env", ".env", "../.env")

# Only these fields may come from the shared .env. That file configures the
# whole stack, and it also defines DOMAIN and TRUSTED_PROXY_CIDRS for the app
# tier — letting it supply those here would silently override the reviewed
# ConfigMap, and TRUSTED_PROXY_CIDRS decides which hop's address is publishable.
DOTENV_FIELDS = frozenset({"namecom_username", "namecom_api_token", "namecom_api_url"})
KUBERNETES_NAME = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$"
)


def _env_file() -> Path | None:
    override = os.environ.get("GATEWAY_ENV_FILE")
    for candidate in (override,) if override else ENV_FILE_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return path
    return None


class NameComDotEnvSource(DotEnvSettingsSource):
    def __call__(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in super().__call__().items()
            if key in DOTENV_FIELDS
        }


def _yaml_settings() -> dict[str, Any]:
    path = Path(os.environ.get("GATEWAY_CONFIG", "config.yaml"))
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    # Provider credentials are intentionally rejected in files. They must be
    # injected by the server runtime's secret manager.
    namecom = raw.pop("namecom", None)
    if isinstance(namecom, dict) and any(namecom.values()):
        raise ValueError("Name.com credentials must not be stored in config.yaml")
    for key in ("namecom_username", "namecom_api_token"):
        if raw.pop(key, None):
            raise ValueError("Name.com credentials must not be stored in config.yaml")
    return raw


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="", case_sensitive=False, extra="ignore",
    )

    domain: str = "syndichan.org"
    public_hostname: str = "syndichan.org"
    subdomain_prefix: str = "gw"
    ttl: int = 300
    health_check_interval: int = 60
    dns_sync_interval: int = 900
    gateway_timeout: int = 15
    registration_lifetime: int = 600
    reservation_lifetime: int = 900
    max_gateways: int = 1000
    max_answers: int = 8
    network_policy_sync_enabled: bool = False
    network_policy_sync_interval: int = 30
    network_policy_namespace: str = "maniwani"
    network_policy_name: str = "nginx-gateway-ingress"
    network_policy_gateway_port: int = 9443
    expected_gateway_header: str = "X-Gateway-Version"
    expected_gateway_path: str = "/readyz"
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    database_url: str = "postgresql+asyncpg://gateway@postgres/gateway"
    redis_url: str | None = None
    namecom_api_url: str = "https://api.name.com/core/v1"
    namecom_username: str | None = None
    namecom_api_token: SecretStr | None = None
    log_level: str = "INFO"

    @classmethod
    def settings_customise_sources(
        cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings
    ):
        # Environment, the shared .env file, and mounted secret files override
        # public YAML. A real environment variable still beats .env, so an
        # injected Secret keeps winning over the file it was derived from.
        env_file = _env_file()
        if env_file is not None:
            dotenv_settings = NameComDotEnvSource(
                settings_cls, env_file=env_file, case_sensitive=False
            )
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            file_secret_settings,
            _yaml_settings,
        )

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if not value or "/" in value or ":" in value:
            raise ValueError("invalid DNS domain")
        return value

    @field_validator("public_hostname")
    @classmethod
    def normalize_public_hostname(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if not value or "/" in value or ":" in value or "*" in value:
            raise ValueError("invalid public hostname")
        return value

    @field_validator("subdomain_prefix")
    @classmethod
    def validate_prefix(cls, value: str) -> str:
        value = value.strip().lower()
        if not value or not value.replace("-", "").isalnum():
            raise ValueError("invalid subdomain prefix")
        return value

    @field_validator("ttl")
    @classmethod
    def minimum_ttl(cls, value: int) -> int:
        if value < 300:
            raise ValueError("Name.com TTL must be at least 300 seconds")
        return value

    @field_validator("namecom_api_url")
    @classmethod
    def validate_namecom_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Name.com API URL must be credential-free HTTPS")
        return value.rstrip("/")

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def validate_proxy_cidrs(cls, values: list[str]) -> list[str]:
        for value in values:
            ipaddress.ip_network(value, strict=False)
        return values

    @field_validator("network_policy_namespace", "network_policy_name")
    @classmethod
    def validate_kubernetes_name(cls, value: str) -> str:
        value = value.strip().lower()
        if not KUBERNETES_NAME.fullmatch(value):
            raise ValueError("invalid Kubernetes resource name")
        return value

    @model_validator(mode="after")
    def validate_durations(self):
        if min(
            self.health_check_interval,
            self.dns_sync_interval,
            self.gateway_timeout,
            self.registration_lifetime,
            self.reservation_lifetime,
            self.max_gateways,
            self.max_answers,
            self.network_policy_sync_interval,
            self.network_policy_gateway_port,
        ) < 1:
            raise ValueError("intervals, timeouts, and max_gateways must be positive")
        if self.public_hostname != self.domain and not self.public_hostname.endswith(
            "." + self.domain
        ):
            raise ValueError("public_hostname must be inside domain")
        if self.network_policy_gateway_port > 65535:
            raise ValueError("network_policy_gateway_port must be a valid TCP port")
        return self

    def require_namecom_credentials(self) -> tuple[str, str]:
        if not self.namecom_username or not self.namecom_api_token:
            raise RuntimeError(
                "NAMECOM_USERNAME and NAMECOM_API_TOKEN must be injected at "
                "runtime, or set in the .env file this service reads"
            )
        return self.namecom_username, self.namecom_api_token.get_secret_value()


@lru_cache
def get_settings() -> Settings:
    return Settings()
