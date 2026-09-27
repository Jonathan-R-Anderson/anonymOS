from __future__ import annotations

import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .config import Settings
from .metrics import (
    network_policy_divergence,
    network_policy_reconcile_failures,
    trusted_gateway_addresses,
)
from .models import Gateway

logger = logging.getLogger(__name__)

_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")


def gateway_ingress_rule(addresses: set[str], port: int) -> dict[str, Any] | None:
    cidrs = sorted(
        {
            str(ipaddress.ip_network(f"{value}/{32 if ipaddress.ip_address(value).version == 4 else 128}"))
            for value in addresses
        }
    )
    if not cidrs:
        return None
    return {
        "from": [{"ipBlock": {"cidr": cidr}} for cidr in cidrs],
        "ports": [{"port": port, "protocol": "TCP"}],
    }


def reconcile_ingress_rules(
    current: list[dict[str, Any]], addresses: set[str], port: int
) -> list[dict[str, Any]]:
    """Replace only rules which expose the dedicated gateway-origin port."""

    retained = [
        rule
        for rule in current
        if not any(item.get("port") == port for item in rule.get("ports", []))
    ]
    gateway_rule = gateway_ingress_rule(addresses, port)
    if gateway_rule is not None:
        retained.append(gateway_rule)
    return retained


def admitted_addresses(rules: list[dict[str, Any]], port: int) -> set[str]:
    result: set[str] = set()
    for rule in rules:
        if not any(item.get("port") == port for item in rule.get("ports", [])):
            continue
        for source in rule.get("from", []):
            cidr = source.get("ipBlock", {}).get("cidr")
            if not cidr:
                continue
            network = ipaddress.ip_network(cidr, strict=False)
            if network.num_addresses == 1:
                result.add(str(network.network_address))
    return result


class NetworkPolicySynchronizer:
    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        client: httpx.AsyncClient | None = None,
    ):
        self.settings = settings
        self.sessions = sessions
        self._client = client
        self._owns_client = client is None

    def _client_for_cluster(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        token = _TOKEN_PATH.read_text(encoding="utf-8").strip()
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        self._client = httpx.AsyncClient(
            base_url=f"https://{host}:{port}",
            verify=str(_CA_PATH),
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        return self._client

    @property
    def _path(self) -> str:
        return (
            "/apis/networking.k8s.io/v1/namespaces/"
            f"{self.settings.network_policy_namespace}/networkpolicies/"
            f"{self.settings.network_policy_name}"
        )

    async def synchronize(self) -> None:
        if not self.settings.network_policy_sync_enabled:
            return
        try:
            await self._synchronize()
        except Exception:
            network_policy_reconcile_failures.inc()
            raise

    async def _synchronize(self) -> None:
        async with self.sessions() as session:
            locked = await session.scalar(
                text(
                    "SELECT pg_try_advisory_xact_lock("
                    "hashtext('syndichan-gateway-network-policy'))"
                )
            )
            if not locked:
                return
            gateways = (
                await session.execute(
                    select(Gateway).where(
                        Gateway.registered.is_(True),
                        Gateway.verified.is_(True),
                        Gateway.healthy.is_(True),
                    )
                )
            ).scalars().all()
            desired = {item.public_ip for item in gateways}
            client = self._client_for_cluster()
            response = await client.get(self._path)
            response.raise_for_status()
            policy = response.json()
            current_rules = policy.get("spec", {}).get("ingress", [])
            current = admitted_addresses(
                current_rules, self.settings.network_policy_gateway_port
            )
            ingress = reconcile_ingress_rules(
                current_rules,
                desired,
                self.settings.network_policy_gateway_port,
            )
            trusted_gateway_addresses.set(len(desired))
            network_policy_divergence.set(
                max(len(desired ^ current), int(current_rules != ingress))
            )
            if current_rules == ingress:
                return
            response = await client.patch(
                self._path,
                content=json.dumps({"spec": {"ingress": ingress}}),
                headers={"Content-Type": "application/merge-patch+json"},
            )
            response.raise_for_status()
            network_policy_divergence.set(0)
            logger.info(
                "gateway origin trust reconciled addresses=%d", len(desired)
            )

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
