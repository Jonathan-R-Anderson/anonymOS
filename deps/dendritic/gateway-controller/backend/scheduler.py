from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .config import Settings
from .dns_sync import DNSSynchronizer
from .health import HealthChecker
from .network_policy import NetworkPolicySynchronizer


def create_scheduler(
    settings: Settings,
    health: HealthChecker,
    dns: DNSSynchronizer,
    network_policy: NetworkPolicySynchronizer,
) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        health.run,
        "interval",
        seconds=settings.health_check_interval,
        id="gateway-health",
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        dns.synchronize,
        "interval",
        seconds=settings.dns_sync_interval,
        id="gateway-dns",
        coalesce=True,
        max_instances=1,
    )
    if settings.network_policy_sync_enabled:
        scheduler.add_job(
            network_policy.synchronize,
            "interval",
            seconds=settings.network_policy_sync_interval,
            id="gateway-network-policy",
            coalesce=True,
            max_instances=1,
        )
    return scheduler
