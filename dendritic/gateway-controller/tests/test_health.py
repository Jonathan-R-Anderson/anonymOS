from datetime import UTC, datetime, timedelta

from backend.health import apply_health_result
from backend.models import Gateway
from backend.verifier import Verification


def gateway(now):
    return Gateway(
        uuid="node",
        public_ip="8.8.8.8",
        hostname="gw-one.syndichan.org",
        port=443,
        last_seen=now,
        registered=True,
        verified=True,
        healthy=True,
        tls_valid=True,
        country=None,
        latency=20.0,
        failure_count=0,
        sequence=1,
        registration_expires_at=now + timedelta(minutes=5),
        registration_json="{}",
        created=now,
        updated=now,
    )


def test_third_consecutive_failure_removes_health():
    now = datetime.now(UTC)
    item = gateway(now)
    failure = Verification(False, False, None, "offline")
    for _ in range(2):
        apply_health_result(item, failure, now)
        assert item.healthy
    apply_health_result(item, failure, now)
    assert not item.healthy
    assert not item.verified


def test_success_resets_failures_and_expiry_overrides_success():
    now = datetime.now(UTC)
    item = gateway(now)
    item.failure_count = 2
    apply_health_result(item, Verification(True, True, 15.0), now)
    assert item.failure_count == 0 and item.healthy
    item.registration_expires_at = now - timedelta(seconds=1)
    apply_health_result(item, Verification(True, True, 15.0), now)
    assert not item.registered and not item.healthy

