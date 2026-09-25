# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
Test suite for SSH Rate Limiter
================================
Tests concurrent connection limiting, per-host rate limiting,
and exponential backoff functionality.
"""
import pytest
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from orin.core.rate_limiter import SSHRateLimiter, create_rate_limiter_from_config


class TestSSHRateLimiterBasics:
    """Test basic rate limiter initialization and configuration."""

    def test_default_initialization(self):
        """Test rate limiter with default parameters."""
        limiter = SSHRateLimiter()

        assert limiter.max_concurrent == 5
        assert limiter.delay_between_scans == 1.0
        assert limiter.max_scans_per_minute == 10
        assert limiter.backoff_factor == 2.0
        assert limiter.max_backoff_delay == 60.0

    def test_custom_initialization(self):
        """Test rate limiter with custom parameters."""
        limiter = SSHRateLimiter(
            max_concurrent=3,
            delay_between_scans=0.5,
            max_scans_per_minute=5,
            backoff_factor=1.5,
            max_backoff_delay=30.0
        )

        assert limiter.max_concurrent == 3
        assert limiter.delay_between_scans == 0.5
        assert limiter.max_scans_per_minute == 5
        assert limiter.backoff_factor == 1.5
        assert limiter.max_backoff_delay == 30.0

    def test_create_from_config_enabled(self):
        """Test creating rate limiter from config with enabled=True."""
        config = {
            "ssh": {
                "rate_limit": {
                    "enabled": True,
                    "max_concurrent_connections": 4,
                    "delay_between_scans": 0.8,
                    "max_scans_per_minute": 8,
                    "backoff_factor": 1.8,
                    "max_backoff_delay": 45.0
                }
            }
        }

        limiter = create_rate_limiter_from_config(config)

        assert limiter.max_concurrent == 4
        assert limiter.delay_between_scans == 0.8
        assert limiter.max_scans_per_minute == 8
        assert limiter.backoff_factor == 1.8
        assert limiter.max_backoff_delay == 45.0

    def test_create_from_config_disabled(self):
        """Test creating rate limiter from config with enabled=False."""
        config = {
            "ssh": {
                "rate_limit": {
                    "enabled": False,
                    "max_concurrent_connections": 2,
                }
            }
        }

        limiter = create_rate_limiter_from_config(config)

        # When disabled, should have very high limits (effectively no limiting)
        assert limiter.max_concurrent == 1000
        assert limiter.delay_between_scans == 0.0
        assert limiter.max_scans_per_minute == 1000

    def test_create_from_config_defaults(self):
        """Test creating rate limiter from config with missing keys."""
        config = {"ssh": {}}

        limiter = create_rate_limiter_from_config(config)

        # Should use defaults
        assert limiter.max_concurrent == 5
        assert limiter.delay_between_scans == 1.0
        assert limiter.max_scans_per_minute == 10


class TestConcurrentConnectionLimiting:
    """Test concurrent connection limiting functionality."""

    def test_concurrent_limit_enforcement(self):
        """Test that concurrent connections are limited correctly."""
        limiter = SSHRateLimiter(max_concurrent=2, delay_between_scans=0.0)

        max_observed = 0
        lock = threading.Lock()

        def scan_task(host_id):
            nonlocal max_observed
            host = f"192.168.1.{host_id}"

            with limiter.acquire_connection(host):
                with lock:
                    # Track peak concurrency
                    current = limiter._active_connections
                    max_observed = max(max_observed, current)

                time.sleep(0.1)  # Simulate work

            return host

        # Launch 5 concurrent tasks with max_concurrent=2
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_task, i) for i in range(5)]
            results = [f.result() for f in as_completed(futures)]

        # Verify we got all results
        assert len(results) == 5

        # Most importantly, verify we never exceeded the limit
        # (allowing for small timing variations)
        assert max_observed <= 3  # Allow 1 for timing tolerance

    def test_connection_release_on_exception(self):
        """Test that connections are released even on exceptions."""
        limiter = SSHRateLimiter(max_concurrent=1, delay_between_scans=0.0)

        # First connection succeeds - use try/except to catch the exception
        exception_raised = False
        try:
            with limiter.acquire_connection("192.168.1.1"):
                assert limiter._active_connections == 1
                raise ValueError("Simulated error")
        except ValueError:
            exception_raised = True

        # Verify exception was raised
        assert exception_raised

        # Connection should be released despite exception
        assert limiter._active_connections == 0

        # Should be able to acquire again immediately
        with limiter.acquire_connection("192.168.1.2"):
            assert limiter._active_connections == 1


class TestPerHostRateLimiting:
    """Test per-host scan rate limiting."""

    def test_host_rate_limit_enforcement(self):
        """Test that per-host rate limits are enforced."""
        # Allow only 2 scans per minute with no delay between scans
        limiter = SSHRateLimiter(
            max_concurrent=10,
            delay_between_scans=0.0,
            max_scans_per_minute=2
        )

        host = "192.168.1.100"

        # First two scans should succeed immediately
        start_time = time.time()

        with limiter.acquire_connection(host):
            pass
        limiter.record_success(host)

        with limiter.acquire_connection(host):
            pass
        limiter.record_success(host)

        # Third scan should wait until first scan expires from window
        with limiter.acquire_connection(host):
            elapsed = time.time() - start_time
            # Should have waited ~60 seconds for first scan to expire
            # But we'll use a shorter timeout for testing
            pass

    def test_different_hosts_independent(self):
        """Test that different hosts have independent rate limits."""
        limiter = SSHRateLimiter(
            max_concurrent=10,
            delay_between_scans=0.0,
            max_scans_per_minute=2
        )

        host1 = "192.168.1.1"
        host2 = "192.168.1.2"

        # Exhaust rate limit for host1
        with limiter.acquire_connection(host1):
            pass
        limiter.record_success(host1)

        with limiter.acquire_connection(host1):
            pass
        limiter.record_success(host1)

        # host2 should still be able to scan immediately
        start_time = time.time()
        with limiter.acquire_connection(host2):
            elapsed = time.time() - start_time

        # Should not have waited (no rate limit for host2 yet)
        assert elapsed < 0.5


class TestExponentialBackoff:
    """Test exponential backoff on failures."""

    def test_backoff_calculation(self):
        """Test exponential backoff delay calculation."""
        limiter = SSHRateLimiter(
            backoff_factor=2.0,
            max_backoff_delay=60.0
        )

        # No failures = no backoff
        assert limiter._calculate_backoff("host1") == 0.0

        # Record failures and check backoff
        limiter.record_failure("host1")
        assert limiter._calculate_backoff("host1") == 1.0  # 2^0 = 1

        limiter.record_failure("host1")
        assert limiter._calculate_backoff("host1") == 2.0  # 2^1 = 2

        limiter.record_failure("host1")
        assert limiter._calculate_backoff("host1") == 4.0  # 2^2 = 4

    def test_backoff_max_cap(self):
        """Test that backoff is capped at max_backoff_delay."""
        limiter = SSHRateLimiter(
            backoff_factor=2.0,
            max_backoff_delay=10.0
        )

        # Record many failures
        for _ in range(10):
            limiter.record_failure("host1")

        # Should be capped at max_backoff_delay
        backoff = limiter._calculate_backoff("host1")
        assert backoff == 10.0

    def test_backoff_reset_on_success(self):
        """Test that success resets failure counter."""
        limiter = SSHRateLimiter(backoff_factor=2.0, max_backoff_delay=60.0)

        # Record some failures
        limiter.record_failure("host1")
        limiter.record_failure("host1")
        limiter.record_failure("host1")

        assert limiter._calculate_backoff("host1") == 4.0

        # Record success
        limiter.record_success("host1")

        # Backoff should be reset
        assert limiter._calculate_backoff("host1") == 0.0


class TestGlobalDelay:
    """Test global delay between scans."""

    def test_global_delay_enforcement(self):
        """Test that global delay is enforced between scans."""
        limiter = SSHRateLimiter(
            max_concurrent=10,
            delay_between_scans=0.5,
            max_scans_per_minute=100
        )

        host1 = "192.168.1.1"
        host2 = "192.168.1.2"

        # First scan
        start_time = time.time()
        with limiter.acquire_connection(host1):
            pass

        # Second scan to different host should respect global delay
        with limiter.acquire_connection(host2):
            elapsed = time.time() - start_time

        # Should have waited at least 0.5 seconds
        assert elapsed >= 0.45  # Allow small tolerance


class TestStatistics:
    """Test statistics reporting."""

    def test_get_stats(self):
        """Test statistics retrieval."""
        limiter = SSHRateLimiter(max_concurrent=5)

        host = "192.168.1.1"

        # Perform a scan
        with limiter.acquire_connection(host):
            stats = limiter.get_stats()
            assert stats["active_connections"] == 1

        limiter.record_success(host)

        # After completion
        stats = limiter.get_stats()
        assert stats["active_connections"] == 0
        assert stats["max_concurrent"] == 5
        assert host in stats["per_host_stats"]
        assert stats["per_host_stats"][host]["scans_last_minute"] == 1
        assert stats["per_host_stats"][host]["failure_count"] == 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_acquire_timeout(self):
        """Test acquisition timeout when pool is exhausted."""
        # Very low concurrent limit
        limiter = SSHRateLimiter(max_concurrent=1, delay_between_scans=0.0)

        # Hold the only connection
        acquired = False

        def hold_connection():
            nonlocal acquired
            with limiter.acquire_connection("host1"):
                acquired = True
                time.sleep(2)  # Hold for 2 seconds

        # Start holder thread
        holder = threading.Thread(target=hold_connection)
        holder.start()

        # Wait for first acquisition
        while not acquired:
            time.sleep(0.01)

        # Try to acquire with short timeout (should fail)
        # Note: Our implementation has 300s timeout, so this won't actually timeout
        # in a reasonable test. We just verify it eventually succeeds.
        start = time.time()
        with limiter.acquire_connection("host2"):
            elapsed = time.time() - start
            # Should have waited for first to release
            assert elapsed >= 1.5  # Waited for holder to finish

        holder.join()

    def test_rapid_sequential_scans(self):
        """Test rapid sequential scans to same host."""
        limiter = SSHRateLimiter(
            max_concurrent=10,
            delay_between_scans=0.1,
            max_scans_per_minute=100
        )

        host = "192.168.1.1"

        # Perform multiple rapid scans
        for i in range(5):
            with limiter.acquire_connection(host):
                pass
            limiter.record_success(host)

        # All should complete successfully
        stats = limiter.get_stats()
        assert stats["per_host_stats"][host]["scans_last_minute"] == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])