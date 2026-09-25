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
# src/orin/core/rate_limiter.py
"""
orin.core.rate_limiter – SSH Rate Limiting Utility
==================================================
Provides thread-safe rate limiting for SSH connections to prevent
overwhelming target systems and avoid triggering security alerts.

Features
--------
- Concurrent connection limiting with semaphore-based control
- Per-target scan rate limiting (max scans per minute)
- Exponential backoff on connection failures
- Configurable delays between scan initiations
"""
import time
import threading
from collections import defaultdict
from typing import Dict
from contextlib import contextmanager


class SSHRateLimiter:
    """Thread-safe rate limiter for SSH operations.

    Manages concurrent connections, enforces per-target scan rates,
    and implements exponential backoff for failed connections.

    Attributes
    ----------
    max_concurrent : int
        Maximum number of simultaneous SSH connections allowed.
    delay_between_scans : float
        Seconds to wait between starting new scans.
    max_scans_per_minute : int
        Maximum scan initiations per minute per target host.
    backoff_factor : float
        Exponential backoff multiplier on connection failures.
    max_backoff_delay : float
        Maximum delay after repeated failures (seconds).
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        delay_between_scans: float = 1.0,
        max_scans_per_minute: int = 10,
        backoff_factor: float = 2.0,
        max_backoff_delay: float = 60.0
    ):
        """Initialize the SSH rate limiter.

        Parameters
        ----------
        max_concurrent : int
            Maximum simultaneous SSH connections (default: 5).
        delay_between_scans : float
            Delay between scan initiations in seconds (default: 1.0).
        max_scans_per_minute : int
            Max scans per minute per target (default: 10).
        backoff_factor : float
            Exponential backoff multiplier (default: 2.0).
        max_backoff_delay : float
            Maximum backoff delay in seconds (default: 60.0).
        """
        self.max_concurrent = max_concurrent
        self.delay_between_scans = delay_between_scans
        self.max_scans_per_minute = max_scans_per_minute
        self.backoff_factor = backoff_factor
        self.max_backoff_delay = max_backoff_delay

        # Semaphore for concurrent connection limiting
        self._connection_semaphore = threading.Semaphore(max_concurrent)

        # Lock for thread-safe access to shared state
        self._lock = threading.Lock()

        # Per-host scan timestamps for rate limiting
        self._host_scan_times: Dict[str, list] = defaultdict(list)

        # Per-host failure counts for backoff
        self._host_failures: Dict[str, int] = defaultdict(int)

        # Last scan time for global delay enforcement
        self._last_scan_time: float = 0.0

        # Track active connections
        self._active_connections: int = 0

    @contextmanager
    def acquire_connection(self, host: str):
        """Context manager for acquiring an SSH connection slot.

        Enforces concurrent connection limits, per-host rate limits,
        and exponential backoff on failures.

        Parameters
        ----------
        host : str
            Target hostname or IP address.

        Yields
        ------
        None

        Raises
        ------
        RuntimeError
            If rate limit cannot be satisfied within reasonable time.

        Examples
        --------
        >>> limiter = SSHRateLimiter()
        >>> with limiter.acquire_connection("192.168.1.1"):
        ...     # Perform SSH operation here
        ...     pass
        """
        # Apply exponential backoff if host has recent failures
        backoff_delay = self._calculate_backoff(host)
        if backoff_delay > 0:
            print(f"[*] Rate limiter: Applying {backoff_delay:.2f}s backoff for {host}")
            time.sleep(backoff_delay)

        # Enforce per-host scan rate limit
        self._enforce_host_rate_limit(host)

        # Enforce global delay between scans
        self._enforce_global_delay()

        # Acquire connection slot (blocks if at capacity)
        acquired = self._connection_semaphore.acquire(timeout=300)  # 5 min timeout
        if not acquired:
            raise RuntimeError(f"Failed to acquire connection slot for {host} - timeout after 300s")

        try:
            with self._lock:
                self._active_connections += 1
                print(f"[*] Rate limiter: Connection acquired for {host} "
                      f"(active: {self._active_connections}/{self.max_concurrent})")
            yield
        finally:
            with self._lock:
                self._active_connections -= 1
            self._connection_semaphore.release()
            print(f"[*] Rate limiter: Connection released for {host} "
                  f"(active: {self._active_connections}/{self.max_concurrent})")

    def record_success(self, host: str):
        """Record a successful scan for a host.

        Resets failure counter and records scan timestamp.

        Parameters
        ----------
        host : str
            Target hostname or IP address.
        """
        with self._lock:
            # Reset failure count on success
            self._host_failures[host] = 0

            # Record scan timestamp
            current_time = time.time()
            self._host_scan_times[host].append(current_time)

            # Clean old timestamps (older than 1 minute)
            self._cleanup_old_timestamps(host, current_time)

            print(f"[+] Rate limiter: Successful scan recorded for {host}")

    def record_failure(self, host: str):
        """Record a failed scan for a host.

        Increments failure counter for exponential backoff calculation.

        Parameters
        ----------
        host : str
            Target hostname or IP address.
        """
        with self._lock:
            self._host_failures[host] += 1
            failure_count = self._host_failures[host]
            print(f"[-] Rate limiter: Failure recorded for {host} (count: {failure_count})")

    def _calculate_backoff(self, host: str) -> float:
        """Calculate exponential backoff delay for a host.

        Parameters
        ----------
        host : str
            Target hostname or IP address.

        Returns
        -------
        float
            Backoff delay in seconds (0 if no failures).
        """
        failure_count = self._host_failures.get(host, 0)

        if failure_count == 0:
            return 0.0

        # Exponential backoff: base_delay * (backoff_factor ^ (failures - 1))
        backoff_delay = min(
            self.backoff_factor ** (failure_count - 1),
            self.max_backoff_delay
        )

        return backoff_delay

    def _enforce_host_rate_limit(self, host: str):
        """Enforce per-host scan rate limit.

        Blocks if host has reached max scans per minute.

        Parameters
        ----------
        host : str
            Target hostname or IP address.

        Raises
        ------
        RuntimeError
            If rate limit cannot be satisfied.
        """
        current_time = time.time()

        with self._lock:
            # Clean old timestamps
            self._cleanup_old_timestamps(host, current_time)

            # Check if at rate limit
            recent_scans = len(self._host_scan_times[host])

            if recent_scans >= self.max_scans_per_minute:
                # Calculate wait time until oldest scan expires
                oldest_scan = min(self._host_scan_times[host])
                wait_time = 60.0 - (current_time - oldest_scan)

                if wait_time > 0:
                    print(f"[*] Rate limiter: Host {host} at rate limit "
                          f"({recent_scans}/{self.max_scans_per_minute} scans/min). "
                          f"Waiting {wait_time:.2f}s...")

                    # Release lock during sleep to avoid blocking other threads
                    self._lock.release()
                    try:
                        time.sleep(wait_time + 0.1)  # Add small buffer
                    finally:
                        self._lock.acquire()

                    # Re-clean after waiting
                    current_time = time.time()
                    self._cleanup_old_timestamps(host, current_time)

    def _enforce_global_delay(self):
        """Enforce global delay between scan initiations."""
        current_time = time.time()

        with self._lock:
            elapsed = current_time - self._last_scan_time

            if elapsed < self.delay_between_scans:
                wait_time = self.delay_between_scans - elapsed

                # Release lock during sleep
                self._lock.release()
                try:
                    time.sleep(wait_time)
                finally:
                    self._lock.acquire()

            # Update last scan time
            self._last_scan_time = time.time()

    def _cleanup_old_timestamps(self, host: str, current_time: float):
        """Remove timestamps older than 1 minute.

        Must be called with lock held.

        Parameters
        ----------
        host : str
            Target hostname or IP address.
        current_time : float
            Current timestamp.
        """
        # Keep only timestamps from last 60 seconds
        cutoff = current_time - 60.0
        self._host_scan_times[host] = [
            ts for ts in self._host_scan_times[host] if ts > cutoff
        ]

    def get_stats(self) -> dict:
        """Get current rate limiter statistics.

        Returns
        -------
        dict
            Statistics including active connections, per-host rates, etc.
        """
        with self._lock:
            current_time = time.time()

            # Clean all hosts before reporting
            for host in list(self._host_scan_times.keys()):
                self._cleanup_old_timestamps(host, current_time)

            return {
                "active_connections": self._active_connections,
                "max_concurrent": self.max_concurrent,
                "hosts_tracked": len(self._host_scan_times),
                "per_host_stats": {
                    host: {
                        "scans_last_minute": len(times),
                        "failure_count": self._host_failures.get(host, 0),
                        "backoff_delay": self._calculate_backoff(host)
                    }
                    for host, times in self._host_scan_times.items()
                }
            }


def create_rate_limiter_from_config(config: dict) -> SSHRateLimiter:
    """Create an SSHRateLimiter instance from configuration dictionary.

    Parameters
    ----------
    config : dict
        Configuration dictionary with ssh.rate_limit settings.

    Returns
    -------
    SSHRateLimiter
        Configured rate limiter instance.
    """
    ssh_config = config.get("ssh", {})
    rate_limit_config = ssh_config.get("rate_limit", {})

    if not rate_limit_config.get("enabled", True):
        # Return a limiter with no restrictions if disabled
        return SSHRateLimiter(
            max_concurrent=1000,
            delay_between_scans=0.0,
            max_scans_per_minute=1000,
            backoff_factor=1.0,
            max_backoff_delay=0.0
        )

    return SSHRateLimiter(
        max_concurrent=rate_limit_config.get("max_concurrent_connections", 5),
        delay_between_scans=rate_limit_config.get("delay_between_scans", 1.0),
        max_scans_per_minute=rate_limit_config.get("max_scans_per_minute", 10),
        backoff_factor=rate_limit_config.get("backoff_factor", 2.0),
        max_backoff_delay=rate_limit_config.get("max_backoff_delay", 60.0)
    )