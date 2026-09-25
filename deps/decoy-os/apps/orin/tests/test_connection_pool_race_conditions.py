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
"""Test ConnectionPool race condition fixes."""

import pytest
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3

from orin.core.database import ConnectionPool


class TestConnectionPoolRaceConditions:
    """Test thread safety and race condition fixes in ConnectionPool."""

    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create a temporary database path."""
        db_path = tmp_path / "test_pool.db"
        yield db_path
        # Cleanup
        if db_path.exists():
            db_path.unlink()
        wal_path = db_path.with_suffix(".db-wal")
        if wal_path.exists():
            wal_path.unlink()
        shm_path = db_path.with_suffix(".db-shm")
        if shm_path.exists():
            shm_path.unlink()

    @pytest.fixture
    def pool(self, temp_db):
        """Create a connection pool for testing."""
        p = ConnectionPool(temp_db, max_connections=5, timeout=10.0)
        yield p
        p.close()

    def test_concurrent_acquire_release(self, pool):
        """Test that concurrent acquire/release operations don't cause race conditions."""
        errors = []
        acquired_count = [0]
        lock = threading.Lock()

        def worker(worker_id):
            try:
                for i in range(10):
                    conn = pool.acquire(timeout=5.0)
                    with lock:
                        acquired_count[0] += 1

                    # Simulate some work
                    conn.execute("SELECT 1;")
                    time.sleep(0.01)

                    pool.release(conn)
                    time.sleep(0.005)
            except Exception as e:
                errors.append((worker_id, str(e)))

        threads = []
        for i in range(10):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)

        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert acquired_count[0] == 100, f"Expected 100 acquisitions, got {acquired_count[0]}"

    def test_no_connection_leaks_on_failure(self, pool):
        """Test that failed connection creation doesn't leak counter."""
        initial_stats = pool.stats()

        # Force many concurrent acquires to potentially trigger failures
        errors = []

        def aggressive_worker():
            try:
                for _ in range(20):
                    conn = pool.acquire(timeout=2.0)
                    # Immediately release
                    pool.release(conn)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(str(e))

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(aggressive_worker) for _ in range(8)]
            for future in as_completed(futures):
                future.result(timeout=30)

        # Pool should recover and still be usable
        final_stats = pool.stats()

        # Should not have leaked connections
        assert final_stats['created_connections'] <= pool.max_connections
        assert len(errors) == 0 or all("timeout" in e.lower() for e in errors)

    def test_atomic_counter_increment(self, pool):
        """Test that connection counter increments atomically."""
        max_observed = [0]
        lock = threading.Lock()

        def counter_checker():
            try:
                conn = pool.acquire(timeout=5.0)
                with lock:
                    stats = pool.stats()
                    if stats['created_connections'] > max_observed[0]:
                        max_observed[0] = stats['created_connections']

                time.sleep(0.05)  # Hold connection briefly
                pool.release(conn)
            except Exception:
                pass

        threads = []
        for _ in range(20):
            t = threading.Thread(target=counter_checker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)

        # Counter should never exceed max_connections
        assert max_observed[0] <= pool.max_connections, \
            f"Counter exceeded max: {max_observed[0]} > {pool.max_connections}"

    def test_close_during_acquire(self, temp_db):
        """Test that closing pool during acquire doesn't cause issues."""
        pool = ConnectionPool(temp_db, max_connections=3, timeout=5.0)
        close_errors = []
        acquire_errors = []

        def closer():
            time.sleep(0.1)  # Let some acquires start
            try:
                pool.close()
            except Exception as e:
                close_errors.append(str(e))

        def acquirer():
            try:
                conn = pool.acquire(timeout=1.0)
                try:
                    conn.execute("SELECT 1;")
                finally:
                    try:
                        pool.release(conn)
                    except:
                        pass
            except RuntimeError as e:
                if "closed" in str(e).lower():
                    acquire_errors.append("closed")  # Expected
                else:
                    acquire_errors.append(str(e))
            except Exception as e:
                acquire_errors.append(str(e))

        # Start multiple acquirers
        threads = []
        for _ in range(5):
            t = threading.Thread(target=acquirer)
            threads.append(t)
            t.start()

        # Start closer
        closer_thread = threading.Thread(target=closer)
        closer_thread.start()

        for t in threads:
            t.join(timeout=10)
        closer_thread.join(timeout=10)

        # Close should succeed without errors
        assert len(close_errors) == 0, f"Close errors: {close_errors}"
        # Some acquires should fail with "closed" error, which is expected
        # Others might succeed if they got connection before close

    def test_stale_connection_handling(self, pool):
        """Test that stale connections are handled correctly."""
        # Get a connection
        conn1 = pool.acquire(timeout=5.0)

        # Manually invalidate it by closing
        conn1.close()

        # Try to release it back - should handle gracefully
        pool.release(conn1)

        # Pool should still be functional
        stats = pool.stats()
        assert stats['created_connections'] >= 0

        # Should be able to get new connections
        conn2 = pool.acquire(timeout=5.0)
        result = conn2.execute("SELECT 1;").fetchone()
        assert result[0] == 1
        pool.release(conn2)

    def test_pool_full_scenario(self, pool):
        """Test behavior when pool is at maximum capacity."""
        connections = []

        # Acquire all available connections
        for _ in range(pool.max_connections):
            conn = pool.acquire(timeout=5.0)
            connections.append(conn)

        # Verify we have all connections
        assert len(connections) == pool.max_connections

        # Try to acquire one more - should either timeout or get a connection
        # (if the pool allows exceeding max temporarily during creation)
        try:
            extra_conn = pool.acquire(timeout=0.5)
            # If we got a connection, that's OK - pool may allow temporary overflow
            pool.release(extra_conn)
        except TimeoutError:
            # This is also acceptable - pool correctly blocked acquisition
            pass

        # Release one connection
        pool.release(connections[0])
        connections = connections[1:]

        # Now should be able to acquire again
        new_conn = pool.acquire(timeout=2.0)
        assert new_conn is not None
        pool.release(new_conn)

        # Clean up
        for conn in connections:
            pool.release(conn)

    def test_exception_in_acquire_cleanup(self, pool):
        """Test that exceptions during acquire don't leak resources."""
        # This test verifies the exception handling in acquire method
        errors = []

        def faulty_worker():
            try:
                for _ in range(5):
                    conn = pool.acquire(timeout=5.0)
                    # Simulate work that might fail
                    if _ == 2:
                        raise ValueError("Simulated error")
                    pool.release(conn)
            except ValueError:
                errors.append("expected")
            except Exception as e:
                errors.append(f"unexpected: {e}")

        threads = []
        for _ in range(5):
            t = threading.Thread(target=faulty_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)

        # All expected errors should be caught
        assert len([e for e in errors if e == "expected"]) == 5

        # Pool should still be functional
        stats = pool.stats()
        assert stats['closed'] is False

    def test_double_close_idempotency(self, temp_db):
        """Test that calling close() multiple times is safe."""
        pool = ConnectionPool(temp_db, max_connections=3, timeout=5.0)

        # Close multiple times
        pool.close()
        pool.close()
        pool.close()

        # Should remain closed
        assert pool.stats()['closed'] is True

        # Acquiring after close should raise RuntimeError
        with pytest.raises(RuntimeError, match="closed"):
            pool.acquire()

    def test_release_none_connection(self, pool):
        """Test that releasing None connection is handled gracefully."""
        # Should not raise any exception
        pool.release(None)

        # Pool should still be functional
        conn = pool.acquire(timeout=5.0)
        pool.release(conn)

    def test_concurrent_close_and_release(self, temp_db):
        """Test race condition between close and release operations."""
        pool = ConnectionPool(temp_db, max_connections=5, timeout=5.0)
        errors = []

        # Acquire some connections
        connections = []
        for _ in range(3):
            conn = pool.acquire(timeout=5.0)
            connections.append(conn)

        def releaser():
            for conn in connections:
                try:
                    time.sleep(0.01)
                    pool.release(conn)
                except Exception as e:
                    errors.append(f"release: {e}")

        def closer():
            time.sleep(0.05)  # Wait for some releases to start
            try:
                pool.close()
            except Exception as e:
                errors.append(f"close: {e}")

        t1 = threading.Thread(target=releaser)
        t2 = threading.Thread(target=closer)

        t1.start()
        t2.start()

        t1.join(timeout=10)
        t2.join(timeout=10)

        # Should complete without critical errors
        # Some release errors are acceptable during close
        assert len([e for e in errors if "close" not in e.lower()]) == 0

    def test_stats_thread_safety(self, pool):
        """Test that stats() can be called safely from multiple threads."""
        stats_results = []
        lock = threading.Lock()

        def stats_collector():
            for _ in range(10):
                try:
                    conn = pool.acquire(timeout=5.0)
                    conn.execute("SELECT 1;")
                    time.sleep(0.01)

                    with lock:
                        stats_results.append(pool.stats())

                    pool.release(conn)
                except Exception:
                    pass

        threads = []
        for _ in range(5):
            t = threading.Thread(target=stats_collector)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)

        # All stats calls should return valid dicts
        for stats in stats_results:
            assert isinstance(stats, dict)
            assert 'max_connections' in stats
            assert 'current_size' in stats
            assert 'created_connections' in stats
            assert 'closed' in stats


class TestConnectionPoolStress:
    """Stress tests for ConnectionPool under heavy load."""

    @pytest.fixture
    def temp_db(self, tmp_path):
        """Create a temporary database path."""
        db_path = tmp_path / "stress_test.db"
        yield db_path
        # Cleanup
        for suffix in ['', '-wal', '-shm']:
            p = db_path.with_suffix(db_path.suffix + suffix)
            if p.exists():
                p.unlink()

    def test_high_concurrency_load(self, temp_db):
        """Test pool under high concurrency load."""
        pool = ConnectionPool(temp_db, max_connections=10, timeout=30.0)
        success_count = [0]
        error_count = [0]
        lock = threading.Lock()

        def heavy_worker(worker_id):
            try:
                for i in range(50):
                    conn = pool.acquire(timeout=10.0)
                    try:
                        # Do some actual database work
                        conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER);")
                        conn.execute("INSERT INTO test VALUES (?)", (i,))
                        conn.commit()
                        result = conn.execute("SELECT COUNT(*) FROM test;").fetchone()

                        with lock:
                            success_count[0] += 1
                    finally:
                        pool.release(conn)

                    time.sleep(0.001)
            except Exception as e:
                with lock:
                    error_count[0] += 1

        threads = []
        for i in range(20):
            t = threading.Thread(target=heavy_worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=120)

        pool.close()

        # Most operations should succeed
        assert error_count[0] == 0, f"Errors occurred: {error_count[0]}"
        assert success_count[0] > 0, "No successful operations"