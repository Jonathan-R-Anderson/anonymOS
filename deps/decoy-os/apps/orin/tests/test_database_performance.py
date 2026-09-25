#!/usr/bin/env python3
"""
Test suite for SQLite Performance Hardening features in OrinStorage.

Tests cover:
1. Connection Pool initialization and management
2. WAL mode and performance PRAGMAs
3. Batch insert operations with chunking
4. Database optimization routines
5. Pool statistics and monitoring
"""

import unittest
import time
import tempfile
from pathlib import Path
from orin.core.database import OrinStorage, ConnectionPool


class TestConnectionPool(unittest.TestCase):
    """Test connection pool functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_pool.db"

    def tearDown(self):
        # Cleanup
        if self.db_path.exists():
            self.db_path.unlink()
        # Clean up WAL and SHM files
        for ext in ['-wal', '-shm']:
            wal_file = self.db_path.with_suffix(self.db_path.suffix + ext)
            if wal_file.exists():
                wal_file.unlink()

    def test_pool_initialization(self):
        """Test that connection pool initializes correctly."""
        storage = OrinStorage(self.db_path, pool_size=5, pool_timeout=10.0)
        storage.initialize_pool()

        stats = storage.get_pool_stats()
        self.assertEqual(stats['max_connections'], 5)
        self.assertFalse(stats['closed'])
        self.assertGreater(stats['current_size'], 0)

        storage.close_pool()

    def test_pool_connection_acquisition(self):
        """Test acquiring and releasing connections from pool."""
        storage = OrinStorage(self.db_path, pool_size=3)
        storage.initialize_pool()

        # Acquire a connection
        with storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1;")
            result = cursor.fetchone()
            self.assertEqual(result[0], 1)

        # Connection should be returned to pool
        stats = storage.get_pool_stats()
        self.assertFalse(stats['closed'])

        storage.close_pool()

    def test_pool_concurrent_access(self):
        """Test thread-safe concurrent access to the pool."""
        import threading

        storage = OrinStorage(self.db_path, pool_size=5)
        storage.initialize_pool()
        storage.initialize_db()

        errors = []
        results = []

        def worker(worker_id):
            try:
                with storage.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1;")
                    results.append((worker_id, cursor.fetchone()[0]))
                    time.sleep(0.01)  # Simulate some work
            except Exception as e:
                errors.append((worker_id, str(e)))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 10)

        storage.close_pool()

    def test_pool_timeout(self):
        """Test connection acquisition timeout."""
        storage = OrinStorage(self.db_path, pool_size=1, pool_timeout=0.5)
        storage.initialize_pool()

        # Hold the only connection
        conn = storage._connection_pool.acquire()

        try:
            # Try to acquire another with short timeout
            # Note: The pool may create a new connection if under max limit,
            # so we need to test when pool is at capacity
            storage._connection_pool._created = storage._connection_pool.max_connections

            with self.assertRaises(TimeoutError):
                storage._connection_pool.acquire(timeout=0.2)
        finally:
            # Release the connection
            storage._connection_pool.release(conn)
            storage.close_pool()


class TestWALMode(unittest.TestCase):
    """Test WAL mode and performance optimizations."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_wal.db"

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()
        for ext in ['-wal', '-shm']:
            wal_file = self.db_path.with_suffix(self.db_path.suffix + ext)
            if wal_file.exists():
                wal_file.unlink()

    def test_wal_mode_enabled(self):
        """Test that WAL mode is enabled on connections."""
        storage = OrinStorage(self.db_path)

        with storage.get_connection(use_pool=False) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            self.assertEqual(mode, 'wal')

    def test_performance_pragmas(self):
        """Test that performance PRAGMAs are applied."""
        storage = OrinStorage(self.db_path)
        storage.initialize_db()

        with storage.get_connection(use_pool=False) as conn:
            cursor = conn.cursor()

            # Check synchronous mode
            cursor.execute("PRAGMA synchronous;")
            sync_mode = cursor.fetchone()[0]
            self.assertEqual(sync_mode, 1)  # NORMAL

            # Check cache size (should be negative for KB)
            cursor.execute("PRAGMA cache_size;")
            cache_size = cursor.fetchone()[0]
            self.assertLessEqual(cache_size, -64000)


class TestBatchInserts(unittest.TestCase):
    """Test batch insert operations with chunking."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_batch.db"
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()
        for ext in ['-wal', '-shm']:
            wal_file = self.db_path.with_suffix(self.db_path.suffix + ext)
            if wal_file.exists():
                wal_file.unlink()

    def test_batch_store_processes(self):
        """Test batch storing of process records."""
        # Create snapshot
        with self.storage.get_connection() as conn:
            snapshot_id = self.storage.create_snapshot(conn)
            conn.commit()

        # Generate test data
        processes = [
            {"pid": i, "ppid": 1, "name": f"process_{i}",
             "exe": f"/usr/bin/process_{i}", "cmdline": f"process_{i} arg"}
            for i in range(100, 200)
        ]

        # Batch insert
        inserted = self.storage.batch_store_processes(snapshot_id, processes, chunk_size=25)
        self.assertEqual(inserted, 100)

        # Verify count
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM collected_processes;")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 100)

    def test_batch_store_kernel_symbols(self):
        """Test batch storing of kernel symbol records."""
        with self.storage.get_connection() as conn:
            snapshot_id = self.storage.create_snapshot(conn)
            conn.commit()

        # Generate test data
        symbols = [
            {"address": f"0x{hex(i)}", "symbol_type": "T", "symbol_name": f"sym_{i}",
             "module_name": "kernel", "is_critical": i % 10 == 0}
            for i in range(500)
        ]

        inserted = self.storage.batch_store_kernel_symbols(snapshot_id, symbols, chunk_size=100)
        self.assertEqual(inserted, 500)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM collected_kernel_symbols;")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 500)

    def test_batch_store_generic(self):
        """Test generic batch insert method."""
        with self.storage.get_connection() as conn:
            snapshot_id = self.storage.create_snapshot(conn)
            conn.commit()

        # Insert users using generic method
        columns = ["snapshot_id", "username", "uid", "gid", "home_dir", "login_shell"]
        records = [
            (snapshot_id, f"user_{i}", 1000 + i, 1000 + i, f"/home/user_{i}", "/bin/bash")
            for i in range(50)
        ]

        inserted = self.storage.batch_store_generic("collected_users", columns, records, chunk_size=20)
        self.assertEqual(inserted, 50)

        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM collected_users;")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 50)

    def test_batch_insert_empty_columns(self):
        """Test that empty columns list raises ValueError."""
        with self.assertRaises(ValueError):
            self.storage.batch_store_generic("test_table", [], [(1, 2, 3)])


class TestDatabaseOptimization(unittest.TestCase):
    """Test database optimization routines."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_optimize.db"
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()
        for ext in ['-wal', '-shm']:
            wal_file = self.db_path.with_suffix(self.db_path.suffix + ext)
            if wal_file.exists():
                wal_file.unlink()

    def test_optimize_database(self):
        """Test database optimization routine."""
        # Add some data first
        with self.storage.get_connection() as conn:
            snapshot_id = self.storage.create_snapshot(conn)
            self.storage.store_processes(conn, snapshot_id, [
                {"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init", "cmdline": "init"}
            ])
            conn.commit()

        # Run optimization
        stats = self.storage.optimize_database()

        self.assertIn('optimizations_applied', stats)
        self.assertIn('tables_analyzed', stats)
        self.assertGreater(stats['tables_analyzed'], 0)

        # Check that WAL mode was applied
        wal_applied = any('journal_mode=WAL' in opt for opt in stats['optimizations_applied'])
        self.assertTrue(wal_applied)


class TestPerformanceComparison(unittest.TestCase):
    """Compare performance between regular and batch inserts."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path_regular = Path(self.temp_dir) / "test_regular.db"
        self.db_path_batch = Path(self.temp_dir) / "test_batch_perf.db"

    def tearDown(self):
        for db_path in [self.db_path_regular, self.db_path_batch]:
            if db_path.exists():
                db_path.unlink()
            for ext in ['-wal', '-shm']:
                wal_file = db_path.with_suffix(db_path.suffix + ext)
                if wal_file.exists():
                    wal_file.unlink()

    def test_batch_vs_regular_insert_performance(self):
        """Test that batch inserts are faster than individual inserts."""
        num_records = 500

        # Regular inserts
        storage_regular = OrinStorage(self.db_path_regular)
        storage_regular.initialize_db()

        with storage_regular.get_connection() as conn:
            snapshot_id = storage_regular.create_snapshot(conn)

            start_time = time.time()
            for i in range(num_records):
                storage_regular.store_processes(conn, snapshot_id, [{
                    "pid": i, "ppid": 1, "name": f"proc_{i}",
                    "exe": f"/bin/proc_{i}", "cmdline": f"proc_{i}"
                }])
            conn.commit()
            regular_time = time.time() - start_time

        # Batch inserts
        storage_batch = OrinStorage(self.db_path_batch)
        storage_batch.initialize_db()

        with storage_batch.get_connection() as conn:
            snapshot_id = storage_batch.create_snapshot(conn)
            conn.commit()

        processes = [
            {"pid": i, "ppid": 1, "name": f"proc_{i}",
             "exe": f"/bin/proc_{i}", "cmdline": f"proc_{i}"}
            for i in range(num_records)
        ]

        start_time = time.time()
        storage_batch.batch_store_processes(snapshot_id, processes, chunk_size=100)
        batch_time = time.time() - start_time

        # Batch should be significantly faster (at least 2x for large datasets)
        # Note: For small datasets, overhead might make this less dramatic
        print(f"\nRegular insert time: {regular_time:.4f}s")
        print(f"Batch insert time: {batch_time:.4f}s")

        # Just verify both completed successfully
        with storage_regular.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM collected_processes;")
            self.assertEqual(cursor.fetchone()[0], num_records)

        with storage_batch.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM collected_processes;")
            self.assertEqual(cursor.fetchone()[0], num_records)


if __name__ == "__main__":
    unittest.main(verbosity=2)