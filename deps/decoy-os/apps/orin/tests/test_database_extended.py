# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Extended unit tests for orin.core.database – covers uncovered store_* methods,
vault_stats, vault_prune, batch_store_*, optimize_database, and get_pool_stats.
"""
import os
import tempfile
import unittest
from pathlib import Path

from orin.core.database import OrinStorage


class TestDatabaseExtended(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()
        with self.storage.get_connection() as conn:
            self.snap_id = self.storage.create_snapshot(conn, hostname="testhost", os_platform="Linux")
            conn.commit()

    def tearDown(self):
        try:
            self.storage.close_pool()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # store_suid_binaries
    # ------------------------------------------------------------------ #
    def test_store_suid_binaries(self):
        records = [
            {"file_path": "/usr/bin/sudo", "owner": "root", "grp": "root",
             "permissions": "4755", "sha256": "abc123"}
        ]
        with self.storage.get_connection() as conn:
            self.storage.store_suid_binaries(conn, self.snap_id, records)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT file_path FROM collected_suid_binaries WHERE snapshot_id = ?;", (self.snap_id,))
            rows = cursor.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file_path"], "/usr/bin/sudo")

    # ------------------------------------------------------------------ #
    # store_privilege_events
    # ------------------------------------------------------------------ #
    def test_store_privilege_events(self):
        records = [
            {
                "event_type": "sudo_exec",
                "syscall": "execve",
                "user": "alice",
                "target_user": "root",
                "pid": 1234,
                "audit_uid": 1000,
                "command": "sudo bash",
                "executable": "/usr/bin/sudo",
                "source_ip": None,
                "auth_method": "sudo",
                "file_path": "/usr/bin/bash",
                "severity": "high",
                "details": "Alice ran sudo bash",
                "raw_record": "raw log line",
                "timestamp": "2026-06-01T12:00:00Z",
            }
        ]
        with self.storage.get_connection() as conn:
            self.storage.store_privilege_events(conn, self.snap_id, records)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT event_type FROM collected_privilege_events WHERE snapshot_id = ?;", (self.snap_id,))
            rows = cursor.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_type"], "sudo_exec")

    # ------------------------------------------------------------------ #
    # store_auth_logs
    # ------------------------------------------------------------------ #
    def test_store_auth_logs(self):
        lines = [
            "Jun 04 12:00:00 host sshd[123]: Failed password for root",
            "Jun 04 12:00:01 host sudo: alice TTY=pts/0 COMMAND=/bin/bash",
        ]
        with self.storage.get_connection() as conn:
            self.storage.store_auth_logs(conn, self.snap_id, lines)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM collected_auth_logs WHERE snapshot_id = ?;", (self.snap_id,))
            count = cursor.fetchone()["cnt"]
        self.assertEqual(count, 2)

    # ------------------------------------------------------------------ #
    # store_ebpf_programs
    # ------------------------------------------------------------------ #
    def test_store_ebpf_programs(self):
        records = [
            {"bpf_id": 42, "name": "suspicious_prog", "type": "socket_filter",
             "tag": "abc123", "gpl_compatible": 1}
        ]
        with self.storage.get_connection() as conn:
            self.storage.store_ebpf_programs(conn, self.snap_id, records)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM collected_ebpf_programs WHERE snapshot_id = ?;", (self.snap_id,))
            rows = cursor.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "suspicious_prog")

    # ------------------------------------------------------------------ #
    # store_ebpf_pinned
    # ------------------------------------------------------------------ #
    def test_store_ebpf_pinned(self):
        records = [{"path": "/sys/fs/bpf/orin_probe", "type": "prog"}]
        with self.storage.get_connection() as conn:
            self.storage.store_ebpf_pinned(conn, self.snap_id, records)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT path FROM collected_ebpf_pinned WHERE snapshot_id = ?;", (self.snap_id,))
            rows = cursor.fetchall()
        self.assertEqual(len(rows), 1)

    # ------------------------------------------------------------------ #
    # store_ld_preload
    # ------------------------------------------------------------------ #
    def test_store_ld_preload(self):
        lines = ["/lib/evil.so", "/tmp/backdoor.so"]
        with self.storage.get_connection() as conn:
            self.storage.store_ld_preload(conn, self.snap_id, lines)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM collected_ld_preload WHERE snapshot_id = ?;", (self.snap_id,))
            count = cursor.fetchone()["cnt"]
        self.assertEqual(count, 2)

    # ------------------------------------------------------------------ #
    # store_special_fds
    # ------------------------------------------------------------------ #
    def test_store_special_fds(self):
        records = [{"pid": 777, "fd_num": 5, "fd_type": "socket", "resolved_path": "socket:[12345]"}]
        with self.storage.get_connection() as conn:
            self.storage.store_special_fds(conn, self.snap_id, records)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT pid FROM collected_special_fds WHERE snapshot_id = ?;", (self.snap_id,))
            rows = cursor.fetchall()
        self.assertEqual(rows[0]["pid"], 777)

    # ------------------------------------------------------------------ #
    # store_persistence_configs
    # ------------------------------------------------------------------ #
    def test_store_persistence_configs(self):
        records = [
            {"source_path": "/etc/rc.local", "persistence_type": "rc_local",
             "content_hash": "deadbeef", "user_owner": "root"}
        ]
        with self.storage.get_connection() as conn:
            self.storage.store_persistence_configs(conn, self.snap_id, records)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT source_path FROM collected_persistence_configs WHERE snapshot_id = ?;", (self.snap_id,))
            rows = cursor.fetchall()
        self.assertEqual(rows[0]["source_path"], "/etc/rc.local")

    # ------------------------------------------------------------------ #
    # store_dns_queries
    # ------------------------------------------------------------------ #
    def test_store_dns_queries(self):
        records = [
            {
                "local_ip": "10.0.0.1", "local_port": 4532,
                "remote_ip": "8.8.8.8", "remote_port": 53,
                "process_name": "curl", "dns_server_type": "public",
                "domain": "evil.com", "query_type": "A",
                "entropy": 3.5, "is_dga": 0, "is_tunneling": 0,
                "anomaly_flags": None
            }
        ]
        with self.storage.get_connection() as conn:
            self.storage.store_dns_queries(conn, self.snap_id, records)
            conn.commit()
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM collected_dns_queries WHERE snapshot_id = ?;", (self.snap_id,))
            rows = cursor.fetchall()
        self.assertEqual(rows[0]["domain"], "evil.com")

    # ------------------------------------------------------------------ #
    # vault_stats
    # ------------------------------------------------------------------ #
    def test_vault_stats(self):
        with self.storage.get_connection() as conn:
            stats = self.storage.vault_stats(conn)
        self.assertIn("snapshot_count", stats)
        self.assertIn("database_size_bytes", stats)
        self.assertIn("table_counts", stats)
        self.assertGreaterEqual(stats["snapshot_count"], 1)

    # ------------------------------------------------------------------ #
    # vault_prune (dry_run=True, legacy mode)
    # ------------------------------------------------------------------ #
    def test_vault_prune_dry_run_no_old_snapshots(self):
        with self.storage.get_connection() as conn:
            # No old snapshots → should return message
            result = self.storage.vault_prune(conn, older_than_days=1, dry_run=True)
        # Either returns a summary or a "no snapshots" message dict
        self.assertIsInstance(result, dict)

    def test_vault_prune_granular_dry_run(self):
        retention = {
            "collected_processes": 0,  # 0 days → all would be pruned
            "default": 30,
        }
        with self.storage.get_connection() as conn:
            result = self.storage.vault_prune(conn, retention_policies=retention, dry_run=True)
        self.assertIn("mode", result)
        self.assertEqual(result["mode"], "granular")
        self.assertTrue(result["dry_run"])

    # ------------------------------------------------------------------ #
    # batch_store_processes
    # ------------------------------------------------------------------ #
    def test_batch_store_processes(self):
        records = [
            {"pid": i, "ppid": 1, "name": f"proc{i}", "exe": f"/bin/proc{i}",
             "cmdline": f"proc{i} -d"}
            for i in range(10)
        ]
        count = self.storage.batch_store_processes(self.snap_id, records, chunk_size=3)
        self.assertEqual(count, 10)

    def test_batch_store_processes_empty(self):
        count = self.storage.batch_store_processes(self.snap_id, [])
        self.assertEqual(count, 0)

    # ------------------------------------------------------------------ #
    # batch_store_kernel_symbols
    # ------------------------------------------------------------------ #
    def test_batch_store_kernel_symbols(self):
        records = [
            {"address": "0xffffffff810001234", "symbol_type": "T",
             "symbol_name": f"kernel_func_{i}", "module_name": "vmlinux",
             "is_critical": True, "suspicious": False, "anomaly_detected": False}
            for i in range(5)
        ]
        count = self.storage.batch_store_kernel_symbols(self.snap_id, records, chunk_size=2)
        self.assertEqual(count, 5)

    # ------------------------------------------------------------------ #
    # batch_store_generic
    # ------------------------------------------------------------------ #
    def test_batch_store_generic_empty_columns_raises(self):
        with self.assertRaises(ValueError):
            self.storage.batch_store_generic("collected_processes", [], [])

    def test_batch_store_generic_inserts(self):
        records = [
            (self.snap_id, 9001, 1, "testproc", "/bin/testproc", "testproc -x", "")
        ]
        count = self.storage.batch_store_generic(
            "collected_processes",
            ["snapshot_id", "pid", "ppid", "name", "exe", "cmdline", "ancestry_path"],
            records
        )
        self.assertEqual(count, 1)

    # ------------------------------------------------------------------ #
    # optimize_database
    # ------------------------------------------------------------------ #
    def test_optimize_database(self):
        stats = self.storage.optimize_database()
        self.assertIn("optimizations_applied", stats)
        self.assertIn("tables_analyzed", stats)
        self.assertGreaterEqual(stats["tables_analyzed"], 0)
        self.assertGreater(len(stats["optimizations_applied"]), 0)

    # ------------------------------------------------------------------ #
    # get_pool_stats
    # ------------------------------------------------------------------ #
    def test_get_pool_stats_without_pool(self):
        # Without explicit pool init, get_pool_stats should handle gracefully
        stats = self.storage.get_pool_stats()
        self.assertIsInstance(stats, dict)

    def test_get_pool_stats_with_pool(self):
        self.storage.initialize_pool()
        stats = self.storage.get_pool_stats()
        self.assertIn("max_connections", stats)
        self.assertIn("current_size", stats)



if __name__ == "__main__":
    unittest.main()
