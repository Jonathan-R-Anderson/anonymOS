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

import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from orin.core.database import OrinStorage
from orin.cli import parse_args

class TestSnapshotRetention(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_retention.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def _insert_snapshot(self, conn, id, timestamp, hostname):
        conn.execute(
            "INSERT INTO system_snapshots (id, timestamp, hostname, os_platform) VALUES (?, ?, ?, ?);",
            (id, timestamp, hostname, "linux")
        )
        conn.execute(
            "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (?, ?, ?, ?, ?, ?);",
            (id, 100 + id, 1, "test-proc", "/bin/test", "/bin/test")
        )

    def test_age_based_retention(self):
        now = datetime.now(timezone.utc)
        ts_old = (now - timedelta(days=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
        ts_new = (now - timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%SZ')

        with self.storage.get_connection() as conn:
            self._insert_snapshot(conn, 1, ts_old, "host1")
            self._insert_snapshot(conn, 2, ts_new, "host1")
            conn.commit()

        # Prune older than 10 days
        with self.storage.get_connection() as conn:
            result = self.storage.vault_prune(conn, older_than_days=10, dry_run=False, preserve_critical=False)
            
        self.assertEqual(result["deleted_snapshots"], 1)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots;")
            snap_ids = [r["id"] for r in cursor.fetchall()]
            
            cursor.execute("SELECT DISTINCT snapshot_id FROM collected_processes;")
            telemetry_snap_ids = [r["snapshot_id"] for r in cursor.fetchall()]
            
        self.assertEqual(snap_ids, [2])
        self.assertEqual(telemetry_snap_ids, [2])

    def test_count_based_retention(self):
        now = datetime.now(timezone.utc)
        ts1 = (now - timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        ts2 = (now - timedelta(minutes=20)).strftime('%Y-%m-%dT%H:%M:%SZ')
        ts3 = (now - timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')

        with self.storage.get_connection() as conn:
            # 3 snapshots on host1
            self._insert_snapshot(conn, 1, ts1, "host1")
            self._insert_snapshot(conn, 2, ts2, "host1")
            self._insert_snapshot(conn, 3, ts3, "host1")
            
            # 2 snapshots on host2
            self._insert_snapshot(conn, 4, ts1, "host2")
            self._insert_snapshot(conn, 5, ts2, "host2")
            conn.commit()

        # Keep last 2 snapshots per host (should delete id 1 on host1, keep everything else)
        with self.storage.get_connection() as conn:
            result = self.storage.vault_prune(conn, keep_last=2, dry_run=False, preserve_critical=False)

        self.assertEqual(result["deleted_snapshots"], 1)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots ORDER BY id;")
            snap_ids = [r["id"] for r in cursor.fetchall()]
            
        self.assertEqual(snap_ids, [2, 3, 4, 5])

    def test_critical_alert_preservation(self):
        now = datetime.now(timezone.utc)
        ts1 = (now - timedelta(days=20)).strftime('%Y-%m-%dT%H:%M:%SZ')
        ts2 = (now - timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        with self.storage.get_connection() as conn:
            self._insert_snapshot(conn, 1, ts1, "host1")
            self._insert_snapshot(conn, 2, ts2, "host1")
            
            # Insert a critical security event associated with snapshot 1
            # (same hostname, same/slightly after timestamp)
            conn.execute("""
                INSERT INTO security_events (timestamp, event_type, severity, description, resolved, hostname)
                VALUES (?, ?, ?, ?, 0, ?);
            """, (ts1, "malware_alert", "critical", "Found malware", "host1"))
            conn.commit()

        # Prune with critical-alert preservation enabled (should keep both since 1 is preserved and 2 is too new)
        with self.storage.get_connection() as conn:
            result = self.storage.vault_prune(conn, older_than_days=10, dry_run=False, preserve_critical=True)
            
        # Snapshot 1 was eligible by age (20 days old) but preserved
        self.assertEqual(result.get("preserved_by_alerts_count", 0), 1)
        self.assertEqual(result["deleted_snapshots"], 0)
        
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots ORDER BY id;")
            snap_ids = [r["id"] for r in cursor.fetchall()]
        self.assertEqual(snap_ids, [1, 2])

        # Now resolve the alert and try again
        with self.storage.get_connection() as conn:
            conn.execute("UPDATE security_events SET resolved = 1 WHERE severity = 'critical';")
            conn.commit()

        # Prune again
        with self.storage.get_connection() as conn:
            result = self.storage.vault_prune(conn, older_than_days=10, dry_run=False, preserve_critical=True)
            
        self.assertEqual(result["deleted_snapshots"], 1)
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM system_snapshots ORDER BY id;")
            snap_ids = [r["id"] for r in cursor.fetchall()]
        self.assertEqual(snap_ids, [2])

    def test_cli_argument_parsing(self):
        # Verify parser handles the mutually exclusive group correctly
        args = parse_args(["vault", "prune", "--older-than", "30"])
        self.assertEqual(args.older_than, 30)
        self.assertIsNone(args.keep_last)
        self.assertTrue(args.preserve_critical)

        args = parse_args(["vault", "prune", "--keep-last", "5", "--no-preserve-critical"])
        self.assertEqual(args.keep_last, 5)
        self.assertIsNone(args.older_than)
        self.assertFalse(args.preserve_critical)

        # Confirm they are mutually exclusive (should raise SystemExit)
        with self.assertRaises(SystemExit):
            parse_args(["vault", "prune", "--older-than", "30", "--keep-last", "5"])

if __name__ == "__main__":
    unittest.main()
