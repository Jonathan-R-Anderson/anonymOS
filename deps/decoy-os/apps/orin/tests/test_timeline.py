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
from orin.core.database import OrinStorage
from orin.analysis.timeline import calculate_snapshot_delta

class TestTimeline(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_timeline.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_calculate_snapshot_delta(self):
        with self.storage.get_connection() as conn:
            # 1. Insert snapshots
            conn.execute(
                "INSERT INTO system_snapshots (id, timestamp, hostname, os_platform) VALUES (?, ?, ?, ?);",
                (1, "2026-06-04T08:00:00Z", "host1", "linux")
            )
            conn.execute(
                "INSERT INTO system_snapshots (id, timestamp, hostname, os_platform) VALUES (?, ?, ?, ?);",
                (2, "2026-06-04T09:00:00Z", "host1", "linux")
            )
            
            # 2. Insert security events (one before, one during, one after)
            conn.execute(
                """
                INSERT INTO security_events (timestamp, event_type, severity, description)
                VALUES (?, ?, ?, ?);
                """,
                ("2026-06-04T07:59:59Z", "pre_event", "low", "before snapshot 1")
            )
            conn.execute(
                """
                INSERT INTO security_events (timestamp, event_type, severity, description)
                VALUES (?, ?, ?, ?);
                """,
                ("2026-06-04T08:30:00Z", "mid_event", "high", "between snapshot 1 and 2")
            )
            conn.execute(
                """
                INSERT INTO security_events (timestamp, event_type, severity, description)
                VALUES (?, ?, ?, ?);
                """,
                ("2026-06-04T09:00:01Z", "post_event", "low", "after snapshot 2")
            )
            
            # 3. Insert collected ports
            # Snapshot 1 has port 80
            # Snapshot 2 has port 80 and port 443 (new port!)
            conn.execute(
                "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (?, ?, ?, ?);",
                (1, 80, "tcp", "nginx")
            )
            conn.execute(
                "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (?, ?, ?, ?);",
                (2, 80, "tcp", "nginx")
            )
            conn.execute(
                "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (?, ?, ?, ?);",
                (2, 443, "tcp", "nginx")
            )
            
            # 4. Insert collected processes
            # Snapshot 1 has pid 100
            # Snapshot 2 has pid 100 and pid 200 (new process!)
            conn.execute(
                "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (?, ?, ?, ?, ?, ?);",
                (1, 100, 1, "systemd", "/sbin/init", "/sbin/init")
            )
            conn.execute(
                "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (?, ?, ?, ?, ?, ?);",
                (2, 100, 1, "systemd", "/sbin/init", "/sbin/init")
            )
            conn.execute(
                "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline) VALUES (?, ?, ?, ?, ?, ?);",
                (2, 200, 100, "malware", "/tmp/malware", "/tmp/malware --daemon")
            )
            
            # 5. Insert collected outbound connections
            # Snapshot 1 has connection to 8.8.8.8:53
            # Snapshot 2 has connection to 8.8.8.8:53 and 9.9.9.9:53 (new connection!)
            conn.execute(
                """
                INSERT INTO collected_outbound_connections (snapshot_id, remote_ip, remote_port, local_port, state)
                VALUES (?, ?, ?, ?, ?);
                """,
                (1, "8.8.8.8", 53, 40001, "ESTABLISHED")
            )
            conn.execute(
                """
                INSERT INTO collected_outbound_connections (snapshot_id, remote_ip, remote_port, local_port, state)
                VALUES (?, ?, ?, ?, ?);
                """,
                (2, "8.8.8.8", 53, 40001, "ESTABLISHED")
            )
            conn.execute(
                """
                INSERT INTO collected_outbound_connections (snapshot_id, remote_ip, remote_port, local_port, state)
                VALUES (?, ?, ?, ?, ?);
                """,
                (2, "9.9.9.9", 53, 40002, "ESTABLISHED")
            )
            
            conn.commit()

        # Run delta calculation
        report = calculate_snapshot_delta(self.db_path, 1, 2)
        
        self.assertEqual(report["base_id"], 1)
        self.assertEqual(report["target_id"], 2)
        
        # Verify ports delta
        self.assertEqual(len(report["new_ports"]), 1)
        self.assertEqual(report["new_ports"][0]["port"], 443)
        self.assertEqual(report["new_ports"][0]["protocol"], "tcp")
        self.assertEqual(report["new_ports"][0]["process"], "nginx")
        
        # Verify processes delta
        self.assertEqual(len(report["new_processes"]), 1)
        self.assertEqual(report["new_processes"][0]["pid"], 200)
        self.assertEqual(report["new_processes"][0]["name"], "malware")
        self.assertEqual(report["new_processes"][0]["exe"], "/tmp/malware")
        self.assertEqual(report["new_processes"][0]["cmdline"], "/tmp/malware --daemon")
        
        # Verify connection delta
        self.assertEqual(len(report["new_connections"]), 1)
        self.assertEqual(report["new_connections"][0]["remote_ip"], "9.9.9.9")
        self.assertEqual(report["new_connections"][0]["remote_port"], 53)
        self.assertEqual(report["new_connections"][0]["local_port"], 40002)
        
        # Verify security events delta
        self.assertEqual(len(report["triggered_alerts"]), 1)
        self.assertEqual(report["triggered_alerts"][0]["type"], "mid_event")
        self.assertEqual(report["triggered_alerts"][0]["description"], "between snapshot 1 and 2")

if __name__ == "__main__":
    unittest.main()
