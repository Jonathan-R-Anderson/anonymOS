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
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import json

from orin.collectors.ebpf import (
    gather_ebpf_programs,
    gather_ebpf_pinned,
    gather_ld_preload,
    gather_special_fds
)
from orin.core.database import OrinStorage
from orin.analysis.engine import run_analysis_cycle

class TestEBPFAuditor(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_ebpf_unit.db")
        for suffix in ["", "-wal", "-shm"]:
            p = self.db_path.with_name(self.db_path.name + suffix)
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

    def tearDown(self):
        if hasattr(self, 'storage'):
            self.storage.cleanup_db()

    @patch("orin.collectors.ebpf.subprocess.run")
    def test_gather_ebpf_programs_success(self, mock_run):
        # Mock successful execution of bpftool prog show -j
        mock_output = json.dumps([
            {"id": 1, "name": "my_prog", "type": "kprobe", "tag": "abc", "gpl_compatible": True},
            {"id": 2, "name": "evil_ebpfkit", "type": "tracepoint", "tag": "def", "gpl_compatible": False}
        ])
        mock_run.return_value = MagicMock(returncode=0, stdout=mock_output)
        
        programs = gather_ebpf_programs()
        self.assertEqual(len(programs), 2)
        self.assertEqual(programs[0]["bpf_id"], 1)
        self.assertEqual(programs[0]["gpl_compatible"], 1)
        self.assertEqual(programs[1]["name"], "evil_ebpfkit")
        self.assertEqual(programs[1]["gpl_compatible"], 0)

    @patch("orin.collectors.ebpf.subprocess.run")
    def test_gather_ebpf_programs_failure(self, mock_run):
        # Mock non-zero return code
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        programs = gather_ebpf_programs()
        self.assertEqual(programs, [])

        # Mock exception
        mock_run.side_effect = Exception("bpftool error")
        programs = gather_ebpf_programs()
        self.assertEqual(programs, [])

    @patch("orin.collectors.ebpf.BPF_FS_PATH")
    def test_gather_ebpf_pinned(self, mock_bpf_fs_path):
        mock_bpf_fs_path.exists.return_value = True
        mock_bpf_fs_path.is_dir.return_value = True
        
        file1 = MagicMock()
        file1.is_file.return_value = True
        file1.is_symlink.return_value = False
        file1.resolve.return_value = "/sys/fs/bpf/my_map"
        
        file2 = MagicMock()
        file2.is_file.return_value = False
        file2.is_symlink.return_value = False

        file3 = MagicMock()
        file3.is_file.return_value = True
        file3.is_symlink.return_value = False
        file3.resolve.side_effect = PermissionError("Denied")

        mock_bpf_fs_path.rglob.return_value = [file1, file2, file3]
        
        pinned = gather_ebpf_pinned()
        self.assertEqual(len(pinned), 1)
        self.assertEqual(pinned[0]["path"], "/sys/fs/bpf/my_map")
        self.assertEqual(pinned[0]["type"], "pinned_object")

    @patch("orin.collectors.ebpf.PRELOAD_PATH")
    def test_gather_ld_preload(self, mock_preload_path):
        mock_preload_path.exists.return_value = True
        
        preload_data = "  \n/usr/local/lib/libevil.so\n# comment line\n  /lib/x86_64-linux-gnu/libsafe.so  \n"
        with patch("orin.collectors.ebpf.open", mock_open(read_data=preload_data), create=True):
            lines = gather_ld_preload()
            
        self.assertEqual(lines, ["/usr/local/lib/libevil.so", "/lib/x86_64-linux-gnu/libsafe.so"])

    @patch("orin.collectors.ebpf.PROC_PATH")
    @patch("orin.collectors.ebpf.os.readlink")
    def test_gather_special_fds(self, mock_readlink, mock_proc_path):
        mock_proc_path.exists.return_value = True
        mock_proc_path.is_dir.return_value = True
        
        # Mock pid directories
        pid1 = MagicMock()
        pid1.is_dir.return_value = True
        pid1.name = "100"
        
        not_pid = MagicMock()
        not_pid.is_dir.return_value = True
        not_pid.name = "self"
        
        not_dir = MagicMock()
        not_dir.is_dir.return_value = False
        not_dir.name = "200"
        
        mock_proc_path.iterdir.return_value = [pid1, not_pid, not_dir]
        
        # Mock fd dir of pid1
        fd_dir = MagicMock()
        fd_dir.exists.return_value = True
        fd_dir.is_dir.return_value = True
        
        fd0 = MagicMock()
        fd0.name = "0"
        fd0.__str__.return_value = "fd/0"
        fd1 = MagicMock()
        fd1.name = "1"
        fd1.__str__.return_value = "fd/1"
        fd2 = MagicMock()
        fd2.name = "2"
        fd2.__str__.return_value = "fd/2"
        fd3 = MagicMock()
        fd3.name = "3"
        fd3.__str__.return_value = "fd/3"
        fd4 = MagicMock()
        fd4.name = "4"
        fd4.__str__.return_value = "fd/4"
        
        fd_dir.iterdir.return_value = [fd0, fd1, fd2, fd3, fd4]
        pid1.__truediv__.return_value = fd_dir
        
        def readlink_side_effect(path_str):
            if "fd/0" in path_str:
                return "/dev/shm/memfd:evil_payload (deleted)"
            elif "fd/1" in path_str:
                return "socket:[4321]"
            elif "fd/2" in path_str:
                return "/tmp/deleted_binary (deleted)"
            elif "fd/3" in path_str:
                return "/etc/passwd"
            elif "fd/4" in path_str:
                raise PermissionError("Access denied")
            return "/etc/passwd"
                
        mock_readlink.side_effect = readlink_side_effect
        
        fds = gather_special_fds()
        self.assertEqual(len(fds), 3)
        
        self.assertEqual(fds[0]["pid"], 100)
        self.assertEqual(fds[0]["fd_num"], 0)
        self.assertEqual(fds[0]["fd_type"], "memfd")
        
        self.assertEqual(fds[1]["fd_num"], 1)
        self.assertEqual(fds[1]["fd_type"], "socket")
        
        self.assertEqual(fds[2]["fd_num"], 2)
        self.assertEqual(fds[2]["fd_type"], "deleted")

    @patch("orin.analysis.engine.load_config")
    def test_database_store_and_threat_assessment(self, mock_load_config):
        mock_load_config.return_value = {
            "expected_ports": [22],
            "whitelisted_processes": ["chrome"],
            "critical_paths": [],
            "critical_dirs": []
        }
        
        with self.storage.get_connection() as conn:
            snap_id = self.storage.create_snapshot(conn, hostname="test_host", os_platform="Linux")
            
            self.storage.store_processes(conn, snap_id, [
                {"pid": 100, "ppid": 1, "name": "chrome", "exe": "/usr/bin/chrome", "cmdline": "chrome"},
                {"pid": 200, "ppid": 1, "name": "evil_payload", "exe": "/tmp/evil_payload", "cmdline": "evil_payload"},
                {"pid": 300, "ppid": 1, "name": "runner", "exe": "/bin/runner", "cmdline": "runner"}
            ])
            
            self.storage.store_ebpf_programs(conn, snap_id, [
                {"bpf_id": 10, "name": "clean_bpf", "type": "cgroup_skb", "tag": "tag1", "gpl_compatible": 1},
                {"bpf_id": 11, "name": "suspicious_rootkit", "type": "kprobe", "tag": "tag2", "gpl_compatible": 1},
                {"bpf_id": 12, "name": "non_gpl_prog", "type": "tracepoint", "tag": "tag3", "gpl_compatible": 0}
            ])
            
            self.storage.store_ebpf_pinned(conn, snap_id, [
                {"path": "/sys/fs/bpf/clean_map", "type": "pinned_object"},
                {"path": "/sys/fs/bpf/evil_ebpfkit_map", "type": "pinned_object"}
            ])
            
            self.storage.store_ld_preload(conn, snap_id, [
                "/usr/local/lib/libevil.so"
            ])
            
            self.storage.store_special_fds(conn, snap_id, [
                {"pid": 100, "fd_num": 5, "fd_type": "memfd", "resolved_path": "/dev/shm/memfd:chrome_seg"},
                {"pid": 200, "fd_num": 5, "fd_type": "memfd", "resolved_path": "/dev/shm/memfd:evil_seg"},
                {"pid": 300, "fd_num": 6, "fd_type": "deleted", "resolved_path": "/tmp/deleted_temp (deleted)"},
                {"pid": 300, "fd_num": 7, "fd_type": "deleted", "resolved_path": "/etc/shadow (deleted)"}
            ])
            
            conn.commit()
            
        with patch("orin.analysis.engine.detect_hidden_processes", return_value=[]):
            run_analysis_cycle(self.db_path)
            
        with self.storage.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type, severity, description FROM security_events ORDER BY id;")
            events = cursor.fetchall()
            
        event_types = [e["event_type"] for e in events]
        
        self.assertEqual(event_types.count("ebpf_rootkit"), 3)
        self.assertIn("ld_preload_hijack", event_types)
        self.assertIn("memfd_execution", event_types)
        self.assertIn("deleted_binary_execution", event_types)
        
        events_by_type = {e["event_type"]: e for e in events}
        self.assertEqual(events_by_type["ld_preload_hijack"]["severity"], "critical")
        self.assertEqual(events_by_type["memfd_execution"]["severity"], "high")
        self.assertEqual(events_by_type["deleted_binary_execution"]["severity"], "high")

if __name__ == "__main__":
    unittest.main()
