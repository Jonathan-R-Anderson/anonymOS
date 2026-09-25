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
import errno
from pathlib import Path
from orin.collectors.processes import gather_active_processes

class TestProcesses(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("os.readlink")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_active_processes_success(self, mock_file_open, mock_readlink, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        
        # Mock PID directories
        pid_dir = MagicMock(spec=Path)
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        non_pid_dir = MagicMock(spec=Path)
        non_pid_dir.is_dir.return_value = True
        non_pid_dir.name = "not_a_pid"
        
        mock_iterdir.return_value = [pid_dir, non_pid_dir]
        
        # Mock files for pid_dir
        # /proc/1234/stat
        # /proc/1234/comm
        # /proc/1234/cmdline
        mock_readlink.return_value = "/usr/bin/my_proc"
        
        # Set up file reads using side_effect
        stat_content = "1234 (my (cool) proc) S 5678 1234 5678"
        comm_content = "my (cool) proc"
        cmdline_content = "my_proc\x00arg1\x00arg2\x00"
        
        mock_file_open.side_effect = [
            mock_open(read_data=stat_content).return_value,
            mock_open(read_data=comm_content).return_value,
            mock_open(read_data=cmdline_content).return_value,
        ]
        
        res = gather_active_processes()
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["pid"], 1234)
        self.assertEqual(res[0]["ppid"], 5678)
        self.assertEqual(res[0]["name"], "my (cool) proc")
        self.assertEqual(res[0]["exe"], "/usr/bin/my_proc")
        self.assertEqual(res[0]["cmdline"], "my_proc arg1 arg2")

    @patch("pathlib.Path.exists")
    def test_gather_active_processes_no_proc(self, mock_exists):
        mock_exists.return_value = False
        res = gather_active_processes()
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("builtins.open")
    def test_gather_active_processes_race_condition_stat(self, mock_file_open, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        pid_dir = MagicMock(spec=Path)
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        mock_iterdir.return_value = [pid_dir]
        
        # Process exits before stat is read
        mock_file_open.side_effect = OSError(errno.ENOENT, "No such file or directory")
        
        res = gather_active_processes()
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("builtins.open")
    def test_gather_active_processes_permission_denied_stat(self, mock_file_open, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        pid_dir = MagicMock(spec=Path)
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        mock_iterdir.return_value = [pid_dir]
        
        # Permission denied on stat
        mock_file_open.side_effect = OSError(errno.EACCES, "Permission denied")
        
        res = gather_active_processes()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["name"], "Permission Denied")
        self.assertEqual(res[0]["ppid"], -1)

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("builtins.open")
    def test_gather_active_processes_other_error_stat(self, mock_file_open, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        pid_dir = MagicMock(spec=Path)
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        mock_iterdir.return_value = [pid_dir]
        
        # Other OS error on stat
        mock_file_open.side_effect = OSError(errno.EIO, "Input/output error")
        
        res = gather_active_processes()
        self.assertEqual(len(res), 1)
        self.assertIn("ERROR: OS read fault", res[0]["name"])

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("os.readlink")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_active_processes_kernel_thread_and_errors(self, mock_file_open, mock_readlink, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        pid_dir = MagicMock(spec=Path)
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        mock_iterdir.return_value = [pid_dir]
        
        # 1. stat: has no closing parenthesis (malformed)
        # 2. comm: OS EACCES
        # 3. exe: OS readlink raises EACCES
        # 4. cmdline: OS readlink raises EACCES
        mock_file_open.side_effect = [
            mock_open(read_data="1234 malformed_stat").return_value,
            OSError(errno.EACCES, "Permission denied"),
            OSError(errno.EACCES, "Permission denied"),
        ]
        
        def readlink_side_effect(path):
            raise OSError(errno.EACCES, "Permission denied")
        mock_readlink.side_effect = readlink_side_effect
        
        res = gather_active_processes()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["name"], "ERROR: Malformed stat descriptor layout")
        self.assertEqual(res[0]["exe"], "Permission Denied")
        self.assertEqual(res[0]["cmdline"], "Permission Denied")

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("os.readlink")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_active_processes_other_failures(self, mock_file_open, mock_readlink, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        pid_dir = MagicMock(spec=Path)
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        mock_iterdir.return_value = [pid_dir]
        
        # 1. stat: OK
        # 2. comm: OK
        # 3. exe: readlink raises EIO (other error)
        # 4. cmdline: open raises EIO (other error)
        mock_file_open.side_effect = [
            mock_open(read_data="1234 (proc) S 5678").return_value,
            mock_open(read_data="proc").return_value,
            OSError(errno.EIO, "I/O error"),
        ]
        
        def readlink_side_effect(path):
            raise OSError(errno.EIO, "I/O error")
        mock_readlink.side_effect = readlink_side_effect
        
        res = gather_active_processes()
        self.assertEqual(len(res), 1)
        self.assertIn("ERROR: Resolution fault", res[0]["exe"])
        self.assertIn("ERROR: Stream fault", res[0]["cmdline"])

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("os.readlink")
    @patch("builtins.open")
    def test_gather_active_processes_comm_enoent_and_other_errors(self, mock_file_open, mock_readlink, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        mock_readlink.return_value = "unknown"
        
        # User 1: ENOENT in comm
        pid_dir1 = MagicMock(spec=Path)
        pid_dir1.is_dir.return_value = True
        pid_dir1.name = "1234"
        
        # User 2: Other error in comm
        pid_dir2 = MagicMock(spec=Path)
        pid_dir2.is_dir.return_value = True
        pid_dir2.name = "5678"
        
        mock_iterdir.return_value = [pid_dir1, pid_dir2]
        
        # For pid_dir1: stat returns OK, comm raises ENOENT
        # For pid_dir2: stat returns OK, comm raises EIO, cmdline returns OK
        mock_file_open.side_effect = [
            mock_open(read_data="1234 (proc1) S 99").return_value,
            OSError(errno.ENOENT, "No such file"),
            mock_open(read_data="5678 (proc2) S 99").return_value,
            OSError(errno.EIO, "I/O error"),
            mock_open(read_data="proc2_cmdline").return_value,
        ]
        
        res = gather_active_processes()
        # pid_dir1 returns nothing because it continued/skipped
        # pid_dir2 should be returned with ERROR in name
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["pid"], 5678)
        self.assertIn("ERROR: Comm link block", res[0]["name"])

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    @patch("os.readlink")
    @patch("builtins.open")
    def test_gather_active_processes_cmdline_enoent_and_fallback(self, mock_file_open, mock_readlink, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        mock_readlink.return_value = "unknown"
        
        # User 1: cmdline is empty (fallback to name)
        pid_dir1 = MagicMock(spec=Path)
        pid_dir1.is_dir.return_value = True
        pid_dir1.name = "1234"
        
        # User 2: cmdline raises ENOENT
        pid_dir2 = MagicMock(spec=Path)
        pid_dir2.is_dir.return_value = True
        pid_dir2.name = "5678"
        
        mock_iterdir.return_value = [pid_dir1, pid_dir2]
        
        # For pid_dir1: stat, comm, cmdline empty
        # For pid_dir2: stat, comm, cmdline raises ENOENT
        mock_file_open.side_effect = [
            mock_open(read_data="1234 (proc1) S 99").return_value,
            mock_open(read_data="proc1").return_value,
            mock_open(read_data="").return_value,
            mock_open(read_data="5678 (proc2) S 99").return_value,
            mock_open(read_data="proc2").return_value,
            OSError(errno.ENOENT, "No such file"),
        ]
        
        res = gather_active_processes()
        # pid_dir1 returns with cmdline = name ("proc1")
        # pid_dir2 returns nothing because it continued
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["pid"], 1234)
        self.assertEqual(res[0]["cmdline"], "proc1")

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.iterdir")
    def test_gather_active_processes_outer_catch_all(self, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        pid_dir = MagicMock(spec=Path)
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        mock_iterdir.return_value = [pid_dir]
        
        # Accessing `pid_dir / "stat"` raises generic exception
        pid_dir.__truediv__.side_effect = Exception("Generic division exception")
        
        res = gather_active_processes()
        self.assertEqual(res, [])

if __name__ == "__main__":
    unittest.main()
