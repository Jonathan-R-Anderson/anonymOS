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
import errno
from unittest.mock import patch, MagicMock
from pathlib import Path
from orin.analysis.unhide import detect_hidden_processes, _get_system_pid_max

class TestUnhide(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.read_text")
    def test_get_system_pid_max_failures(self, mock_read_text, mock_exists):
        mock_exists.return_value = True
        
        # ValueError
        mock_read_text.return_value = "invalid_pid\n"
        self.assertEqual(_get_system_pid_max(), 32768)
        
        # OSError
        mock_read_text.side_effect = OSError("Read error")
        self.assertEqual(_get_system_pid_max(), 32768)

    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.iterdir")
    @patch("pathlib.Path.read_text")
    @patch("os.kill")
    def test_detect_hidden_processes(self, mock_kill, mock_read_text, mock_iterdir, mock_exists):
        # /proc exists, but the hidden PIDs (200, 250) do not exist in /proc
        # /proc/100/task exists and contains thread 101
        def exists_side_effect(self_path):
            p_str = str(self_path)
            if p_str == "/proc":
                return True
            if "200" in p_str or "250" in p_str:
                return False
            if "task" in p_str:
                return True
            return True
        mock_exists.side_effect = exists_side_effect
        
        # Mock visible PIDs
        visible_pid_dir = MagicMock(spec=Path)
        visible_pid_dir.is_dir.return_value = True
        visible_pid_dir.name = "100"
        
        # Set up task dir for TIDs
        task_dir = MagicMock(spec=Path)
        task_dir.exists.return_value = True
        thread_dir = MagicMock(spec=Path)
        
        # First access of t.name returns "101" (which isdigit() is True), second access raises OSError
        from unittest.mock import PropertyMock
        type(thread_dir).name = PropertyMock(side_effect=["101", OSError("Cannot read thread name")])
        
        task_dir.iterdir.return_value = [thread_dir]
        
        visible_pid_dir.__truediv__.return_value = task_dir
        
        mock_iterdir.return_value = [visible_pid_dir]
        
        # Mock pid_max to a small number
        mock_read_text.return_value = "300\n"
        
        # Mock os.kill
        # 200: Hidden process
        # 250: Hidden process but EPERM
        # 101: TID, should be skipped
        def kill_side_effect(pid, sig):
            if pid == 200:
                return
            elif pid == 250:
                raise OSError(errno.EPERM, "Operation not permitted")
            else:
                raise OSError(errno.ESRCH, "No such process")
                
        mock_kill.side_effect = kill_side_effect
        
        hidden = detect_hidden_processes()
        
        self.assertEqual(len(hidden), 2)
        pids = {h["pid"] for h in hidden}
        self.assertEqual(pids, {200, 250})

    @patch("pathlib.Path.exists")
    def test_detect_hidden_processes_no_proc(self, mock_exists):
        mock_exists.return_value = False
        hidden = detect_hidden_processes()
        self.assertEqual(hidden, [])

    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.iterdir")
    def test_detect_hidden_processes_no_visible_pids(self, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        mock_iterdir.return_value = []
        hidden = detect_hidden_processes()
        self.assertEqual(hidden, [])

    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.iterdir")
    @patch("pathlib.Path.read_text")
    @patch("os.kill")
    def test_detect_hidden_processes_adaptive_buffer(self, mock_kill, mock_read_text, mock_iterdir, mock_exists):
        mock_exists.return_value = True
        
        visible_pid_dir = MagicMock(spec=Path)
        visible_pid_dir.is_dir.return_value = True
        visible_pid_dir.name = "100"
        visible_pid_dir.__truediv__.return_value.exists.return_value = False
        
        mock_iterdir.return_value = [visible_pid_dir]
        
        # pid_max is very large (e.g. 200000)
        mock_read_text.return_value = "200000\n"
        
        mock_kill.side_effect = OSError(errno.ESRCH, "No such process")
        
        hidden = detect_hidden_processes()
        self.assertEqual(hidden, [])

    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.iterdir")
    @patch("pathlib.Path.read_text")
    @patch("os.kill")
    def test_detect_hidden_processes_transient_and_eperm_race(self, mock_kill, mock_read_text, mock_iterdir, mock_exists):
        def exists_side_effect(self_path):
            p_str = str(self_path)
            if p_str == "/proc":
                return True
            return False  # /proc/{pid} does not exist
        mock_exists.side_effect = exists_side_effect
        
        visible_pid_dir = MagicMock(spec=Path)
        visible_pid_dir.is_dir.return_value = True
        visible_pid_dir.name = "10"
        visible_pid_dir.__truediv__.return_value.exists.return_value = False
        mock_iterdir.return_value = [visible_pid_dir]
        
        mock_read_text.return_value = "50\n"
        
        # 15: Transient process (first kill succeeds, second kill throws ESRCH)
        # 20: EPERM race process (first kill throws EPERM, second kill throws ESRCH)
        kill_calls = {}
        def kill_side_effect(pid, sig):
            if pid == 15:
                count = kill_calls.get(pid, 0) + 1
                kill_calls[pid] = count
                if count == 1:
                    return
                else:
                    raise OSError(errno.ESRCH, "No such process")
            elif pid == 20:
                count = kill_calls.get(pid, 0) + 1
                kill_calls[pid] = count
                if count == 1:
                    raise OSError(errno.EPERM, "Operation not permitted")
                else:
                    raise OSError(errno.ESRCH, "No such process")
            else:
                raise OSError(errno.ESRCH, "No such process")
                
        mock_kill.side_effect = kill_side_effect
        
        hidden = detect_hidden_processes()
        # Neither 15 nor 20 should be returned because they died during verification
        self.assertEqual(hidden, [])

if __name__ == "__main__":
    unittest.main()
