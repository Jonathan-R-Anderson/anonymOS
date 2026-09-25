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
from unittest.mock import patch, MagicMock
from pathlib import Path
import hashlib
from io import BytesIO
from orin.collectors.deleted_binaries import gather_deleted_binaries

class TestDeletedBinaries(unittest.TestCase):
    @patch("orin.collectors.deleted_binaries.load_config")
    @patch("orin.collectors.deleted_binaries.Path")
    def test_gather_deleted_binaries_vault_dir_none(self, mock_path, mock_load_config):
        mock_load_config.return_value = {"vault_path": "/configured/vault"}
        
        mock_path_instance = MagicMock()
        mock_path.return_value = mock_path_instance
        mock_path_instance.exists.return_value = False
        
        res = gather_deleted_binaries(vault_dir=None)
        
        self.assertEqual(res, [])
        mock_load_config.assert_called_once()
        mock_path.assert_any_call("/configured/vault")
        mock_path.assert_any_call("/proc")

    @patch("orin.collectors.deleted_binaries.Path")
    def test_proc_path_does_not_exist(self, mock_path):
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance
        
        res = gather_deleted_binaries(vault_dir="/fake/vault")
        self.assertEqual(res, [])

    @patch("orin.collectors.deleted_binaries.Path")
    @patch("orin.collectors.deleted_binaries.os.readlink")
    def test_gather_deleted_binaries_readlink_error(self, mock_readlink, mock_path):
        proc_path = MagicMock()
        proc_path.exists.return_value = True
        
        pid_dir = MagicMock()
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        non_pid_dir = MagicMock()
        non_pid_dir.is_dir.return_value = True
        non_pid_dir.name = "not_a_pid"
        
        file_dir = MagicMock()
        file_dir.is_dir.return_value = False
        file_dir.name = "5678"
        
        proc_path.iterdir.return_value = [pid_dir, non_pid_dir, file_dir]
        
        def path_side_effect(arg, *args, **kwargs):
            if arg == "/proc":
                return proc_path
            return MagicMock()
            
        mock_path.side_effect = path_side_effect
        mock_readlink.side_effect = PermissionError("Permission Denied")
        
        res = gather_deleted_binaries(vault_dir="/fake/vault")
        self.assertEqual(res, [])

    @patch("orin.collectors.deleted_binaries.Path")
    @patch("orin.collectors.deleted_binaries.os.readlink")
    def test_gather_deleted_binaries_not_deleted(self, mock_readlink, mock_path):
        proc_path = MagicMock()
        proc_path.exists.return_value = True
        
        pid_dir = MagicMock()
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        proc_path.iterdir.return_value = [pid_dir]
        
        def path_side_effect(arg, *args, **kwargs):
            if arg == "/proc":
                return proc_path
            return MagicMock()
            
        mock_path.side_effect = path_side_effect
        mock_readlink.return_value = "/usr/bin/python3"
        
        res = gather_deleted_binaries(vault_dir="/fake/vault")
        self.assertEqual(res, [])

    @patch("orin.collectors.deleted_binaries.Path")
    @patch("orin.collectors.deleted_binaries.os.readlink")
    @patch("orin.collectors.deleted_binaries.open", create=True)
    def test_gather_deleted_binaries_success_dest_not_exists(self, mock_builtin_open, mock_readlink, mock_path):
        proc_path = MagicMock()
        proc_path.exists.return_value = True
        
        pid_dir = MagicMock()
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        proc_path.iterdir.return_value = [pid_dir]
        
        vault_dir = MagicMock()
        
        exe_link = MagicMock()
        pid_dir.__truediv__.return_value = exe_link
        
        # We need exe_link.open("rb") to return a handle whose read returns data
        src_f = MagicMock()
        src_f.read.side_effect = [b"malware_code", b""]
        exe_link.open.return_value.__enter__.return_value = src_f
        
        def path_side_effect(*args):
            arg = args[0]
            if arg == "/proc":
                return proc_path
            elif arg == "/fake/vault":
                return vault_dir
            return MagicMock()
            
        mock_path.side_effect = path_side_effect
        mock_readlink.return_value = "/usr/bin/malware (deleted)"
        
        vault_dir.mkdir = MagicMock()
        temp_dest = MagicMock()
        dest_file = MagicMock()
        dest_file.exists.return_value = False
        dest_file.resolve.return_value = "/fake/vault/hash_val"
        
        vault_dir.__truediv__.side_effect = lambda filename: temp_dest if "recovery_" in str(filename) else dest_file
        
        # mock open(temp_dest, "wb")
        dest_f = MagicMock()
        mock_builtin_open.return_value.__enter__.return_value = dest_f
        
        res = gather_deleted_binaries(vault_dir="/fake/vault")
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["pid"], 1234)
        self.assertEqual(res[0]["vault_path"], "/fake/vault/hash_val")
        temp_dest.rename.assert_called_once_with(dest_file)

    @patch("orin.collectors.deleted_binaries.Path")
    @patch("orin.collectors.deleted_binaries.os.readlink")
    @patch("orin.collectors.deleted_binaries.open", create=True)
    def test_gather_deleted_binaries_success_dest_exists(self, mock_builtin_open, mock_readlink, mock_path):
        proc_path = MagicMock()
        proc_path.exists.return_value = True
        
        pid_dir = MagicMock()
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        proc_path.iterdir.return_value = [pid_dir]
        
        vault_dir = MagicMock()
        
        exe_link = MagicMock()
        pid_dir.__truediv__.return_value = exe_link
        
        src_f = MagicMock()
        src_f.read.side_effect = [b"malware_code", b""]
        exe_link.open.return_value.__enter__.return_value = src_f
        
        def path_side_effect(*args):
            arg = args[0]
            if arg == "/proc":
                return proc_path
            elif arg == "/fake/vault":
                return vault_dir
            return MagicMock()
            
        mock_path.side_effect = path_side_effect
        mock_readlink.return_value = "/usr/bin/malware (deleted)"
        
        vault_dir.mkdir = MagicMock()
        temp_dest = MagicMock()
        dest_file = MagicMock()
        dest_file.exists.return_value = True
        dest_file.resolve.return_value = "/fake/vault/hash_val"
        
        vault_dir.__truediv__.side_effect = lambda filename: temp_dest if "recovery_" in str(filename) else dest_file
        
        dest_f = MagicMock()
        mock_builtin_open.return_value.__enter__.return_value = dest_f
        
        res = gather_deleted_binaries(vault_dir="/fake/vault")
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["pid"], 1234)
        self.assertEqual(res[0]["vault_path"], "/fake/vault/hash_val")
        temp_dest.unlink.assert_called_once_with(missing_ok=True)

    @patch("orin.collectors.deleted_binaries.Path")
    @patch("orin.collectors.deleted_binaries.os.readlink")
    @patch("orin.collectors.deleted_binaries.open", create=True)
    def test_gather_deleted_binaries_storage_fallback_success(self, mock_builtin_open, mock_readlink, mock_path):
        proc_path = MagicMock()
        proc_path.exists.return_value = True
        
        pid_dir = MagicMock()
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        proc_path.iterdir.return_value = [pid_dir]
        
        vault_dir = MagicMock()
        vault_dir.mkdir.side_effect = PermissionError("No write access")
        
        exe_link = MagicMock()
        pid_dir.__truediv__.return_value = exe_link
        
        src_f = MagicMock()
        src_f.read.side_effect = [b"fallback_code", b""]
        exe_link.open.return_value.__enter__.return_value = src_f
        
        def path_side_effect(*args):
            arg = args[0]
            if arg == "/proc":
                return proc_path
            elif arg == "/fake/vault":
                return vault_dir
            return MagicMock()
            
        mock_path.side_effect = path_side_effect
        mock_readlink.return_value = "/usr/bin/malware (deleted)"
        
        res = gather_deleted_binaries(vault_dir="/fake/vault")
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["pid"], 1234)
        self.assertTrue(res[0]["vault_path"].startswith("failed_to_write_vault: No write access"))
        self.assertEqual(res[0]["md5"], hashlib.md5(b"fallback_code", usedforsecurity=False).hexdigest())

    @patch("orin.collectors.deleted_binaries.Path")
    @patch("orin.collectors.deleted_binaries.os.readlink")
    @patch("orin.collectors.deleted_binaries.open", create=True)
    def test_gather_deleted_binaries_storage_fallback_failure(self, mock_builtin_open, mock_readlink, mock_path):
        proc_path = MagicMock()
        proc_path.exists.return_value = True
        
        pid_dir = MagicMock()
        pid_dir.is_dir.return_value = True
        pid_dir.name = "1234"
        
        proc_path.iterdir.return_value = [pid_dir]
        
        vault_dir = MagicMock()
        vault_dir.mkdir.side_effect = OSError("Read-only filesystem")
        
        exe_link = MagicMock()
        pid_dir.__truediv__.return_value = exe_link
        exe_link.open.side_effect = PermissionError("Cannot open exe link")
        
        def path_side_effect(*args):
            arg = args[0]
            if arg == "/proc":
                return proc_path
            elif arg == "/fake/vault":
                return vault_dir
            return MagicMock()
            
        mock_path.side_effect = path_side_effect
        mock_readlink.return_value = "/usr/bin/malware (deleted)"
        
        res = gather_deleted_binaries(vault_dir="/fake/vault")
        
        self.assertEqual(res, [])

if __name__ == "__main__":
    unittest.main()
