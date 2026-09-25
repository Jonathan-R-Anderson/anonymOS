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
import sqlite3
from pathlib import Path
from orin.collectors.integrity import gather_file_integrity_signatures

class TestIntegrity(unittest.TestCase):
    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_symlink")
    @patch("os.open")
    @patch("os.fstat")
    @patch("os.close")
    @patch("builtins.open", new_callable=mock_open, read_data=b"hello world")
    def test_gather_file_integrity_signatures_cache_hit(
        self, mock_file_open, mock_os_close, mock_os_fstat, mock_os_open, mock_is_symlink, mock_exists, mock_load_config
    ):
        # Set up config
        mock_load_config.return_value = {
            "critical_paths": ["/etc/passwd"]
        }
        mock_exists.return_value = True
        mock_is_symlink.return_value = False
        mock_os_open.return_value = 100
        
        # Mock fstat
        mock_stat = MagicMock()
        mock_stat.st_mtime = 12345.6
        mock_stat.st_ctime = 78910.1
        mock_stat.st_size = 11
        mock_os_fstat.return_value = mock_stat
        
        # Mock database connection cache hit
        mock_conn = MagicMock()
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("fake_sha256", "12345.6", "78910.1", "11")
        
        res = gather_file_integrity_signatures(db_conn=mock_conn)
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["file_path"], "/etc/passwd")
        self.assertEqual(res[0]["sha256_hash"], "fake_sha256")
        self.assertEqual(res[0]["size"], 11)
        mock_file_open.assert_not_called()
        mock_os_close.assert_called_once_with(100)

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_symlink")
    @patch("os.open")
    @patch("os.fstat")
    @patch("os.close")
    @patch("builtins.open", new_callable=mock_open, read_data=b"hello world")
    def test_gather_file_integrity_signatures_cache_miss(
        self, mock_file_open, mock_os_close, mock_os_fstat, mock_os_open, mock_is_symlink, mock_exists, mock_load_config
    ):
        mock_load_config.return_value = {
            "critical_paths": ["/etc/passwd"]
        }
        mock_exists.return_value = True
        mock_is_symlink.return_value = False
        mock_os_open.return_value = 100
        
        mock_stat = MagicMock()
        mock_stat.st_mtime = 12345.6
        mock_stat.st_ctime = 78910.1
        mock_stat.st_size = 11
        mock_os_fstat.return_value = mock_stat
        
        # Mock database connection cache miss (different size)
        mock_conn = MagicMock()
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.fetchone.return_value = ("old_sha256", "12345.6", "78910.1", "999")
        
        res = gather_file_integrity_signatures(db_conn=mock_conn)
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["file_path"], "/etc/passwd")
        # SHA256 of "hello world"
        self.assertEqual(res[0]["sha256_hash"], "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        mock_os_close.assert_called_once_with(100)

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    def test_missing_file(self, mock_exists, mock_load_config):
        mock_load_config.return_value = {
            "critical_paths": ["/etc/missing"]
        }
        mock_exists.return_value = False
        res = gather_file_integrity_signatures()
        self.assertEqual(len(res), 0)

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_symlink")
    def test_symlink_file(self, mock_is_symlink, mock_exists, mock_load_config):
        mock_load_config.return_value = {
            "critical_paths": ["/etc/symlink"]
        }
        mock_exists.return_value = True
        mock_is_symlink.return_value = True
        res = gather_file_integrity_signatures()
        self.assertEqual(len(res), 0)

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_symlink")
    @patch("os.open")
    @patch("os.fstat")
    @patch("os.close")
    @patch("builtins.open")
    def test_gather_file_integrity_signatures_read_error(
        self, mock_file_open, mock_os_close, mock_os_fstat, mock_os_open, mock_is_symlink, mock_exists, mock_load_config
    ):
        mock_load_config.return_value = {
            "critical_paths": ["/etc/passwd"]
        }
        mock_exists.return_value = True
        mock_is_symlink.return_value = False
        mock_os_open.return_value = 100
        
        mock_stat = MagicMock()
        mock_stat.st_mtime = 12345.6
        mock_stat.st_ctime = 78910.1
        mock_stat.st_size = 11
        mock_os_fstat.return_value = mock_stat
        
        # Raise error when reading
        mock_file_open.side_effect = PermissionError("Permission denied reading file contents")
        
        res = gather_file_integrity_signatures()
        self.assertEqual(len(res), 1)
        self.assertIn("ERROR: Content extraction failure", res[0]["sha256_hash"])

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_symlink")
    @patch("os.open")
    @patch("os.fstat")
    @patch("os.close")
    @patch("builtins.open", new_callable=mock_open, read_data=b"hello world")
    def test_gather_file_integrity_signatures_close_error(
        self, mock_file_open, mock_os_close, mock_os_fstat, mock_os_open, mock_is_symlink, mock_exists, mock_load_config
    ):
        mock_load_config.return_value = {
            "critical_paths": ["/etc/passwd"]
        }
        mock_exists.return_value = True
        mock_is_symlink.return_value = False
        mock_os_open.return_value = 100
        
        mock_stat = MagicMock()
        mock_stat.st_mtime = 12345.6
        mock_stat.st_ctime = 78910.1
        mock_stat.st_size = 11
        mock_os_fstat.return_value = mock_stat
        
        mock_os_close.side_effect = OSError(errno.EBADF, "Bad file descriptor")
        
        res = gather_file_integrity_signatures()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["sha256_hash"], "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_symlink")
    @patch("os.open")
    @patch("os.fstat")
    @patch("os.close")
    def test_sqlite_error_fallback(
        self, mock_os_close, mock_os_fstat, mock_os_open, mock_is_symlink, mock_exists, mock_load_config
    ):
        mock_load_config.return_value = {
            "critical_paths": ["/etc/passwd"]
        }
        mock_exists.return_value = True
        mock_is_symlink.return_value = False
        mock_os_open.return_value = 100
        
        mock_stat = MagicMock()
        mock_stat.st_mtime = 12345.6
        mock_stat.st_ctime = 78910.1
        mock_stat.st_size = 11
        mock_os_fstat.return_value = mock_stat
        
        # Mock database connection cursor executing a query and raising sqlite3.Error
        mock_conn = MagicMock()
        mock_cursor = mock_conn.cursor.return_value
        mock_cursor.execute.side_effect = sqlite3.Error("Table not found")
        
        # Open mock
        with patch("builtins.open", mock_open(read_data=b"hello")):
            res = gather_file_integrity_signatures(db_conn=mock_conn)
            
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["sha256_hash"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_symlink")
    @patch("os.open")
    def test_gather_file_integrity_signatures_os_errors(
        self, mock_os_open, mock_is_symlink, mock_exists, mock_load_config
    ):
        mock_load_config.return_value = {
            "critical_paths": ["/etc/passwd1", "/etc/passwd2", "/etc/passwd3"]
        }
        mock_exists.return_value = True
        mock_is_symlink.return_value = False
        
        def os_open_side_effect(path, flags):
            if "passwd1" in path:
                raise OSError(errno.ELOOP, "Symlink loop")
            elif "passwd2" in path:
                raise OSError(errno.EACCES, "Permission denied")
            else:
                raise OSError(errno.ENOENT, "No such file")

        mock_os_open.side_effect = os_open_side_effect
        
        res = gather_file_integrity_signatures()
        self.assertEqual(len(res), 3)
        self.assertIn("Symlink exploit signature detected", res[0]["sha256_hash"])
        self.assertIn("Permission denied accessing target", res[1]["sha256_hash"])
        self.assertIn("OS file descriptor allocation fault", res[2]["sha256_hash"])

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    @patch("pathlib.Path.rglob")
    @patch("orin.collectors.integrity._hash_file_opportunistically")
    def test_directory_traversal(self, mock_hash_file, mock_rglob, mock_is_dir, mock_exists, mock_load_config):
        mock_load_config.return_value = {
            "critical_dirs": ["/etc/critical"]
        }
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        
        file1 = MagicMock(spec=Path)
        file1.is_file.return_value = True
        file1.is_symlink.return_value = False
        
        mock_rglob.return_value = [file1]
        
        res = gather_file_integrity_signatures()
        mock_hash_file.assert_called_once()

    @patch("orin.collectors.integrity.load_config")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    @patch("pathlib.Path.rglob")
    def test_directory_traversal_failure(self, mock_rglob, mock_is_dir, mock_exists, mock_load_config):
        mock_load_config.return_value = {
            "critical_dirs": ["/etc/critical"]
        }
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        mock_rglob.side_effect = PermissionError("Access denied")
        
        res = gather_file_integrity_signatures()
        self.assertEqual(len(res), 1)
        self.assertIn("ERROR: Directory traversal failure", res[0]["sha256_hash"])

if __name__ == "__main__":
    unittest.main()
