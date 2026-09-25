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
import stat
from pathlib import Path
from orin.collectors.suid import gather_suid_binaries

class TestSUID(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    @patch("pathlib.Path.rglob")
    @patch("pwd.getpwuid")
    @patch("grp.getgrgid")
    @patch("builtins.open", new_callable=mock_open, read_data=b"binary_payload")
    def test_gather_suid_binaries_success(self, mock_file_open, mock_getgrgid, mock_getpwuid, mock_rglob, mock_is_dir, mock_exists):
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        # Mock two files: one SUID and one normal binary
        mock_entry_suid = MagicMock(spec=Path)
        mock_entry_suid.is_symlink.return_value = False
        mock_entry_suid.is_file.return_value = True
        mock_entry_suid.resolve.return_value = Path("/bin/su")
        
        # SUID bit set (stat.S_ISUID is 0o4000)
        st_suid = MagicMock()
        st_suid.st_mode = stat.S_IFREG | stat.S_ISUID | 0o755
        st_suid.st_uid = 0
        st_suid.st_gid = 0
        mock_entry_suid.stat.return_value = st_suid

        mock_entry_normal = MagicMock(spec=Path)
        mock_entry_normal.is_symlink.return_value = False
        mock_entry_normal.is_file.return_value = True
        mock_entry_normal.resolve.return_value = Path("/bin/ls")
        
        # Normal permissions (no SUID/SGID)
        st_normal = MagicMock()
        st_normal.st_mode = stat.S_IFREG | 0o755
        st_normal.st_uid = 1000
        st_normal.st_gid = 1000
        mock_entry_normal.stat.return_value = st_normal

        mock_rglob.return_value = [mock_entry_suid, mock_entry_normal]

        # Mock user/group names
        mock_getpwuid.return_value.pw_name = "root"
        mock_getgrgid.return_value.gr_name = "root"

        records = gather_suid_binaries(["/bin"])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["file_path"], "/bin/su")
        self.assertEqual(records[0]["owner"], "root")
        self.assertEqual(records[0]["grp"], "root")
        self.assertEqual(records[0]["permissions"], "0o4755")
        # SHA256 of b"binary_payload" is '601750dc6a1f0346acb6c487d277470b91a4c2decb2dc93b207e707b9a23ad71'
        self.assertEqual(records[0]["sha256"], "601750dc6a1f0346acb6c487d277470b91a4c2decb2dc93b207e707b9a23ad71")

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    @patch("pathlib.Path.rglob")
    @patch("pwd.getpwuid")
    @patch("grp.getgrgid")
    def test_gather_sgid_and_key_errors(self, mock_getgrgid, mock_getpwuid, mock_rglob, mock_is_dir, mock_exists):
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        mock_entry_sgid = MagicMock(spec=Path)
        mock_entry_sgid.is_symlink.return_value = False
        mock_entry_sgid.is_file.return_value = True
        mock_entry_sgid.resolve.return_value = Path("/usr/bin/wall")
        
        # SGID bit set (stat.S_ISGID is 0o2000)
        st_sgid = MagicMock()
        st_sgid.st_mode = stat.S_IFREG | stat.S_ISGID | 0o755
        st_sgid.st_uid = 1001
        st_sgid.st_gid = 1002
        mock_entry_sgid.stat.return_value = st_sgid

        mock_rglob.return_value = [mock_entry_sgid]

        # pwd/grp raise KeyError
        mock_getpwuid.side_effect = KeyError()
        mock_getgrgid.side_effect = KeyError()

        with patch("builtins.open", side_effect=PermissionError()):
            records = gather_suid_binaries(["/usr/bin"])

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["file_path"], "/usr/bin/wall")
        self.assertEqual(records[0]["owner"], "1001")
        self.assertEqual(records[0]["grp"], "1002")
        self.assertEqual(records[0]["permissions"], "0o2755")
        self.assertEqual(records[0]["sha256"], "unknown")

if __name__ == "__main__":
    unittest.main()
