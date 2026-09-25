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
from unittest.mock import patch, mock_open
import errno
from pathlib import Path
from orin.collectors.users import gather_system_accounts

class TestUsers(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_system_accounts_success(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        
        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "# Comment line\n"
            "\n"
            "alice:x:1000:1000:Alice:/home/alice:/bin/zsh\n"
        )
        mock_file_open.return_value = mock_open(read_data=passwd_content).return_value
        
        res = gather_system_accounts()
        self.assertEqual(len(res), 2)
        
        root_res = res[0]
        self.assertEqual(root_res["username"], "root")
        self.assertEqual(root_res["uid"], 0)
        self.assertEqual(root_res["gid"], 0)
        self.assertEqual(root_res["home_dir"], "/root")
        self.assertEqual(root_res["login_shell"], "/bin/bash")
        
        alice_res = res[1]
        self.assertEqual(alice_res["username"], "alice")
        self.assertEqual(alice_res["uid"], 1000)
        self.assertEqual(alice_res["gid"], 1000)
        self.assertEqual(alice_res["home_dir"], "/home/alice")
        self.assertEqual(alice_res["login_shell"], "/bin/zsh")

    @patch("pathlib.Path.exists")
    def test_gather_system_accounts_no_file(self, mock_exists):
        mock_exists.return_value = False
        res = gather_system_accounts()
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_system_accounts_malformed_and_errors(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        
        # Line 1: Malformed (less than 7 fields)
        # Line 2: Invalid UID cast (ValueError)
        passwd_content = (
            "malformed_user:x:0\n"
            "bad_uid:x:invalid_uid:1000::/home/bad_uid:/bin/bash\n"
        )
        mock_file_open.return_value = mock_open(read_data=passwd_content).return_value
        
        res = gather_system_accounts()
        self.assertEqual(len(res), 2)
        
        self.assertEqual(res[0]["username"], "ERROR_MALFORMED_ROW_1")
        self.assertEqual(res[0]["anomaly_detected"], 1)
        self.assertIn("Malformed passwd entry layout", res[0]["anomaly_reason"])
        
        self.assertEqual(res[1]["username"], "ERROR_INVALID_UID_bad_uid")
        self.assertEqual(res[1]["anomaly_detected"], 1)
        self.assertIn("integer type validation fault", res[1]["anomaly_reason"])

    @patch("pathlib.Path.exists")
    @patch("builtins.open")
    def test_gather_system_accounts_permission_denied(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        mock_file_open.side_effect = PermissionError("Permission denied")
        
        res = gather_system_accounts()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["username"], "ERROR_PASSWD_IO_FAULT")
        self.assertEqual(res[0]["anomaly_detected"], 1)
        self.assertIn("Critical identity harvesting failure", res[0]["anomaly_reason"])

if __name__ == "__main__":
    unittest.main()
