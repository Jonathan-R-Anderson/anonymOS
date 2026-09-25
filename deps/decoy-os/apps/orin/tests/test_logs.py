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
import sys
from io import StringIO
from orin.collectors.logs import parse_authentication_logs

class TestLogs(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_parse_authentication_logs_success(self, mock_file_open, mock_exists):
        mock_exists.return_value = True
        
        log_content = (
            "Jun  4 09:00:00 server sshd[123]: Failed password for root from 192.168.1.50 port 54321 ssh2\n"
            "Jun  4 09:01:00 server sshd[123]: Failed password for root from 192.168.1.50 port 54322 ssh2\n"
            "Jun  4 09:02:00 server sshd[123]: Failed password for alice from 10.0.0.5 port 54323 ssh2\n"
            "Jun  4 09:03:00 server useradd[456]: new user: name=bob, UID=1001, GID=1001\n"
            "Jun  4 09:04:00 server usermod[789]: add 'bob' to group 'sudo'\n"
            "Jun  4 09:05:00 server usermod[789]: add 'alice' to group 'root'\n"
            "Jun  4 09:06:00 server usermod[789]: add 'nobody' to group 'other'\n" # non-privileged group, ignored
            "Jun  4 09:07:00 server some_random_log_line\n"
        )
        mock_file_open.return_value = mock_open(read_data=log_content).return_value
        
        res = parse_authentication_logs()
        
        self.assertEqual(res["failed_ssh_counts"], {
            "192.168.1.50": 2,
            "10.0.0.5": 1
        })
        
        priv = res["privileged_additions"]
        self.assertEqual(len(priv), 3)
        
        self.assertEqual(priv[0]["type"], "new_user")
        self.assertIn("user=bob", priv[0]["details"])
        
        self.assertEqual(priv[1]["type"], "privileged_group_escalation")
        self.assertIn("user=bob group=sudo", priv[1]["details"])
        
        self.assertEqual(priv[2]["type"], "privileged_group_escalation")
        self.assertIn("user=alice group=root", priv[2]["details"])

    @patch("pathlib.Path.exists")
    def test_parse_authentication_logs_no_file(self, mock_exists):
        mock_exists.return_value = False
        res = parse_authentication_logs()
        self.assertEqual(res, {
            "failed_ssh_counts": {},
            "privileged_additions": []
        })

    @patch("pathlib.Path.exists")
    @patch("builtins.open")
    @patch("sys.stderr", new_callable=StringIO)
    def test_parse_authentication_logs_access_error(self, mock_stderr, mock_file_open, mock_exists):
        mock_exists.return_value = True
        mock_file_open.side_effect = PermissionError("Permission denied")
        
        res = parse_authentication_logs()
        
        self.assertEqual(res["failed_ssh_counts"], {})
        self.assertEqual(len(res["privileged_additions"]), 1)
        self.assertEqual(res["privileged_additions"][0]["type"], "auth_log_access_failure")
        self.assertIn("CRITICAL", res["privileged_additions"][0]["details"])
        self.assertIn("Access Failure", mock_stderr.getvalue())

if __name__ == "__main__":
    unittest.main()
