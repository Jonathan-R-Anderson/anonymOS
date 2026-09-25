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
import pwd
from orin.collectors.persistence import gather_active_ssh_keys

class TestPersistence(unittest.TestCase):
    @patch("pwd.getpwall")
    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_active_ssh_keys_success(self, mock_file_open, mock_exists, mock_getpwall):
        # Setup getpwall
        mock_user1 = MagicMock()
        mock_user1.pw_name = "alice"
        mock_user1.pw_dir = "/home/alice"
        
        mock_user2 = MagicMock()
        mock_user2.pw_name = "bob"
        mock_user2.pw_dir = "/home/bob"
        
        # User without home directory
        mock_user3 = MagicMock()
        mock_user3.pw_name = "nobody"
        mock_user3.pw_dir = ""
        
        mock_getpwall.return_value = [mock_user1, mock_user2, mock_user3]
        
        # /home/alice/.ssh/authorized_keys exists
        # /home/bob/.ssh/authorized_keys exists
        mock_exists.return_value = True
        
        # Mock file content reads
        mock_file_open.side_effect = [
            mock_open(read_data="ssh-rsa AAAAB3NzaC1yc2E... alice@local\n# Comment line\n\n").return_value,
            mock_open(read_data="command=\"uptime\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... bob@local\n").return_value,
        ]
        
        res = gather_active_ssh_keys()
        
        self.assertEqual(len(res), 2)
        
        alice_res = next(r for r in res if r["user_account"] == "alice")
        self.assertEqual(alice_res["key_type"], "ssh-rsa")
        self.assertEqual(alice_res["raw_key_comment"], "alice@local")
        
        bob_res = next(r for r in res if r["user_account"] == "bob")
        self.assertEqual(bob_res["key_type"], "ssh-ed25519")
        self.assertEqual(bob_res["raw_key_comment"], "bob@local")

    @patch("pwd.getpwall")
    def test_gather_active_ssh_keys_passwd_error(self, mock_getpwall):
        mock_getpwall.side_effect = OSError("Passwd database error")
        res = gather_active_ssh_keys()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["user_account"], "root")
        self.assertEqual(res[0]["key_type"], "ERROR")
        self.assertEqual(res[0]["fingerprint"], "SYSTEM_PASSWD_READ_FAULT")

    @patch("pwd.getpwall")
    @patch("pathlib.Path.exists")
    @patch("builtins.open")
    def test_gather_active_ssh_keys_file_read_error(self, mock_file_open, mock_exists, mock_getpwall):
        mock_user = MagicMock()
        mock_user.pw_name = "alice"
        mock_user.pw_dir = "/home/alice"
        mock_getpwall.return_value = [mock_user]
        mock_exists.return_value = True
        mock_file_open.side_effect = PermissionError("Permission denied")
        
        res = gather_active_ssh_keys()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["user_account"], "alice")
        self.assertEqual(res[0]["key_type"], "ERROR")
        self.assertEqual(res[0]["fingerprint"], "ACCESS_DENIED_INVENTORY_FAULT")

    @patch("pwd.getpwall")
    @patch("builtins.open", new_callable=mock_open)
    def test_gather_active_ssh_keys_malformed_and_edge_cases(self, mock_file_open, mock_getpwall):
        # We want to test:
        # User 1: authorized_keys does not exist (covers line 64)
        # User 2: authorized_keys exists but has:
        #   - Line 1: Less than 2 parts (ignored)
        #   - Line 2: Options but less than 3 parts (ignored, covers line 94)
        #   - Line 3: Options with comment
        mock_user1 = MagicMock()
        mock_user1.pw_name = "alice"
        mock_user1.pw_dir = "/home/alice"
        
        mock_user2 = MagicMock()
        mock_user2.pw_name = "bob"
        mock_user2.pw_dir = "/home/bob"
        
        mock_getpwall.return_value = [mock_user1, mock_user2]
        
        # Patch Path.exists with a bound-like function
        def exists_fake(self_path):
            return "bob" in str(self_path)
            
        file_content = (
            "short_line\n"
            "command=\"/usr/bin/uptime\" ssh-rsa\n"
            "command=\"/usr/bin/uptime\" ssh-rsa AAAAB3... comment_here\n"
        )
        mock_file_open.side_effect = [mock_open(read_data=file_content).return_value]
        
        with patch("pathlib.Path.exists", new=exists_fake):
            res = gather_active_ssh_keys()
            
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["user_account"], "bob")
        self.assertEqual(res[0]["key_type"], "ssh-rsa")
        self.assertEqual(res[0]["raw_key_comment"], "comment_here")

    @patch("pwd.getpwall")
    @patch("pathlib.Path.exists")
    @patch("builtins.open", new_callable=mock_open)
    @patch("hashlib.sha256")
    def test_gather_active_ssh_keys_hash_error(self, mock_sha256, mock_file_open, mock_exists, mock_getpwall):
        mock_user = MagicMock()
        mock_user.pw_name = "alice"
        mock_user.pw_dir = "/home/alice"
        mock_getpwall.return_value = [mock_user]
        mock_exists.return_value = True
        mock_file_open.return_value = mock_open(read_data="ssh-rsa AAAAB3... comment\n").return_value
        
        mock_sha256.side_effect = Exception("Hashing failed")
        
        res = gather_active_ssh_keys()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["key_type"], "ERROR")
        self.assertEqual(res[0]["fingerprint"], "HASH_FAULT_LINE_1")

if __name__ == "__main__":
    unittest.main()
