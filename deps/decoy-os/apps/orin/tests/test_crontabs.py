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
from orin.collectors.crontabs import parse_cron_line, gather_crontabs

class TestCrontabs(unittest.TestCase):
    def test_parse_cron_line_no_user_field(self):
        # 1. Standard line with default user
        res = parse_cron_line("*/5 * * * * /usr/bin/check_health", default_user="bob", has_user_field=False)
        self.assertIsNotNone(res)
        self.assertEqual(res["user"], "bob")
        self.assertEqual(res["schedule"], "*/5 * * * *")
        self.assertEqual(res["command"], "/usr/bin/check_health")

        # 2. Comment line
        self.assertIsNone(parse_cron_line("# This is a comment", default_user="bob", has_user_field=False))
        self.assertIsNone(parse_cron_line("   # Comment with spaces", default_user="bob", has_user_field=False))

        # 3. Empty line
        self.assertIsNone(parse_cron_line("", default_user="bob", has_user_field=False))
        self.assertIsNone(parse_cron_line("    ", default_user="bob", has_user_field=False))

        # 4. Environment variables
        self.assertIsNone(parse_cron_line("SHELL=/bin/bash", default_user="bob", has_user_field=False))
        self.assertIsNone(parse_cron_line("MAILTO=\"\"", default_user="bob", has_user_field=False))

        # 5. Special schedule @reboot without user field
        res = parse_cron_line("@reboot /usr/local/bin/start.sh", default_user="alice", has_user_field=False)
        self.assertIsNotNone(res)
        self.assertEqual(res["user"], "alice")
        self.assertEqual(res["schedule"], "@reboot")
        self.assertEqual(res["command"], "/usr/local/bin/start.sh")

        # 6. Invalid lines
        self.assertIsNone(parse_cron_line("invalid cron pattern", default_user="bob", has_user_field=False))

    def test_parse_cron_line_with_user_field(self):
        # 1. Standard line with user field
        res = parse_cron_line("*/5 * * * * root /usr/bin/check_health", default_user="nobody", has_user_field=True)
        self.assertIsNotNone(res)
        self.assertEqual(res["user"], "root")
        self.assertEqual(res["schedule"], "*/5 * * * *")
        self.assertEqual(res["command"], "/usr/bin/check_health")

        # 2. Special schedule @reboot with user field
        res = parse_cron_line("@reboot devops /usr/local/bin/start.sh", default_user="nobody", has_user_field=True)
        self.assertIsNotNone(res)
        self.assertEqual(res["user"], "devops")
        self.assertEqual(res["schedule"], "@reboot")
        self.assertEqual(res["command"], "/usr/local/bin/start.sh")

        # 3. Special schedule @reboot with user field but missing command
        res = parse_cron_line("@reboot devops", default_user="nobody", has_user_field=True)
        self.assertIsNotNone(res)
        self.assertEqual(res["user"], "devops")
        self.assertEqual(res["schedule"], "@reboot")
        self.assertEqual(res["command"], "")

    @patch("pathlib.Path.exists", autospec=True)
    @patch("pathlib.Path.iterdir", autospec=True)
    @patch("pathlib.Path.is_file", autospec=True)
    @patch("pathlib.Path.read_text", autospec=True)
    def test_gather_crontabs(self, mock_read_text, mock_is_file, mock_iterdir, mock_exists):
        # We need mock_exists to return True for directories we care about:
        # /var/spool/cron/crontabs, /etc/crontab, /etc/cron.d, and timed dirs
        def exists_side_effect(path_obj):
            path_str = str(path_obj)
            return path_str in [
                "/var/spool/cron/crontabs",
                "/etc/crontab",
                "/etc/cron.d",
                "/etc/cron.hourly",
                "/etc/cron.daily",
                "/etc/cron.weekly",
                "/etc/cron.monthly",
            ]
        mock_exists.side_effect = exists_side_effect

        # Mock iterdir for directories
        def iterdir_side_effect(path_obj):
            path_str = str(path_obj)
            if path_str == "/var/spool/cron/crontabs":
                return [Path("/var/spool/cron/crontabs/alice"), Path("/var/spool/cron/crontabs/bob")]
            elif path_str == "/etc/cron.d":
                return [Path("/etc/cron.d/anacron"), Path("/etc/cron.d/placeholder.bak"), Path("/etc/cron.d/.hidden")]
            elif path_str == "/etc/cron.hourly":
                return [Path("/etc/cron.hourly/0anacron")]
            elif path_str == "/etc/cron.daily":
                return [Path("/etc/cron.daily/logrotate")]
            return []
        mock_iterdir.side_effect = iterdir_side_effect

        # Mock is_file
        def is_file_side_effect(path_obj):
            path_str = str(path_obj)
            return "crontabs/" in path_str or "cron.d/" in path_str or "cron.hourly/" in path_str or "cron.daily/" in path_str or path_str == "/etc/crontab"
        mock_is_file.side_effect = is_file_side_effect

        # Mock read_text
        def read_text_side_effect(path_obj, *args, **kwargs):
            path_str = str(path_obj)
            if path_str == "/var/spool/cron/crontabs/alice":
                return "0 5 * * * /home/alice/backup.sh\n# comment\n"
            elif path_str == "/var/spool/cron/crontabs/bob":
                return "* * * * * /home/bob/miner.sh\n"
            elif path_str == "/etc/crontab":
                return (
                    "SHELL=/bin/sh\n"
                    "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
                )
            elif path_str == "/etc/cron.d/anacron":
                return "30 7 * * * root /usr/sbin/anacron -s\n"
            return ""
        mock_read_text.side_effect = read_text_side_effect

        results = gather_crontabs()
        
        # We expect:
        # alice: 1 item
        # bob: 1 item
        # /etc/crontab: 1 item
        # /etc/cron.d/anacron: 1 item
        # /etc/cron.hourly/0anacron: 1 item
        # /etc/cron.daily/logrotate: 1 item
        self.assertEqual(len(results), 6)

        # Check alice
        alice_entry = next(r for r in results if r["user"] == "alice")
        self.assertEqual(alice_entry["source"], "/var/spool/cron/crontabs/alice")
        self.assertEqual(alice_entry["schedule"], "0 5 * * *")
        self.assertEqual(alice_entry["command"], "/home/alice/backup.sh")

        # Check bob
        bob_entry = next(r for r in results if r["user"] == "bob")
        self.assertEqual(bob_entry["source"], "/var/spool/cron/crontabs/bob")
        self.assertEqual(bob_entry["schedule"], "* * * * *")
        self.assertEqual(bob_entry["command"], "/home/bob/miner.sh")

        # Check /etc/crontab
        sys_entry = next(r for r in results if r["source"] == "/etc/crontab")
        self.assertEqual(sys_entry["user"], "root")
        self.assertEqual(sys_entry["schedule"], "17 * * * *")
        self.assertEqual(sys_entry["command"], "cd / && run-parts --report /etc/cron.hourly")

        # Check /etc/cron.d/anacron
        anacron_entry = next(r for r in results if r["source"] == "/etc/cron.d/anacron")
        self.assertEqual(anacron_entry["user"], "root")
        self.assertEqual(anacron_entry["schedule"], "30 7 * * *")
        self.assertEqual(anacron_entry["command"], "/usr/sbin/anacron -s")

        # Check hourly script
        hourly_entry = next(r for r in results if r["source"] == "/etc/cron.hourly/0anacron")
        self.assertEqual(hourly_entry["user"], "root")
        self.assertEqual(hourly_entry["schedule"], "@hourly")
        self.assertEqual(hourly_entry["command"], "/etc/cron.hourly/0anacron")

        # Check daily script
        daily_entry = next(r for r in results if r["source"] == "/etc/cron.daily/logrotate")
        self.assertEqual(daily_entry["user"], "root")
        self.assertEqual(daily_entry["schedule"], "@daily")
        self.assertEqual(daily_entry["command"], "/etc/cron.daily/logrotate")

if __name__ == "__main__":
    unittest.main()
