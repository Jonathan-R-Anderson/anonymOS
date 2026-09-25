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
import struct
import io
from pathlib import Path
from unittest.mock import patch, MagicMock
from orin.collectors.session_audit import gather_wtmp_sessions, gather_lastlog_records

class TestSessionAudit(unittest.TestCase):
    @patch("pathlib.Path.exists")
    def test_gather_wtmp_sessions(self, mock_exists):
        mock_exists.return_value = True
        
        # Format: <h2xi32s4s32s256shhiii4I20s
        login_record = struct.pack(
            "<h2xi32s4s32s256shhiii4I20s",
            7, 5555, b"pts/1", b"1", b"alice", b"192.168.1.10",
            0, 0, 0, 1600000000, 0, 0, 0, 0, 0, b""
        )
        logout_record = struct.pack(
            "<h2xi32s4s32s256shhiii4I20s",
            8, 5555, b"pts/1", b"1", b"", b"",
            0, 0, 0, 1600003600, 0, 0, 0, 0, 0, b""
        )
        
        fake_data = login_record + logout_record
        
        with patch("builtins.open", return_value=io.BytesIO(fake_data)):
            sessions = gather_wtmp_sessions(Path("/var/log/wtmp"))
            
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["user"], "alice")
        self.assertEqual(sessions[0]["line"], "pts/1")
        self.assertEqual(sessions[0]["host"], "192.168.1.10")
        self.assertEqual(sessions[0]["pid"], 5555)
        self.assertEqual(sessions[0]["login_time"], "2020-09-13T12:26:40Z")
        self.assertEqual(sessions[0]["logout_time"], "2020-09-13T13:26:40Z")
        self.assertEqual(sessions[0]["anomaly_detected"], 0)

    @patch("pathlib.Path.exists")
    def test_gather_wtmp_tampered_records(self, mock_exists):
        mock_exists.return_value = True
        zero_record = b"\x00" * 384
        
        with patch("builtins.open", return_value=io.BytesIO(zero_record)):
            sessions = gather_wtmp_sessions(Path("/var/log/wtmp"))
            
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["anomaly_detected"], 1)
        self.assertEqual(sessions[0]["anomaly_reason"], "Zeroed-out wtmp record detected (potential log tampering)")

    @patch("pathlib.Path.exists")
    @patch("orin.collectors.session_audit.gather_system_accounts")
    @patch("pathlib.Path.stat")
    def test_gather_lastlog_records(self, mock_stat, mock_gather_accounts, mock_exists):
        mock_exists.return_value = True
        mock_gather_accounts.return_value = [{"username": "alice", "uid": 1000}]
        
        mock_stat_res = MagicMock()
        mock_stat_res.st_size = 292000 + 292
        mock_stat.return_value = mock_stat_res
        
        # Lastlog record format: <I32s256s
        lastlog_record = struct.pack(
            "<I32s256s",
            1600000000, b"pts/1", b"192.168.1.10"
        )
        
        fake_data = b'\x00' * 292000 + lastlog_record
        
        with patch("builtins.open", return_value=io.BytesIO(fake_data)):
            records = gather_lastlog_records(Path("/var/log/lastlog"))
            
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["username"], "alice")
        self.assertEqual(records[0]["line"], "pts/1")
        self.assertEqual(records[0]["host"], "192.168.1.10")
        self.assertEqual(records[0]["login_time"], "2020-09-13T12:26:40Z")
        self.assertEqual(records[0]["anomaly_detected"], 0)

if __name__ == "__main__":
    unittest.main()

# ---------------------------------------------------------------------------
# Extended tests to achieve complete path coverage
# ---------------------------------------------------------------------------
import os
import tempfile


# WTMP format
_UTMP_FORMAT = "<h2xi32s4s32s256shhiii4I20s"
_RECORD_SIZE = struct.calcsize(_UTMP_FORMAT)

UT_USER = 7
UT_DEAD = 8
UT_BOOT = 2


def _make_rec(ut_type=UT_USER, pid=1, line=b"pts/0", uid=b"",
              user=b"user", host=b"host", tv_sec=1700000000, tv_usec=0):
    return struct.pack(
        _UTMP_FORMAT,
        ut_type, pid,
        line.ljust(32, b"\x00")[:32],
        uid.ljust(4, b"\x00")[:4],
        user.ljust(32, b"\x00")[:32],
        host.ljust(256, b"\x00")[:256],
        0, 0, 0, tv_sec, tv_usec,
        0, 0, 0, 0,
        b"\x00" * 20,
    )


def _write_tmp(data):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".wtmp")
    tmp.write(data)
    tmp.close()
    return Path(tmp.name)


class TestSessionAuditExtended(unittest.TestCase):

    def test_short_record_triggers_anomaly(self):
        # Write less than a full record
        path = _write_tmp(b"\x00" * 10)
        try:
            sessions = gather_wtmp_sessions(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["anomaly_detected"], 1)
        self.assertIn("Corrupted", sessions[0]["anomaly_reason"])

    def test_orphaned_logout(self):
        # DEAD_PROCESS with no prior USER_PROCESS
        rec = _make_rec(ut_type=UT_DEAD, pid=9999, line=b"pts/7",
                        user=b"ghost", tv_sec=1700000100)
        path = _write_tmp(rec)
        try:
            sessions = gather_wtmp_sessions(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(sessions), 1)
        self.assertIsNone(sessions[0]["login_time"])
        self.assertIn("Orphaned", sessions[0]["anomaly_reason"])

    def test_reboot_terminates_active_sessions(self):
        login = _make_rec(ut_type=UT_USER, pid=11, line=b"pts/0",
                          user=b"carol", tv_sec=1700000000)
        reboot = _make_rec(ut_type=UT_BOOT, pid=0, line=b"~",
                           user=b"reboot", tv_sec=1700001000)
        path = _write_tmp(login + reboot)
        try:
            sessions = gather_wtmp_sessions(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(sessions), 1)
        self.assertIn("reboot", sessions[0]["logout_time"])

    def test_login_remains_active_at_eof(self):
        login = _make_rec(ut_type=UT_USER, pid=22, line=b"pts/1",
                          user=b"dave", tv_sec=1700000000)
        path = _write_tmp(login)
        try:
            sessions = gather_wtmp_sessions(path)
        finally:
            os.unlink(path)
        self.assertEqual(sessions[0]["logout_time"], "active")

    def test_zero_tv_sec_on_user_process_flagged(self):
        rec = _make_rec(ut_type=UT_USER, pid=33, user=b"eve", tv_sec=0)
        path = _write_tmp(rec)
        try:
            sessions = gather_wtmp_sessions(path)
        finally:
            os.unlink(path)
        # Should still create a session entry (active), with anomaly
        self.assertTrue(any(s["anomaly_detected"] == 1 for s in sessions))

    def test_multiple_logins_matched(self):
        r1 = _make_rec(ut_type=UT_USER, pid=101, line=b"pts/0",
                       user=b"user1", tv_sec=1700000000)
        r2 = _make_rec(ut_type=UT_USER, pid=102, line=b"pts/1",
                       user=b"user2", tv_sec=1700000010)
        d1 = _make_rec(ut_type=UT_DEAD, pid=101, line=b"pts/0",
                       tv_sec=1700000100)
        d2 = _make_rec(ut_type=UT_DEAD, pid=102, line=b"pts/1",
                       tv_sec=1700000110)
        path = _write_tmp(r1 + r2 + d1 + d2)
        try:
            sessions = gather_wtmp_sessions(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(sessions), 2)
        users = {s["user"] for s in sessions}
        self.assertIn("user1", users)
        self.assertIn("user2", users)

    def test_empty_file_returns_empty(self):
        path = _write_tmp(b"")
        try:
            sessions = gather_wtmp_sessions(path)
        finally:
            os.unlink(path)
        self.assertEqual(sessions, [])


class TestLastlogExtended(unittest.TestCase):
    _LASTLOG_FORMAT = "<I32s256s"
    _LASTLOG_SIZE = struct.calcsize(_LASTLOG_FORMAT)

    def _make_ll(self, ll_time, line=b"", host=b""):
        return struct.pack(
            self._LASTLOG_FORMAT,
            ll_time,
            line.ljust(32, b"\x00")[:32],
            host.ljust(256, b"\x00")[:256],
        )

    def test_zeroed_time_with_non_empty_host_triggers_tamper(self):
        mock_accounts = [{"username": "hacker", "uid": 0, "gid": 0,
                          "home": "/home/hacker", "shell": "/bin/bash"}]
        rec = self._make_ll(ll_time=0, line=b"pts/1", host=b"attacker.com")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".lastlog") as f:
            f.write(rec)
            path = Path(f.name)
        try:
            with patch("orin.collectors.session_audit.gather_system_accounts",
                       return_value=mock_accounts):
                records = gather_lastlog_records(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["anomaly_detected"], 1)
        self.assertIn("tamper", records[0]["anomaly_reason"].lower())

    def test_zeroed_time_with_empty_metadata_skipped(self):
        mock_accounts = [{"username": "nobody", "uid": 0, "gid": 0,
                          "home": "/", "shell": "/bin/false"}]
        rec = self._make_ll(ll_time=0, line=b"", host=b"")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".lastlog") as f:
            f.write(rec)
            path = Path(f.name)
        try:
            with patch("orin.collectors.session_audit.gather_system_accounts",
                       return_value=mock_accounts):
                records = gather_lastlog_records(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(records), 0)

    def test_uid_beyond_file_size_skipped(self):
        # File only has 1 record (uid=0), so uid=500 would be beyond file size
        mock_accounts = [
            {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
            {"username": "user", "uid": 500, "gid": 500, "home": "/home/user", "shell": "/bin/bash"},
        ]
        rec = self._make_ll(ll_time=1700000000, line=b"tty1", host=b"localhost")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".lastlog") as f:
            f.write(rec)  # Only uid=0
            path = Path(f.name)
        try:
            with patch("orin.collectors.session_audit.gather_system_accounts",
                       return_value=mock_accounts):
                records = gather_lastlog_records(path)
        finally:
            os.unlink(path)
        # Only uid=0 should be processed
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["username"], "root")

    def test_no_accounts_returns_empty(self):
        rec = self._make_ll(ll_time=1700000000)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".lastlog") as f:
            f.write(rec)
            path = Path(f.name)
        try:
            with patch("orin.collectors.session_audit.gather_system_accounts",
                       return_value=[]):
                records = gather_lastlog_records(path)
        finally:
            os.unlink(path)
        self.assertEqual(records, [])

