# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
import unittest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import os
import subprocess

from orin.collectors.privilege_audit import (
    gather_privilege_escalation_events,
    gather_syscall_audit_logs,
    gather_pam_auth_events,
    extract_timestamp_from_log_line,
    gather_credential_access_events,
    gather_all_privilege_events
)

class TestPrivilegeAudit(unittest.TestCase):

    @patch("subprocess.run")
    @patch("orin.collectors.privilege_audit.Path")
    def test_gather_privilege_escalation_events(self, mock_path_cls, mock_run):
        # 1. bpftool success
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '[{"name": "test_setuid_probe", "id": 1, "type": "kprobe"}]'
        mock_run.return_value = mock_proc

        # Mock tracefs check to return true and file with kprobe
        mock_tracefs = MagicMock()
        mock_tracefs.exists.return_value = True
        mock_kprobe_events = MagicMock()
        mock_kprobe_events.exists.return_value = True
        
        # When path is instantiated:
        # First call is Path("/sys/kernel/debug/tracing")
        mock_path_cls.side_effect = lambda *args: mock_tracefs if args[0] == "/sys/kernel/debug/tracing" else mock_kprobe_events

        with patch("builtins.open", mock_open(read_data="p:kprobes/my_probe setuid\n")):
            events = gather_privilege_escalation_events()

        self.assertTrue(any(e["event_type"] == "ebpf_probe_detected" for e in events))
        self.assertTrue(any(e["event_type"] == "kprobe_active" for e in events))

        # 2. bpftool fails, tracefs permission error
        mock_proc.returncode = 1
        mock_run.side_effect = subprocess.TimeoutExpired(["bpftool"], 5)
        
        with patch("builtins.open", side_effect=PermissionError):
            events = gather_privilege_escalation_events()
        self.assertEqual(len(events), 0)

    @patch("orin.collectors.privilege_audit.Path")
    def test_gather_syscall_audit_logs(self, mock_path_cls):
        mock_audit = MagicMock()
        mock_audit.exists.return_value = True
        mock_path_cls.return_value = mock_audit

        audit_lines = (
            'type=SYSCALL msg=audit(1672531199.000:123): arch=c000003e syscall=105 success=yes exit=0 '
            'a0=0 a1=0 a2=0 a3=0 items=0 ppid=100 pid=1234 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 '
            'egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm="sudo" exe="/usr/bin/sudo" subj=unconfined_u\n'
            'type=OTHER_RECORD msg=blah\n'
        )

        # Success path
        with patch("builtins.open", mock_open(read_data=audit_lines)):
            events = gather_syscall_audit_logs()
        
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["syscall"], "setuid")
        self.assertEqual(events[0]["uid"], 0)
        self.assertEqual(events[0]["audit_uid"], 1000)
        self.assertEqual(events[0]["pid"], 1234)
        self.assertEqual(events[0]["command"], "sudo")
        self.assertEqual(events[0]["executable"], "/usr/bin/sudo")
        self.assertEqual(events[0]["success"], "yes")

        # Missing file path
        mock_audit.exists.return_value = False
        events = gather_syscall_audit_logs()
        self.assertEqual(len(events), 0)

        # Exception read error
        mock_audit.exists.return_value = True
        with patch("builtins.open", side_effect=PermissionError("Denied")):
            events = gather_syscall_audit_logs()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "audit_read_error")

    def test_extract_timestamp_from_log_line(self):
        # Syslog format
        line = "Jun 11 14:30:15 hostname sshd[1234]: Accepted publickey"
        ts = extract_timestamp_from_log_line(line)
        self.assertIsNotNone(ts)
        self.assertTrue(ts.endswith("Z"))

        # ISO format
        line = "2026-06-11T14:30:15.123456Z hostname sshd[1234]: Accepted"
        ts = extract_timestamp_from_log_line(line)
        self.assertEqual(ts, "2026-06-11T14:30:15")

        # Unknown
        self.assertIsNone(extract_timestamp_from_log_line("hello world"))

    def test_gather_pam_auth_events(self):
        mock_log = MagicMock()
        mock_log.exists.return_value = True
        mock_log.__str__.return_value = "/dummy/auth.log"

        log_lines = (
            "Jun 11 14:00:00 host pam_unix(sshd:session): session opened for user musa by (uid=0)\n"
            "Jun 11 14:05:00 host pam_unix(sshd:session): session closed for user musa\n"
            "Jun 11 14:10:00 host pam_unix(sudo:auth): authentication failure; logname= uid=1000 user=musa\n"
            "Jun 11 14:15:00 host sudo:   musa : TTY=pts/1 ; PWD=/home/musa ; USER=root ; COMMAND=/bin/sh\n"
            "Jun 11 14:20:00 host sshd[100]: Accepted publickey for musa from 1.2.3.4 port 12345 ssh2\n"
            "Jun 11 14:25:00 host sshd[100]: Failed password for invalid user admin from 4.3.2.1 port 54321 ssh2\n"
            "Jun 11 14:30:00 host su[200]: Successful su for root by musa\n"
            "Jun 11 14:35:00 host su[200]: pam_unix(su:session): session opened for user admin by musa(uid=1000)\n"
        )

        with patch("builtins.open", mock_open(read_data=log_lines)):
            events = gather_pam_auth_events([mock_log])

        event_types = [e["event_type"] for e in events]
        self.assertIn("pam_session_opened", event_types)
        self.assertIn("pam_session_closed", event_types)
        self.assertIn("pam_auth_failure", event_types)
        self.assertIn("sudo_execution", event_types)
        self.assertIn("ssh_login_success", event_types)
        self.assertIn("ssh_login_failed", event_types)
        self.assertIn("su_execution", event_types)

        # Test read exception
        with patch("builtins.open", side_effect=OSError("Read error")):
            events = gather_pam_auth_events([mock_log])
        self.assertEqual(events[0]["event_type"], "log_read_error")

    @patch("subprocess.run")
    @patch("orin.collectors.privilege_audit.Path")
    @patch("os.readlink")
    def test_gather_credential_access_events(self, mock_readlink, mock_path_cls, mock_run):
        # Setup mocks
        mock_etc_shadow = MagicMock()
        mock_etc_shadow.exists.return_value = True
        
        # subprocess.run for lsof +D /etc, lsof ssh socket, and find command
        mock_lsof_etc = MagicMock()
        mock_lsof_etc.returncode = 0
        mock_lsof_etc.stdout = "sudo 1234 root 3r REG 8,1 1234 9999 /etc/shadow\n"
        
        mock_lsof_ssh = MagicMock()
        mock_lsof_ssh.returncode = 0
        mock_lsof_ssh.stdout = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nssh-agent 5678 musa 4u unix 0x123 9999 8888 /tmp/ssh-123/agent.123\n"
        
        mock_find = MagicMock()
        mock_find.returncode = 0
        mock_find.stdout = "/usr/bin/secretsdump\n"
        
        mock_run.side_effect = [mock_lsof_etc, mock_lsof_ssh, mock_find]

        # Path glob mocks
        mock_tmp = MagicMock()
        mock_tmp.exists.return_value = True
        mock_ssh_agent_path = MagicMock()
        mock_ssh_agent_path.exists.return_value = True
        mock_ssh_agent_path.__str__.return_value = "/tmp/ssh-123/agent.123"

        mock_krb5_ticket_path = MagicMock()
        mock_krb5_ticket_path.exists.return_value = True
        mock_krb5_ticket_path.stat.return_value.st_uid = 1000
        mock_krb5_ticket_path.__str__.return_value = "/tmp/krb5cc_1000"

        mock_tmp.glob.side_effect = [
            [mock_ssh_agent_path], # ssh-*/agent.*
            [mock_krb5_ticket_path] # krb5cc_*
        ]
        
        # Proc filesystem mock
        mock_proc = MagicMock()
        mock_proc.exists.return_value = True
        mock_pid_dir = MagicMock()
        mock_pid_dir.is_dir.return_value = True
        mock_pid_dir.name = "9999"
        
        mock_fd_dir = MagicMock()
        mock_fd_dir.exists.return_value = True
        mock_fd_file = MagicMock()
        mock_fd_file.exists.return_value = True
        mock_fd_dir.iterdir.return_value = [mock_fd_file]
        
        mock_cmdline_path = MagicMock()
        mock_cmdline_path.exists.return_value = True

        def div_side_effect(x):
            if x == "fd":
                return mock_fd_dir
            elif x == "cmdline":
                return mock_cmdline_path
            return MagicMock()
        mock_pid_dir.__truediv__.side_effect = div_side_effect
        
        mock_proc.iterdir.return_value = [mock_pid_dir]
        mock_pid_dir.iterdir.return_value = [mock_pid_dir]
        
        # File path resolution side_effect
        def path_side_effect(*args):
            p_str = args[0]
            if p_str == "/tmp":
                return mock_tmp
            elif p_str == "/proc":
                return mock_proc
            else:
                m = MagicMock()
                m.exists.return_value = True
                return m

        mock_path_cls.side_effect = path_side_effect

        mock_readlink.return_value = "/proc/9999/mem"
        
        with patch("builtins.open", mock_open(read_data=b"my_command_dump\x00")):
            events = gather_credential_access_events()
            
        event_types = [e["event_type"] for e in events]
        self.assertIn("credential_file_access", event_types)
        self.assertIn("ssh_agent_access", event_types)
        self.assertIn("kerberos_ticket_present", event_types)
        self.assertIn("process_memory_access", event_types)
        self.assertIn("suspicious_binary_detected", event_types)

    @patch("orin.collectors.privilege_audit.gather_privilege_escalation_events", return_value=[])
    @patch("orin.collectors.privilege_audit.gather_syscall_audit_logs", return_value=[])
    @patch("orin.collectors.privilege_audit.gather_pam_auth_events", return_value=[])
    @patch("orin.collectors.privilege_audit.gather_credential_access_events", return_value=[])
    def test_gather_all_privilege_events(self, mock_cred, mock_pam, mock_syscall, mock_priv):
        res = gather_all_privilege_events()
        self.assertIn("collection_timestamp", res)
        self.assertIn("privilege_escalation_events", res)
        self.assertIn("summary", res)

if __name__ == "__main__":
    unittest.main()