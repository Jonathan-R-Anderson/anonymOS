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
"""
tests/test_notifier.py
======================
Comprehensive unit tests for the Alert Forwarding Framework
(orin.core.notifier).

Coverage targets
----------------
* Payload formatters: Slack Block Kit, Teams Adaptive Card, generic JSON
* Severity filtering (global + per-webhook override)
* Webhook dispatch: success, retry on failure, exhausted retries
* Syslog dispatch (mocked stdlib syslog module)
* Audit log: written on success, written on failure, directory creation
* Global enabled/disabled flag
* Multiple webhooks, per-hook enabled flag
* Empty alert list → no work done
* Build-from-config helper
* alerts_from_db_rows helper
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch, mock_open

from orin.core.notifier import (
    AlertForwarder,
    AlertNotification,
    alerts_from_db_rows,
    build_forwarder_from_config,
    format_generic_payload,
    format_slack_payload,
    format_teams_payload,
    _syslog_priority,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_alert(severity: str = "critical", event_type: str = "test_event") -> AlertNotification:
    return AlertNotification(
        severity=severity,
        event_type=event_type,
        description="Test alert description",
        hostname="testhost",
        snapshot_id=7,
        attck_technique="T1055",
        attck_tactic="privilege-escalation",
    )


def enabled_cfg(**overrides) -> dict:
    cfg = {
        "enabled": True,
        "min_severity": "high",
        "syslog": {"enabled": False, "tag": "orin-alert"},
        "webhooks": [],
        "retry": {"max_attempts": 1, "backoff_seconds": 0},
        "audit_log": "/tmp/orin_test_audit.log",
    }
    cfg.update(overrides)
    return cfg


def webhook_entry(url: str = "http://localhost:9999/hook", fmt: str = "generic", **overrides) -> dict:
    entry = {"name": "test-hook", "url": url, "format": fmt, "enabled": True, "timeout_seconds": 5}
    entry.update(overrides)
    return entry


# ---------------------------------------------------------------------------
# Payload formatter tests
# ---------------------------------------------------------------------------

class TestSlackPayload(unittest.TestCase):
    def setUp(self):
        self.alert = make_alert(severity="critical")
        self.payload = format_slack_payload(self.alert)

    def test_has_blocks_key(self):
        self.assertIn("blocks", self.payload)

    def test_header_block_contains_severity(self):
        header = self.payload["blocks"][0]
        self.assertEqual(header["type"], "header")
        self.assertIn("CRITICAL", header["text"]["text"])

    def test_fields_contain_hostname(self):
        section = self.payload["blocks"][1]
        all_text = " ".join(f["text"] for f in section["fields"])
        self.assertIn("testhost", all_text)

    def test_fields_contain_snapshot_id(self):
        section = self.payload["blocks"][1]
        all_text = " ".join(f["text"] for f in section["fields"])
        self.assertIn("7", all_text)

    def test_description_in_body(self):
        section = self.payload["blocks"][2]
        self.assertIn("Test alert description", section["text"]["text"])

    def test_attck_technique_included_when_present(self):
        section = self.payload["blocks"][2]
        self.assertIn("T1055", section["text"]["text"])

    def test_no_attck_line_when_empty(self):
        alert = make_alert()
        alert.attck_technique = ""
        payload = format_slack_payload(alert)
        section = payload["blocks"][2]
        self.assertNotIn("ATT&CK", section["text"]["text"])

    def test_emoji_in_header(self):
        header = self.payload["blocks"][0]["text"]["text"]
        self.assertIn("🔴", header)


class TestTeamsPayload(unittest.TestCase):
    def setUp(self):
        self.alert = make_alert(severity="high")
        self.payload = format_teams_payload(self.alert)

    def test_top_level_type_is_message(self):
        self.assertEqual(self.payload["type"], "message")

    def test_attachments_present(self):
        self.assertIn("attachments", self.payload)
        self.assertGreater(len(self.payload["attachments"]), 0)

    def test_adaptive_card_schema(self):
        card = self.payload["attachments"][0]["content"]
        self.assertEqual(card["type"], "AdaptiveCard")

    def test_severity_in_title(self):
        card = self.payload["attachments"][0]["content"]
        title_block = card["body"][0]
        self.assertIn("HIGH", title_block["text"])

    def test_description_in_body(self):
        card = self.payload["attachments"][0]["content"]
        desc_block = card["body"][1]
        self.assertIn("Test alert description", desc_block["text"])

    def test_facts_include_hostname(self):
        card = self.payload["attachments"][0]["content"]
        fact_set = card["body"][2]
        all_values = " ".join(f["value"] for f in fact_set["facts"])
        self.assertIn("testhost", all_values)

    def test_attck_fact_present_when_set(self):
        card = self.payload["attachments"][0]["content"]
        fact_set = card["body"][2]
        titles = [f["title"] for f in fact_set["facts"]]
        self.assertIn("ATT&CK", titles)

    def test_attck_fact_absent_when_empty(self):
        alert = make_alert()
        alert.attck_technique = ""
        payload = format_teams_payload(alert)
        card = payload["attachments"][0]["content"]
        fact_set = card["body"][2]
        titles = [f["title"] for f in fact_set["facts"]]
        self.assertNotIn("ATT&CK", titles)


class TestGenericPayload(unittest.TestCase):
    def setUp(self):
        self.alert = make_alert(severity="medium")
        self.payload = format_generic_payload(self.alert)

    def test_source_is_orin(self):
        self.assertEqual(self.payload["source"], "orin")

    def test_all_required_fields_present(self):
        for field in ("severity", "event_type", "description", "hostname",
                      "snapshot_id", "attck_technique", "attck_tactic", "timestamp"):
            self.assertIn(field, self.payload)

    def test_values_match_alert(self):
        self.assertEqual(self.payload["severity"], "medium")
        self.assertEqual(self.payload["hostname"], "testhost")
        self.assertEqual(self.payload["snapshot_id"], 7)

    def test_json_serializable(self):
        # Must not raise
        json.dumps(self.payload)


# ---------------------------------------------------------------------------
# Severity rank / filter tests
# ---------------------------------------------------------------------------

class TestSeverityFilter(unittest.TestCase):
    def test_critical_rank_highest(self):
        a = make_alert("critical")
        self.assertEqual(a.severity_rank, 3)

    def test_high_rank(self):
        self.assertEqual(make_alert("high").severity_rank, 2)

    def test_medium_rank(self):
        self.assertEqual(make_alert("medium").severity_rank, 1)

    def test_low_rank(self):
        self.assertEqual(make_alert("low").severity_rank, 0)

    def test_unknown_severity_rank_zero(self):
        a = make_alert("banana")
        self.assertEqual(a.severity_rank, 0)

    def test_syslog_priority_critical(self):
        # LOG_LOCAL0 (16<<3 = 128) | LOG_CRIT (2) = 130
        self.assertEqual(_syslog_priority("critical"), 130)

    def test_syslog_priority_high(self):
        self.assertEqual(_syslog_priority("high"), 131)

    def test_syslog_priority_medium(self):
        self.assertEqual(_syslog_priority("medium"), 132)


class TestGlobalDisabledFlag(unittest.TestCase):
    """When enabled=False, no channels should be contacted at all."""

    @patch("orin.core.notifier.AlertForwarder._deliver_webhook")
    @patch("orin.core.notifier.AlertForwarder._deliver_syslog")
    def test_nothing_called_when_disabled(self, mock_syslog, mock_webhook):
        cfg = enabled_cfg(enabled=False)
        cfg["syslog"]["enabled"] = True
        cfg["webhooks"] = [webhook_entry()]
        fwd = AlertForwarder(cfg)
        fwd.dispatch([make_alert("critical")])
        mock_syslog.assert_not_called()
        mock_webhook.assert_not_called()

    def test_empty_list_no_calls(self):
        cfg = enabled_cfg()
        cfg["webhooks"] = [webhook_entry()]
        fwd = AlertForwarder(cfg)
        # Should complete without error and call nothing
        with patch.object(fwd, "_dispatch_single") as mock_ds:
            fwd.dispatch([])
            mock_ds.assert_not_called()


# ---------------------------------------------------------------------------
# Severity filter tests (enabled forwarder)
# ---------------------------------------------------------------------------

class TestSeverityFiltering(unittest.TestCase):
    """min_severity=high should skip medium/low alerts."""

    def _make_forwarder(self, **overrides):
        cfg = enabled_cfg(**overrides)
        return AlertForwarder(cfg)

    @patch("orin.core.notifier.AlertForwarder._deliver_webhook")
    def test_medium_skipped_when_min_high(self, mock_wh):
        cfg = enabled_cfg(min_severity="high")
        cfg["webhooks"] = [webhook_entry()]
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("medium")])
        mock_wh.assert_not_called()

    @patch("orin.core.notifier.AlertForwarder._deliver_webhook")
    def test_high_passes_when_min_high(self, mock_wh):
        cfg = enabled_cfg(min_severity="high")
        cfg["webhooks"] = [webhook_entry()]
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("high")])
        mock_wh.assert_called_once()

    @patch("orin.core.notifier.AlertForwarder._deliver_webhook")
    def test_critical_always_passes(self, mock_wh):
        cfg = enabled_cfg(min_severity="high")
        cfg["webhooks"] = [webhook_entry()]
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("critical")])
        mock_wh.assert_called_once()

    @patch("orin.core.notifier.AlertForwarder._deliver_webhook")
    def test_per_webhook_min_severity_override_blocks_high(self, mock_wh):
        """Webhook min_severity=critical → high alert should be skipped."""
        cfg = enabled_cfg(min_severity="high")
        cfg["webhooks"] = [webhook_entry(min_severity="critical")]
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("high")])
        mock_wh.assert_not_called()

    @patch("orin.core.notifier.AlertForwarder._deliver_webhook")
    def test_per_webhook_min_severity_override_passes_critical(self, mock_wh):
        cfg = enabled_cfg(min_severity="high")
        cfg["webhooks"] = [webhook_entry(min_severity="critical")]
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("critical")])
        mock_wh.assert_called_once()

    @patch("orin.core.notifier.AlertForwarder._deliver_webhook")
    def test_disabled_webhook_entry_skipped(self, mock_wh):
        cfg = enabled_cfg()
        cfg["webhooks"] = [webhook_entry(enabled=False)]
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("critical")])
        mock_wh.assert_not_called()


# ---------------------------------------------------------------------------
# Webhook delivery tests
# ---------------------------------------------------------------------------

class TestWebhookDelivery(unittest.TestCase):

    def _fwd_with_webhook(self, fmt="generic", **wh_overrides):
        wh = webhook_entry(fmt=fmt, **wh_overrides)
        cfg = enabled_cfg(webhooks=[wh], retry={"max_attempts": 3, "backoff_seconds": 0})
        return AlertForwarder(cfg)

    @patch("urllib.request.urlopen")
    def test_successful_post(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ok"
        mock_urlopen.return_value = mock_resp

        fwd = self._fwd_with_webhook()
        with patch.object(fwd, "_write_audit"):
            fwd._deliver_webhook(make_alert(), webhook_entry())

        mock_urlopen.assert_called_once()

    @patch("time.sleep", return_value=None)
    @patch("urllib.request.urlopen")
    def test_retries_on_failure_then_succeeds(self, mock_urlopen, _sleep):
        """First 2 calls raise URLError; third succeeds."""
        import urllib.error

        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ok"

        mock_urlopen.side_effect = [
            urllib.error.URLError("timeout"),
            urllib.error.URLError("timeout"),
            mock_resp,
        ]

        fwd = self._fwd_with_webhook()
        # Should not raise
        fwd._deliver_webhook(make_alert(), webhook_entry())
        self.assertEqual(mock_urlopen.call_count, 3)

    @patch("time.sleep", return_value=None)
    @patch("urllib.request.urlopen")
    def test_all_retries_exhausted_raises(self, mock_urlopen, _sleep):
        """Exhaust all attempts → RuntimeError raised."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        fwd = self._fwd_with_webhook()
        with self.assertRaises(RuntimeError):
            fwd._deliver_webhook(make_alert(), webhook_entry())

    @patch("time.sleep", return_value=None)
    @patch("urllib.request.urlopen")
    def test_all_retries_exhausted_no_caller_exception(self, mock_urlopen, _sleep):
        """dispatch() itself must not raise even when a webhook fails completely."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        cfg = enabled_cfg(
            webhooks=[webhook_entry()],
            retry={"max_attempts": 2, "backoff_seconds": 0},
        )
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):  # suppress FS writes
            # Must not raise
            fwd.dispatch([make_alert("critical")])

    @patch("urllib.request.urlopen")
    def test_slack_format_used_for_slack_webhook(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ok"
        mock_urlopen.return_value = mock_resp

        fwd = self._fwd_with_webhook(fmt="slack")
        with patch.object(fwd, "_write_audit"):
            fwd._deliver_webhook(make_alert(), webhook_entry(fmt="slack"))

        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data)
        self.assertIn("blocks", body)

    @patch("urllib.request.urlopen")
    def test_teams_format_used_for_teams_webhook(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ok"
        mock_urlopen.return_value = mock_resp

        fwd = self._fwd_with_webhook(fmt="teams")
        with patch.object(fwd, "_write_audit"):
            fwd._deliver_webhook(make_alert(), webhook_entry(fmt="teams"))

        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data)
        self.assertEqual(body["type"], "message")

    @patch("urllib.request.urlopen")
    def test_multiple_webhooks_all_called(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ok"
        mock_urlopen.return_value = mock_resp

        cfg = enabled_cfg(
            webhooks=[
                webhook_entry(url="http://hook1/"),
                webhook_entry(url="http://hook2/", name="hook2"),
            ]
        )
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("critical")])

        self.assertEqual(mock_urlopen.call_count, 2)

    @patch("urllib.request.urlopen")
    def test_custom_headers_forwarded(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"ok"
        mock_urlopen.return_value = mock_resp

        wh = webhook_entry(headers={"X-Auth-Token": "secret123"})
        fwd = self._fwd_with_webhook()
        with patch.object(fwd, "_write_audit"):
            fwd._deliver_webhook(make_alert(), wh)

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("X-auth-token"), "secret123")


# ---------------------------------------------------------------------------
# Syslog delivery tests
# ---------------------------------------------------------------------------

class TestSyslogDelivery(unittest.TestCase):

    def _fwd_with_syslog(self):
        cfg = enabled_cfg(
            syslog={"enabled": True, "tag": "orin-test"},
            webhooks=[],
        )
        return AlertForwarder(cfg)

    @patch("orin.core.notifier._send_to_syslog")
    def test_syslog_called_on_dispatch(self, mock_send):
        fwd = self._fwd_with_syslog()
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("critical")])
        mock_send.assert_called_once()

    @patch("orin.core.notifier._send_to_syslog")
    def test_syslog_tag_passed(self, mock_send):
        fwd = self._fwd_with_syslog()
        with patch.object(fwd, "_write_audit"):
            fwd._deliver_syslog(make_alert("critical"), {"enabled": True, "tag": "my-tag"})
        mock_send.assert_called_once_with(mock_send.call_args[0][0], tag="my-tag")

    @patch("orin.core.notifier._send_to_syslog")
    def test_syslog_not_called_when_disabled(self, mock_send):
        cfg = enabled_cfg(
            syslog={"enabled": False, "tag": "orin-test"},
            webhooks=[],
        )
        fwd = AlertForwarder(cfg)
        with patch.object(fwd, "_write_audit"):
            fwd.dispatch([make_alert("critical")])
        mock_send.assert_not_called()

    @patch("orin.core.notifier._send_to_syslog")
    def test_syslog_failure_doesnt_raise_from_dispatch(self, mock_send):
        mock_send.side_effect = OSError("syslog unavailable")
        fwd = self._fwd_with_syslog()
        # Must not propagate
        fwd.dispatch([make_alert("critical")])

    def test_send_to_syslog_stdlib(self):
        """_send_to_syslog uses the stdlib syslog module when available."""
        import sys as _sys
        alert = make_alert("high")
        mock_syslog_mod = MagicMock()
        mock_syslog_mod.LOG_PID = 1
        mock_syslog_mod.LOG_LOCAL0 = 128
        mock_syslog_mod.LOG_CRIT = 2
        mock_syslog_mod.LOG_ERR = 3
        mock_syslog_mod.LOG_WARNING = 4
        mock_syslog_mod.LOG_NOTICE = 5

        from orin.core import notifier as notif_mod
        with patch.dict(_sys.modules, {"syslog": mock_syslog_mod}):
            notif_mod._send_to_syslog(alert, tag="test-tag")

        mock_syslog_mod.syslog.assert_called_once()


# ---------------------------------------------------------------------------
# Audit log tests
# ---------------------------------------------------------------------------

class TestAuditLog(unittest.TestCase):

    def test_audit_log_written_on_success(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "audit.log")
            cfg = enabled_cfg(audit_log=log_path)
            cfg["webhooks"] = [webhook_entry()]
            fwd = AlertForwarder(cfg)

            with patch("urllib.request.urlopen") as mock_ul:
                mock_resp = MagicMock()
                mock_resp.__enter__ = lambda s: s
                mock_resp.__exit__ = MagicMock(return_value=False)
                mock_resp.read.return_value = b"ok"
                mock_ul.return_value = mock_resp
                fwd.dispatch([make_alert("critical")])

            self.assertTrue(os.path.exists(log_path))
            with open(log_path) as f:
                line = json.loads(f.readline())
            self.assertEqual(line["status"], "delivered")
            self.assertEqual(line["severity"], "critical")

    def test_audit_log_written_on_failure(self):
        import urllib.error
        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "audit.log")
            cfg = enabled_cfg(audit_log=log_path)
            cfg["webhooks"] = [webhook_entry()]
            cfg["retry"] = {"max_attempts": 1, "backoff_seconds": 0}
            fwd = AlertForwarder(cfg)

            with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
                fwd.dispatch([make_alert("critical")])

            with open(log_path) as f:
                line = json.loads(f.readline())
            self.assertEqual(line["status"], "failed")
            self.assertIn("error", line)

    def test_audit_log_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "deep", "nested", "audit.log")
            cfg = enabled_cfg(audit_log=log_path)
            fwd = AlertForwarder(cfg)
            alert = make_alert("critical")
            # Write directly
            fwd._write_audit(
                channel="test",
                alert=alert,
                status="delivered",
                error=None,
                timestamp="2026-01-01T00:00:00+00:00",
            )
            self.assertTrue(os.path.exists(log_path))

    def test_audit_log_failure_doesnt_raise(self):
        """A write failure must be swallowed silently."""
        cfg = enabled_cfg(audit_log="/proc/noaccess/audit.log")
        fwd = AlertForwarder(cfg)
        alert = make_alert("critical")
        # Must not raise
        fwd._write_audit(
            channel="test",
            alert=alert,
            status="delivered",
            error=None,
            timestamp="now",
        )

    def test_audit_log_multiple_entries(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "audit.log")
            cfg = enabled_cfg(audit_log=log_path)
            fwd = AlertForwarder(cfg)
            for i in range(3):
                fwd._write_audit(
                    channel=f"ch{i}",
                    alert=make_alert("high"),
                    status="delivered",
                    error=None,
                    timestamp="now",
                )
            with open(log_path) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 3)


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------

class TestAlertsFromDbRows(unittest.TestCase):

    def test_empty_input(self):
        self.assertEqual(alerts_from_db_rows([]), [])

    def test_basic_mapping(self):
        rows = [{
            "severity": "high",
            "event_type": "file_modification",
            "description": "passwd changed",
            "hostname": "host1",
            "snapshot_id": 5,
            "attck_technique": "T1222",
            "attck_tactic": "defense-evasion",
        }]
        alerts = alerts_from_db_rows(rows)
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual(a.severity, "high")
        self.assertEqual(a.event_type, "file_modification")
        self.assertEqual(a.hostname, "host1")
        self.assertEqual(a.snapshot_id, 5)
        self.assertEqual(a.attck_technique, "T1222")

    def test_missing_optional_fields_default(self):
        rows = [{"severity": "medium", "event_type": "test", "description": "d",
                 "hostname": "h", "snapshot_id": 1}]
        alerts = alerts_from_db_rows(rows)
        self.assertEqual(alerts[0].attck_technique, "")
        self.assertEqual(alerts[0].attck_tactic, "")

    def test_none_hostname_becomes_unknown(self):
        rows = [{"severity": "medium", "event_type": "t", "description": "d",
                 "hostname": None, "snapshot_id": 1}]
        alerts = alerts_from_db_rows(rows)
        self.assertEqual(alerts[0].hostname, "unknown")

    def test_snapshot_id_coercion(self):
        rows = [{"severity": "low", "event_type": "t", "description": "d",
                 "hostname": "h", "snapshot_id": "42"}]
        alerts = alerts_from_db_rows(rows)
        self.assertEqual(alerts[0].snapshot_id, 42)


class TestBuildForwarderFromConfig(unittest.TestCase):

    def test_returns_alert_forwarder_instance(self):
        cfg = {"notifications": {"enabled": False}}
        fwd = build_forwarder_from_config(cfg)
        self.assertIsInstance(fwd, AlertForwarder)

    def test_missing_notifications_key_uses_defaults(self):
        fwd = build_forwarder_from_config({})
        # Default is enabled=False, so dispatch should be a no-op
        with patch.object(fwd, "_dispatch_single") as mock_ds:
            fwd.dispatch([make_alert("critical")])
            mock_ds.assert_not_called()

    def test_config_propagated(self):
        cfg = {
            "notifications": {
                "enabled": True,
                "min_severity": "low",
                "webhooks": [],
                "retry": {"max_attempts": 1, "backoff_seconds": 0},
                "audit_log": "/tmp/test_audit.log",
                "syslog": {"enabled": False}
            }
        }
        fwd = build_forwarder_from_config(cfg)
        self.assertTrue(fwd._cfg["enabled"])
        self.assertEqual(fwd._cfg["min_severity"], "low")


# ---------------------------------------------------------------------------
# AlertNotification helpers
# ---------------------------------------------------------------------------

class TestAlertNotification(unittest.TestCase):

    def test_severity_emoji_critical(self):
        self.assertEqual(make_alert("critical").severity_emoji(), "🔴")

    def test_severity_emoji_high(self):
        self.assertEqual(make_alert("high").severity_emoji(), "🟠")

    def test_severity_emoji_medium(self):
        self.assertEqual(make_alert("medium").severity_emoji(), "🟡")

    def test_severity_emoji_low(self):
        self.assertEqual(make_alert("low").severity_emoji(), "🔵")

    def test_severity_emoji_unknown(self):
        self.assertEqual(make_alert("banana").severity_emoji(), "⚪")

    def test_timestamp_auto_set(self):
        a = make_alert()
        self.assertIsNotNone(a.timestamp)
        self.assertIn("T", a.timestamp)


if __name__ == "__main__":
    unittest.main()
