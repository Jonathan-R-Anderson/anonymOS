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
# src/orin/core/notifier.py
"""
orin.core.notifier – Alert Forwarding Framework
================================================
Routes newly detected security alerts to external notification channels
without requiring cloud dependencies or persistent daemons.

Supported channels
------------------
* **Webhooks** — HTTP POST to any endpoint.  Built-in payload formatters
  for Slack Block Kit, Microsoft Teams Adaptive Cards, and generic JSON.
* **Syslog** — Writes to the local syslog facility via the stdlib
  ``syslog`` module.  Falls back to a raw ``/dev/log`` UDP socket on
  systems that lack the C extension.

All transports are fully offline-capable and use only Python stdlib.

Design contract
---------------
* :meth:`AlertForwarder.dispatch` is the single public entry point.
* A channel failure never raises — it is caught, logged to the audit
  log, and execution continues with the next channel.
* Retry logic uses simple exponential backoff bounded by
  ``retry.max_attempts`` and ``retry.backoff_seconds``.
* Every notification attempt (success or failure) appends a structured
  JSON line to ``notifications.audit_log``.
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Severity ordering (ascending)
# ---------------------------------------------------------------------------
_SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AlertNotification:
    """A single alert ready for dispatch to notification channels."""
    severity: str           # "low" | "medium" | "high" | "critical"
    event_type: str         # e.g. "file_modification", "untrusted_kernel_module"
    description: str        # Human-readable description
    hostname: str           # Originating host
    snapshot_id: int        # Vault snapshot ID the alert came from
    attck_technique: str = ""  # MITRE ATT&CK technique ID (may be empty)
    attck_tactic: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_RANK.get(self.severity.lower(), 0)

    def severity_emoji(self) -> str:
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
        }.get(self.severity.lower(), "⚪")


# ---------------------------------------------------------------------------
# Payload formatters
# ---------------------------------------------------------------------------

def format_slack_payload(alert: AlertNotification) -> dict[str, Any]:
    """Return a Slack Block Kit payload for the given alert."""
    emoji = alert.severity_emoji()
    attck_line = (
        f"\n*ATT&CK:* {alert.attck_technique} / {alert.attck_tactic}"
        if alert.attck_technique else ""
    )
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Orin Security Alert — {alert.severity.upper()}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Host:*\n{alert.hostname}"},
                    {"type": "mrkdwn", "text": f"*Type:*\n{alert.event_type}"},
                    {"type": "mrkdwn", "text": f"*Snapshot:*\n#{alert.snapshot_id}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{alert.timestamp}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{alert.description}{attck_line}",
                },
            },
            {"type": "divider"},
        ]
    }


def format_teams_payload(alert: AlertNotification) -> dict[str, Any]:
    """Return a Microsoft Teams Adaptive Card (via Incoming Webhook) payload."""
    emoji = alert.severity_emoji()
    color_map = {
        "critical": "attention",
        "high": "warning",
        "medium": "accent",
        "low": "good",
    }
    accent = color_map.get(alert.severity.lower(), "default")

    facts = [
        {"title": "Host", "value": alert.hostname},
        {"title": "Type", "value": alert.event_type},
        {"title": "Snapshot", "value": f"#{alert.snapshot_id}"},
        {"title": "Time", "value": alert.timestamp},
    ]
    if alert.attck_technique:
        facts.append({"title": "ATT&CK", "value": f"{alert.attck_technique} / {alert.attck_tactic}"})

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"{emoji} Orin Security Alert — {alert.severity.upper()}",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": accent,
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.description,
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": facts,
                        },
                    ],
                },
            }
        ],
    }


def format_generic_payload(alert: AlertNotification) -> dict[str, Any]:
    """Return a flat JSON dict suitable for any generic webhook consumer."""
    return {
        "source": "orin",
        "severity": alert.severity,
        "event_type": alert.event_type,
        "description": alert.description,
        "hostname": alert.hostname,
        "snapshot_id": alert.snapshot_id,
        "attck_technique": alert.attck_technique,
        "attck_tactic": alert.attck_tactic,
        "timestamp": alert.timestamp,
    }


# ---------------------------------------------------------------------------
# Syslog helper (stdlib only, with /dev/log fallback)
# ---------------------------------------------------------------------------

def _syslog_priority(severity: str) -> int:
    """Map an Orin severity string to a syslog priority integer.

    Uses LOG_LOCAL0 as the facility (24 << 3).  Priority constants:
    LOG_CRIT=2, LOG_ERR=3, LOG_WARNING=4, LOG_NOTICE=5.
    """
    # Facility LOG_LOCAL0 = 16; shifted left 3 for OR with level
    facility = 16 << 3
    level_map = {
        "critical": 2,  # LOG_CRIT
        "high": 3,      # LOG_ERR
        "medium": 4,    # LOG_WARNING
        "low": 5,       # LOG_NOTICE
    }
    return facility | level_map.get(severity.lower(), 4)


def _send_to_syslog(alert: AlertNotification, tag: str = "orin-alert") -> None:
    """Write alert to local syslog.

    Prefers the stdlib ``syslog`` C-extension.  On systems where it is
    unavailable, falls back to a raw DGRAM socket on ``/dev/log``.
    """
    msg = (
        f"{tag}: [{alert.severity.upper()}] {alert.event_type} on "
        f"{alert.hostname} (snap #{alert.snapshot_id}): {alert.description}"
    )
    try:
        import syslog as _syslog  # C extension, may be absent on some distros
        _syslog.openlog(tag, _syslog.LOG_PID, _syslog.LOG_LOCAL0)
        priority_level = {
            "critical": _syslog.LOG_CRIT,
            "high": _syslog.LOG_ERR,
            "medium": _syslog.LOG_WARNING,
            "low": _syslog.LOG_NOTICE,
        }.get(alert.severity.lower(), _syslog.LOG_WARNING)
        _syslog.syslog(priority_level, msg)
        _syslog.closelog()
    except (ImportError, AttributeError):
        # Fallback: write to /dev/log as a raw UNIX DGRAM socket
        dev_log = "/dev/log"
        if os.path.exists(dev_log):
            priority = _syslog_priority(alert.severity)
            raw = f"<{priority}>{tag}: {msg}".encode("utf-8", errors="replace")
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                try:
                    sock.connect(dev_log)
                    sock.send(raw[:1024])  # syslog max line is typically 1024 bytes
                except OSError:
                    pass  # Best effort — don't crash if /dev/log is inaccessible


# ---------------------------------------------------------------------------
# Main forwarder class
# ---------------------------------------------------------------------------

class AlertForwarder:
    """Dispatches :class:`AlertNotification` objects to configured channels.

    Parameters
    ----------
    config:
        The ``notifications`` sub-dict from the Orin config (as returned
        by :func:`orin.core.config.load_config`).  Missing keys fall back
        to built-in safe defaults.

    Example usage::

        from orin.core.config import load_config
        from orin.core.notifier import AlertForwarder, AlertNotification

        cfg = load_config()
        forwarder = AlertForwarder(cfg.get("notifications", {}))
        forwarder.dispatch([
            AlertNotification(
                severity="critical",
                event_type="untrusted_kernel_module",
                description="diamorphine.ko loaded",
                hostname="server01",
                snapshot_id=42,
            )
        ])
    """

    # Default values when individual config keys are absent
    _DEFAULTS: dict[str, Any] = {
        "enabled": False,
        "min_severity": "high",
        "syslog": {"enabled": False, "facility": "LOG_LOCAL0", "tag": "orin-alert"},
        "webhooks": [],
        "retry": {"max_attempts": 3, "backoff_seconds": 5},
        "audit_log": "/var/log/orin/notification_audit.log",
    }

    def __init__(self, notifications_config: dict[str, Any] | None = None) -> None:
        cfg = notifications_config or {}
        # Merge top-level keys only (shallow is fine here — sub-dicts are
        # accessed with individual .get() calls below)
        self._cfg: dict[str, Any] = {**self._DEFAULTS, **cfg}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, alerts: list[AlertNotification]) -> None:
        """Dispatch a list of alerts to all enabled channels.

        Filters by ``min_severity`` before forwarding.  Each channel
        failure is caught and written to the audit log — it never
        propagates to the caller.

        Parameters
        ----------
        alerts:
            Alerts produced by the current analysis cycle.
        """
        if not self._cfg.get("enabled", False):
            return

        if not alerts:
            return

        min_rank = _SEVERITY_RANK.get(
            self._cfg.get("min_severity", "high").lower(), 2
        )

        qualifying = [a for a in alerts if a.severity_rank >= min_rank]
        if not qualifying:
            return

        for alert in qualifying:
            self._dispatch_single(alert)

    # ------------------------------------------------------------------
    # Internal dispatch helpers
    # ------------------------------------------------------------------

    def _dispatch_single(self, alert: AlertNotification) -> None:
        """Send *alert* to every enabled channel."""
        # Syslog
        syslog_cfg = self._cfg.get("syslog", {})
        if syslog_cfg.get("enabled", False):
            self._safe_call(
                self._deliver_syslog,
                alert,
                syslog_cfg,
                channel="syslog",
            )

        # Webhooks
        for wh_cfg in self._cfg.get("webhooks", []):
            if not wh_cfg.get("enabled", True):
                continue

            # Per-webhook min_severity override
            wh_min = wh_cfg.get("min_severity", self._cfg.get("min_severity", "high"))
            if alert.severity_rank < _SEVERITY_RANK.get(wh_min.lower(), 2):
                continue

            self._safe_call(
                self._deliver_webhook,
                alert,
                wh_cfg,
                channel=wh_cfg.get("name", wh_cfg.get("url", "unknown")),
            )

    def _safe_call(
        self,
        fn,
        alert: AlertNotification,
        cfg: dict[str, Any],
        channel: str,
    ) -> None:
        """Call *fn(alert, cfg)* inside a try/except and write the audit log."""
        started = datetime.now(timezone.utc).isoformat()
        try:
            fn(alert, cfg)
            self._write_audit(
                channel=channel,
                alert=alert,
                status="delivered",
                error=None,
                timestamp=started,
            )
        except Exception as exc:  # noqa: BLE001
            self._write_audit(
                channel=channel,
                alert=alert,
                status="failed",
                error=str(exc),
                timestamp=started,
            )

    # ------------------------------------------------------------------
    # Channel: Webhook
    # ------------------------------------------------------------------

    def _deliver_webhook(
        self, alert: AlertNotification, wh_cfg: dict[str, Any]
    ) -> None:
        """POST alert to a webhook URL with retries."""
        retry_cfg = self._cfg.get("retry", {})
        max_attempts = int(retry_cfg.get("max_attempts", 3))
        backoff = float(retry_cfg.get("backoff_seconds", 5))

        fmt = wh_cfg.get("format", "generic").lower()
        if fmt == "slack":
            payload = format_slack_payload(alert)
        elif fmt == "teams":
            payload = format_teams_payload(alert)
        else:
            payload = format_generic_payload(alert)

        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(wh_cfg.get("headers", {}))
        timeout = int(wh_cfg.get("timeout_seconds", 10))
        url = wh_cfg["url"]

        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    _ = resp.read()  # consume body
                return  # success
            except (urllib.error.URLError, OSError) as exc:
                last_exc = exc
                if attempt < max_attempts:
                    time.sleep(backoff * (2 ** (attempt - 1)))  # exponential backoff

        raise RuntimeError(
            f"Webhook delivery to '{url}' failed after {max_attempts} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # Channel: Syslog
    # ------------------------------------------------------------------

    def _deliver_syslog(
        self, alert: AlertNotification, syslog_cfg: dict[str, Any]
    ) -> None:
        """Write alert to local syslog."""
        tag = syslog_cfg.get("tag", "orin-alert")
        _send_to_syslog(alert, tag=tag)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def _write_audit(
        self,
        channel: str,
        alert: AlertNotification,
        status: str,
        error: str | None,
        timestamp: str,
    ) -> None:
        """Append a JSON line to the notification audit log.

        Creates parent directories and the file if they do not exist.
        A write failure is silently swallowed — the audit log must never
        cause the analysis cycle to abort.
        """
        audit_path_str = self._cfg.get("audit_log", "/var/log/orin/notification_audit.log")
        try:
            audit_path = Path(audit_path_str)
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "timestamp": timestamp,
                "channel": channel,
                "status": status,
                "severity": alert.severity,
                "event_type": alert.event_type,
                "hostname": alert.hostname,
                "snapshot_id": alert.snapshot_id,
                "description": alert.description[:200],  # truncate for log hygiene
            }
            if error:
                record["error"] = error
            with open(audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:  # noqa: BLE001
            pass  # audit log failure must never crash the analysis cycle


# ---------------------------------------------------------------------------
# Convenience builder
# ---------------------------------------------------------------------------

def build_forwarder_from_config(config: dict[str, Any]) -> AlertForwarder:
    """Construct an :class:`AlertForwarder` from a full Orin config dict.

    Parameters
    ----------
    config:
        Dict as returned by :func:`orin.core.config.load_config`.

    Returns
    -------
    AlertForwarder
        Ready-to-use forwarder instance.
    """
    return AlertForwarder(config.get("notifications", {}))


def alerts_from_db_rows(rows: list[dict[str, Any]]) -> list[AlertNotification]:
    """Convert raw ``security_events`` database rows to notification objects.

    Parameters
    ----------
    rows:
        List of dicts with at minimum keys: severity, event_type,
        description, hostname, id (snapshot_id via join or context).

    Returns
    -------
    list[AlertNotification]
    """
    result: list[AlertNotification] = []
    for row in rows:
        result.append(
            AlertNotification(
                severity=row.get("severity", "medium"),
                event_type=row.get("event_type", "unknown"),
                description=row.get("description", ""),
                hostname=row.get("hostname") or "unknown",
                snapshot_id=int(row.get("snapshot_id", 0)),
                attck_technique=row.get("attck_technique") or "",
                attck_tactic=row.get("attck_tactic") or "",
            )
        )
    return result
