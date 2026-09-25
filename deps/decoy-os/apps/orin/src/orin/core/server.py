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
# src/orin/core/server.py
"""
orin.core.server – Web Dashboard HTTP Server
===========================================
Provides a lightweight, zero-dependency local web server utilizing Python's
standard library `http.server`. Exposes the REST API and serves the single-page
HTML console for system audits, timeline drift, and rule configurations.
"""

import sys
import os
import json
import base64
import hmac
import ssl
import subprocess
import time
import threading
from pathlib import Path
from typing import Any
import hashlib
import socket
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

from orin.core.database import OrinStorage
from orin.core.config import load_config
from orin.core.credentials import CredentialManager, SecureCredential
from orin.core.health import liveness_response, readiness_response, metrics_response
from orin.analysis.timeline import calculate_snapshot_delta
from orin.collectors.users import gather_system_accounts
from orin.collectors.kernel import gather_loaded_kernel_modules
from orin.core.scheduler import CRON_D_FILE
from orin.core.logging import get_logger

# Helper for resolving static dashboard assets
DASHBOARD_FILE = Path(__file__).parent / "dashboard.html"


class TokenBucketLimiter:
    """A standard Token Bucket rate limiter implementation."""
    def __init__(self, rate: float, capacity: float):
        self.rate = rate          # tokens per second
        self.capacity = capacity  # max tokens
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.last_refill = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class IPTokenBucketLimiter:
    """Thread-safe mapping of client IPs to TokenBucketLimiter instances."""
    def __init__(self, rate: float = 5.0, capacity: float = 10.0):
        self.rate = rate
        self.capacity = capacity
        self.limiters = {}
        self.lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        with self.lock:
            if ip not in self.limiters:
                self.limiters[ip] = TokenBucketLimiter(self.rate, self.capacity)
            limiter = self.limiters[ip]
        return limiter.consume()


class OrinHTTPHandler(BaseHTTPRequestHandler):
    """Custom HTTP Request Handler for Orin Console and API endpoints."""

    def log_message(self, format, *args):
        # Mute default request logs on stderr to avoid terminal clutter
        pass

    def send_response(self, code, message=None):
        super().send_response(code, message)
        # Log the access event
        authenticated = getattr(self, "_authenticated", False)
        self.log_access_event(authenticated=authenticated, status=code)

    def log_access_event(self, authenticated: bool, status: int, detail: str = ""):
        """Log structured JSON access & authentication event to /var/log/orin/access.log."""
        # Try to resolve user if auth header is present
        user = None
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            user = "TokenBearer"
        elif auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                user = decoded.split(":", 1)[0]
            except Exception:
                user = "MalformedBasic"

        parsed_url = urlparse(self.path)
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": self.client_address[0],
            "method": self.command,
            "path": parsed_url.path,
            "status": status,
            "authenticated": authenticated,
            "user": user,
            "detail": detail
        }

        log_dir = Path("/var/log/orin")
        log_file = log_dir / "access.log"

        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except (PermissionError, OSError):
            # Graceful fallback: write to user-local directory (e.g. ~/.orin/logs/access.log)
            try:
                fallback_dir = Path.home() / ".orin" / "logs"
                fallback_dir.mkdir(parents=True, exist_ok=True)
                fallback_file = fallback_dir / "access.log"
                with open(fallback_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry) + "\n")
            except Exception:
                # If everything fails, write to stderr or ignore silently to not crash the server
                sys.stderr.write(f"[!] Access log fallback failed: {json.dumps(log_entry)}\n")

    def handle_rate_limit(self) -> bool:
        """Check if request exceeds rate limits. Returns True if allowed, False if rate limited."""
        limiter = getattr(self.server, "rate_limiter", None)
        if limiter is None:
            return True

        client_ip = self.client_address[0]
        if not limiter.is_allowed(client_ip):
            self._send_rate_limited()
            return False
        return True

    def _send_rate_limited(self):
        body = json.dumps({"status": "error", "message": "Too many requests. Please slow down."}).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def check_auth(self) -> bool:
        """Validate access via Bearer session token or legacy Basic Auth."""
        is_auth = self._check_auth_internal()
        self._authenticated = is_auth
        return is_auth

    def _check_auth_internal(self) -> bool:
        # Support both legacy string tokens and new SecureCredential wrappers
        session_token_obj = getattr(self.server, "session_token", None)
        no_auth = getattr(self.server, "no_auth", False)

        # Auth explicitly disabled
        if no_auth:
            return True

        parsed_url = urlparse(self.path)
        query = parse_qs(parsed_url.query)

        # --- Bearer token (primary, auto-generated) ---
        if session_token_obj:
            # Extract actual token value from SecureCredential if wrapped
            if isinstance(session_token_obj, SecureCredential):
                session_token = session_token_obj.get_value()
            else:
                session_token = session_token_obj

            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                provided = auth_header[7:].strip()
                if hmac.compare_digest(provided, session_token):
                    return True

            # Accept ?token= on GET requests (initial URL open from terminal)
            token_param = query.get("token", [None])[0]
            if token_param and hmac.compare_digest(token_param, session_token):
                return True

            self._send_token_required()
            return False

        # --- Legacy Basic Auth fallback ---
        username = getattr(self.server, "username", None)
        password = getattr(self.server, "password", None)
        if username and password:
            auth_header = self.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Basic "):
                self.send_auth_challenge()
                return False
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                u, p = decoded.split(":", 1)
                if hmac.compare_digest(u, username) and hmac.compare_digest(p, password):
                    return True
            except Exception:
                pass
            self.send_auth_challenge()
            return False

        # No auth configured
        return True

    def _send_token_required(self):
        """Respond with a user-friendly 401 page when token is missing or wrong."""
        body = (
            b"<!DOCTYPE html><html><head><title>401 \xe2\x80\x94 Orin Access Denied</title>"
            b"<style>body{font-family:monospace;background:#0d1117;color:#e6edf3;"
            b"display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
            b"div{text-align:center;padding:2rem}code{background:#161b22;padding:.2em .4em;border-radius:4px}"
            b"</style></head><body><div>"
            b"<h1 style='color:#f85149'>&#128274; 401 &mdash; Access Denied</h1>"
            b"<p>This Orin console requires a valid session token.</p>"
            b"<p>Use the URL printed in the terminal where <code>sudo orin serve</code> is running.</p>"
            b"</div></body></html>"
        )
        self.send_response(401)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("WWW-Authenticate", 'Bearer realm="Orin Forensic Console"')
        self.end_headers()
        self.wfile.write(body)

    def send_auth_challenge(self):
        """Respond with HTTP 401 WWW-Authenticate challenge (Basic Auth legacy)."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Orin Forensic Console"')
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>401 Unauthorized</h1><p>Invalid credentials.</p>")

    def handle_websocket(self):
        """Handle WebSocket handshake and maintain connection for alert broadcasts."""
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self.send_error_response("Missing Sec-WebSocket-Key", 400)
            return

        accept_val = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("utf-8")).digest()
        ).decode("utf-8")

        try:
            self.wfile.write(b"HTTP/1.1 101 Switching Protocols\r\n")
            self.wfile.write(b"Upgrade: websocket\r\n")
            self.wfile.write(b"Connection: Upgrade\r\n")
            self.wfile.write(f"Sec-WebSocket-Accept: {accept_val}\r\n\r\n".encode("utf-8"))
            self.wfile.flush()
        except Exception as e:
            get_logger().error(f"WebSocket handshake failed: {e}", component="server")
            return

        if not hasattr(self.server, "active_ws_clients"):
            self.server.active_ws_clients = set()
            self.server.active_ws_lock = threading.Lock()

        with self.server.active_ws_lock:
            self.server.active_ws_clients.add(self)

        get_logger().info(f"WebSocket client connected from {self.client_address[0]}", component="server")

        import select
        self.connection.settimeout(None)
        try:
            while not getattr(self.server, "_shutdown", False):
                try:
                    r, _, _ = select.select([self.connection], [], [], 1.0)
                    if not r:
                        continue
                    
                    header = self.rfile.read(2)
                    if not header or len(header) < 2:
                        get_logger().warning(f"WebSocket read EOF or short read: {header!r}", component="server")
                        break
                    
                    opcode = header[0] & 0x0F
                    if opcode == 0x08:  # Connection Close
                        get_logger().info("WebSocket client sent close opcode", component="server")
                        break
                    
                    if opcode == 0x09:  # Ping
                        self.wfile.write(bytes([0x8A, 0x00]))
                        self.wfile.flush()
                    
                    payload_len = header[1] & 0x7F
                    if payload_len == 126:
                        len_bytes = self.rfile.read(2)
                        payload_len = int.from_bytes(len_bytes, byteorder='big')
                    elif payload_len == 127:
                        len_bytes = self.rfile.read(8)
                        payload_len = int.from_bytes(len_bytes, byteorder='big')
                    
                    is_masked = (header[1] & 0x80) != 0
                    if is_masked:
                        self.rfile.read(4)
                    
                    if payload_len > 0:
                        self.rfile.read(payload_len)
                        
                except (TimeoutError, socket.timeout):
                    continue
                except (socket.error, ConnectionResetError) as se:
                    get_logger().debug(f"WebSocket socket error: {se}", component="server")
                    break
        except Exception as e:
            get_logger().error(f"WebSocket client loop exception: {e}", component="server", exc_info=True)
        finally:
            with self.server.active_ws_lock:
                self.server.active_ws_clients.discard(self)
            get_logger().info("WebSocket client disconnected", component="server")



    def send_json(self, data, status=200):
        """Helper to send a JSON response payload."""
        try:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            get_logger().error(f"Failed to send JSON response: {e}", component="server")

    def send_error_response(self, message, status=500):
        """Helper to send standard JSON error summaries."""
        self.send_json({"status": "error", "message": message}, status)

    def do_GET(self):
        """Handle GET routes: dashboard assets and API endpoints."""
        self._authenticated = False
        if not self.handle_rate_limit():
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # WebSocket Upgrade Route
        if path == "/ws":
            if self.headers.get("Upgrade", "").lower() == "websocket":
                if not self.check_auth():
                    return
                self.handle_websocket()
                return
            else:
                self.send_error_response("Expected WebSocket upgrade request", 400)
                return

        # Serve favicon.ico without authentication to avoid 401 errors
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        # Health & readiness probes — no auth, no rate-limit accounting.
        # These must always respond quickly for external monitoring systems.
        if path == "/health":
            status, payload = liveness_response(self.server.db_path)
            self.send_json(payload, status)
            return

        if path == "/ready":
            status, payload = readiness_response(self.server.db_path)
            self.send_json(payload, status)
            return

        if not self.check_auth():
            return

        # 1. Serve Dashboard HTML Console — inject session token as JS constant
        if path in ("/", "/index.html"):
            if not DASHBOARD_FILE.exists():
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Dashboard template not found.")
                return

            # Extract token from SecureCredential wrapper if present
            session_token_obj = getattr(self.server, "session_token", None)
            if isinstance(session_token_obj, SecureCredential):
                session_token = session_token_obj.get_value()
            elif session_token_obj:
                session_token = session_token_obj
            else:
                session_token = ""

            html = DASHBOARD_FILE.read_text(encoding="utf-8")
            # Inject session token as a JS constant so the dashboard can pick
            # it up and include it in all subsequent API fetch() calls.
            token_script = (
                f'<script>const ORIN_SESSION_TOKEN = "{session_token}";</script>\n'
            )
            html = html.replace("</head>", token_script + "</head>", 1)
            content = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; base-uri 'self'; form-action 'self';")
            self.end_headers()
            self.wfile.write(content)
            return

        # 2. API: Status and Posture Metrics
        if path == "/api/status":
            self.handle_api_status()
            return

        # 3. API: Active Alerts Ledger
        if path == "/api/alerts":
            self.handle_api_alerts()
            return

        # 4. API: System Snapshot List
        if path == "/api/snapshots":
            self.handle_api_snapshots()
            return

        # 5. API: Rule Configuration Loader
        if path == "/api/config":
            self.send_json(load_config())
            return

        # 6. API: Snapshot Timeline Diff delta
        if path == "/api/delta":
            self.handle_api_delta(parsed_url)
            return

        # 7. API: Automation Schedule Status
        if path == "/api/schedule/status":
            self.handle_api_schedule_status()
            return

        # 8. API: Snapshot Telemetry details
        if path == "/api/snapshot/telemetry":
            self.handle_api_snapshot_telemetry(parsed_url)
            return

        # 9. API: Operational metrics (collection stats, DB perf, alert trends)
        if path == "/api/metrics":
            status, payload = metrics_response(self.server.db_path)
            self.send_json(payload, status)
            return

        # Fallback for unrecognized paths
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        """Handle POST routes: updates, captures, and baseline managers."""
        self._authenticated = False
        if not self.handle_rate_limit():
            return
        if not self.check_auth():
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # Read JSON body content
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = {}
        if content_length > 0:
            try:
                post_data = json.loads(self.rfile.read(content_length).decode("utf-8"))
            except Exception as e:
                self.send_error_response(f"Malformed JSON body request: {e}", 400)
                return

        # 1. API: Trigger on-demand collect & analysis cycle
        if path == "/api/collect":
            self.handle_api_collect()
            return

        # 2. API: Update alert flags and analyst annotations
        if path == "/api/alerts/action":
            self.handle_api_alert_action(post_data)
            return

        # 3. API: Refresh baseline ledger from system state
        if path == "/api/baseline/refresh":
            self.handle_api_baseline_refresh()
            return

        # 4. API: Explicitly allowlist/baseline single entities
        if path == "/api/baseline/add":
            self.handle_api_baseline_add(post_data)
            return

        # 5. API: Serialize config file updates atomically
        if path == "/api/config/update":
            self.handle_api_config_update(post_data)
            return

        # 6. API: Install automation schedule
        if path == "/api/schedule/install":
            self.handle_api_schedule_install(post_data)
            return

        # 7. API: Remove automation schedule
        if path == "/api/schedule/remove":
            self.handle_api_schedule_remove()
            return

        # 8. API: Trigger a remote agentless SSH scan
        if path == "/api/scan":
            self.handle_api_scan(post_data)
            return

        # 9. API: Local AI correlation
        if path == "/api/correlate":
            self.handle_api_correlate(post_data)
            return

        # 10. API: Process Kill action
        if path == "/api/process/kill":
            self.handle_api_process_kill(post_data)
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    # API GET Router Handlers
    def handle_api_status(self):
        """Fetch statistics and live risk score assessment from the vault."""
        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json({
                "vault_path": str(db_path),
                "total_snapshots": 0,
                "total_baseline_modules": 0,
                "total_baseline_users": 0,
                "total_alerts": 0,
                "unresolved_alerts": 0,
                "risk_score": 0,
                "latest_snapshot": None,
                "total_hosts": 0,
                "fleet_hosts": []
            })
            return

        storage = OrinStorage(db_path)
        try:
            import platform
            with storage.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) as total FROM system_snapshots;")
                total_snapshots = cursor.fetchone()["total"]

                cursor.execute("SELECT COUNT(*) as total FROM baseline_kernel_modules;")
                total_baseline_modules = cursor.fetchone()["total"]

                cursor.execute("SELECT COUNT(*) as total FROM baseline_users;")
                total_baseline_users = cursor.fetchone()["total"]

                cursor.execute("SELECT COUNT(*) as total FROM security_events;")
                total_alerts = cursor.fetchone()["total"]

                cursor.execute("PRAGMA table_info(security_events);")
                columns = {row["name"] for row in cursor.fetchall()}
                has_suppressed = "suppressed" in columns
                suppressed_cond = " AND suppressed = 0" if has_suppressed else ""

                cursor.execute(f"SELECT COUNT(*) as total FROM security_events WHERE resolved = 0{suppressed_cond};")
                unresolved_alerts = cursor.fetchone()["total"]

                latest_snapshot = None
                if total_snapshots > 0:
                    cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots ORDER BY id DESC LIMIT 1;")
                    latest = cursor.fetchone()
                    latest_snapshot = dict(latest)

                cursor.execute(f"SELECT severity FROM security_events WHERE resolved = 0{suppressed_cond};")
                unresolved_sevs = [row["severity"].lower() for row in cursor.fetchall()]

                risk_score = 0
                if unresolved_sevs:
                    crit_count = unresolved_sevs.count("critical")
                    high_count = unresolved_sevs.count("high")
                    med_count = unresolved_sevs.count("medium")
                    low_count = len(unresolved_sevs) - crit_count - high_count - med_count

                    if crit_count > 0:
                        risk_score = min(90 + (crit_count - 1) * 5, 100)
                    elif high_count > 0:
                        risk_score = min(65 + (high_count - 1) * 3 + med_count * 1.5 + low_count * 0.5, 89)
                    elif med_count > 0:
                        risk_score = min(35 + (med_count - 1) * 1.5 + low_count * 0.5, 64)
                    else:
                        risk_score = min(15 + (low_count - 1) * 0.5, 34)

                    risk_score = int(risk_score + 0.5)

                # Fleet statistics query
                cursor.execute("SELECT DISTINCT hostname FROM system_snapshots;")
                unique_hosts = [row["hostname"] for row in cursor.fetchall()]

                fleet_hosts = []
                for h in unique_hosts:
                    cursor.execute("SELECT id, timestamp, os_platform FROM system_snapshots WHERE hostname = ? ORDER BY id DESC LIMIT 1;", (h,))
                    h_snap = cursor.fetchone()
                    if not h_snap:
                        continue
                    h_snap_id = h_snap["id"]
                    h_timestamp = h_snap["timestamp"]
                    h_os = h_snap["os_platform"]

                    cursor.execute(f"SELECT severity FROM security_events WHERE resolved = 0{suppressed_cond} AND (hostname = ? OR (hostname IS NULL AND ? = ?));", (h, h, platform.node() or "unknown_host"))
                    h_unresolved_sevs = [row["severity"].lower() for row in cursor.fetchall()]

                    h_risk_score = 0
                    if h_unresolved_sevs:
                        crit_count = h_unresolved_sevs.count("critical")
                        high_count = h_unresolved_sevs.count("high")
                        med_count = h_unresolved_sevs.count("medium")
                        low_count = len(h_unresolved_sevs) - crit_count - high_count - med_count

                        if crit_count > 0:
                            h_risk_score = min(90 + (crit_count - 1) * 5, 100)
                        elif high_count > 0:
                            h_risk_score = min(65 + (high_count - 1) * 3 + med_count * 1.5 + low_count * 0.5, 89)
                        elif med_count > 0:
                            h_risk_score = min(35 + (med_count - 1) * 1.5 + low_count * 0.5, 64)
                        else:
                            h_risk_score = min(15 + (low_count - 1) * 0.5, 34)

                        h_risk_score = int(h_risk_score + 0.5)

                    fleet_hosts.append({
                        "hostname": h,
                        "os_platform": h_os,
                        "latest_snapshot_id": h_snap_id,
                        "latest_snapshot_timestamp": h_timestamp,
                        "unresolved_alerts": len(h_unresolved_sevs),
                        "risk_score": h_risk_score
                    })

                self.send_json({
                    "vault_path": str(db_path),
                    "total_snapshots": total_snapshots,
                    "total_baseline_modules": total_baseline_modules,
                    "total_baseline_users": total_baseline_users,
                    "total_alerts": total_alerts,
                    "unresolved_alerts": unresolved_alerts,
                    "risk_score": risk_score,
                    "latest_snapshot": latest_snapshot,
                    "total_hosts": len(unique_hosts),
                    "fleet_hosts": fleet_hosts
                })
        except Exception as e:
            self.send_error_response(f"Database query failure: {e}")

    def handle_api_alerts(self):
        """Retrieve security events ledger rows."""
        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json([])
            return

        parsed_url = urlparse(self.path)
        query = parse_qs(parsed_url.query)
        host_filter = query.get("host", [None])[0]

        import platform
        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(security_events);")
                columns = {row["name"] for row in cursor.fetchall()}

                query_cols = ["id", "timestamp", "event_type", "severity", "description", "raw_details", "resolved"]
                for col in ("notes", "suppressed", "reviewed_at", "attck_technique", "attck_tactic", "attck_url", "hostname"):
                    if col in columns:
                        query_cols.append(col)

                sql = f"SELECT {', '.join(query_cols)} FROM security_events"
                params = []
                if host_filter:
                    sql += " WHERE (hostname = ? OR (hostname IS NULL AND ? = ?))"
                    params.extend([host_filter, host_filter, platform.node() or "unknown_host"])
                sql += " ORDER BY id DESC;"

                cursor.execute(sql, params)

                alerts = []
                for row in cursor.fetchall():
                    alert_dict = dict(row)
                    for col in ("notes", "suppressed", "reviewed_at", "hostname"):
                        if col not in alert_dict:
                            alert_dict[col] = "" if col in ("notes", "hostname") else (0 if col == "suppressed" else None)
                    for col in ("attck_technique", "attck_tactic", "attck_url"):
                        if col not in alert_dict:
                            alert_dict[col] = None
                    alerts.append(alert_dict)
                self.send_json(alerts)
        except Exception as e:
            self.send_error_response(f"Database query failure: {e}")

    def handle_api_scan(self, post_data):
        """Orchestrate remote fleet scan or remote baseline initialization."""
        host = post_data.get("host")
        user = post_data.get("user")
        key_path = post_data.get("key_path")
        port = post_data.get("port", 22)
        init_flag = post_data.get("init", False)

        if not host or not user:
            self.send_error_response("Missing host or user parameters", 400)
            return

        db_path = self.server.db_path

        if init_flag:
            try:
                current_dir = Path(__file__).resolve().parent
                agent_path = current_dir.parent / "collectors" / "remote_agent.py"
                if not agent_path.exists():
                    self.send_error_response(f"Remote agent script missing at: {agent_path}", 500)
                    return

                remote_agent_code = agent_path.read_text(encoding="utf-8")
                ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
                if port:
                    ssh_cmd.extend(["-p", str(port)])
                if key_path:
                    ssh_cmd.extend(["-i", str(key_path)])

                agent_config = {"critical_paths": [], "critical_dirs": []}
                ssh_cmd.extend([f"{user}@{host}", f"python3 - '{json.dumps(agent_config)}'"])

                proc = subprocess.Popen(
                    ssh_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(input=remote_agent_code)

                if proc.returncode != 0:
                    self.send_error_response(f"SSH baselining failed: {stderr}", 500)
                    return

                telemetry = json.loads(stdout.strip())
                remote_hostname = telemetry.get("hostname", host)

                storage = OrinStorage(db_path)
                with storage.get_connection() as conn:
                    conn.execute("DELETE FROM baseline_kernel_modules WHERE hostname = ?;", (remote_hostname,))
                    conn.execute("DELETE FROM baseline_users WHERE hostname = ?;", (remote_hostname,))
                    conn.execute("DELETE FROM baseline_suid_binaries WHERE hostname = ?;", (remote_hostname,))

                    if "modules" in telemetry:
                         conn.executemany(
                             "INSERT OR IGNORE INTO baseline_kernel_modules (hostname, module_name, memory_size) VALUES (?, ?, ?);",
                             [(remote_hostname, m["module_name"], m["memory_size"]) for m in telemetry["modules"]]
                         )
                    if "users" in telemetry:
                         conn.executemany(
                             """
                             INSERT OR IGNORE INTO baseline_users (hostname, username, uid, gid, home_dir, login_shell)
                             VALUES (?, ?, ?, ?, ?, ?);
                             """,
                             [(remote_hostname, u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in telemetry["users"]]
                         )
                    if "suid" in telemetry:
                         conn.executemany(
                             """
                             INSERT OR IGNORE INTO baseline_suid_binaries (hostname, file_path, owner, grp, permissions, sha256)
                             VALUES (?, ?, ?, ?, ?, ?);
                             """,
                             [(remote_hostname, s["file_path"], s["owner"], s["grp"], s["permissions"], s["sha256"]) for s in telemetry["suid"]]
                         )
                    conn.commit()

                self.send_json({"status": "success", "message": f"Baseline initialized for remote host {remote_hostname}"})
            except Exception as e:
                self.send_error_response(f"Baselines collection/storage error: {e}", 500)
        else:
            from orin.core.scanner import run_remote_scan
            try:
                metrics = run_remote_scan(
                    host=host,
                    user=user,
                    key_path=key_path,
                    port=port,
                    db_path=db_path
                )
                self.send_json({"status": "success", "metrics": metrics})
            except Exception as e:
                self.send_error_response(f"Remote scan error: {e}", 500)

    def handle_api_correlate(self, data):
        """Invoke local AI correlation and return the Markdown briefing."""
        from orin.analysis.ai import run_ai_correlation

        hostnames = data.get("hostnames")
        url = data.get("url", "http://127.0.0.1:11434")
        model = data.get("model", "gemma3:1b")

        try:
            briefing = run_ai_correlation(self.server.db_path, hostnames=hostnames, url=url, model=model)
            self.send_json({"status": "success", "briefing": briefing})
        except Exception as e:
            self.send_error_response(f"AI Correlation failed: {e}")

    def handle_api_snapshots(self):
        """Retrieve historical system snapshots ledger."""
        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json([])
            return

        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots ORDER BY id DESC;")
                snapshots = [dict(row) for row in cursor.fetchall()]
                self.send_json(snapshots)
        except Exception as e:
            self.send_error_response(f"Failed to load snapshots: {e}")

    def handle_api_delta(self, parsed_url):
        """Compute relative telemetry modifications between snapshot IDs."""
        query_params = parse_qs(parsed_url.query)
        base_id = query_params.get("base", [None])[0]
        target_id = query_params.get("target", [None])[0]

        if not base_id or not target_id:
            self.send_error_response("Missing 'base' or 'target' query parameter.", 400)
            return

        db_path = self.server.db_path
        try:
            base_id = int(base_id)
            target_id = int(target_id)
        except ValueError:
            self.send_error_response("Snapshot IDs must be numeric integers.", 400)
            return

        try:
            delta = calculate_snapshot_delta(db_path, base_id, target_id)

            storage = OrinStorage(db_path)
            with storage.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT username, uid, login_shell FROM collected_users WHERE snapshot_id = ?;", (base_id,))
                base_users = {row["username"]: row for row in cursor.fetchall()}
                cursor.execute("SELECT username, uid, login_shell FROM collected_users WHERE snapshot_id = ?;", (target_id,))
                target_users = {row["username"]: row for row in cursor.fetchall()}

                new_users = []
                for username, row in target_users.items():
                    if username not in base_users:
                        new_users.append(dict(row))
                delta["new_users"] = new_users

                cursor.execute("SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ?;", (base_id,))
                base_mods = {row["module_name"]: row for row in cursor.fetchall()}
                cursor.execute("SELECT module_name, memory_size FROM collected_kernel_modules WHERE snapshot_id = ?;", (target_id,))
                target_mods = {row["module_name"]: row for row in cursor.fetchall()}

                new_mods = []
                for mod_name, row in target_mods.items():
                    if mod_name not in base_mods:
                        new_mods.append({"name": row["module_name"], "size": row["memory_size"]})
                delta["new_modules"] = new_mods

                cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (base_id,))
                base_files = {row["file_path"]: row["sha256_hash"] for row in cursor.fetchall()}
                cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (target_id,))
                target_files = {row["file_path"]: row["sha256_hash"] for row in cursor.fetchall()}

                modified_files = []
                for file_path, current_hash in target_files.items():
                    if file_path not in base_files:
                        modified_files.append({"path": file_path, "status": "added"})
                    elif base_files[file_path] != current_hash:
                        modified_files.append({"path": file_path, "status": "modified"})
                for file_path in base_files:
                    if file_path not in target_files:
                        modified_files.append({"path": file_path, "status": "removed"})
                delta["modified_files"] = modified_files

            self.send_json(delta)
        except Exception as e:
            self.send_error_response(f"Timeline delta calculation failure: {e}")

    # API POST Router Handlers
    def handle_api_collect(self):
        """Execute telemetry collector scans and threat rule audits on demand."""
        db_path = self.server.db_path

        # Check if database exists first
        if not db_path.exists():
            self.send_error_response(f"Database vault missing at '{db_path}'. Run 'orin init' first.", 400)
            return

        class MockArgs:
            def __init__(self, database):
                self.database = str(database)

        try:
            from orin.orchestrator import cmd_collect, cmd_analyze

            # Check if database exists before attempting collection
            if not db_path.exists():
                self.send_error_response("Database vault missing. Run 'orin init' first.", 400)
                return

            args = MockArgs(db_path)

            # Capture stdout and stderr to prevent print statements from breaking the response
            import io
            from contextlib import redirect_stdout, redirect_stderr

            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()

            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                try:
                    cmd_collect(args)
                    cmd_analyze(args)
                except SystemExit as e:
                    # If cmd_collect/cmd_analyze calls sys.exit, capture the code
                    if e.code != 0:
                        error_output = stderr_capture.getvalue() or stdout_capture.getvalue()
                        raise RuntimeError(f"Collection process failed with exit code {e.code}: {error_output}")

            storage = OrinStorage(db_path)
            latest_id = None
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM system_snapshots ORDER BY id DESC LIMIT 1;")
                row = cursor.fetchone()
                if row:
                    latest_id = row["id"]

            self.send_json({"status": "success", "snapshot_id": latest_id})
        except SystemExit:
            # Prevent sys.exit() from killing the server
            self.send_error_response("Collection failed: Database operation terminated unexpectedly", 500)
        except Exception as e:
            self.send_error_response(f"On-demand telemetry capture failed: {e}")

    def handle_api_alert_action(self, data):
        """Process analyst triage annotations or status updates on an alert."""
        alert_id = data.get("alert_id")
        action = data.get("action")

        if not alert_id or not action:
            self.send_error_response("Missing 'alert_id' or 'action' parameter.", 400)
            return

        db_path = self.server.db_path
        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%fZ')

                if action == "acknowledge":
                    cursor.execute("UPDATE security_events SET resolved = 1, reviewed_at = ? WHERE id = ?;", (now_str, alert_id))
                elif action == "unresolve":
                    cursor.execute("UPDATE security_events SET resolved = 0, reviewed_at = NULL WHERE id = ?;", (alert_id,))
                elif action == "suppress":
                    cursor.execute("UPDATE security_events SET suppressed = 1 WHERE id = ?;", (alert_id,))
                elif action == "unsuppress":
                    cursor.execute("UPDATE security_events SET suppressed = 0 WHERE id = ?;", (alert_id,))
                elif action == "update_notes":
                    notes = data.get("notes", "")
                    cursor.execute("UPDATE security_events SET notes = ? WHERE id = ?;", (notes, alert_id))
                elif action == "override_severity":
                    severity = data.get("severity", "").lower()
                    if severity not in ("low", "medium", "high", "critical"):
                        self.send_error_response("Invalid severity value.", 400)
                        return
                    cursor.execute("UPDATE security_events SET severity = ? WHERE id = ?;", (severity, alert_id))
                else:
                    self.send_error_response(f"Unsupported alert action: {action}", 400)
                    return

                conn.commit()
            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Failed to update alert state: {e}")

    def handle_api_baseline_refresh(self):
        """Regenerate baseline system configuration logs."""
        db_path = self.server.db_path
        storage = OrinStorage(db_path)
        try:
            baseline_modules = gather_loaded_kernel_modules()
            baseline_accounts = gather_system_accounts()

            with storage.get_connection() as conn:
                if baseline_modules:
                    conn.executemany(
                        "INSERT OR IGNORE INTO baseline_kernel_modules (module_name, memory_size) VALUES (?, ?);",
                        [(m["module_name"], m["memory_size"]) for m in baseline_modules]
                    )
                if baseline_accounts:
                    conn.executemany(
                        """
                        INSERT OR IGNORE INTO baseline_users (username, uid, gid, home_dir, login_shell)
                        VALUES (?, ?, ?, ?, ?);
                        """,
                        [(u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"]) for u in baseline_accounts]
                    )
                conn.commit()

            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Baseline synchronization routine failed: {e}")

    def handle_api_baseline_add(self, data):
        """Insert a specific user or LKM kernel module into allowlist tables."""
        target_type = data.get("type")
        name = data.get("name")

        if not target_type or not name:
            self.send_error_response("Missing 'type' or 'name' parameter.", 400)
            return

        db_path = self.server.db_path
        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                if target_type == "user":
                    accounts = gather_system_accounts()
                    found = [u for u in accounts if u["username"] == name]

                    if found:
                        u = found[0]
                        conn.execute(
                            "INSERT OR REPLACE INTO baseline_users (username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?);",
                            (u["username"], u["uid"], u["gid"], u["home_dir"], u["login_shell"])
                        )
                    else:
                        conn.execute(
                            "INSERT OR REPLACE INTO baseline_users (username, uid, gid, home_dir, login_shell) VALUES (?, 1000, 1000, NULL, '/bin/bash');",
                            (name,)
                        )
                elif target_type == "module":
                    mods = gather_loaded_kernel_modules()
                    found = [m for m in mods if m["module_name"] == name]
                    size = found[0]["memory_size"] if found else 16384

                    conn.execute(
                        "INSERT OR REPLACE INTO baseline_kernel_modules (module_name, memory_size) VALUES (?, ?);",
                        (name, size)
                    )
                else:
                    self.send_error_response("Invalid baseline allowlist type.", 400)
                    return

                conn.commit()
            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Allowlist registration failed: {e}")

    def handle_api_config_update(self, data):
        """Validate and write configuration updates atomically back to the resolved source path."""
        required_keys = {"expected_ports", "whitelisted_processes", "critical_paths", "critical_dirs"}

        if not all(key in data for key in required_keys):
            self.send_error_response("Missing required configuration fields.", 400)
            return

        try:
            data["expected_ports"] = [int(p) for p in data["expected_ports"]]
            data["whitelisted_processes"] = [str(p).strip() for p in data["whitelisted_processes"]]
            data["critical_paths"] = [str(p).strip() for p in data["critical_paths"]]
            data["critical_dirs"] = [str(p).strip() for p in data["critical_dirs"]]
        except Exception as e:
            self.send_error_response(f"Invalid field values or formatting: {e}", 400)
            return

        try:
            # Dynamically import and fetch the active file location source configuration mapping
            from orin.core.config import load_config_with_source
            _, active_config_path = load_config_with_source()

            # Write to a temp staging file and rename atomically
            temp_path = active_config_path.with_suffix(".tmp")
            with open(temp_path, "w") as f:
                json.dump(data, f, indent=2)
            temp_path.rename(active_config_path)
            self.send_json({"status": "success"})
        except Exception as e:
            self.send_error_response(f"Atomic configuration serialization failed: {e}")

    def handle_api_schedule_status(self):
        """Return the current cron automation schedule status."""
        result = {"active": False, "mode": None, "cron_entry": None, "interval_minutes": None}

        # Check system-wide file first
        if CRON_D_FILE.exists():
            try:
                content = CRON_D_FILE.read_text().strip()
                result["active"] = True
                result["mode"] = "system"
                result["cron_entry"] = content
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if parts and parts[0].startswith("*/"):
                            try:
                                result["interval_minutes"] = int(parts[0][2:])
                            except ValueError:
                                pass
                        break
            except Exception:
                pass

        if not result["active"]:
            # Check user crontab
            try:
                cron_output = subprocess.check_output(
                    ["crontab", "-l"], stderr=subprocess.DEVNULL
                ).decode()
                for line in cron_output.splitlines():
                    if "orin collect" in line or "orin-collect" in line:
                        result["active"] = True
                        result["mode"] = "user"
                        result["cron_entry"] = line.strip()
                        parts = line.strip().split()
                        if parts and parts[0].startswith("*/"):
                            try:
                                result["interval_minutes"] = int(parts[0][2:])
                            except ValueError:
                                pass
                        break
            except Exception:
                pass

        self.send_json(result)

    def handle_api_schedule_install(self, data):
        """Install or update the cron automation schedule."""
        interval = data.get("interval_minutes", 10)
        try:
            interval = int(interval)
            if interval < 1 or interval > 1440:
                self.send_error_response("Interval must be between 1 and 1440 minutes.", 400)
                return
        except (TypeError, ValueError):
            self.send_error_response("Invalid interval value.", 400)
            return

        try:
            from orin.core.scheduler import install_schedule
            install_schedule(self.server.db_path, interval)
            self.send_json({"status": "success", "interval_minutes": interval})
        except Exception as e:
            self.send_error_response(f"Failed to install schedule: {e}")

    def handle_api_schedule_remove(self):
        """Remove the active cron automation schedule."""
        try:
            from orin.core.scheduler import remove_schedule
            remove_schedule()
            self.send_json({"status": "success"})
        except SystemExit:
            # remove_schedule may call sys.exit(1) on permission errors
            self.send_error_response("Permission denied. Run orin serve as root to manage the system-wide schedule.")
        except Exception as e:
            self.send_error_response(f"Failed to remove schedule: {e}")

    def handle_api_snapshot_telemetry(self, parsed_url: Any) -> None:
        """Fetch all collected telemetry records for a given snapshot ID.

        Parameters
        ----------
        parsed_url : Any
            The parsed request URL.
        """
        from urllib.parse import parse_qs
        query_params = parse_qs(parsed_url.query)
        snap_id_str = query_params.get("id", [None])[0]

        db_path = self.server.db_path
        if not db_path.exists():
            self.send_json({})
            return

        storage = OrinStorage(db_path)
        try:
            with storage.get_connection() as conn:
                cursor = conn.cursor()

                if not snap_id_str:
                    cursor.execute("SELECT id FROM system_snapshots ORDER BY id DESC LIMIT 1;")
                    row = cursor.fetchone()
                    if not row:
                        self.send_json({})
                        return
                    snap_id = row["id"]
                else:
                    try:
                        snap_id = int(snap_id_str)
                    except ValueError:
                        self.send_error_response("Snapshot ID must be an integer.", 400)
                        return

                cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots WHERE id = ?;", (snap_id,))
                meta_row = cursor.fetchone()
                if not meta_row:
                    self.send_error_response(f"Snapshot with ID {snap_id} not found.", 404)
                    return
                metadata = dict(meta_row)

                cursor.execute("SELECT pid, ppid, name, exe, cmdline FROM collected_processes WHERE snapshot_id = ?;", (snap_id,))
                processes = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT port, protocol, process_name FROM collected_ports WHERE snapshot_id = ?;", (snap_id,))
                ports = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT local_ip, local_port, remote_ip, remote_port, state, process_name FROM collected_outbound_connections WHERE snapshot_id = ?;", (snap_id,))
                outbound = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT module_name, memory_size, instances_loaded FROM collected_kernel_modules WHERE snapshot_id = ?;", (snap_id,))
                kernel_modules = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT user_account, key_type, fingerprint, raw_key_comment FROM collected_ssh_keys WHERE snapshot_id = ?;", (snap_id,))
                ssh_keys = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT username, uid, gid, home_dir, login_shell FROM collected_users WHERE snapshot_id = ?;", (snap_id,))
                users = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT file_path, sha256_hash FROM collected_file_hashes WHERE snapshot_id = ?;", (snap_id,))
                file_hashes = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT pid, exe, sha256, md5, vault_path FROM collected_deleted_binaries WHERE snapshot_id = ?;", (snap_id,))
                deleted_binaries = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT interface, flags, is_promiscuous FROM collected_promisc_interfaces WHERE snapshot_id = ?;", (snap_id,))
                promisc_interfaces = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason FROM collected_wtmp_sessions WHERE snapshot_id = ?;", (snap_id,))
                wtmp_sessions = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT username, uid, line, host, login_time, anomaly_detected, anomaly_reason FROM collected_lastlog_records WHERE snapshot_id = ?;", (snap_id,))
                lastlog_records = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT package, file_path, expected_md5, actual_md5, actual_sha256, status FROM collected_pkg_integrity WHERE snapshot_id = ?;", (snap_id,))
                pkg_integrity = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT source, user, schedule, command FROM collected_crontabs WHERE snapshot_id = ?;", (snap_id,))
                crontabs = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT file_path, owner, grp, permissions, sha256 FROM collected_suid_binaries WHERE snapshot_id = ?;", (snap_id,))
                suid_binaries = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT bpf_id, name, type, tag, gpl_compatible FROM collected_ebpf_programs WHERE snapshot_id = ?;", (snap_id,))
                ebpf_programs = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT path, type FROM collected_ebpf_pinned WHERE snapshot_id = ?;", (snap_id,))
                ebpf_pinned = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT line FROM collected_ld_preload WHERE snapshot_id = ?;", (snap_id,))
                ld_preload = [r["line"] for r in cursor.fetchall()]

                cursor.execute("SELECT pid, fd_num, fd_type, resolved_path FROM collected_special_fds WHERE snapshot_id = ?;", (snap_id,))
                special_fds = [dict(r) for r in cursor.fetchall()]

                cursor.execute("SELECT log_line FROM collected_auth_logs WHERE snapshot_id = ?;", (snap_id,))
                auth_logs = [r["log_line"] for r in cursor.fetchall()]

                cursor.execute("SELECT name, status, enabled, user, description FROM collected_services WHERE snapshot_id = ?;", (snap_id,))
                services = [dict(r) for r in cursor.fetchall()]

                self.send_json({
                    "metadata": metadata,
                    "processes": processes,
                    "ports": ports,
                    "outbound": outbound,
                    "kernel_modules": kernel_modules,
                    "ssh_keys": ssh_keys,
                    "users": users,
                    "file_hashes": file_hashes,
                    "deleted_binaries": deleted_binaries,
                    "promisc_interfaces": promisc_interfaces,
                    "wtmp_sessions": wtmp_sessions,
                    "lastlog_records": lastlog_records,
                    "pkg_integrity": pkg_integrity,
                    "crontabs": crontabs,
                    "suid_binaries": suid_binaries,
                    "ebpf_programs": ebpf_programs,
                    "ebpf_pinned": ebpf_pinned,
                    "ld_preload": ld_preload,
                    "special_fds": special_fds,
                    "auth_logs": auth_logs,
                    "services": services
                })
        except Exception as e:
            self.send_error_response(f"Failed to load snapshot telemetry: {e}")

    def handle_api_process_kill(self, data: dict[str, Any]) -> None:
        """Terminate a process on the local node or a remote node over SSH.

        Parameters
        ----------
        data : dict[str, Any]
            The request payload containing process and connection info.
        """
        pid = data.get("pid")
        hostname = data.get("hostname")

        if pid is None:
            self.send_error_response("Missing 'pid' parameter.", 400)
            return

        try:
            pid = int(pid)
        except ValueError:
            self.send_error_response("Process ID must be an integer.", 400)
            return

        import platform
        local_host = platform.node() or "unknown_host"

        if not hostname or hostname == local_host or hostname in ("localhost", "127.0.0.1"):
            import signal
            try:
                os.kill(pid, signal.SIGKILL)
                self.send_json({"status": "success", "message": f"Successfully killed local PID {pid}."})
            except ProcessLookupError:
                self.send_error_response(f"Process with PID {pid} not found.", 404)
            except PermissionError:
                self.send_error_response(f"Permission denied killing PID {pid}.", 403)
            except Exception as e:
                self.send_error_response(f"Failed to kill process locally: {e}")
        else:
            ssh_host = data.get("ssh_host")
            ssh_user = data.get("ssh_user")
            ssh_port = data.get("ssh_port", 22)
            ssh_key = data.get("ssh_key")

            if not ssh_host or not ssh_user:
                self.send_error_response("Remote process requires 'ssh_host' and 'ssh_user' parameters.", 400)
                return

            import subprocess
            ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
            if ssh_port:
                ssh_cmd.extend(["-p", str(ssh_port)])
            if ssh_key:
                ssh_cmd.extend(["-i", str(ssh_key)])

            ssh_cmd.extend([f"{ssh_user}@{ssh_host}", f"kill -9 {pid}"])

            try:
                proc = subprocess.Popen(
                    ssh_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(timeout=10)
                if proc.returncode == 0:
                    self.send_json({"status": "success", "message": f"Successfully killed remote PID {pid} on host {hostname}."})
                else:
                    self.send_error_response(f"Remote command execution failed over SSH (code {proc.returncode}): {stderr.strip()}")
            except subprocess.TimeoutExpired:
                self.send_error_response("SSH connection timed out trying to kill process.", 504)
            except Exception as e:
                self.send_error_response(f"Failed to execute remote SSH command: {e}")


def make_websocket_frame(text: str) -> bytes:
    """Construct an RFC 6455 unmasked WebSocket text frame from the server."""
    data = text.encode('utf-8')
    length = len(data)
    if length < 126:
        header = bytes([0x81, length])
    elif length < 65536:
        header = bytes([0x81, 126]) + length.to_bytes(2, byteorder='big')
    else:
        header = bytes([0x81, 127]) + length.to_bytes(8, byteorder='big')
    return header + data


def start_websocket_alert_poller(server_instance):
    """Start background daemon thread polling security_events for real-time WebSocket delivery."""
    def poller_loop():
        db_path = server_instance.db_path
        last_seen_id = 0

        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path), timeout=30.0)
                conn.execute("PRAGMA busy_timeout=30000;")
                try:
                    cur = conn.execute("SELECT MAX(id) FROM security_events;")
                    row = cur.fetchone()
                    if row and row[0] is not None:
                        last_seen_id = row[0]
                finally:
                    conn.close()
            except Exception:
                pass

        while not getattr(server_instance, "_shutdown", False):
            time.sleep(2.0)

            has_clients = False
            with server_instance.active_ws_lock:
                has_clients = len(server_instance.active_ws_clients) > 0

            if not has_clients or not db_path.exists():
                continue

            try:
                conn = sqlite3.connect(str(db_path), timeout=30.0)
                conn.execute("PRAGMA busy_timeout=30000;")
                conn.row_factory = sqlite3.Row
                try:
                    cur = conn.execute(
                        "SELECT id, timestamp, event_type, severity, description, resolved, suppressed FROM security_events WHERE id > ? ORDER BY id ASC;",
                        (last_seen_id,)
                    )
                    rows = cur.fetchall()
                    if rows:
                        new_alerts = [dict(r) for r in rows]
                        last_seen_id = max(r["id"] for r in new_alerts)
                        
                        broadcast_data = json.dumps({
                            "type": "new_alerts",
                            "alerts": new_alerts
                        })
                        frame = make_websocket_frame(broadcast_data)
                        
                        with server_instance.active_ws_lock:
                            dead_clients = set()
                            for client in server_instance.active_ws_clients:
                                try:
                                    client.wfile.write(frame)
                                    client.wfile.flush()
                                except Exception:
                                    dead_clients.add(client)
                            
                            for client in dead_clients:
                                server_instance.active_ws_clients.discard(client)
                finally:
                    conn.close()
            except Exception:
                pass

    t = threading.Thread(target=poller_loop, daemon=True)
    t.start()


def start_server(
    db_path,
    host="127.0.0.1",
    port=8000,
    username=None,
    password=None,
    cert_path=None,
    key_path=None,
    no_auth=False,
    passphrase_file=None,
    passphrase_prompt=False,
    passphrase_env_var=None,
    token_file=None
):
    """Initialize and run the blocking HTTPServer loop.

    Parameters
    ----------
    db_path : Union[str, Path]
        Path to the SQLite database vault
    host : str, optional
        Host address to bind (default: 127.0.0.1)
    port : int, optional
        Port to bind (default: 8000)
    username : str, optional
        Username for legacy Basic Auth
    password : str, optional
        Password for legacy Basic Auth
    cert_path : str, optional
        Path to SSL certificate file
    key_path : str, optional
        Path to SSL private key file
    no_auth : bool, optional
        Disable authentication entirely
    passphrase_file : str, optional
        Path to file containing vault passphrase
    passphrase_prompt : bool, optional
        Prompt interactively for vault passphrase
    passphrase_env_var : str, optional
        Custom environment variable name for vault passphrase
    token_file : str, optional
        Path to save/load session token file
    """
    db_path = Path(db_path).resolve()

    # Initialize credential manager for secure token handling
    cred_manager = CredentialManager()

    # Load vault passphrase using specified method
    passphrase_loaded = False
    if passphrase_file:
        try:
            cred_manager.load_vault_passphrase_from_file(passphrase_file, required=False)
            passphrase_loaded = cred_manager.get_vault_passphrase() is not None
            if passphrase_loaded:
                print(f"[*] Vault passphrase loaded from file: {passphrase_file}")
        except Exception as e:
            print(f"[!] Warning: Failed to load vault passphrase from file: {e}", file=sys.stderr)
    elif passphrase_prompt:
        try:
            cred_manager.load_vault_passphrase_from_prompt(required=False, confirm=False)
            passphrase_loaded = cred_manager.get_vault_passphrase() is not None
            if passphrase_loaded:
                print("[*] Vault passphrase loaded via interactive prompt")
        except Exception as e:
            print(f"[!] Warning: Failed to load vault passphrase from prompt: {e}", file=sys.stderr)
    elif passphrase_env_var:
        try:
            cred_manager.load_vault_passphrase_from_env_var_name(passphrase_env_var, required=False)
            passphrase_loaded = cred_manager.get_vault_passphrase() is not None
            if passphrase_loaded:
                print(f"[*] Vault passphrase loaded from environment variable: {passphrase_env_var}")
        except Exception as e:
            print(f"[!] Warning: Failed to load vault passphrase from env var: {e}", file=sys.stderr)
    else:
        # Default: use standard ORIN_VAULT_PASSPHRASE env var
        cred_manager.load_vault_passphrase(required=False)
        passphrase_loaded = cred_manager.get_vault_passphrase() is not None
        if passphrase_loaded:
            print(f"[*] Vault passphrase loaded from environment variable: {cred_manager.vault_passphrase_env}")

    # Auto-generate a cryptographically random session token unless auth is
    # explicitly disabled (--no-auth) or legacy Basic Auth credentials were supplied.
    # Only the person who ran `sudo orin serve` sees the token in stdout — this is
    # the Jupyter-style protection model.
    if not no_auth and not (username and password):
        # Check if token should be loaded from file first
        if token_file and Path(token_file).exists():
            try:
                cred_manager.load_session_token_from_file(token_file, required=False)
                if cred_manager.get_session_token():
                    print(f"[*] Session token loaded from file: {token_file}")
            except Exception as e:
                print(f"[!] Warning: Failed to load session token from file, generating new one: {e}", file=sys.stderr)
                cred_manager.generate_session_token()
        else:
            cred_manager.generate_session_token()

        # Save token to file if requested
        if token_file and cred_manager.get_session_token():
            try:
                saved_path = cred_manager.save_session_token_to_file(token_file)
                if saved_path:
                    print(f"[*] Session token saved to file with restricted permissions (0600): {saved_path}")
            except Exception as e:
                print(f"[!] Warning: Failed to save session token to file: {e}", file=sys.stderr)

    # Load dashboard rate limiting configuration from config
    config_dict = load_config()
    dashboard_config = config_dict.get("dashboard", {})
    rl_config = dashboard_config.get("rate_limit", {})
    rl_enabled = rl_config.get("enabled", True)
    rl_rate = float(rl_config.get("rate", 5.0))
    rl_capacity = float(rl_config.get("capacity", 10.0))

    class OrinHTTPServer(ThreadingHTTPServer):
        def __init__(self, *args, **kwargs):
            self.db_path = db_path
            self.username = username
            self.password = password
            # Store SecureCredential wrapper instead of raw token
            self.session_token = cred_manager.get_session_token()
            self.no_auth = no_auth
            self.rate_limiter = IPTokenBucketLimiter(rate=rl_rate, capacity=rl_capacity) if rl_enabled else None
            self.active_ws_clients = set()
            self.active_ws_lock = threading.Lock()
            self._shutdown = False
            super().__init__(*args, **kwargs)

    server_address = (host, port)
    httpd = OrinHTTPServer(server_address, OrinHTTPHandler)

    if cert_path and key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Add this line
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        proto = "https"
    else:
        proto = "http"

    if db_path.exists():
        try:
            storage = OrinStorage(db_path)
            storage.initialize_db()
        except Exception as e:
            print(f"[!] Warning: Database migration failed on startup: {e}", file=sys.stderr)

    base_url = f"{proto}://{host}:{port}"
    print("[+] Orin Forensic Console bound to local socket interface.")

    if no_auth:
        print("[!] WARNING: Authentication DISABLED. Any user on this host can access the console.")
        print(f"[+] Access: {base_url}/")
    elif cred_manager.get_session_token():
        # Use credential manager to generate display URL
        access_url = cred_manager.get_token_display_url(base_url)
        w = max(len(access_url) + 4, 66)
        border = "=" * w
        print("")
        print(f"  {border}")
        print(f"  {'ORIN FORENSIC CONSOLE — SECURE ACCESS TOKEN':^{w}}")
        print(f"  {border}")
        print(f"  {'Open this URL in your browser (token refreshes on restart):':^{w}}")
        print(f"  {border}")
        print(f"  {access_url}")
        print(f"  {border}")
        print(f"  {'Keep this URL private — it grants full console access.':^{w}}")
        print(f"  {border}")
        print("")
    else:
        print(f"[+] Access: {base_url}/  (Basic Auth: {username})")

    # Start background WebSocket alert checker
    start_websocket_alert_poller(httpd)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Orin Forensic Console server...")
        httpd._shutdown = True
        httpd.server_close()
        sys.exit(0)