# Copyright (C) 2026 Musa Jaradat
# Licensed under GNU AGPLv3
"""
Unit tests for orin.core.hub_server – TenantManager and supporting functions.
The HTTP handler is tested via integration tests for the core functionality.
"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from orin.core.hub_server import TenantManager, OrinHubHTTPHandler, start_server


class TestTenantManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)
        self.manager = TenantManager(self.db_path)

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # TenantManager initialization
    # ------------------------------------------------------------------ #
    def test_init_creates_tables(self):
        """Tables should exist after TenantManager initialization."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cursor.fetchall()}
        conn.close()
        self.assertIn("hub_tenants", tables)
        self.assertIn("hub_hosts", tables)
        self.assertIn("hub_admins", tables)
        self.assertIn("hub_audit_log", tables)
        self.assertIn("hub_rate_limits", tables)

    def test_init_with_nonexistent_db(self):
        """Initializing with a new path should create the database file."""
        new_path = self.db_path.parent / "new_hub_test.db"
        try:
            tm = TenantManager(new_path)
            self.assertTrue(new_path.exists())
        finally:
            if new_path.exists():
                os.unlink(new_path)

    def test_init_loads_active_tenants(self):
        """Tenants flagged is_active=1 should be loaded on init."""
        # Create a tenant and then reload
        t_id, api_key = self.manager.create_tenant("test-org")
        # Reload manager
        new_manager = TenantManager(self.db_path)
        self.assertIn(t_id, new_manager.tenants)

    # ------------------------------------------------------------------ #
    # Tenant CRUD
    # ------------------------------------------------------------------ #
    def test_create_tenant_returns_id_and_key(self):
        t_id, api_key = self.manager.create_tenant("org-alpha")
        self.assertIsNotNone(t_id)
        self.assertTrue(api_key.startswith("orin_hub_"))
        self.assertIn(t_id, self.manager.tenants)

    def test_create_tenant_with_metadata(self):
        t_id, _ = self.manager.create_tenant(
            "meta-org", max_hosts=50, metadata={"env": "prod"}, is_admin=True
        )
        tenant = self.manager.tenants[t_id]
        self.assertEqual(tenant["max_hosts"], 50)
        self.assertEqual(tenant["is_admin"], True)

    def test_validate_api_key_success(self):
        t_id, api_key = self.manager.create_tenant("secure-org")
        tenant = self.manager.validate_api_key(api_key)
        self.assertIsNotNone(tenant)
        self.assertEqual(tenant["id"], t_id)

    def test_validate_api_key_wrong_key(self):
        self.manager.create_tenant("secure-org")
        result = self.manager.validate_api_key("wrong_key_xyz")
        self.assertIsNone(result)

    def test_validate_api_key_updates_activity(self):
        t_id, api_key = self.manager.create_tenant("active-org")
        self.assertIsNone(self.manager.tenants[t_id].get("last_activity"))
        self.manager.validate_api_key(api_key)
        self.assertIsNotNone(self.manager.tenants[t_id].get("last_activity"))

    # ------------------------------------------------------------------ #
    # Host management
    # ------------------------------------------------------------------ #
    def test_register_host_success(self):
        t_id, _ = self.manager.create_tenant("hosting-org")
        host_id = self.manager.register_host(t_id, "web01", agent_version="1.0")
        self.assertIsNotNone(host_id)
        self.assertIn("web01", host_id)

    def test_register_host_unknown_tenant(self):
        result = self.manager.register_host("nonexistent-tenant", "host")
        self.assertIsNone(result)

    def test_register_host_respects_limit(self):
        t_id, _ = self.manager.create_tenant("limited-org", max_hosts=1)
        h1 = self.manager.register_host(t_id, "host-a")
        h2 = self.manager.register_host(t_id, "host-b")
        self.assertIsNotNone(h1)
        self.assertIsNone(h2)  # Should be rejected

    def test_update_host_heartbeat(self):
        t_id, _ = self.manager.create_tenant("heartbeat-org")
        host_id = self.manager.register_host(t_id, "server01")
        # Should not raise
        self.manager.update_host_heartbeat(host_id)

    def test_list_hosts_empty(self):
        t_id, _ = self.manager.create_tenant("empty-org")
        hosts = self.manager.list_hosts(t_id)
        self.assertEqual(hosts, [])

    def test_list_hosts_returns_registered(self):
        t_id, _ = self.manager.create_tenant("list-org")
        self.manager.register_host(t_id, "host-a")
        self.manager.register_host(t_id, "host-b")
        hosts = self.manager.list_hosts(t_id)
        self.assertEqual(len(hosts), 2)

    def test_list_hosts_unknown_tenant(self):
        result = self.manager.list_hosts("not-a-tenant")
        self.assertEqual(result, [])

    def test_get_tenant_stats(self):
        t_id, _ = self.manager.create_tenant("stats-org")
        self.manager.register_host(t_id, "h1")
        self.manager.register_host(t_id, "h2")
        stats = self.manager.get_tenant_stats(t_id)
        self.assertIsNotNone(stats)
        self.assertEqual(stats["total_hosts"], 2)

    def test_get_tenant_stats_unknown_tenant(self):
        result = self.manager.get_tenant_stats("no-tenant")
        self.assertIsNone(result)

    # ------------------------------------------------------------------ #
    # Admin user management
    # ------------------------------------------------------------------ #
    def test_create_admin_user(self):
        admin_id = self.manager.create_admin_user("admin1", "secret123")
        self.assertIsNotNone(admin_id)

    def test_create_admin_user_duplicate_raises(self):
        self.manager.create_admin_user("admin1", "secret123")
        with self.assertRaises(ValueError):
            self.manager.create_admin_user("admin1", "other_pass")

    def test_validate_admin_credentials_success(self):
        self.manager.create_admin_user("sysadmin", "strongpass")
        result = self.manager.validate_admin_credentials("sysadmin", "strongpass")
        self.assertIsNotNone(result)
        self.assertEqual(result["username"], "sysadmin")
        # Password hash should NOT be in result
        self.assertNotIn("password_hash", result)

    def test_validate_admin_credentials_wrong_password(self):
        self.manager.create_admin_user("sysadmin", "correct_pass")
        result = self.manager.validate_admin_credentials("sysadmin", "wrong_pass")
        self.assertIsNone(result)

    def test_validate_admin_credentials_unknown_user(self):
        result = self.manager.validate_admin_credentials("nobody", "pass")
        self.assertIsNone(result)

    # ------------------------------------------------------------------ #
    # Audit log
    # ------------------------------------------------------------------ #
    def test_log_audit_event(self):
        self.manager.log_audit_event(
            actor_type="admin",
            action="login",
            actor_id="admin-1",
            resource_type="session",
            details={"ip": "127.0.0.1"},
            ip_address="127.0.0.1",
            user_agent="TestAgent/1.0",
        )
        logs = self.manager.get_audit_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["action"], "login")
        self.assertEqual(logs[0]["actor_type"], "admin")

    def test_get_audit_logs_filtered_by_actor_type(self):
        self.manager.log_audit_event(actor_type="admin", action="login")
        self.manager.log_audit_event(actor_type="agent", action="heartbeat")
        admin_logs = self.manager.get_audit_logs(actor_type="admin")
        self.assertEqual(len(admin_logs), 1)
        self.assertEqual(admin_logs[0]["actor_type"], "admin")

    def test_get_audit_logs_filtered_by_action(self):
        self.manager.log_audit_event(actor_type="admin", action="login")
        self.manager.log_audit_event(actor_type="agent", action="data_upload")
        upload_logs = self.manager.get_audit_logs(action="data_upload")
        self.assertEqual(len(upload_logs), 1)
        self.assertEqual(upload_logs[0]["action"], "data_upload")

    def test_get_audit_logs_limit(self):
        for i in range(10):
            self.manager.log_audit_event(actor_type="system", action=f"action_{i}")
        logs = self.manager.get_audit_logs(limit=5)
        self.assertLessEqual(len(logs), 5)

    # ------------------------------------------------------------------ #
    # Rate limiting
    # ------------------------------------------------------------------ #
    def test_rate_limit_allows_initial_requests(self):
        allowed = self.manager.check_rate_limit("127.0.0.1", "/api/data", max_requests=5)
        self.assertTrue(allowed)

    def test_rate_limit_blocks_after_max(self):
        identifier = "192.168.1.1"
        endpoint = "/api/upload"
        # Make max_requests requests (all should succeed)
        for _ in range(3):
            self.manager.check_rate_limit(identifier, endpoint, max_requests=3)
        # Next request should be blocked
        result = self.manager.check_rate_limit(identifier, endpoint, max_requests=3)
        self.assertFalse(result)

    def test_rate_limit_different_endpoints_independent(self):
        identifier = "10.0.0.1"
        self.manager.check_rate_limit(identifier, "/api/v1", max_requests=1)
        self.manager.check_rate_limit(identifier, "/api/v1", max_requests=1)
        # Different endpoint should still be allowed
        allowed = self.manager.check_rate_limit(identifier, "/api/v2", max_requests=1)
        self.assertTrue(allowed)

    def test_rate_limit_different_identifiers_independent(self):
        endpoint = "/api/data"
        # Fill up for identifier A
        for _ in range(2):
            self.manager.check_rate_limit("client-A", endpoint, max_requests=2)
        result_a = self.manager.check_rate_limit("client-A", endpoint, max_requests=2)
        result_b = self.manager.check_rate_limit("client-B", endpoint, max_requests=2)
        self.assertFalse(result_a)
        self.assertTrue(result_b)


class TestOrinHubServer(unittest.TestCase):
    def setUp(self):
        import threading
        import urllib.request
        from orin.core.database import OrinStorage
        from http.server import HTTPServer

        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = Path(self.tmp.name)

        self.manager = TenantManager(self.db_path)
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()

        OrinHubHTTPHandler.db_path = self.db_path
        OrinHubHTTPHandler.tenant_manager = self.manager
        OrinHubHTTPHandler.no_auth = False
        OrinHubHTTPHandler.basic_auth_file = None
        OrinHubHTTPHandler.token_file = None
        OrinHubHTTPHandler.basic_auth_users = {}

        self.httpd = HTTPServer(("127.0.0.1", 0), OrinHubHTTPHandler)
        self.port = self.httpd.server_port

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def make_request(self, path, method="GET", headers=None, data=None):
        import urllib.request
        import json
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if data is not None:
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(data).encode("utf-8")
        return urllib.request.urlopen(req)

    def test_health_check(self):
        import json
        res = self.make_request("/health")
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        # /health now returns the structured liveness payload from orin.core.health
        self.assertEqual(data["status"], "alive")
        self.assertIn("version", data)
        self.assertIn("uptime_s", data)
        self.assertIn("vault_exists", data)
        self.assertIn("timestamp", data)

    def test_dashboard(self):
        res = self.make_request("/dashboard")
        self.assertEqual(res.status, 200)
        content = res.read().decode()
        self.assertIn("<!DOCTYPE html>", content)

    def test_auth_failures(self):
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/status")
        self.assertEqual(ctx.exception.code, 401)

        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/status", headers={"X-API-Key": "invalid_key"})
        self.assertEqual(ctx.exception.code, 401)

    def test_admin_and_tenant_operations(self):
        import json
        import urllib.error
        # Create admin user
        self.manager.create_admin_user("superadmin", "pass123")

        # Test creating tenant
        headers = {
            "X-Admin-Username": "superadmin",
            "X-Admin-Password": "pass123"
        }
        res = self.make_request("/api/tenants", method="POST", headers=headers, data={"name": "org-x"})
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode())
        tenant_id = data["tenant_id"]
        api_key = data["api_key"]

        # Register host
        headers = {"X-API-Key": api_key}
        res = self.make_request("/api/register", method="POST", headers=headers, data={"hostname": "host-1", "agent_version": "1.1"})
        self.assertEqual(res.status, 200)
        reg_data = json.loads(res.read().decode())
        host_id = reg_data["host_id"]

        # Send heartbeat
        res = self.make_request("/api/heartbeat", method="POST", headers=headers, data={"host_id": host_id})
        self.assertEqual(res.status, 200)

        # Get status
        res = self.make_request("/api/status", headers=headers)
        self.assertEqual(res.status, 200)

        # Get hosts
        res = self.make_request("/api/hosts", headers=headers)
        self.assertEqual(res.status, 200)
        hosts_data = json.loads(res.read().decode())
        self.assertEqual(hosts_data["count"], 1)

        # Import snapshot data
        snapshot_data = {
            "type": "snapshot",
            "host_id": host_id,
            "data": {
                "processes": [{"pid": 101, "ppid": 1, "name": "systemd", "exe": "/lib/systemd", "cmdline": "/lib/systemd", "ancestry_path": ""}],
                "ports": [{"port": 80, "protocol": "tcp", "process_name": "nginx", "address": "0.0.0.0"}],
                "kernel_modules": [{"module_name": "ext4", "memory_size": 1000, "holders": "", "instances_loaded": 1}],
                "users": [{"username": "root", "uid": 0, "gid": 0, "home_dir": "/root", "login_shell": "/bin/bash"}],
                "security_events": [{"event_type": "rootkit", "severity": "critical", "description": "Diamorphine detected", "timestamp": "2026-06-11T12:00:00Z"}]
            }
        }
        res = self.make_request("/api/import", method="POST", headers=headers, data=snapshot_data)
        self.assertEqual(res.status, 200)

        # Import events data
        events_data = {
            "type": "events",
            "host_id": host_id,
            "data": [
                {"event_type": "ssh_login", "severity": "medium", "description": "Successful root login", "timestamp": "2026-06-11T12:00:00Z"}
            ]
        }
        res = self.make_request("/api/import", method="POST", headers=headers, data=events_data)
        self.assertEqual(res.status, 200)

        # Import baseline data
        baseline_data = {
            "type": "baseline",
            "host_id": host_id,
            "data": {
                "hostname": "host-1",
                "kernel_modules": [{"module_name": "ext4", "memory_size": 1000}]
            }
        }
        res = self.make_request("/api/import", method="POST", headers=headers, data=baseline_data)
        self.assertEqual(res.status, 200)

        # Get stats
        res = self.make_request("/api/stats", headers=headers)
        self.assertEqual(res.status, 200)

        # Get vault info
        res = self.make_request("/api/vault/info", headers=headers)
        self.assertEqual(res.status, 200)

        # Get alerts
        res = self.make_request("/api/alerts", headers=headers)
        self.assertEqual(res.status, 200)

        # Get diff
        res = self.make_request("/api/diff", headers=headers)
        self.assertEqual(res.status, 200)

        # Get telemetry
        res = self.make_request("/api/telemetry", headers=headers)
        self.assertEqual(res.status, 200)

        # Get config
        res = self.make_request("/api/config", headers=headers)
        self.assertEqual(res.status, 200)

        # Get export
        res = self.make_request("/api/export/snapshot", headers=headers)
        self.assertEqual(res.status, 200)

        res = self.make_request("/api/export/events", headers=headers)
        self.assertEqual(res.status, 200)

        # Get admin audit logs
        res = self.make_request("/api/admin/audit-logs", headers={
            "X-Admin-Username": "superadmin",
            "X-Admin-Password": "pass123"
        })
        self.assertEqual(res.status, 200)

        # Test token file auth
        token_tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        token_tmp.write(api_key.encode())
        token_tmp.close()
        OrinHubHTTPHandler.token_file = token_tmp.name

        try:
            res = self.make_request("/api/status")  # uses token from token_file
            self.assertEqual(res.status, 200)
        finally:
            os.unlink(token_tmp.name)
            OrinHubHTTPHandler.token_file = None

        # Test basic auth file auth
        basic_auth_tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        basic_auth_tmp.write(b"user1:pass123\n")
        basic_auth_tmp.close()
        OrinHubHTTPHandler.basic_auth_file = basic_auth_tmp.name

        try:
            import base64
            credentials = b"user1:pass123"
            auth_str = base64.b64encode(credentials).decode("utf-8")
            res = self.make_request("/api/status", headers={"Authorization": f"Basic {auth_str}"})
            self.assertEqual(res.status, 200)
        finally:
            os.unlink(basic_auth_tmp.name)
            OrinHubHTTPHandler.basic_auth_file = None

    @patch("orin.core.hub_server.HTTPServer")
    def test_start_server_helper(self, mock_server):
        from orin.core.hub_server import start_server
        passphrase_tmp = tempfile.NamedTemporaryFile(delete=False)
        passphrase_tmp.write(b"passphrase123\n")
        passphrase_tmp.close()

        try:
            with patch("orin.core.hub_server.TenantManager") as mock_tm:
                start_server(
                    db_path=self.db_path,
                    no_auth=True,
                    passphrase_file=passphrase_tmp.name,
                    init_admin_user="admin2",
                    init_admin_password="pass"
                )
                mock_tm.return_value.create_admin_user.assert_called_with("admin2", "pass")
        finally:
            os.unlink(passphrase_tmp.name)

    def test_options_request(self):
        res = self.make_request("/api/status", method="OPTIONS")
        self.assertEqual(res.status, 200)
        self.assertIn("Access-Control-Allow-Methods", res.headers)

    @patch("orin.core.hub_server.Path.exists")
    def test_serve_dashboard_missing(self, mock_exists):
        mock_exists.return_value = False
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/dashboard")
        self.assertEqual(ctx.exception.code, 404)

    @patch("orin.core.hub_server.open")
    def test_serve_dashboard_error(self, mock_open):
        mock_open.side_effect = IOError("failed to open")
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/dashboard")
        self.assertEqual(ctx.exception.code, 500)

    def test_basic_auth_checking_bad_headers(self):
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/status", headers={"Authorization": "Basic xxx"})
        self.assertEqual(ctx.exception.code, 401)

    def test_basic_auth_file_various_hashes(self):
        import urllib.error
        import base64
        # Create user with plain text pass and invalid hash format pass
        basic_auth_tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        basic_auth_tmp.write(b"plainuser:plainpass\n")
        basic_auth_tmp.write(b"bcryptuser:$2b$12$nonsensebcryptcheckfail\n")
        basic_auth_tmp.write(b"cryptuser:$1$nonsensecryptcheckfail\n")
        basic_auth_tmp.write(b"# commented line\n")
        basic_auth_tmp.write(b"badline\n")
        basic_auth_tmp.close()
        OrinHubHTTPHandler.basic_auth_file = basic_auth_tmp.name

        try:
            # 1. Plain text pass verification
            auth_str = base64.b64encode(b"plainuser:plainpass").decode("utf-8")
            res = self.make_request("/api/status", headers={"Authorization": f"Basic {auth_str}"})
            self.assertEqual(res.status, 200)

            # 2. Bcrypt hash failure (checkpw exception)
            auth_str = base64.b64encode(b"bcryptuser:wrong").decode("utf-8")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/status", headers={"Authorization": f"Basic {auth_str}"})
            self.assertEqual(ctx.exception.code, 401)

            # 3. Crypt hash failure (crypt exception)
            auth_str = base64.b64encode(b"cryptuser:wrong").decode("utf-8")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/status", headers={"Authorization": f"Basic {auth_str}"})
            self.assertEqual(ctx.exception.code, 401)

            # 4. Unknown user in basic auth file
            auth_str = base64.b64encode(b"unknownuser:pass").decode("utf-8")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/status", headers={"Authorization": f"Basic {auth_str}"})
            self.assertEqual(ctx.exception.code, 401)

        finally:
            os.unlink(basic_auth_tmp.name)
            OrinHubHTTPHandler.basic_auth_file = None

    def test_mtls_authentication_mocked(self):
        # We can simulate the peer cert CN mapping by mocking self.connection in the request handler
        # Let's test _authenticate directly or by mocking connection properties
        # Creating a tenant for mtls:valid_client CN
        t_id, _ = self.manager.create_tenant("mtls-tenant", is_admin=False)
        # We need to map api_key hash in manager. Since MTLS does f"mtls:{cn}" as API Key:
        # validate_api_key uses SHA-256 of the api_key. Let's create a tenant whose API Key is exactly "mtls:valid_client"
        import hashlib
        api_key = "mtls:valid_client"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Modify the created tenant's api_key_hash in sqlite to match
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE hub_tenants SET api_key_hash = ? WHERE id = ?", (api_key_hash, t_id))
        conn.commit()
        conn.close()
        
        # Reload manager to update memory cache
        self.manager = TenantManager(self.db_path)
        OrinHubHTTPHandler.tenant_manager = self.manager
        
        # Set handler settings
        OrinHubHTTPHandler.client_ca_cert = "dummy_ca.crt"
        
        # Mock getpeercert on the request connection object
        original_setup = OrinHubHTTPHandler.setup
        def setup_with_mock_cert(handler_inst):
            original_setup(handler_inst)
            mock_conn = MagicMock()
            mock_conn.getpeercert.return_value = {
                'subject': ((('commonName', 'valid_client'),),)
            }
            handler_inst.connection = mock_conn

        with patch.object(OrinHubHTTPHandler, 'setup', setup_with_mock_cert):
            # Send a request. It should authenticate using the mock peer cert subject
            res = self.make_request("/api/status")
            self.assertEqual(res.status, 200)

        OrinHubHTTPHandler.client_ca_cert = None

    def test_token_file_read_error(self):
        import urllib.error
        OrinHubHTTPHandler.token_file = "/nonexistent_or_unreadable_token_file_xyz"
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/status")
            self.assertEqual(ctx.exception.code, 401)
        finally:
            OrinHubHTTPHandler.token_file = None

    def test_invalid_json_request_body(self):
        import urllib.error
        import urllib.request
        # Create admin user
        self.manager.create_admin_user("superadmin", "pass123")
        headers = {
            "X-Admin-Username": "superadmin",
            "X-Admin-Password": "pass123"
        }
        
        url = f"http://127.0.0.1:{self.port}/api/tenants"
        req = urllib.request.Request(url, method="POST", headers=headers)
        req.add_header("Content-Type", "application/json")
        req.data = b"{invalid json..."
        
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)

    def test_rate_limiting_exceeded_http(self):
        import urllib.error
        # Rapidly make requests to /api/alerts to trigger rate limit (max 30)
        # We can bypass making 31 requests by mocking the rate limit check
        with patch.object(TenantManager, "check_rate_limit", return_value=False):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/alerts")
            self.assertEqual(ctx.exception.code, 429)

    def test_admin_only_endpoints_403(self):
        import urllib.error
        # Create tenant and try to access /api/admin/audit-logs
        t_id, api_key = self.manager.create_tenant("regular-tenant")
        headers = {"X-API-Key": api_key}
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/admin/audit-logs", headers=headers)
        self.assertEqual(ctx.exception.code, 403)

    def test_unknown_endpoints_404(self):
        import urllib.error
        # Authenticated but invalid GET
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/unknown_endpoint", headers=headers)
        self.assertEqual(ctx.exception.code, 404)

        # Authenticated but invalid POST
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/unknown_endpoint", method="POST", headers=headers, data={})
        self.assertEqual(ctx.exception.code, 404)

    def test_vault_stats_exception_handling(self):
        import json
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}
        # Force sqlite3.connect to raise in stats endpoint
        original_connect = sqlite3.connect
        def mock_connect(database, *args, **kwargs):
            import traceback
            tb = "".join(traceback.format_stack())
            if "_handle_stats" in tb and "get_tenant_stats" not in tb:
                raise sqlite3.Error("stats connection error")
            return original_connect(database, *args, **kwargs)

        with patch("sqlite3.connect", side_effect=mock_connect):
            res = self.make_request("/api/stats", headers=headers)
            self.assertEqual(res.status, 200)
            data = json.loads(res.read().decode())
            self.assertIn("error", data["vault"])
            self.assertEqual(data["vault"]["error"], "stats connection error")

    def test_telemetry_errors_and_modes(self):
        import urllib.error
        import json
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}

        # 1. Telemetry invalid snapshot id format (non-integer)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/telemetry/invalid_id", headers=headers)
        self.assertEqual(ctx.exception.code, 500)

        # 2. Telemetry snapshot not found
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/telemetry/9999", headers=headers)
        self.assertEqual(ctx.exception.code, 404)

        # 3. No snapshots found (telemetry latest but db is empty of snapshots)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/telemetry/latest", headers=headers)
        self.assertEqual(ctx.exception.code, 404)

        # Create a mock snapshot to retrieve different telemetry types
        from orin.core.database import OrinStorage
        storage = OrinStorage(self.db_path)
        with storage.get_connection() as conn:
            snapshot_id = storage.create_snapshot(conn)
            # Store some sample telemetry with all required dictionary keys
            storage.store_processes(conn, snapshot_id, [{
                "pid": 102, "ppid": 1, "name": "nginx", "exe": "/usr/sbin/nginx", "cmdline": "nginx", "ancestry_path": ""
            }])
            storage.store_ports(conn, snapshot_id, [{
                "port": 8080, "protocol": "tcp", "process_name": "nginx", "address": "0.0.0.0"
            }])
            storage.store_kernel_modules(conn, snapshot_id, [{
                "module_name": "dummy", "memory_size": 1024, "holders": "", "instances_loaded": 1
            }])
            storage.store_users(conn, snapshot_id, [{
                "username": "alice", "uid": 1001, "gid": 1001, "home_dir": "/home/alice", "login_shell": "/bin/bash"
            }])
            conn.commit()

        # Telemetry default / summary query
        res = self.make_request(f"/api/telemetry/{snapshot_id}", headers=headers)
        self.assertEqual(res.status, 200)

        # Telemetry all / specific types
        for t in ["all", "ports", "connections", "kernel_modules", "users", "ebpf"]:
            res = self.make_request(f"/api/telemetry/{snapshot_id}?type={t}", headers=headers)
            self.assertEqual(res.status, 200)

    def test_vault_info_missing_db(self):
        import urllib.error
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}
        OrinHubHTTPHandler.db_path = None
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/vault/info", headers=headers)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            OrinHubHTTPHandler.db_path = self.db_path

    def test_alerts_missing_db(self):
        import urllib.error
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}
        OrinHubHTTPHandler.db_path = None
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/alerts", headers=headers)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            OrinHubHTTPHandler.db_path = self.db_path

    def test_diff_missing_db(self):
        import urllib.error
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}
        OrinHubHTTPHandler.db_path = None
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/diff", headers=headers)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            OrinHubHTTPHandler.db_path = self.db_path

    def test_import_baseline_errors(self):
        import urllib.error
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}

        # Unknown import type
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.make_request("/api/import", method="POST", headers=headers, data={
                "type": "unknown_type",
                "data": {}
            })
        self.assertEqual(ctx.exception.code, 400)

        # Import failure (Exception raised)
        with patch.object(OrinHubHTTPHandler, "_process_events_import", side_effect=Exception("process failed")):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/import", method="POST", headers=headers, data={
                    "type": "events",
                    "data": [{"event_type": "ssh_login"}]
                })
            self.assertEqual(ctx.exception.code, 500)

    def test_export_failures_and_types(self):
        import urllib.error
        t_id, api_key = self.manager.create_tenant("test-tenant")
        headers = {"X-API-Key": api_key}

        # 1. Export type full
        res = self.make_request("/api/export/full", headers=headers)
        self.assertEqual(res.status, 200)

        # 2. Export failure (missing db)
        OrinHubHTTPHandler.db_path = None
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/export/snapshot", headers=headers)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            OrinHubHTTPHandler.db_path = self.db_path

        # 3. Export exception (general exception)
        original_connect = sqlite3.connect
        def mock_connect(database, *args, **kwargs):
            import traceback
            tb = "".join(traceback.format_stack())
            if "_handle_export" in tb:
                raise sqlite3.Error("export error")
            return original_connect(database, *args, **kwargs)

        with patch("sqlite3.connect", side_effect=mock_connect):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.make_request("/api/export/snapshot", headers=headers)
            self.assertEqual(ctx.exception.code, 500)

    @patch("orin.core.hub_server.HTTPServer")
    def test_start_server_various_arguments(self, mock_server):
        from orin.core.hub_server import start_server
        
        # Test backward compatibility args
        with patch("orin.core.hub_server.TenantManager") as mock_tm:
            start_server(
                db_path=self.db_path,
                no_auth=True,
                username="admin_compat",
                password="password_compat"
            )
            mock_tm.return_value.create_admin_user.assert_called_with("admin_compat", "password_compat")

        # Test passphrase_env_var
        with patch.dict(os.environ, {"VAULT_PASS": "env_pass"}):
            start_server(db_path=self.db_path, no_auth=True, passphrase_env_var="VAULT_PASS")
            self.assertEqual(OrinHubHTTPHandler.vault_passphrase, "env_pass")

        # Test passphrase_prompt
        with patch("getpass.getpass", return_value="prompt_pass"):
            start_server(db_path=self.db_path, no_auth=True, passphrase_prompt=True)
            self.assertEqual(OrinHubHTTPHandler.vault_passphrase, "prompt_pass")


if __name__ == "__main__":
    unittest.main()
