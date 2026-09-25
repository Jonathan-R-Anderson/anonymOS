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
Test suite for input validation functionality.
Tests snapshot_id validation, host validation, SQL injection prevention,
and command injection prevention.
"""

import pytest
import tempfile
from pathlib import Path
from orin.core.validators import (
    ValidationError,
    SnapshotIDValidator,
    HostValidator,
    SQLInjectionValidator,
    PathValidator,
    validate_snapshot_id,
    validate_host,
    validate_sql_input,
    validate_path
)
from orin.core.database import OrinStorage


class TestSnapshotIDValidator:
    """Test snapshot ID validation."""

    def test_valid_snapshot_id_int(self):
        """Test valid integer snapshot IDs."""
        assert validate_snapshot_id(1) == 1
        assert validate_snapshot_id(100) == 100
        assert validate_snapshot_id(2**63 - 1) == 2**63 - 1

    def test_valid_snapshot_id_string(self):
        """Test valid string snapshot IDs that can be converted."""
        assert validate_snapshot_id("1") == 1
        assert validate_snapshot_id("100") == 100

    def test_snapshot_id_none_not_allowed(self):
        """Test that None raises error when not allowed."""
        with pytest.raises(ValidationError, match="cannot be None"):
            validate_snapshot_id(None)

    def test_snapshot_id_none_allowed(self):
        """Test that None is allowed when specified."""
        assert validate_snapshot_id(None, allow_none=True) is None

    def test_snapshot_id_zero_invalid(self):
        """Test that zero is invalid."""
        with pytest.raises(ValidationError, match="must be >= 1"):
            validate_snapshot_id(0)

    def test_snapshot_id_negative_invalid(self):
        """Test that negative numbers are invalid."""
        with pytest.raises(ValidationError, match="must be >= 1"):
            validate_snapshot_id(-1)
        with pytest.raises(ValidationError, match="must be >= 1"):
            validate_snapshot_id(-100)

    def test_snapshot_id_too_large(self):
        """Test that values exceeding max are invalid."""
        with pytest.raises(ValidationError, match="must be <="):
            validate_snapshot_id(2**63)

    def test_snapshot_id_invalid_type(self):
        """Test that invalid types raise errors."""
        with pytest.raises(ValidationError, match="must be an integer"):
            validate_snapshot_id(1.5)
        with pytest.raises(ValidationError, match="must be an integer"):
            validate_snapshot_id([1])
        with pytest.raises(ValidationError, match="must be an integer"):
            validate_snapshot_id({"id": 1})

    def test_snapshot_id_non_numeric_string(self):
        """Test that non-numeric strings raise errors."""
        with pytest.raises(ValidationError, match="must be a valid integer"):
            validate_snapshot_id("abc")
        with pytest.raises(ValidationError, match="must be a valid integer"):
            validate_snapshot_id("1.5")


class TestHostValidator:
    """Test hostname and IP address validation."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_host("192.168.1.1") == "192.168.1.1"
        assert validate_host("10.0.0.1") == "10.0.0.1"
        assert validate_host("255.255.255.255") == "255.255.255.255"

    def test_valid_hostname(self):
        """Test valid hostnames."""
        assert validate_host("example.com") == "example.com"
        assert validate_host("server1.example.com") == "server1.example.com"
        assert validate_host("my-server.test.local") == "my-server.test.local"

    def test_host_none_invalid(self):
        """Test that None raises error."""
        with pytest.raises(ValidationError, match="cannot be None"):
            validate_host(None)

    def test_host_empty_invalid(self):
        """Test that empty strings raise errors."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_host("")
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_host("   ")

    def test_host_invalid_type(self):
        """Test that invalid types raise errors."""
        with pytest.raises(ValidationError, match="must be a string"):
            validate_host(123)
        with pytest.raises(ValidationError, match="must be a string"):
            validate_host(["host"])

    def test_host_command_injection_semicolon(self):
        """Test that semicolon command injection is blocked."""
        with pytest.raises(ValidationError, match="invalid/dangerous characters"):
            validate_host("192.168.1.1; rm -rf /")

    def test_host_command_injection_pipe(self):
        """Test that pipe command injection is blocked."""
        with pytest.raises(ValidationError, match="invalid/dangerous characters"):
            validate_host("host|cat /etc/passwd")

    def test_host_command_injection_backtick(self):
        """Test that backtick command injection is blocked."""
        with pytest.raises(ValidationError, match="invalid/dangerous characters"):
            validate_host("host`whoami`")

    def test_host_command_injection_dollar(self):
        """Test that dollar sign variable expansion is blocked."""
        with pytest.raises(ValidationError, match="invalid/dangerous characters"):
            validate_host("host$VAR")

    def test_host_path_traversal(self):
        """Test that path traversal is blocked."""
        with pytest.raises(ValidationError, match="invalid/dangerous characters"):
            validate_host("../etc/passwd")
        with pytest.raises(ValidationError, match="invalid/dangerous characters"):
            validate_host("host/../../etc")

    def test_host_localhost_blocked_by_default(self):
        """Test that localhost is blocked by default."""
        with pytest.raises(ValidationError, match="reserved"):
            validate_host("localhost")
        with pytest.raises(ValidationError, match="reserved"):
            validate_host("127.0.0.1")

    def test_host_localhost_allowed(self):
        """Test that localhost can be allowed explicitly."""
        assert validate_host("localhost", allow_localhost=True) == "localhost"
        assert validate_host("127.0.0.1", allow_localhost=True) == "127.0.0.1"

    def test_host_too_long(self):
        """Test that very long hostnames are rejected."""
        long_host = "a" * 254 + ".com"
        with pytest.raises(ValidationError, match="too long"):
            validate_host(long_host)

    def test_invalid_hostname_format(self):
        """Test that invalid hostname formats are rejected."""
        with pytest.raises(ValidationError, match="Invalid host format"):
            validate_host("-invalid.com")  # Starts with hyphen
        # Double dot is caught by dangerous patterns check (..)
        with pytest.raises(ValidationError, match="invalid/dangerous characters"):
            validate_host("invalid..com")  # Double dot


class TestSQLInjectionValidator:
    """Test SQL injection prevention."""

    def test_clean_string(self):
        """Test that clean strings pass validation."""
        assert validate_sql_input("normal_value") == "normal_value"
        assert validate_sql_input("test123") == "test123"

    def test_sql_comment_blocked(self):
        """Test that SQL comments are blocked."""
        with pytest.raises(ValidationError, match="SQL injection"):
            validate_sql_input("value--comment")

    def test_sql_union_injection_blocked(self):
        """Test that UNION SELECT injection is blocked."""
        with pytest.raises(ValidationError, match="SQL injection"):
            validate_sql_input("test UNION SELECT * FROM users")
        with pytest.raises(ValidationError, match="SQL injection"):
            validate_sql_input("test UNION ALL SELECT password FROM users")

    def test_sql_or_injection_blocked(self):
        """Test that OR 1=1 injection is blocked."""
        with pytest.raises(ValidationError, match="SQL injection"):
            validate_sql_input("' OR 1=1")

    def test_sql_drop_injection_blocked(self):
        """Test that DROP TABLE injection is blocked."""
        with pytest.raises(ValidationError, match="SQL injection"):
            validate_sql_input("test; DROP TABLE users")

    def test_sql_sleep_injection_blocked(self):
        """Test that time-based injection is blocked."""
        with pytest.raises(ValidationError, match="SQL injection"):
            validate_sql_input("test SLEEP(10)")

    def test_none_value(self):
        """Test that None passes through."""
        assert validate_sql_input(None) is None

    def test_non_string_value(self):
        """Test that non-string values pass through unchanged."""
        assert validate_sql_input(123) == 123
        assert validate_sql_input([1, 2, 3]) == [1, 2, 3]


class TestPathValidator:
    """Test path validation."""

    def test_valid_path_string(self):
        """Test valid path strings."""
        result = validate_path("/tmp/test.txt")
        assert isinstance(result, Path)
        assert str(result) == "/tmp/test.txt"

    def test_valid_path_object(self):
        """Test valid Path objects."""
        input_path = Path("/tmp/test.txt")
        result = validate_path(input_path)
        assert result == input_path

    def test_path_none_invalid(self):
        """Test that None raises error."""
        with pytest.raises(ValidationError, match="cannot be None"):
            validate_path(None)

    def test_path_invalid_type(self):
        """Test that invalid types raise errors."""
        with pytest.raises(ValidationError, match="must be a string or Path"):
            validate_path(123)

    def test_path_must_exist(self):
        """Test must_exist parameter."""
        # Non-existent path without must_exist should pass
        result = validate_path("/nonexistent/path.txt")
        assert isinstance(result, Path)

        # Non-existent path with must_exist should fail
        with pytest.raises(ValidationError, match="does not exist"):
            validate_path("/nonexistent/path.txt", must_exist=True)

        # Existing path with must_exist should pass
        with tempfile.NamedTemporaryFile(delete=False) as f:
            try:
                result = validate_path(f.name, must_exist=True)
                assert result.exists()
            finally:
                Path(f.name).unlink()


class TestDatabaseIntegration:
    """Test validation integration with database operations."""

    def test_store_processes_valid_snapshot(self):
        """Test storing processes with valid snapshot ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            storage = OrinStorage(db_path)
            try:
                storage.initialize_db()
                # Initialize the connection pool and create tables
                with storage.get_connection() as conn:
                    snapshot_id = storage.create_snapshot(conn, hostname="test-host", os_platform="Linux")

                    # Valid snapshot ID should work
                    storage.store_processes(conn, snapshot_id, [
                        {"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init", "cmdline": "/sbin/init"}
                    ])
            finally:
                storage.close_pool()

    def test_store_processes_invalid_snapshot(self):
        """Test storing processes with invalid snapshot ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            storage = OrinStorage(db_path)
            try:
                storage.initialize_db()
                with storage.get_connection() as conn:
                    # Invalid snapshot ID (0) should raise ValidationError
                    with pytest.raises(ValidationError):
                        storage.store_processes(conn, 0, [
                            {"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init", "cmdline": "/sbin/init"}
                        ])

                    # Negative snapshot ID should raise ValidationError
                    with pytest.raises(ValidationError):
                        storage.store_processes(conn, -1, [
                            {"pid": 1, "ppid": 0, "name": "init", "exe": "/sbin/init", "cmdline": "/sbin/init"}
                        ])
            finally:
                storage.close_pool()

    def test_create_snapshot_valid_hostname(self):
        """Test creating snapshot with valid hostname."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            storage = OrinStorage(db_path)
            try:
                storage.initialize_db()
                with storage.get_connection() as conn:
                    snapshot_id = storage.create_snapshot(conn, hostname="valid-host.example.com", os_platform="Linux")
                    assert snapshot_id > 0
            finally:
                storage.close_pool()

    def test_create_snapshot_invalid_hostname(self):
        """Test creating snapshot with invalid hostname."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            storage = OrinStorage(db_path)
            try:
                storage.initialize_db()
                with storage.get_connection() as conn:
                    # Hostname with command injection should fail
                    with pytest.raises(ValidationError):
                        storage.create_snapshot(conn, hostname="host;rm -rf /", os_platform="Linux")
            finally:
                storage.close_pool()

    def test_create_snapshot_sql_injection_os_platform(self):
        """Test creating snapshot with SQL injection in OS platform."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            storage = OrinStorage(db_path)
            try:
                storage.initialize_db()
                with storage.get_connection() as conn:
                    # SQL injection in os_platform should fail
                    with pytest.raises(ValidationError):
                        storage.create_snapshot(conn, hostname="test-host", os_platform="Linux'; DROP TABLE system_snapshots; --")
            finally:
                storage.close_pool()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])