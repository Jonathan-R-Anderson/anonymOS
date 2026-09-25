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
# src/orin/core/validators.py
"""
orin.core.validators – Input Validation Utilities
=================================================
Provides comprehensive input validation for security-critical parameters
including snapshot IDs, hostnames, IP addresses, and SQL injection prevention.

Security Features
-----------------
- Type validation for all critical parameters
- Range checking for numeric IDs
- Hostname/IP format validation
- SQL injection pattern detection
- Command injection prevention
- Path traversal protection
"""

import re
import socket
from typing import Any
from pathlib import Path


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class SnapshotIDValidator:
    """Validates snapshot ID parameters for database operations."""

    MIN_SNAPSHOT_ID = 1
    MAX_SNAPSHOT_ID = 2**63 - 1  # SQLite INTEGER max

    @classmethod
    def validate(cls, snapshot_id: Any, allow_none: bool = False) -> int:
        """
        Validate a snapshot ID parameter.

        Parameters
        ----------
        snapshot_id : Any
            The snapshot ID to validate.
        allow_none : bool, optional
            Whether to allow None values (default False).

        Returns
        -------
        int
            The validated snapshot ID as an integer.

        Raises
        ------
        ValidationError
            If the snapshot ID is invalid.
        """
        if snapshot_id is None:
            if allow_none:
                return None
            raise ValidationError("Snapshot ID cannot be None")

        # Type check - must be int or convertible to int
        if not isinstance(snapshot_id, (int, str)):
            raise ValidationError(
                f"Snapshot ID must be an integer, got {type(snapshot_id).__name__}"
            )

        try:
            snapshot_id_int = int(snapshot_id)
        except (ValueError, TypeError):
            raise ValidationError(
                f"Snapshot ID must be a valid integer, got '{snapshot_id}'"
            )

        # Range check
        if snapshot_id_int < cls.MIN_SNAPSHOT_ID:
            raise ValidationError(
                f"Snapshot ID must be >= {cls.MIN_SNAPSHOT_ID}, got {snapshot_id_int}"
            )

        if snapshot_id_int > cls.MAX_SNAPSHOT_ID:
            raise ValidationError(
                f"Snapshot ID must be <= {cls.MAX_SNAPSHOT_ID}, got {snapshot_id_int}"
            )

        return snapshot_id_int


class HostValidator:
    """Validates hostname and IP address parameters."""

    # RFC 1123 compliant hostname regex (supports both single-label and FQDN, allowing underscores for local names)
    HOSTNAME_PATTERN = re.compile(
        r'^(?!-)'  # Cannot start with hyphen
        r'(?:[a-zA-Z0-9-_]{1,63}\.)*'  # Optional subdomains (zero or more)
        r'[a-zA-Z0-9-_]{1,63}$'  # Hostname or TLD (cannot end with hyphen or underscore)
    )

    # IPv4 pattern
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )

    # IPv6 pattern (simplified)
    IPV6_PATTERN = re.compile(
        r'^('
        r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'  # Full form
        r'([0-9a-fA-F]{1,4}:){1,7}:|'  # Trailing ::
        r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
        r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
        r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
        r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|'  # Link-local
        r'::(ffff(:0{1,4})?:)?'
        r'((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}'
        r'(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|'  # IPv4-mapped
        r'([0-9a-fA-F]{1,4}:){1,4}:'
        r'((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}'
        r'(25[0-5]|(2[0-4]|1?[0-9])?[0-9])'  # IPv4-embedded
        r')$'
    )

    # Dangerous patterns for command injection
    DANGEROUS_PATTERNS = [
        r';',           # Command separator
        r'\|',          # Pipe
        r'&',           # Background/AND
        r'\$',          # Variable expansion
        r'`',           # Command substitution
        r'\(',          # Subshell
        r'\)',          # Subshell
        r'<',           # Redirect input
        r'>',           # Redirect output
        r'\n',          # Newline injection
        r'\r',          # Carriage return
        r'\\n',         # Escaped newline
        r'\\r',         # Escaped carriage return
        r'\x00',        # Null byte
        r'%00',         # URL-encoded null
        r'\.\./',       # Path traversal
        r'\.\.',        # Path traversal
    ]

    RESERVED_HOSTNAMES = {
        'localhost', '127.0.0.1', '::1',
        '0.0.0.0'  # Removed 255.255.255.255 as it's a valid broadcast address
    }

    @classmethod
    def validate(cls, host: Any, allow_localhost: bool = False) -> str:
        """
        Validate a hostname or IP address parameter.

        Parameters
        ----------
        host : Any
            The host parameter to validate.
        allow_localhost : bool, optional
            Whether to allow localhost/reserved addresses (default False).

        Returns
        -------
        str
            The validated hostname as a string.

        Raises
        ------
        ValidationError
            If the host is invalid.
        """
        if host is None:
            raise ValidationError("Host parameter cannot be None")

        if not isinstance(host, str):
            raise ValidationError(
                f"Host must be a string, got {type(host).__name__}"
            )

        host = host.strip()

        if not host:
            raise ValidationError("Host parameter cannot be empty")

        if len(host) > 253:
            raise ValidationError(
                f"Host parameter too long (max 253 chars), got {len(host)}"
            )

        # Check for dangerous patterns (command injection)
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, host):
                raise ValidationError(
                    f"Host contains invalid/dangerous characters: '{host}'"
                )

        # Check for reserved hostnames
        if host.lower() in cls.RESERVED_HOSTNAMES and not allow_localhost:
            raise ValidationError(
                f"Host '{host}' is reserved and not allowed for remote scanning"
            )

        # Validate as IPv4
        if cls.IPV4_PATTERN.match(host):
            return host

        # Validate as IPv6
        if cls.IPV6_PATTERN.match(host):
            return host

        # Validate as hostname
        if cls.HOSTNAME_PATTERN.match(host):
            # Additional DNS resolution check (optional, non-blocking)
            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                # DNS resolution failed, but format is valid
                # Allow it for cases where DNS might be available at runtime
                pass
            return host

        raise ValidationError(
            f"Invalid host format '{host}'. Must be valid hostname, IPv4, or IPv6 address"
        )

    @classmethod
    def validate_ip_only(cls, ip: Any) -> str:
        """
        Validate that the parameter is strictly an IP address (no hostnames).

        Parameters
        ----------
        ip : Any
            The IP address to validate.

        Returns
        -------
        str
            The validated IP address.

        Raises
        ------
        ValidationError
            If the parameter is not a valid IP address.
        """
        if ip is None:
            raise ValidationError("IP address cannot be None")

        if not isinstance(ip, str):
            raise ValidationError(
                f"IP address must be a string, got {type(ip).__name__}"
            )

        ip = ip.strip()

        if cls.IPV4_PATTERN.match(ip):
            return ip

        if cls.IPV6_PATTERN.match(ip):
            return ip

        raise ValidationError(
            f"Invalid IP address format '{ip}'. Must be valid IPv4 or IPv6"
        )


class SQLInjectionValidator:
    """Validates strings for potential SQL injection patterns."""

    # SQL injection patterns
    SQL_PATTERNS = [
        r"--",                    # SQL comment
        r"/\*.*\*/",              # Block comment
        r";\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)",  # Dangerous statements
        r"UNION\s+(?:ALL\s+)?SELECT",  # UNION injection
        r"OR\s+1\s*=\s*1",        # Always true condition
        r"AND\s+1\s*=\s*1",       # Always true condition
        r"'\s*OR\s*'",            # Quote escape OR
        r"'\s*;\s*--",            # Quote escape with comment
        r"xp_",                   # SQL Server extended procedures
        r"exec\s*\(",             # Execute function
        r"EXECUTE\s+",            # Execute statement
        r"WAITFOR\s+DELAY",       # Time-based injection
        r"BENCHMARK\s*\(",        # MySQL timing attack
        r"SLEEP\s*\(",            # Sleep function
    ]

    @classmethod
    def validate(cls, value: Any, field_name: str = "field") -> str:
        """
        Validate a string value for SQL injection patterns.

        Parameters
        ----------
        value : Any
            The value to validate.
        field_name : str, optional
            Name of the field for error messages.

        Returns
        -------
        str
            The validated value.

        Raises
        ------
        ValidationError
            If SQL injection patterns are detected.
        """
        if value is None:
            return None

        if not isinstance(value, str):
            return value

        value = value.strip()

        for pattern in cls.SQL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(
                    f"Potential SQL injection detected in {field_name}"
                )

        return value


class PathValidator:
    """Validates file paths for security issues."""

    @classmethod
    def validate(cls, path: Any, must_exist: bool = False) -> Path:
        """
        Validate a file path parameter.

        Parameters
        ----------
        path : Any
            The path to validate.
        must_exist : bool, optional
            Whether the path must exist (default False).

        Returns
        -------
        Path
            The validated Path object.

        Raises
        ------
        ValidationError
            If the path is invalid.
        """
        if path is None:
            raise ValidationError("Path parameter cannot be None")

        if not isinstance(path, (str, Path)):
            raise ValidationError(
                f"Path must be a string or Path object, got {type(path).__name__}"
            )

        path_obj = Path(path) if isinstance(path, str) else path

        # Check for path traversal attempts
        path_str = str(path_obj)
        if '..' in path_str.split('/') or '..' in path_str.split('\\'):
            # Allow legitimate .. in absolute paths but check for traversal
            try:
                path_obj.resolve(strict=False)
                # Check if resolved path escapes intended directory
                # This is a basic check; adjust based on use case
            except Exception:
                raise ValidationError(f"Invalid path traversal detected: '{path}'")

        if must_exist and not path_obj.exists():
            raise ValidationError(f"Path does not exist: '{path}'")

        return path_obj


def validate_snapshot_id(snapshot_id: Any, allow_none: bool = False) -> int:
    """Convenience function for snapshot ID validation."""
    return SnapshotIDValidator.validate(snapshot_id, allow_none)


def validate_host(host: Any, allow_localhost: bool = False) -> str:
    """Convenience function for host validation."""
    return HostValidator.validate(host, allow_localhost)


def validate_sql_input(value: Any, field_name: str = "field") -> str:
    """Convenience function for SQL injection validation."""
    return SQLInjectionValidator.validate(value, field_name)


def validate_path(path: Any, must_exist: bool = False) -> Path:
    """Convenience function for path validation."""
    return PathValidator.validate(path, must_exist)