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
# src/orin/core/logging.py
"""
orin.core.logging – Structured JSON Logging for SIEM Integration
================================================================
Provides production-grade structured logging with JSON output format,
severity levels, and optional file/stderr destinations for security
information and event management (SIEM) integration.

Features
--------
- JSON-formatted log entries for easy parsing by SIEM systems
- Multiple severity levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Configurable output destinations (stderr, file, or both)
- Automatic inclusion of timestamp, hostname, component, and context
- Thread-safe logging operations
- Optional log rotation for file-based logging
"""
import json
import sys
import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs log records as JSON structures."""

    def __init__(self, include_extra: bool = True):
        """Initialize the JSON formatter.

        Args:
            include_extra: Whether to include extra fields from LogRecord
        """
        super().__init__()
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as a JSON string.

        Args:
            record: The logging.LogRecord to format

        Returns:
            JSON-formatted string representation of the log entry
        """
        # Build base log structure
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "severity": record.levelno,
            "logger": record.name,
            "message": record.getMessage(),
            "component": getattr(record, 'component', 'orin'),
            "hostname": getattr(record, 'hostname', os.uname().nodename if hasattr(os, 'uname') else 'unknown'),
            "pid": getattr(record, 'pid', os.getpid()),
            "thread": getattr(record, 'thread_name', None),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields if enabled
        if self.include_extra:
            skip_fields = {
                'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
                'funcName', 'levelname', 'levelno', 'lineno', 'module', 'msecs',
                'msg', 'name', 'pathname', 'process', 'processName', 'relativeCreated',
                'stack_info', 'thread', 'threadName', 'message', 'component',
                'hostname', 'pid'
            }
            extra_fields = {}
            for key, value in record.__dict__.items():
                if key not in skip_fields:
                    try:
                        # Ensure the value is JSON-serializable
                        json.dumps(value)
                        extra_fields[key] = value
                    except (TypeError, ValueError):
                        # Convert non-serializable values to strings
                        extra_fields[key] = str(value)

            if extra_fields:
                log_entry["extra"] = extra_fields

        return json.dumps(log_entry, ensure_ascii=False)


class OrinLogger:
    """Main logger class providing structured JSON logging for Orin."""

    _instance: Optional['OrinLogger'] = None
    _initialized: bool = False

    def __new__(cls, *args, **kwargs) -> 'OrinLogger':
        """Implement singleton pattern for global logger instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(
        self,
        name: str = "orin",
        level: int = logging.INFO,
        output_stderr: bool = True,
        output_file: Optional[str] = None,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
        include_hostname: bool = True
    ):
        """Initialize the Orin structured logger.

        Args:
            name: Logger name (default: "orin")
            level: Minimum logging level (default: INFO)
            output_stderr: Whether to output logs to stderr (default: True)
            output_file: Optional path to log file for file-based logging
            max_bytes: Maximum size of log file before rotation (default: 10MB)
            backup_count: Number of backup log files to keep (default: 5)
            include_hostname: Whether to include hostname in log entries
        """
        if OrinLogger._initialized:
            return

        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers.clear()

        # Create JSON formatter
        formatter = JSONFormatter(include_extra=True)

        # Stderr handler
        if output_stderr:
            stderr_handler = logging.StreamHandler(sys.stderr)
            stderr_handler.setLevel(level)
            stderr_handler.setFormatter(formatter)
            self.logger.addHandler(stderr_handler)

        # File handler (optional)
        if output_file:
            log_path = Path(output_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        # Store default context values
        self.default_context = {
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
            'pid': os.getpid()
        } if include_hostname else {'pid': os.getpid()}

        OrinLogger._initialized = True

    def _log_with_context(
        self,
        level: int,
        message: str,
        component: str = "orin",
        **extra_kwargs
    ):
        """Internal method to log with additional context.

        Args:
            level: Logging level
            message: Log message
            component: Component name generating the log
            **extra_kwargs: Additional context fields to include
        """
        extra = self.default_context.copy()
        extra['component'] = component
        extra.update(extra_kwargs)

        # Use stacklevel=2 to point to the caller, not this method
        self.logger.log(level, message, extra=extra, stacklevel=2)

    def debug(self, message: str, component: str = "orin", **kwargs):
        """Log a DEBUG level message.

        Args:
            message: Log message
            component: Component name
            **kwargs: Additional context fields
        """
        self._log_with_context(logging.DEBUG, message, component, **kwargs)

    def info(self, message: str, component: str = "orin", **kwargs):
        """Log an INFO level message.

        Args:
            message: Log message
            component: Component name
            **kwargs: Additional context fields
        """
        self._log_with_context(logging.INFO, message, component, **kwargs)

    def warning(self, message: str, component: str = "orin", **kwargs):
        """Log a WARNING level message.

        Args:
            message: Log message
            component: Component name
            **kwargs: Additional context fields
        """
        self._log_with_context(logging.WARNING, message, component, **kwargs)

    def error(self, message: str, component: str = "orin", **kwargs):
        """Log an ERROR level message.

        Args:
            message: Log message
            component: Component name
            **kwargs: Additional context fields
        """
        self._log_with_context(logging.ERROR, message, component, **kwargs)

    def critical(self, message: str, component: str = "orin", **kwargs):
        """Log a CRITICAL level message.

        Args:
            message: Log message
            component: Component name
            **kwargs: Additional context fields
        """
        self._log_with_context(logging.CRITICAL, message, component, **kwargs)

    def set_level(self, level: int):
        """Change the logging level.

        Args:
            level: New logging level (e.g., logging.DEBUG, logging.INFO)
        """
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)

    def get_logger(self) -> logging.Logger:
        """Get the underlying Python logger instance.

        Returns:
            The underlying logging.Logger instance
        """
        return self.logger


def get_logger(
    name: str = "orin",
    level: int = logging.INFO,
    output_stderr: bool = True,
    output_file: Optional[str] = None,
    **kwargs
) -> OrinLogger:
    """Get or create a configured OrinLogger instance.

    This is the main entry point for obtaining a logger instance.

    Args:
        name: Logger name (default: "orin")
        level: Minimum logging level (default: INFO)
        output_stderr: Whether to output to stderr (default: True)
        output_file: Optional path to log file
        **kwargs: Additional arguments passed to OrinLogger constructor

    Returns:
        Configured OrinLogger instance

    Example:
        >>> from orin.core.logging import get_logger
        >>> logger = get_logger(level=logging.INFO, output_file="/var/log/orin/orin.log")
        >>> logger.info("System initialized", component="main", user="admin")
    """
    return OrinLogger(
        name=name,
        level=level,
        output_stderr=output_stderr,
        output_file=output_file,
        **kwargs
    )


# Convenience constants for logging levels
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL


# Module-level convenience functions using default logger
_default_logger: Optional[OrinLogger] = None


def _get_default_logger() -> OrinLogger:
    """Get or create the default module-level logger."""
    global _default_logger
    if _default_logger is None:
        _default_logger = get_logger()
    return _default_logger


def debug(message: str, **kwargs):
    """Log DEBUG message using default logger."""
    _get_default_logger().debug(message, **kwargs)


def info(message: str, **kwargs):
    """Log INFO message using default logger."""
    _get_default_logger().info(message, **kwargs)


def warning(message: str, **kwargs):
    """Log WARNING message using default logger."""
    _get_default_logger().warning(message, **kwargs)


def error(message: str, **kwargs):
    """Log ERROR message using default logger."""
    _get_default_logger().error(message, **kwargs)


def critical(message: str, **kwargs):
    """Log CRITICAL message using default logger."""
    _get_default_logger().critical(message, **kwargs)


def configure_logging(
    level: int = logging.INFO,
    output_stderr: bool = True,
    output_file: Optional[str] = None,
    **kwargs
) -> OrinLogger:
    """Configure the default module-level logger.

    Args:
        level: Logging level
        output_stderr: Enable stderr output
        output_file: Optional log file path
        **kwargs: Additional configuration options

    Returns:
        Configured OrinLogger instance
    """
    global _default_logger
    _default_logger = get_logger(
        level=level,
        output_stderr=output_stderr,
        output_file=output_file,
        **kwargs
    )
    return _default_logger