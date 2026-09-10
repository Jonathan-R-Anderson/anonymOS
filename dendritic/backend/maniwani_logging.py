"""Shared, modular logging setup for all Maniwani Python services.

Every Python container (the Flask backend, the board scrapers, the Reddit
aggregator) calls :func:`setup_logging` once at startup. Logs are written to a
single shared folder (a Docker volume mounted at ``/var/log/maniwani``) inside a
per-service subdirectory so it is always obvious which container a line came
from. Records are *also* echoed to stdout so ``docker logs`` keeps working.

The module is intentionally self-contained (no third-party deps) and identical
across every Python build context so behaviour is uniform everywhere.

Environment variables:
    LOG_DIR           Shared log folder. Default: ``/var/log/maniwani``.
    SERVICE_NAME      Identifies the container. Used for the subdir/file name.
    LOG_LEVEL         Root log level (e.g. ``DEBUG``/``INFO``). Default: INFO.
    LOG_MAX_BYTES     Rotate after this many bytes. Default: 10 MiB.
    LOG_BACKUP_COUNT  Number of rotated files to keep. Default: 5.
    LOG_TO_STDOUT     Set to a falsey value to disable the console handler.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

DEFAULT_LOG_DIR = "/var/log/maniwani"

_configured_service = None


def _env_flag(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return default
    return str(value).strip().lower() not in ("", "0", "false", "no", "off")


def _int_env(name, default):
    try:
        return int(str(os.environ.get(name, default)).strip())
    except (TypeError, ValueError):
        return default


def _utf8_stream(stream):
    """Return a stream that can encode any Unicode character.

    Containers frequently run under the ``C``/POSIX locale, which makes
    ``sys.stdout`` use the ASCII codec and crash on characters like an en-dash.
    Force UTF-8 (replacing anything truly unencodable) so logging never raises.
    """
    try:
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        return stream
    except Exception:
        pass
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        try:
            import io
            return io.TextIOWrapper(
                buffer, encoding="utf-8", errors="backslashreplace", line_buffering=True
            )
        except Exception:
            pass
    return stream


def setup_logging(service_name=None, level=None):
    """Configure the root logger for this service. Idempotent.

    Returns a logger named after the service. Safe to call from any container:
    if the shared folder is not writable, it falls back to stdout-only logging
    and never raises.
    """
    global _configured_service

    service = (
        service_name
        or os.environ.get("SERVICE_NAME")
        or os.environ.get("HOSTNAME")
        or "app"
    )

    if _configured_service == service:
        return logging.getLogger(service)

    log_dir = os.environ.get("LOG_DIR", DEFAULT_LOG_DIR)
    level_name = (level or os.environ.get("LOG_LEVEL") or "INFO").upper()
    log_level = getattr(logging, level_name, logging.INFO)

    # A line clearly tagged with the originating service.
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s [{service}] %(name)s: %(message)s".format(
            service=service
        ),
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    handlers = []

    if _env_flag("LOG_TO_STDOUT", default=True):
        console = logging.StreamHandler(_utf8_stream(sys.stdout))
        console.setFormatter(formatter)
        handlers.append(console)

    file_error = None
    try:
        service_dir = os.path.join(log_dir, service)
        os.makedirs(service_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(service_dir, service + ".log"),
            maxBytes=_int_env("LOG_MAX_BYTES", 10 * 1024 * 1024),
            backupCount=_int_env("LOG_BACKUP_COUNT", 5),
            encoding="utf-8",
            delay=True,
        )
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    except OSError as exc:  # pragma: no cover - depends on volume perms
        file_error = exc

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(log_level)

    _configured_service = service

    logger = logging.getLogger(service)
    if file_error is not None:
        logger.warning(
            "File logging disabled (%s not writable: %s); logging to stdout only.",
            log_dir,
            file_error,
        )
    else:
        logger.info("Logging to %s/%s/%s.log", log_dir, service, service)

    return logger
