"""Upload security checks ported from gh0stgrid.

Two additive protections applied to every stored attachment, layered on top of
maniwani's existing per-board MIME allowlist and blocked-hash checks:

* **Content-signature verification** (from gh0stgrid's ``sanitizer``): confirm
  the file's magic bytes actually match its declared MIME type, so a payload
  cannot masquerade as an allowed type by lying about its content type.
* **Antivirus scanning** (from gh0stgrid's ``clamav`` service): POST the bytes
  to the ClamAV HTTP service; a 409 means an infection was found.

Both are best-effort about availability: if the scanner is unreachable the
upload is allowed through by default (set ``CLAMAV_FAIL_CLOSED=1`` to reject
instead), because taking uploads offline when a sidecar is down is worse than
the marginal risk of an unscanned file for most deployments.
"""

import os

import requests

from shared import app


# --- Magic-byte signature validators (ported from sanitizer/app.py) ---------


def _is_safe_text(payload: bytes) -> bool:
    sample = payload[:4096]
    if b"\x00" in sample:
        return False
    control = sum(1 for byte in sample if byte < 0x09 or (0x0E <= byte < 0x20))
    return control == 0


def _is_mp4(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    if int.from_bytes(payload[0:4], "big", signed=False) < 8:
        return False
    return payload[4:8] == b"ftyp"


FILE_SIGNATURE_VALIDATORS = {
    "image/png": lambda d: d.startswith(b"\x89PNG\r\n\x1a\n"),
    "image/jpeg": lambda d: len(d) >= 4 and d.startswith(b"\xff\xd8") and d.rstrip(b"\x00").endswith(b"\xff\xd9"),
    "image/gif": lambda d: d.startswith((b"GIF87a", b"GIF89a")),
    "image/webp": lambda d: len(d) >= 12 and d[:4] == b"RIFF" and d[8:12] == b"WEBP",
    "image/bmp": lambda d: d.startswith(b"BM"),
    "application/pdf": lambda d: d.startswith(b"%PDF-"),
    "text/plain": _is_safe_text,
    "video/mp4": _is_mp4,
    # maniwani additionally accepts these container/media types by default.
    "video/webm": lambda d: d.startswith(b"\x1a\x45\xdf\xa3"),
    "audio/webm": lambda d: d.startswith(b"\x1a\x45\xdf\xa3"),
    "video/ogg": lambda d: d.startswith(b"OggS"),
    "audio/ogg": lambda d: d.startswith(b"OggS"),
}


class UnsafeUploadError(Exception):
    """Raised when an upload fails a content-signature or antivirus check."""


def _normalize_mime(mime: str) -> str:
    return (mime or "").split(";", 1)[0].strip().lower()


def content_signature_matches(mimetype: str, payload: bytes) -> bool:
    """Return True if the payload's magic bytes match its declared MIME type.

    Types without a known signature validator are allowed (returns True) so
    this only ever rejects a concrete content-vs-declaration mismatch.
    """
    validator = FILE_SIGNATURE_VALIDATORS.get(_normalize_mime(mimetype))
    if validator is None:
        return True
    try:
        return bool(validator(payload or b""))
    except Exception:  # pragma: no cover - defensive guard
        return False


# --- ClamAV client (ported from clamav/app.py contract) ---------------------


def _clamav_scan_url():
    return (os.getenv("CLAMAV_SCAN_URL") or "").strip() or None


def _clamav_fail_closed() -> bool:
    return (os.getenv("CLAMAV_FAIL_CLOSED") or "").strip().lower() in ("1", "true", "yes", "on")


def scan_bytes_with_clamav(payload: bytes, filename: str = "upload") -> None:
    """Scan bytes via the ClamAV HTTP service. Raise UnsafeUploadError if infected.

    Contract (from gh0stgrid clamav): 200 clean, 409 infected, 413 too large,
    400 no files, 5xx scanner error.
    """
    scan_url = _clamav_scan_url()
    if not scan_url:
        return  # scanning not configured

    # Keep this short: a slow/unready scanner must fail open fast rather than
    # stall the caller (uploads and, especially, the aggregator media import
    # which scans many files in sequence).
    timeout = float(os.getenv("CLAMAV_TIMEOUT", "8"))
    try:
        response = requests.post(
            scan_url,
            files={"file": (filename or "upload", payload or b"", "application/octet-stream")},
            timeout=(3, timeout),
        )
    except requests.RequestException as exc:
        if _clamav_fail_closed():
            raise UnsafeUploadError("Upload could not be virus-scanned; rejected.")
        app.logger.warning("ClamAV scan unavailable (%s); allowing upload through", exc)
        return

    if response.status_code == 200:
        return
    if response.status_code == 409:
        signature = "malware"
        try:
            body = response.json()
            for entry in body.get("files", []):
                if entry.get("signature"):
                    signature = entry["signature"]
                    break
        except ValueError:
            pass
        app.logger.warning("ClamAV rejected upload %s: %s", filename, signature)
        raise UnsafeUploadError("This file was rejected by the virus scanner (%s)." % signature)
    if response.status_code == 413:
        # Too large for the scanner (videos routinely exceed the size cap).
        # Treat this like any other scan failure and honour the fail-open /
        # fail-closed policy instead of always rejecting — otherwise large but
        # legitimate media (the whole point of a video site) can never upload.
        if _clamav_fail_closed():
            raise UnsafeUploadError("This file is too large to be virus-scanned.")
        app.logger.warning(
            "ClamAV: %s (%d bytes) exceeds the scanner size cap; allowing upload through",
            filename,
            len(payload or b""),
        )
        return

    # Any other status is a scanner error.
    if _clamav_fail_closed():
        raise UnsafeUploadError("Upload could not be virus-scanned; rejected.")
    app.logger.warning(
        "ClamAV returned unexpected status %s for %s; allowing upload through",
        response.status_code,
        filename,
    )
