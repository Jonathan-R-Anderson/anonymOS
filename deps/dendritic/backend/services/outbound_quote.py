import json
import hashlib
import re
import secrets


def normalized_body_digest(body):
    normalized = re.sub(r"\s+", " ", str(body or "")).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def normalized_idempotency_key(value):
    key = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9_-]{16,64}", key):
        return key
    return secrets.token_urlsafe(24)[:64]


def translate_source_quotes(body, raw_mapping):
    """Translate only quote markers inserted by the imported-post composer."""
    if not raw_mapping:
        return body
    try:
        mapping = json.loads(raw_mapping) if isinstance(raw_mapping, str) else raw_mapping
    except (TypeError, ValueError):
        return body
    if not isinstance(mapping, dict):
        return body
    translated = body
    for local_id, source_id in mapping.items():
        local_id = str(local_id or "").strip()
        source_id = str(source_id or "").strip()
        if not local_id.isdigit() or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", source_id):
            continue
        translated = re.sub(
            r"(?<!\d)>>%s(?!\d)" % re.escape(local_id),
            ">>" + source_id,
            translated,
        )
    return translated
