import base64
import datetime
import hashlib
import json
import os
from copy import deepcopy

from board_access import get_board_by_name_or_404, get_thread_and_board_or_404
from model.BoardListCatalog import BoardCatalog
from model.Post import render_for_catalog, render_for_threads
from model.Tag import Tag
from model.Thread import Thread
from model.ThreadPosts import ThreadPosts
from shared import app, db

try:
    from nacl.signing import SigningKey
except Exception:
    SigningKey = None


DISTRIBUTED_SCHEMA_VERSION = 1
DEFAULT_SYNC_INTERVAL_MS = 10 * 60 * 1000
DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000
DEFAULT_FEED_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_SUPERPEER_RATIO = 0.05
_PUBLIC_POST_STRIP_KEYS = {
    "ban_url",
    "block_media_url",
    "delete_url",
    "move_url",
    "viewer_can_moderate",
    "viewer_is_admin",
}


def distributed_enabled():
    return bool(_private_key_hex()) and SigningKey is not None


def distributed_client_config(page_type, board_name, thread_id=None):
    return {
        "enabled": distributed_enabled(),
        "boardName": board_name,
        "threadId": thread_id,
        "pageType": page_type,
        "scopeId": scope_id_for_page(page_type, board_name, thread_id=thread_id),
        "manifestUrl": _scope_url("/api/v1/manifest", board_name, page_type, thread_id=thread_id),
        "deltaUrl": _scope_url("/api/v1/posts", board_name, page_type, thread_id=thread_id),
        "feedUrl": _scope_url("/api/v1/feed", board_name, page_type, thread_id=thread_id),
        "gunRelayUrl": "/gun",
        "gunScriptUrl": "/static/js/gun.js",
        "workerUrl": "/static/js/distributed-crypto-worker.js",
        "signerPublicKeyHex": public_key_hex(),
        "syncIntervalMs": int(os.getenv("DISTRIBUTED_SYNC_INTERVAL_MS") or DEFAULT_SYNC_INTERVAL_MS),
        "maxClockSkewMs": int(os.getenv("DISTRIBUTED_CLOCK_SKEW_MS") or DEFAULT_CLOCK_SKEW_MS),
        "superPeerRatio": float(os.getenv("DISTRIBUTED_SUPERPEER_RATIO") or DEFAULT_SUPERPEER_RATIO),
        "feedPollIntervalSeconds": float(
            os.getenv("DISTRIBUTED_FEED_POLL_INTERVAL_SECONDS") or DEFAULT_FEED_POLL_INTERVAL_SECONDS
        ),
    }


def public_key_hex():
    if SigningKey is None or not _private_key_hex():
        return ""
    try:
        signing_key = SigningKey(bytes.fromhex(_private_key_hex()))
        return signing_key.verify_key.encode().hex()
    except Exception:
        app.logger.exception("Failed deriving distributed public key")
        return ""


def scope_id_for_page(page_type, board_name, thread_id=None):
    normalized_type = "thread" if str(page_type) == "thread" else "catalog"
    if normalized_type == "thread" and thread_id is not None:
        return "thread:local:%s:%s" % (board_name, thread_id)
    return "board:local:%s:catalog" % board_name


def scope_manifest(board_name, page_type="catalog", thread_id=None):
    scope = build_scope_records(board_name, page_type=page_type, thread_id=thread_id)
    checksum_input = [
        {
            "id": record["id"],
            "seq": record["seq"],
            "type": record["type"],
            "prev_hash": record["prev_hash"],
        }
        for record in scope["records"]
    ]
    checksum = hashlib.sha256(_canonical_json(checksum_input).encode("utf-8")).hexdigest()
    return {
        "board_id": scope["board_name"],
        "scope_id": scope["scope_id"],
        "page_type": scope["page_type"],
        "thread_id": scope.get("thread_id"),
        "last_seq": max([record["seq"] for record in scope["records"]] or [0]),
        "record_count": len(scope["records"]),
        "checksum": checksum,
        "signer": public_key_hex(),
    }


def scope_delta(board_name, after_seq=0, page_type="catalog", thread_id=None, limit=None):
    scope = build_scope_records(board_name, page_type=page_type, thread_id=thread_id)
    filtered_records = [record for record in scope["records"] if int(record["seq"]) > int(after_seq or 0)]
    filtered_records.sort(key=lambda record: (record["seq"], record["id"]))
    if limit is not None:
        filtered_records = filtered_records[: max(0, int(limit))]
    return {
        "board_id": scope["board_name"],
        "scope_id": scope["scope_id"],
        "page_type": scope["page_type"],
        "thread_id": scope.get("thread_id"),
        "last_seq": max([record["seq"] for record in scope["records"]] or [0]),
        "records": filtered_records,
    }


def build_scope_records(board_name, page_type="catalog", thread_id=None):
    board = get_board_by_name_or_404(board_name)
    normalized_page_type = "thread" if str(page_type) == "thread" else "catalog"
    tag_styles = {}
    records = []
    if normalized_page_type == "thread":
        if thread_id is None:
            raise ValueError("thread_id is required for thread scope")
        thread, thread_board = get_thread_and_board_or_404(int(thread_id))
        if thread_board.id != board.id:
            raise ValueError("Thread %s does not belong to /%s/" % (thread_id, board_name))
        posts = ThreadPosts().retrieve(thread.id)
        posts = _sanitize_posts(posts)
        render_for_threads(posts)
        catalog_threads = BoardCatalog().retrieve(board.id)
        render_for_catalog(catalog_threads)
        tag_styles = _tag_styles_for_threads(catalog_threads)
        thread_summary = None
        for candidate in catalog_threads:
            if int(candidate.get("id")) == int(thread.id):
                thread_summary = candidate
                break
        board_payload = _board_payload(board, tag_styles)
        records.append(_signed_record("board", board_payload, _board_seq(board, posts=posts, thread_summary=thread_summary)))
        if thread_summary is not None:
            records.append(_signed_record("thread", _thread_payload(board, thread_summary), _thread_seq(thread_summary)))
        elif posts:
            records.append(
                _signed_record(
                    "thread",
                    _thread_payload(board, _thread_summary_from_posts(thread, posts)),
                    _thread_seq(_thread_summary_from_posts(thread, posts)),
                )
            )
        for post in posts:
            records.append(
                _signed_record(
                    "post",
                    _post_payload(board, thread, thread_summary or _thread_summary_from_posts(thread, posts), post),
                    _post_seq(post),
                )
            )
    else:
        catalog_threads = BoardCatalog().retrieve(board.id)
        render_for_catalog(catalog_threads)
        tag_styles = _tag_styles_for_threads(catalog_threads)
        board_payload = _board_payload(board, tag_styles)
        records.append(_signed_record("board", board_payload, _board_seq(board, catalog_threads=catalog_threads)))
        for thread_payload in catalog_threads:
            records.append(_signed_record("thread", _thread_payload(board, thread_payload), _thread_seq(thread_payload)))
    records = _attach_prev_hash(records)
    return {
        "board_name": board.name,
        "scope_id": scope_id_for_page(normalized_page_type, board.name, thread_id=thread_id),
        "page_type": normalized_page_type,
        "thread_id": int(thread_id) if thread_id is not None else None,
        "records": records,
    }


def _scope_url(base_path, board_name, page_type, thread_id=None):
    params = [
        "board_name=%s" % board_name,
        "page_type=%s" % ("thread" if str(page_type) == "thread" else "catalog"),
    ]
    if thread_id is not None:
        params.append("thread_id=%s" % int(thread_id))
    return "%s?%s" % (base_path, "&".join(params))


def _private_key_hex():
    return (os.getenv("ANUBIS_ED25519_PRIVATE_KEY_HEX") or "").strip()


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _json_ready(value):
    if isinstance(value, datetime.datetime):
        dt_value = value
        if value.tzinfo is None:
            dt_value = value.replace(tzinfo=datetime.timezone.utc)
        else:
            dt_value = value.astimezone(datetime.timezone.utc)
        return dt_value.isoformat().replace("+00:00", "Z")
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    return value


def _datetime_to_epoch_ms(value):
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        else:
            value = value.astimezone(datetime.timezone.utc)
        return int(value.timestamp() * 1000)
    if isinstance(value, (int, float)):
        return int(value)
    return 0


def _current_epoch_ms():
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)


def _seq_from_parts(timestamp_ms, discriminator):
    # Use seconds (not ms) so seq stays within JS MAX_SAFE_INTEGER (~9e15).
    # timestamp_ms (~1.75e12) * 1_000_000 = ~1.75e18, which JS float64 cannot
    # represent exactly, causing canonical JSON mismatch and signature failure.
    # timestamp_s (~1.75e9) * 1_000_000 = ~1.75e15, safely within 9e15.
    return (int(timestamp_ms) // 1000) * 1_000_000 + int(discriminator)


def _board_record_id(board_name):
    return "board:local:%s" % board_name


def _thread_record_id(source, board_name, thread_id):
    return "thread:%s:%s:%s" % (source or "local", board_name, thread_id)


def _post_record_id(source, board_name, post_id):
    return "post:%s:%s:%s" % (source or "local", board_name, post_id)


def _tag_styles_for_threads(threads):
    tag_names = set()
    for thread in threads:
        for tag in thread.get("tags") or []:
            tag_names.add(tag)
    if not tag_names:
        return {}
    styles = {}
    for tag in db.session.query(Tag).filter(Tag.name.in_(tag_names)).all():
        styles[tag.name] = {}
        if tag.bg_style:
            styles[tag.name]["bg_style"] = tag.bg_style
        if tag.text_style:
            styles[tag.name]["text_style"] = tag.text_style
    return styles


def _sanitize_posts(posts):
    sanitized = []
    for post in posts:
        cloned = deepcopy(post)
        for key in _PUBLIC_POST_STRIP_KEYS:
            cloned.pop(key, None)
        sanitized.append(cloned)
    return sanitized


def _board_payload(board, tag_styles):
    return {
        "id": _board_record_id(board.name),
        "source": "local",
        "name": board.name,
        "display_name": board.title,
        "description": board.rules or "",
        "tag_styles": tag_styles or {},
    }


def _thread_payload(board, thread_payload):
    source = thread_payload.get("source_type") or "local"
    body = thread_payload.get("body") or ""
    subject = thread_payload.get("subject") or ""
    last_activity_ms = _datetime_to_epoch_ms(thread_payload.get("last_updated"))
    return {
        "id": _thread_record_id(source, board.name, thread_payload.get("id")),
        "source": source,
        "board_id": board.name,
        "thread_numeric_id": int(thread_payload.get("id")),
        "title": subject,
        "content": body,
        "media_hash": _media_hash_from_payload(thread_payload),
        "created_at": last_activity_ms,
        "last_activity": last_activity_ms,
        "post_count": int(thread_payload.get("num_replies") or 0) + 1,
        "media_count": int(thread_payload.get("num_media") or 0),
        "verified": 1,
        "display": _json_ready(thread_payload),
    }


def _post_payload(board, thread, thread_summary, post_payload):
    thread_source = (thread_summary or {}).get("source_type") or getattr(thread, "source_type", None) or "local"
    source = post_payload.get("source_type") or "local"
    media_hash = _media_hash_from_payload(post_payload)
    created_at = _datetime_to_epoch_ms(post_payload.get("datetime"))
    return {
        "id": _post_record_id(source, board.name, post_payload.get("id")),
        "source": source,
        "board_id": board.name,
        "thread_id": _thread_record_id(thread_source, board.name, thread.id),
        "thread_numeric_id": int(thread.id),
        "author": post_payload.get("poster") or "Anonymous",
        "content": post_payload.get("body") or "",
        "media_hash": media_hash,
        "created_at": created_at,
        "verified": 1,
        "display": _json_ready(post_payload),
    }


def _thread_summary_from_posts(thread, posts):
    op_post = posts[0] if posts else {}
    return {
        "id": thread.id,
        "subject": op_post.get("subject"),
        "last_updated": posts[-1].get("datetime") if posts else getattr(thread, "last_updated", None),
        "body": op_post.get("body") or "",
        "thread_url": "/threads/%d" % thread.id,
        "spoiler": op_post.get("spoiler"),
        "tags": op_post.get("tags") or [],
        "views": getattr(thread, "views", 0),
        "num_replies": max(0, len(posts) - 1),
        "num_media": sum(1 for post in posts if post.get("media")),
        "admin_post": False,
        "source_type": getattr(thread, "source_type", "local"),
        "source_name": getattr(thread, "source_name", None),
        "source_url": getattr(thread, "source_url", None),
        "media": op_post.get("media"),
        "media_url": op_post.get("media_url"),
        "direct_media_url": op_post.get("direct_media_url"),
        "magnet_media_url": op_post.get("magnet_media_url"),
        "thumb_url": op_post.get("thumb_url"),
        "torrent": op_post.get("torrent"),
        "mimetype": op_post.get("mimetype"),
        "is_imported": op_post.get("is_imported"),
        "source_label": op_post.get("source_label"),
    }


def _media_hash_from_payload(payload):
    torrent_payload = payload.get("torrent") or {}
    info_hash = torrent_payload.get("info_hash")
    if info_hash:
        return info_hash
    media_id = payload.get("media")
    if media_id is None:
        return None
    return "media:%s" % media_id


def _board_seq(board, catalog_threads=None, posts=None, thread_summary=None):
    candidate_ms = 0
    for thread_payload in catalog_threads or []:
        candidate_ms = max(candidate_ms, _datetime_to_epoch_ms(thread_payload.get("last_updated")))
    if thread_summary is not None:
        candidate_ms = max(candidate_ms, _datetime_to_epoch_ms(thread_summary.get("last_updated")))
    for post in posts or []:
        candidate_ms = max(candidate_ms, _datetime_to_epoch_ms(post.get("datetime")))
    if candidate_ms <= 0:
        candidate_ms = _datetime_to_epoch_ms(getattr(board, "created_at", None)) or _current_epoch_ms()
    return _seq_from_parts(candidate_ms, (int(board.id) * 10) + 3)


def _thread_seq(thread_payload):
    timestamp_ms = _datetime_to_epoch_ms(thread_payload.get("last_updated"))
    if timestamp_ms <= 0:
        timestamp_ms = _datetime_to_epoch_ms(thread_payload.get("created_at"))
    if timestamp_ms <= 0:
        timestamp_ms = _current_epoch_ms()
    return _seq_from_parts(
        timestamp_ms,
        (int(thread_payload.get("id") or 0) * 10) + 2,
    )


def _post_seq(post_payload):
    timestamp_ms = _datetime_to_epoch_ms(post_payload.get("datetime"))
    if timestamp_ms <= 0:
        timestamp_ms = _datetime_to_epoch_ms(post_payload.get("created_at"))
    if timestamp_ms <= 0:
        timestamp_ms = _current_epoch_ms()
    return _seq_from_parts(
        timestamp_ms,
        (int(post_payload.get("id") or 0) * 10) + 1,
    )


def _signed_record(record_type, payload, seq):
    envelope = {
        "v": DISTRIBUTED_SCHEMA_VERSION,
        "id": payload["id"],
        "type": record_type,
        "seq": int(seq),
        "ts": int(seq // 1_000_000) * 1000,
        "signer": public_key_hex(),
        "payload": base64.b64encode(_canonical_json(payload).encode("utf-8")).decode("ascii"),
        "prev_hash": None,
    }
    envelope["sig"] = _sign_envelope(envelope)
    return envelope


def _attach_prev_hash(records):
    ordered_records = sorted(records, key=lambda record: (record["seq"], record["id"]))
    previous_hash = None
    for record in ordered_records:
        record["prev_hash"] = previous_hash
        record["sig"] = _sign_envelope(record)
        previous_hash = envelope_hash(record)
    return ordered_records


def envelope_hash(record):
    material = {key: record[key] for key in ("v", "id", "type", "seq", "ts", "signer", "payload", "prev_hash")}
    return hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()


def _sign_envelope(record):
    if SigningKey is None or not _private_key_hex():
        return ""
    signing_key = SigningKey(bytes.fromhex(_private_key_hex()))
    material = {key: record[key] for key in ("v", "id", "type", "seq", "ts", "signer", "payload", "prev_hash")}
    return signing_key.sign(_canonical_json(material).encode("utf-8")).signature.hex()
