"""Federate the distance-based image banlist over NNTPChan.

Local bans AND removals are POSTed as small JSON articles to a dedicated banlist
newsgroup; peers pull that group, re-derive the same perceptual fingerprint
math, and either add (action=ban) or revoke (action=unban) matching entries.
Only fingerprints/hashes travel — never the image.

Each message carries the perceptual fingerprint and, when known, the exact
SHA-256 of the reference file, so a peer can match a ban/unban by exact file OR
by Manhattan distance. Trust: if `nntpchan_banlist_secret` is set, only messages
with a matching HMAC (over action|algorithm|dims|fingerprint) are honored.
"""
import email.utils
import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict

from shared import app, db
from model.SiteSetting import get_setting
from model.BannedImageFingerprint import (
    pending_ban_broadcasts,
    pending_unban_broadcasts,
    mark_broadcasted,
    mark_revoke_broadcasted,
    ingest_remote_fingerprint,
    apply_unban,
    distance_threshold,
)
from services.nntpchan.client import NNTPError


BANLIST_GROUP_SETTING = "nntpchan_banlist_group"
DEFAULT_BANLIST_GROUP = "overchan.maniwani.imgban"
INGEST_SETTING = "nntpchan_banlist_ingest"
SECRET_SETTING = "nntpchan_banlist_secret"
NODE_ID_SETTING = "nntpchan_node_id"
DEFAULT_NODE_ID = "maniwani"
_MESSAGE_TYPE = "maniwani-image-ban"


def banlist_group():
    return (get_setting(BANLIST_GROUP_SETTING, DEFAULT_BANLIST_GROUP) or DEFAULT_BANLIST_GROUP).strip()


def ingest_enabled():
    return str(get_setting(INGEST_SETTING, "1")).strip().lower() not in ("", "0", "false", "no", "off")


def _secret():
    return (get_setting(SECRET_SETTING, "") or "").strip()


def _node_id():
    return (get_setting(NODE_ID_SETTING, DEFAULT_NODE_ID) or DEFAULT_NODE_ID).strip() or DEFAULT_NODE_ID


def _sign(action, algorithm, dims, fingerprint_hex, secret):
    canonical = ("%s|%s|%s|%s" % (action, algorithm, dims, fingerprint_hex)).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def build_message(row, action):
    node = _node_id()
    group = banlist_group()
    message_id = "<%s%x@%s>" % (secrets.token_hex(8), int(time.time()), node)
    payload = {
        "type": _MESSAGE_TYPE,
        "v": 1,
        "action": action,             # "ban" | "unban"
        "algorithm": row.algorithm,
        "dims": row.dims,
        "fingerprint": row.fingerprint,
        "sha256": row.sha256 or "",
        "reason": row.reason or "",
        "threshold_hint": distance_threshold(),
    }
    secret = _secret()
    if secret:
        payload["hmac"] = _sign(action, row.algorithm, row.dims, row.fingerprint, secret)
    headers = OrderedDict([
        ("Message-ID", message_id),
        ("Newsgroups", group),
        ("From", "maniwani banlist <banlist@%s>" % node),
        ("Subject", "maniwani image %s %s" % (action, row.fingerprint[:12])),
        ("Date", email.utils.formatdate(usegmt=True)),
        ("Path", node),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=UTF-8"),
        ("X-Maniwani-Banlist", action),
    ])
    return message_id, headers, json.dumps(payload)


def _post_rows(client, rows, action, on_success):
    posted = 0
    for row in rows:
        message_id, headers, body = build_message(row, action)
        try:
            client.post_article(headers, body)
        except NNTPError as exc:
            app.logger.warning("NNTPChan banlist: %s broadcast refused (%s); will retry", action, exc)
            break
        on_success(row, message_id)
        posted += 1
    return posted


def broadcast_pending(client):
    """POST pending local bans and unbans through `client`. Returns count posted.

    Stops (without marking) if the peer refuses a POST so a later peer/cycle can
    retry; one successful POST is enough since NNTP flooding propagates it.
    """
    total = 0
    total += _post_rows(client, pending_ban_broadcasts(), "ban",
                        lambda row, mid: mark_broadcasted(row, mid))
    total += _post_rows(client, pending_unban_broadcasts(), "unban",
                        lambda row, _mid: mark_revoke_broadcasted(row))
    if total:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("NNTPChan banlist: commit after broadcast failed")
    return total


def parse_ban_article(article):
    """Validate a banlist article -> dict(action,algorithm,dims,fingerprint,sha256,reason) or None."""
    body = (article.body_text or "").strip()
    if not body:
        return None
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or payload.get("type") != _MESSAGE_TYPE:
        return None
    action = (payload.get("action") or "ban").strip().lower()
    if action not in ("ban", "unban"):
        return None
    fingerprint = (payload.get("fingerprint") or "").strip().lower()
    algorithm = (payload.get("algorithm") or "").strip()
    dims = payload.get("dims")
    if not fingerprint or not algorithm:
        return None
    try:
        dims = int(dims)
    except (TypeError, ValueError):
        return None
    secret = _secret()
    if secret:
        expected = _sign(action, algorithm, dims, fingerprint, secret)
        if not hmac.compare_digest(expected, (payload.get("hmac") or "")):
            app.logger.warning("NNTPChan banlist: dropping unsigned/invalid %s %s", action, article.message_id)
            return None
    return {
        "action": action,
        "algorithm": algorithm,
        "dims": dims,
        "fingerprint": fingerprint,
        "sha256": (payload.get("sha256") or "").strip().lower() or None,
        "reason": (payload.get("reason") or "")[:500] or None,
    }


def ingest_ban_article(article):
    """Apply one banlist article locally. Returns True if it changed state."""
    if not ingest_enabled():
        return False
    parsed = parse_ban_article(article)
    if parsed is None:
        return False
    if parsed["action"] == "unban":
        revoked = apply_unban(
            parsed["fingerprint"], sha256=parsed["sha256"],
            algorithm=parsed["algorithm"], dims=parsed["dims"],
            source_message_id=article.message_id,
        )
        return revoked > 0
    row = ingest_remote_fingerprint(
        parsed["fingerprint"], parsed["algorithm"], parsed["dims"],
        reason=parsed["reason"], source_message_id=article.message_id,
        sha256=parsed["sha256"],
    )
    return row is not None
