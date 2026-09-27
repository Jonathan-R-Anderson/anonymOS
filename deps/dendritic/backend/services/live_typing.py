"""Real-time capture of text being composed on the imageboard's post/reply
forms, for the admin live-monitor panel.

Posters' post-body textareas stream their current draft (throttled) to
record_draft(); the admin panel polls active_drafts() a few times a second to
watch text populate against each visitor's IP. Everything lives in Redis with a
short TTL so a draft disappears seconds after someone stops typing. Scope is the
operator's own site only — the site's own forms feeding the site's own admin.
"""
import json
import time

import keystore

_DRAFT_TTL = 30          # seconds a single draft key lives without an update
_WINDOW = 25             # a typist's card lingers this long after they stop typing
_MAX_TEXT = 4096         # matches the post body maxlength
_MAX_TRACKED = 300       # safety cap on concurrent tracked drafts

_client = None


def _redis():
    global _client
    if _client is None:
        _client = keystore.make_redis()
    return _client


def _key(comp_id):
    return "livetype:draft:" + comp_id


def record_draft(comp_id, ip, text, path=None, board=None, name=None):
    """Store (or refresh) one visitor's in-progress draft. Best-effort: never
    raises into the request that called it."""
    comp_id = (comp_id or "").strip()[:64]
    if not comp_id:
        return
    try:
        now = time.time()
        payload = json.dumps({
            "ip": (ip or "?")[:64],
            "text": (text or "")[:_MAX_TEXT],
            "path": (path or "")[:200],
            "board": (board or "")[:64],
            "name": (name or "")[:64],
            "ts": now,
        })
        r = _redis()
        pipe = r.pipeline()
        pipe.setex(_key(comp_id), _DRAFT_TTL, payload)
        pipe.zadd("livetype:index", {comp_id: now})
        pipe.zremrangebyscore("livetype:index", 0, now - _WINDOW)
        pipe.execute()
    except Exception:
        pass


def clear_draft(comp_id):
    """Drop a draft immediately (e.g. once the post is submitted)."""
    comp_id = (comp_id or "").strip()[:64]
    if not comp_id:
        return
    try:
        r = _redis()
        r.delete(_key(comp_id))
        r.zrem("livetype:index", comp_id)
    except Exception:
        pass


def active_drafts(window_seconds=_WINDOW):
    """Every draft touched within the window, newest first, for the admin feed."""
    try:
        r = _redis()
        now = time.time()
        r.zremrangebyscore("livetype:index", 0, now - window_seconds)
        comp_ids = r.zrevrangebyscore("livetype:index", now, now - window_seconds)
    except Exception:
        return []
    out = []
    for comp_id in comp_ids[:_MAX_TRACKED]:
        try:
            raw = r.get(_key(comp_id))
        except Exception:
            continue
        if not raw:
            continue
        try:
            draft = json.loads(raw)
        except Exception:
            continue
        draft["comp_id"] = comp_id
        draft["age"] = round(max(0.0, now - float(draft.get("ts", now))), 1)
        out.append(draft)
    return out
