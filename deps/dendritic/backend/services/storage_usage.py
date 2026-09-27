"""Bytes stored locally vs bytes the DHT network is offering.

There is no size column on Media, so "how much are we storing" has to come from
the object store itself: one paginated ListObjects per bucket, summing Size.
That is cheap enough to run hourly and far too expensive to run per page load,
so it is memoized with a TTL and served stale while a refresh is pending.

CHART CHOICE (why a stacked bar and not a pie)
----------------------------------------------
Used is ~21 GiB against ~999 GiB offered -- roughly 2%. A pie or donut renders
2% as a slice a couple of pixels wide: technically correct, visually useless,
and it invites the reader to conclude "basically empty" without being able to
tell 2% from 0.2%. A single horizontal stacked bar keeps the part-to-whole
relationship honest at extreme ratios, and pairing it with explicit byte labels
covers what the geometry cannot show at that scale. Log axes were rejected: they
make a part-to-whole comparison unreadable, because the segments no longer sum
to the whole.
"""
import threading
import time

from shared import app


_CACHE = {"at": 0.0, "value": None}
_LOCK = threading.Lock()
_TTL_SECONDS = 3600


def _sum_bucket(storage, bucket_attr):
    """Total bytes in one bucket, or None if it cannot be listed."""
    try:
        name = getattr(storage, bucket_attr)
        bucket = storage._s3_client.Bucket(storage._bucket_name(name)
                                           if hasattr(storage, "_bucket_name") else name)
        return sum(int(obj.size or 0) for obj in bucket.objects.all())
    except Exception:
        app.logger.info("storage usage: could not list %s", bucket_attr, exc_info=True)
        return None


def _measure():
    from model.Media import storage

    buckets = {}
    total = 0
    known = False
    for attr, label in (
        ("_ATTACHMENT_BUCKET", "attachments"),
        ("_THUMBNAIL_BUCKET", "thumbs"),
        ("_PREVIEW_BUCKET", "previews"),
    ):
        value = _sum_bucket(storage, attr)
        buckets[label] = value
        if value is not None:
            total += value
            known = True
    # None, not 0, when nothing could be listed: "we don't know" and "we store
    # nothing" must not render as the same bar.
    return {"buckets": buckets, "used_bytes": total if known else None}


def local_usage(force=False):
    """Cached {buckets, used_bytes}. Serves stale rather than blocking."""
    now = time.time()
    if not force and _CACHE["value"] is not None and now - _CACHE["at"] < _TTL_SECONDS:
        return _CACHE["value"]
    if not _LOCK.acquire(blocking=False):
        return _CACHE["value"] or {"buckets": {}, "used_bytes": None}
    try:
        value = _measure()
        _CACHE["value"] = value
        _CACHE["at"] = now
        return value
    finally:
        _LOCK.release()


def human(value):
    if value is None:
        return "unknown"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if size < 1024 or unit == "PiB":
            return "%.1f %s" % (size, unit)
        size /= 1024
    return "%.1f PiB" % size


def summary(force=False):
    """Everything the admin storage chart needs, in one call."""
    from model.StorageNode import network_summary

    usage = local_usage(force=force)
    net = network_summary()
    used = usage.get("used_bytes")
    capacity = int(net.get("capacity_bytes") or 0)
    free = max(0, capacity - (used or 0)) if capacity else 0
    return {
        "used_bytes": used,
        "used_human": human(used),
        "capacity_bytes": capacity,
        "capacity_human": net.get("capacity_human"),
        "free_bytes": free,
        "free_human": human(free) if capacity else "unknown",
        # Percent of OFFERED capacity currently consumed. None when either side
        # is unknown, so the bar renders an explicit "unknown" state instead of
        # a confident 0%.
        "used_percent": (round(used / capacity * 100.0, 2)
                         if (used is not None and capacity) else None),
        "nodes": net.get("nodes", 0),
        "buckets": usage.get("buckets", {}),
        "buckets_human": {k: human(v) for k, v in (usage.get("buckets") or {}).items()},
    }
