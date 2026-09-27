"""Snapshot objects live in the DHT. This is the path to them.

The store is the DHT, reached through the storage node's S3 gateway
(``services/snapshot_dht.py``). Local disk is a CACHE in front of it: it saves
the origin a round trip, and losing it costs latency rather than the snapshot.
That is why nothing here fails a publish when a local write does — but a failed
READ, which falls through to the DHT, does fail it.

Objects are content-addressed, which is what makes the arrangement safe. Every
retrieval re-checks that the bytes hash to the name asked for, so a cache that
returns something stale, a gateway that returns something wrong, and a volunteer
that returns something malicious are all the same detectable event rather than
three kinds of trust.
"""

import os
import tempfile

from shared import app

# A local cache, NOT the store. The DHT is where snapshots live; this is a copy
# the origin can serve from without a round trip, and losing it costs latency
# rather than the snapshot.
#
# Under the system temp directory because it needs no configuration and no
# volume: a path that must be set correctly is a path that can be set wrongly,
# and the first version of this shipped pointing at /var/lib/maniwani, which the
# container user cannot write.
_CACHE_ROOT = os.path.join(tempfile.gettempdir(), "syndichan-snapshots")


def root():
    return (app.config.get("SNAPSHOT_DIR") or _CACHE_ROOT).rstrip("/")


def _object_path(digest):
    # Two-level fan-out: a single directory with tens of thousands of entries is
    # slow to list and unpleasant to inspect by hand during an incident.
    return os.path.join(root(), "objects", digest[:2], digest[2:4], digest)


def put_object(digest, body):
    """Store one object. Returns False if it could not be written.

    Writes are skipped when the file already exists — the point of content
    addressing is that identical bytes are the same object, so an hourly rebuild
    rewrites only what changed.
    """
    path = _object_path(digest)
    if os.path.exists(path):
        return True
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Written to a temporary name and renamed, so a reader can never observe
        # a half-written object under a hash that promises the whole thing.
        temporary = path + ".tmp"
        with open(temporary, "wb") as handle:
            handle.write(body)
        os.replace(temporary, path)
        return True
    except Exception:
        app.logger.exception("snapshot: could not store object %s", digest[:12])
        return False


def get_object(digest):
    """Fetch one object, verifying it hashes to its name.

    The check is not paranoia about the filesystem. It is what makes this layer
    replaceable: every consumer already assumes bytes are validated at the point
    of retrieval, so the DHT implementation that follows inherits a caller that
    was never trusting its storage.
    """
    from services.snapshot import sha256_hex

    path = _object_path(digest)
    body = None
    try:
        with open(path, "rb") as handle:
            body = handle.read()
    except Exception:
        body = None
    if body is not None and sha256_hex(body) == digest:
        return body
    if body is not None:
        app.logger.error("snapshot: cached object %s does not match its hash; "
                         "discarding and refetching", digest[:12])

    # The DHT is the store; the local copy is only a cache. A miss here is
    # normal after a restart and must not read as a missing snapshot.
    try:
        from services import snapshot_dht

        if not snapshot_dht.enabled():
            return None
        fetched = snapshot_dht.get(digest)
    except Exception:
        app.logger.exception("snapshot: could not fetch %s from the DHT store",
                             digest[:12])
        return None
    if fetched is not None:
        put_object(digest, fetched)   # repopulate the cache, best effort
    return fetched


def _cache_manifest(manifest, body):
    """Write a manifest to the LOCAL cache only.

    Separate from put_manifest so that refilling the cache after reading from
    the DHT cannot write straight back to it — a read that triggers a write is
    a round trip nobody asked for, on every request.
    """
    sequence = int(manifest.get("sequence") or 0)
    try:
        os.makedirs(os.path.join(root(), "manifests"), exist_ok=True)
        path = os.path.join(root(), "manifests", "%d.json" % sequence)
        temporary = path + ".tmp"
        with open(temporary, "wb") as handle:
            handle.write(body)
        os.replace(temporary, path)
        # The pointer moves LAST and atomically. A reader that catches this
        # mid-update sees either the old snapshot or the new one, never a
        # manifest whose objects have not finished being written.
        current = os.path.join(root(), "current.json")
        current_tmp = current + ".tmp"
        with open(current_tmp, "wb") as handle:
            handle.write(body)
        os.replace(current_tmp, current)
        return True
    except Exception:
        app.logger.exception("snapshot: could not cache manifest %d", sequence)
        return False


def put_manifest(manifest, body):
    """Cache a manifest locally, then mirror it to the DHT. Local first."""
    sequence = int(manifest.get("sequence") or 0)
    if not _cache_manifest(manifest, body):
        return False

    # The manifest belongs in the DHT too, or a gateway serving during an outage
    # has the objects and no way to know which of them answers a given path.
    # Written AFTER the objects and after they read back, so a manifest in the
    # store is always a manifest whose contents are fetchable.
    try:
        from services import snapshot_dht

        if snapshot_dht.enabled():
            client = snapshot_dht._client()
            snapshot_dht.put_manifest(sequence, body, client=client)
    except Exception:
        # A manifest that reached local disk is still an active snapshot the
        # origin can serve; failing the publish over the mirror would trade a
        # working snapshot for none.
        app.logger.exception("snapshot: manifest %d not mirrored to the DHT", sequence)
    return True


def current_manifest():
    """The manifest a client should be verifying against, or None.

    Falls back to the DHT, for the same reason get_object does and for a reason
    that bit harder: the local copy lives under the system temp directory, so a
    pod restart wipes it. Without this fallback the site answered 404 for a
    snapshot that was sitting intact in the store, which reads as "no snapshot
    has ever been published" — the most misleading possible answer.
    """
    import json

    try:
        with open(os.path.join(root(), "current.json"), "rb") as handle:
            return json.loads(handle.read().decode("utf-8"))
    except Exception:
        pass

    try:
        from services import snapshot_dht

        if not snapshot_dht.enabled():
            return None
        manifest = snapshot_dht.current_manifest()
    except Exception:
        app.logger.exception("snapshot: could not read the manifest from the DHT")
        return None
    if manifest is not None:
        # Repopulate the local cache so the next read is a file read.
        try:
            from services.snapshot import canonical_manifest_json

            _cache_manifest(manifest, canonical_manifest_json(manifest))
        except Exception:
            pass
    return manifest


def publish(manifest, objects):
    """Store, verify, then activate — in that order, always.

    THE THREE PHASES, AND WHY THE ORDER IS THE WHOLE POINT
    ------------------------------------------------------
    1. PREPARE   every object is written, everywhere it goes.
    2. VERIFY    every object is READ BACK and checked against its hash.
    3. ACTIVATE  the current pointer moves, last and atomically.

    A manifest is a promise that its objects exist. Publishing it before they do
    would advertise a snapshot that half-loads during exactly the outage it was
    built for — and the reader would see a broken site rather than an honest
    "unavailable", which is worse because it looks like syndichan's fault.

    Verification is a separate phase from writing because a write that returned
    success and a read that returns the right bytes are different claims. Only
    the second one means somebody can actually be served.

    The previous snapshot stays active throughout. If any phase fails, nothing
    changes: the site keeps whatever it already had, which is always better than
    a newer snapshot that cannot be served.
    """
    from services.snapshot import canonical_manifest_json

    # Local first, best effort: it is a cache, so a failure here costs latency
    # and must not stop a snapshot from existing.
    for digest, body in objects.items():
        put_object(digest, body)

    # Phase 2: prove every object can be READ, not merely that a write returned
    # success. get_object falls through to the DHT, so this verifies the whole
    # path a reader will take rather than the copy that happens to be nearby.
    missing = [digest for digest in objects if get_object(digest) is None]
    if missing:
        app.logger.error("snapshot: %d of %d object(s) did not read back "
                         "(%s...); not activating", len(missing), len(objects),
                         missing[0][:12])
        return False

    return put_manifest(manifest, canonical_manifest_json(manifest))


def publish_to_dht(manifest, objects):
    """Mirror a snapshot into the object store the DHT serves from.

    Reported separately from the local publish and never gates it: the local
    copy is what makes phase 1 work, and a DHT that is refusing writes — which
    at the time of writing most peers do — must not stop the site from having a
    snapshot at all.
    """
    from services import snapshot_dht

    if not snapshot_dht.enabled():
        return {"attempted": False, "reason": "no object store configured"}

    client = None
    try:
        client = snapshot_dht._client()
        snapshot_dht.ensure_bucket(client)
    except Exception:
        app.logger.exception("snapshot: object store unreachable")
        return {"attempted": False, "reason": "object store unreachable"}

    expires_at = manifest.get("expires_at")
    written = 0
    for digest, body in objects.items():
        if snapshot_dht.put(digest, body, expires_at=expires_at, client=client):
            written += 1

    confirmed, missing = snapshot_dht.readback(list(objects), client=client)
    return {
        "attempted": True,
        "written": written,
        "of": len(objects),
        # Retrievability, NOT replication breadth. The gateway does not report
        # how many peers hold an object, and inventing a number here would be
        # believed during the outage it was supposed to protect.
        "readback_confirmed": confirmed,
        "readback_missing": len(missing),
        "note": "readback proves the object can be fetched, not that it is "
                "replicated across distinct peers — that needs the node's DHT "
                "API and is not claimed here",
    }


# Retention, from the roadmap: the active snapshot plus two, so a malformed
# newest one can be rolled back to something that worked.
RETAINED_SNAPSHOTS = 3
# Objects outlive their manifest by this much before collection. A gateway that
# fetched a manifest a moment before it was superseded must still be able to
# complete the download it started.
GC_GRACE_SECONDS = 6 * 3600


def collect(now=None):
    """Remove snapshots and objects nothing retained still references.

    REFERENCE COUNTING, not age. An object is shared between snapshots by
    construction — that is what content addressing buys — so deleting by age
    would delete the unchanged CSS every retained snapshot still points at.

    Returns a summary rather than raising: garbage collection failing is a disk
    that fills slowly, while garbage collection deleting the wrong thing is a
    snapshot that cannot be served during an outage.
    """
    import time as _time

    now = now or _time.time()
    summary = {"kept": [], "dropped": [], "objects_removed": 0, "errors": 0}
    try:
        manifests = _stored_manifests()
    except Exception:
        app.logger.exception("snapshot gc: could not list manifests")
        summary["errors"] += 1
        return summary

    keep = manifests[:RETAINED_SNAPSHOTS]
    drop = manifests[RETAINED_SNAPSHOTS:]
    summary["kept"] = [m["sequence"] for m in keep]

    referenced = set()
    for entry in keep:
        referenced.update(entry["objects"])

    for entry in drop:
        # Expiry plus grace, so a gateway mid-download of a just-superseded
        # snapshot is not cut off partway.
        if now < entry["expires_at"] + GC_GRACE_SECONDS:
            summary["kept"].append(entry["sequence"])
            referenced.update(entry["objects"])
            continue
        try:
            os.remove(entry["path"])
            summary["dropped"].append(entry["sequence"])
        except Exception:
            summary["errors"] += 1

    summary["objects_removed"] = _remove_unreferenced(referenced)
    return summary


def _stored_manifests():
    """Every retained manifest, newest first, with the objects it references."""
    import json

    directory = os.path.join(root(), "manifests")
    found = []
    for name in os.listdir(directory):
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, "rb") as handle:
                manifest = json.loads(handle.read().decode("utf-8"))
        except Exception:
            continue
        found.append({
            "sequence": int(manifest.get("sequence") or 0),
            "expires_at": int(manifest.get("expires_at") or 0),
            "path": path,
            "objects": {entry.get("object") for entry
                        in (manifest.get("routes") or {}).values()
                        if entry.get("object")},
        })
    found.sort(key=lambda entry: entry["sequence"], reverse=True)
    return found


def _remove_unreferenced(referenced):
    """Delete cached objects no retained manifest names."""
    removed = 0
    objects_root = os.path.join(root(), "objects")
    for current, _dirs, files in os.walk(objects_root):
        for name in files:
            if name.endswith(".tmp") or name in referenced:
                continue
            try:
                os.remove(os.path.join(current, name))
                removed += 1
            except Exception:
                pass
    return removed
