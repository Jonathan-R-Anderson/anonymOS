"""Moving finished stream recordings off local disk and onto the DHT.

THE PROBLEM THIS SOLVES
-----------------------
The RTMP server writes each broadcast to `<rtmp>/dynamic/<account>/sessions/`
as an MP4, and the site served those straight off that volume through nginx's
`/stream-media/` alias. That volume is a local-path hostPath on ONE node. Every
archived broadcast therefore existed exactly once, on one disk, with no
replication -- while the rest of the site's media already lives on the DHT.
A disk loss or an image-GC sweep took every recording with it.

WHAT HAPPENS INSTEAD
--------------------
A finished recording is ingested as an ordinary Media row. That is the whole
trick: this deployment runs STORAGE_PROVIDER=S3 against the node's DHT gateway,
so `save_attachment` already writes to the DHT. Nothing DHT-specific is needed
here -- the archive becomes normal site media and inherits replication, the
content hash, and the torrent metadata every other upload gets.

Then the local copy is DELETED. That is the point of the exercise; keeping it
would leave the PVC growing exactly as before and make "on the DHT" a claim
about a second copy rather than about where the archive lives.

WHY THE READBACK IS NOT OPTIONAL
--------------------------------
Deletion is irreversible and a write that reported success is not the same as
an object that reads back. Between the two sits a gateway that can accept bytes
and lose them. So every publish reads the object back and compares its length
to the source before anything is unlinked, and a mismatch leaves the local file
untouched -- a recording stuck on local disk is a storage-cost problem, and a
recording deleted against a bad write is gone.

WHY A LIVE SESSION IS SKIPPED
-----------------------------
The newest MP4 may still be open by the remuxer. Publishing it would archive a
truncated broadcast and then delete the file out from under a running ffmpeg.
Files are left alone until they have been quiet for QUIET_SECONDS.
"""

import json
import glob
import os
import time

from shared import app, db
from model.SiteSetting import get_setting, set_setting

# A recording is only a candidate once it has stopped growing. The remuxer
# finalises an MP4 well inside this window; the margin is for a publisher whose
# connection is stalling rather than ended.
QUIET_SECONDS = 180

_KEY_PREFIX = "stream-archive:"

# 4MB, deliberately BELOW the gateway's measured 5MB per-request ceiling, so
# every chunk is one ordinary PUT and multipart never enters the picture. See
# model/Media.py for how that ceiling was measured.
#
# WHY CHUNKS AND NOT ONE OBJECT
# -----------------------------
# A content-addressed store is chunk-shaped; a 400MB blob is the anomaly. The
# first version of this uploaded whole recordings and could not store anything
# past ~256MB, which is a gateway limit this design simply does not depend on.
# Chunking also makes a failure cost ONE chunk instead of the entire transfer,
# lets identical chunks dedup, and turns seeking into "fetch the two chunks
# covering this range" rather than asking a huge object to honour a byte range.
CHUNK_BYTES = 4 * 1024 * 1024

_BUCKET = "stream-archives"

# How many chunks are in flight at once. Each is uploaded AND read back, so this
# is really 2x this many requests outstanding.
#
# Modest on purpose: the gateway is a single node that is also serving the site,
# and the whole point of doing this in a background sweep is that nobody is
# waiting on it. Saturating the gateway to finish an archive faster would trade
# a slow background job for a slow website.
_UPLOAD_CONCURRENCY = 6


def _client():
    """The S3-compatible DHT gateway client, or None when unconfigured.

    Same client the arcade publisher uses, so there is one place that knows the
    endpoint, credentials and addressing style.
    """
    from services.codeplay_content import _s3_client

    return _s3_client()


def _bucket_name():
    prefix = (app.config.get("DHT_S3_UUID_PREFIX") or "").strip()
    return (prefix + _BUCKET) if prefix else _BUCKET


def _ensure_bucket(client):
    name = _bucket_name()
    try:
        client.head_bucket(Bucket=name)
    except Exception:
        try:
            client.create_bucket(Bucket=name)
        except Exception:
            app.logger.exception("stream_archive: cannot ensure bucket %s", name)
            return None
    return name


def _chunk_key(account, basename, index):
    # Zero-padded so the keys sort in playback order when listed, which makes a
    # partially-uploaded recording legible from the gateway side.
    return "%s/%s/%06d" % (account, basename, index)


def _storage_root():
    return os.getenv("RTMP_STORAGE_ROOT", "/rtmp-storage")


def _sessions_dir(account):
    return os.path.join(_storage_root(), "dynamic", account, "sessions")


def _key(account):
    # SiteSetting.key is String(64); a 0x-prefixed account is 42, so this fits
    # with room to spare. Worth knowing before adding to the prefix.
    return _KEY_PREFIX + account


def published(account):
    """{basename: {media_id, ext, size, mtime}} for one account."""
    raw = get_setting(_key(account), "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        app.logger.warning("stream_archive: unreadable index for %s", account)
        return {}
    return data if isinstance(data, dict) else {}


def _remember(account, basename, entry):
    index = published(account)
    index[basename] = entry
    set_setting(_key(account), json.dumps(index, sort_keys=True))
    db.session.commit()


# After this many failed attempts a recording is left alone. These are hundreds
# of megabytes each: a file the gateway cannot accept would otherwise be
# re-uploaded in full every pass, forever, saturating the node with traffic that
# has never once succeeded. Failures are recorded in the same index as
# successes, distinguished by having no media_id.
_MAX_ATTEMPTS = 3


def _record_failure(account, basename, detail):
    index = published(account)
    prior = index.get(basename) or {}
    attempts = int(prior.get("attempts") or 0) + 1
    index[basename] = {"attempts": attempts, "last_error": str(detail)[:200]}
    set_setting(_key(account), json.dumps(index, sort_keys=True))
    db.session.commit()
    if attempts >= _MAX_ATTEMPTS:
        app.logger.error(
            "stream_archive: giving up on %s after %d attempts (%s); the local "
            "copy is intact and nothing was deleted",
            basename, attempts, detail,
        )
    return attempts


def _is_archived(entry):
    """A real DHT copy, as opposed to a failure record.

    Accepts the older whole-object form (media_id) as well as the chunked one,
    so archives written before chunking stay playable.
    """
    entry = entry or {}
    return bool(entry.get("chunks")) or bool(entry.get("media_id"))


def _exhausted(entry):
    return int((entry or {}).get("attempts") or 0) >= _MAX_ATTEMPTS


def newest(account):
    """The most recent archived recording, or None.

    Ordered by the ORIGINAL file mtime, not by publish order: a backlog sweep
    sends older recordings up after newer ones, and publish order would then
    advertise a week-old broadcast as the latest.
    """
    archived = [e for e in published(account).values() if _is_archived(e)]
    if not archived:
        return None
    return max(archived, key=lambda entry: entry.get("mtime") or 0)


def _candidates(account):
    """Local recordings that are finished and not yet on the DHT."""
    try:
        paths = glob.glob(os.path.join(_sessions_dir(account), "*.mp4"))
    except OSError:
        return []
    known = published(account)
    now = time.time()
    out = []
    for path in paths:
        base = os.path.basename(path)
        entry = known.get(base)
        if _is_archived(entry):
            # Already on the DHT; the local copy should be gone. If it is still
            # here the delete failed after a good write, so clean it up now
            # rather than leaving it to grow the volume forever.
            _unlink(path)
            continue
        if _exhausted(entry):
            # Repeatedly refused by the gateway. Left on local disk on purpose:
            # it is the only copy.
            continue
        try:
            if now - os.path.getmtime(path) < QUIET_SECONDS:
                continue
            if os.path.getsize(path) <= 0:
                continue
        except OSError:
            continue
        out.append(path)
    return sorted(out)


def _unlink(path):
    try:
        os.unlink(path)
        return True
    except OSError as exc:
        app.logger.warning("stream_archive: cannot delete %s: %s", path, exc)
        return False


def _put_and_verify(client, bucket, key, block):
    """Upload one chunk and prove it reads back. True when it is good.

    The verification is not optional and not deferrable: the local recording is
    deleted on the strength of it, and a write reporting success is not the same
    as an object that reads back.
    """
    client.put_object(
        Bucket=bucket, Key=key, Body=block,
        ContentType="video/mp4", ACL="public-read",
    )
    got = client.get_object(Bucket=bucket, Key=key)["Body"].read()
    return len(got) == len(block) and got == block


def _upload_batch(client, bucket, batch):
    """Upload a batch concurrently. Returns the index of the first bad chunk.

    Returns None when every chunk in the batch stored and verified. An exception
    inside a worker propagates, because a gateway that has started refusing
    should stop the transfer rather than be retried per chunk forever.
    """
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=len(batch)) as pool:
        results = list(pool.map(
            lambda item: (item[0], _put_and_verify(client, bucket, item[1], item[2])),
            batch,
        ))
    bad = [i for i, ok in results if not ok]
    # Lowest index first, so the log names the earliest failure rather than
    # whichever worker happened to finish last.
    return min(bad) if bad else None


def publish_one(account, path):
    """Ingest one recording to the DHT and delete the local copy.

    Returns (ok, detail). Never raises: this runs in a sweep and one bad file
    must not stop the rest of the backlog.
    """
    import hashlib

    base = os.path.basename(path)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return False, "unsized: %s" % exc

    client = _client()
    if client is None:
        return False, "no_dht_client"
    bucket = _ensure_bucket(client)
    if bucket is None:
        return False, "no_bucket"

    chunks = []
    whole = hashlib.sha256()
    index = 0
    try:
        with open(path, "rb") as handle:
            while True:
                # Read a batch, hashing IN READ ORDER before anything is
                # dispatched. The uploads below complete in whatever order the
                # gateway allows, and the whole-file digest depends on order --
                # hashing inside the workers would produce a digest that varies
                # run to run.
                batch = []
                for _ in range(_UPLOAD_CONCURRENCY):
                    block = handle.read(CHUNK_BYTES)
                    if not block:
                        break
                    key = _chunk_key(account, base, index)
                    whole.update(block)
                    batch.append((index, key, block))
                    chunks.append({"key": key, "len": len(block)})
                    index += 1
                if not batch:
                    break

                failed = _upload_batch(client, bucket, batch)
                if failed is not None:
                    app.logger.error(
                        "stream_archive: %s chunk %d did not read back intact; "
                        "keeping the local copy", base, failed,
                    )
                    return False, "chunk_readback_mismatch"
    except Exception as exc:
        app.logger.exception("stream_archive: chunk upload failed for %s", base)
        return False, "upload_failed: %s" % exc

    if not chunks:
        return False, "empty_file"

    stored_total = sum(c["len"] for c in chunks)
    if stored_total != size:
        # The file changed under us mid-read, which for a recording means the
        # remuxer was not finished with it after all.
        app.logger.error(
            "stream_archive: %s stored %d bytes but the file is %d; "
            "keeping the local copy", base, stored_total, size,
        )
        return False, "size_mismatch"

    mtime = 0
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        pass

    _remember(account, base, {
        # The manifest. media_id is absent by design -- these are not Media
        # rows, and _is_archived() keys off "chunks" for chunked entries.
        "chunks": chunks,
        "bucket": bucket,
        "size": size,
        "sha256": whole.hexdigest(),
        "mtime": mtime,
    })

    _unlink(path)
    app.logger.info(
        "stream_archive: %s -> %d chunks on the DHT (%d bytes), local copy removed",
        base, len(chunks), size,
    )
    return True, "published"


def read_range(entry, start, end):
    """Bytes [start, end] INCLUSIVE from a chunked archive.

    Fetches only the chunks the range actually covers. This is the payoff of
    chunking for playback: seeking pulls two small objects rather than asking
    the gateway to honour a byte range over a whole recording.
    """
    client = _client()
    if client is None:
        raise RuntimeError("no DHT client configured")
    bucket = entry.get("bucket") or _bucket_name()

    out = bytearray()
    offset = 0
    for chunk in entry.get("chunks") or []:
        length = int(chunk.get("len") or 0)
        chunk_end = offset + length - 1
        if chunk_end < start:
            offset += length
            continue
        if offset > end:
            break
        body = client.get_object(Bucket=bucket, Key=chunk["key"])["Body"].read()
        take_from = max(0, start - offset)
        take_to = min(length - 1, end - offset)
        out += body[take_from:take_to + 1]
        offset += length
    return bytes(out)


def _accounts():
    root = os.path.join(_storage_root(), "dynamic")
    try:
        return sorted(os.listdir(root))
    except OSError:
        return []


def publish_pending(limit=4):
    """Sweep every account for finished recordings. Returns a summary.

    `limit` bounds one pass because these are large objects and the sweep
    shares a worker with request traffic.
    """
    done, failed = 0, 0
    for account in _accounts():
        for path in _candidates(account):
            if done + failed >= limit:
                return {"published": done, "failed": failed, "more": True}
            ok, detail = publish_one(account, path)
            if ok:
                done += 1
            else:
                _record_failure(account, os.path.basename(path), detail)
                failed += 1
    return {"published": done, "failed": failed, "more": False}
