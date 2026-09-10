"""Offload stored media from the local object store into the storage DHT.

WHAT THIS DOES
--------------
Walks Media rows, reads each object out of the CURRENT store, writes it
through a syndichan-node S3 gateway -- which encrypts it, splits it into
Reed-Solomon shards and distributes them across volunteer nodes -- verifies the
object reads back byte-identically, and records the media as offloaded.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It never deletes from the source. Offload and reclaim are separate operations on
purpose: with a young network and few nodes, "it uploaded without error" is not
the same as "it is durably stored and retrievable". Deleting the only verified
copy on the strength of a 200 response is how an archive disappears. Reclaiming
primary-store space is a later, deliberate step against media that has been offloaded AND
re-verified after the fact.

The three buckets are handled separately (attachments / thumbs / previews),
because they are three independent key namespaces and a thumbnail can be
regenerated from its attachment while the reverse is not true. Attachments are
therefore the ones that matter; a failed thumb offload is logged and skipped
rather than failing the row.

CONFIGURATION
-------------
DHT_S3_ENDPOINT / DHT_S3_ACCESS_KEY / DHT_S3_SECRET_KEY point at a storage node's
S3 gateway. If DHT_S3_ENDPOINT is unset the whole service is disabled and every
entry point no-ops -- there is no implicit fallback to the primary store, since
"offloading" media onto the machine it already lives on would report success
while achieving nothing.
"""
import hashlib
import io

from shared import app, db


# Attempts before a row is set aside. Low, because the dominant failure is
# permanent (the source object no longer exists), not transient.
MAX_ATTEMPTS = 3


def dht_enabled():
    return bool((app.config.get("DHT_S3_ENDPOINT") or "").strip())


def dht_write_enabled():
    """Whether the DHT target is distinct from the primary S3 gateway."""
    if not dht_enabled():
        return False
    primary = (app.config.get("S3_ENDPOINT") or "").strip().rstrip("/")
    target = (app.config.get("DHT_S3_ENDPOINT") or "").strip().rstrip("/")
    return not primary or primary != target


class _DHTStorage(object):
    """An S3Storage pointed at the storage-node gateway.

    Subclasses the real thing so bucket naming, key layout and the read/write
    helpers stay identical -- the whole point is that the DHT gateway is
    S3-compatible, so anything that diverges here is a bug waiting to happen.
    """

    _instance = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            from model.Media import S3Storage

            class DHTStorage(S3Storage):
                def reload_config(self):
                    import boto3
                    from botocore.config import Config

                    self._endpoint = app.config["DHT_S3_ENDPOINT"]
                    self._access_key = app.config.get("DHT_S3_ACCESS_KEY") or ""
                    self._secret_key = app.config.get("DHT_S3_SECRET_KEY") or ""
                    self._bucket_uuid = app.config.get("DHT_S3_UUID_PREFIX") or ""
                    import threading
                    self._bucket_check_lock = threading.Lock()
                    self._verified_buckets = set()
                    # Longer than the primary store's 20s: a node has to encrypt,
                    # erasure-code and place shards before it acknowledges a PUT,
                    # so writes are legitimately slower than a local write. Still
                    # bounded -- an unbounded write here would hold whatever
                    # transaction the caller is in (see the S3Storage comment).
                    # TLS trust for the node gateway. The gateway MUST use TLS
                    # once it leaves loopback (storage-client config.go:128) and
                    # its certificate is self-signed, so the default public CA
                    # bundle cannot verify it.
                    #
                    # Preferred: DHT_S3_CA_BUNDLE points at that certificate,
                    # which is its own CA -- verification stays ON and a MITM
                    # inside the cluster still cannot present a different cert.
                    # DHT_S3_INSECURE_TLS=1 disables verification entirely and is
                    # the fallback, not the default: what TLS protects on this
                    # hop is the SigV4 credential, since the object bytes are
                    # already encrypted by the node before they leave it.
                    ca_bundle = (app.config.get("DHT_S3_CA_BUNDLE") or "").strip()
                    insecure = str(app.config.get("DHT_S3_INSECURE_TLS") or "").strip().lower()
                    if insecure in ("1", "true", "yes"):
                        verify = False
                    elif ca_bundle:
                        verify = ca_bundle
                    else:
                        verify = None      # botocore default (public CAs)

                    # botocore >= 1.36 computes a DEFAULT CRC32 checksum on
                    # PutObject, which switches the request to aws-chunked with
                    # a trailer and sets x-amz-content-sha256 to
                    # STREAMING-UNSIGNED-PAYLOAD-TRAILER. The node hashes the
                    # raw body, so every write failed with
                    # XAmzContentSHA256Mismatch -- even via put_object, which is
                    # why switching away from upload_fileobj alone did not fix
                    # it. "when_required" restores a plain signed PUT whose
                    # digest is the real body hash.
                    #
                    # Passed defensively: the kwarg does not exist before
                    # botocore 1.36 and would raise TypeError there.
                    extra = {}
                    try:
                        Config(request_checksum_calculation="when_required")
                        extra["request_checksum_calculation"] = "when_required"
                        extra["response_checksum_validation"] = "when_required"
                    except Exception:
                        pass

                    self._s3_client = boto3.resource(
                        "s3",
                        endpoint_url=self._endpoint,
                        aws_access_key_id=self._access_key,
                        aws_secret_access_key=self._secret_key,
                        verify=verify,
                        config=Config(
                            **extra,
                            s3={"addressing_style": "path"},
                            connect_timeout=5,
                            read_timeout=120,
                            retries={"max_attempts": 2, "mode": "standard"},
                        ),
                    )

                # --- plain signed PUTs, not upload_fileobj -------------
                # boto3's upload_fileobj signs the payload with chunked
                # streaming (STREAMING-...-TRAILER / aws-chunked). The node's
                # SigV4 verifier hashes the raw body, so every write was
                # rejected with XAmzContentSHA256Mismatch: "object payload
                # digest mismatch". put_object with a bytes Body sends a single
                # request whose x-amz-content-sha256 is the real digest, which
                # is what the node validates against.
                #
                # These override S3Storage rather than changing it: the primary
                # accepts the streaming form, and the primary write path is on
                # the hot post-submission route -- not somewhere to take risk
                # for the benefit of the offload.
                def _put(self, bucket_name, key, data, mimetype=None):
                    body = data.getvalue() if hasattr(data, "getvalue") else data
                    # Encrypt before it leaves the site: volunteer nodes hold only
                    # ciphertext they cannot read. The object id namespaces the
                    # key derivation and is embedded in the blob, so the read path
                    # decrypts without needing it. See services/content_keys.py.
                    from services import content_keys

                    if content_keys.enabled():
                        body = content_keys.encrypt(bucket_name + "/" + key, body)
                    bucket = self._get_bucket(bucket_name)
                    kwargs = {"Key": key, "Body": body, "ACL": "public-read"}
                    if mimetype:
                        kwargs["ContentType"] = mimetype
                    try:
                        bucket.put_object(**kwargs)
                    except Exception as exc:
                        if "NoSuchBucket" in str(exc) or "404" in str(exc):
                            self._ensure_buckets((bucket_name,), force=True)
                            self._get_bucket(bucket_name).put_object(**kwargs)
                        else:
                            raise

                def _write_attachment(self, attachment_file, media_id, media_ext):
                    key = self._s3_attachment_key(media_id, media_ext)
                    self._put(self._ATTACHMENT_BUCKET, key, attachment_file,
                              self._get_mimetype(key))

                def _write_thumbnail(self, thumbnail_bytes, media_id):
                    key = self._s3_thumbnail_key(media_id)
                    self._put(self._THUMBNAIL_BUCKET, key, thumbnail_bytes, "image/jpeg")

                def _write_video_preview(self, preview_bytes, media_id):
                    key = self._s3_preview_key(media_id)
                    self._put(self._PREVIEW_BUCKET, key, preview_bytes, "video/mp4")

                # Decrypt on the way back out. These override the base S3Storage
                # readers ONLY on the DHT store, so primary plaintext objects
                # are never touched. A blob is self-describing, so decrypt needs
                # nothing but the bytes; pre-encryption objects pass through.
                @staticmethod
                def _maybe_decrypt(raw):
                    from services import content_keys

                    if content_keys.enabled() and content_keys.is_encrypted_blob(raw):
                        return content_keys.decrypt(raw)
                    return raw

                def read_attachment_bytes(self, media_id, media_ext):
                    return self._maybe_decrypt(
                        super().read_attachment_bytes(media_id, media_ext)
                    )

                def read_thumbnail_bytes(self, media_id):
                    return self._maybe_decrypt(super().read_thumbnail_bytes(media_id))

                def read_video_preview_bytes(self, media_id):
                    return self._maybe_decrypt(
                        super().read_video_preview_bytes(media_id)
                    )

            cls._instance = DHTStorage()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None


def _digest(data):
    return hashlib.sha256(data).hexdigest() if data else None


def offload_media(media, include_derived=True):
    """Copy one Media object into the DHT and verify it reads back.

    Returns (ok, detail). Never raises -- this runs in a sweep over thousands of
    rows and one unreadable object must not stop the rest.
    """
    if not dht_write_enabled():
        return False, "dht_disabled"

    from model.Media import storage as primary

    try:
        source = primary.read_attachment_bytes(media.id, media.ext)
    except Exception as exc:
        app.logger.warning("offload: cannot read attachment %s: %s", media.id, exc)
        return False, "source_unreadable"
    if not source:
        return False, "source_empty"

    target = _DHTStorage.get()
    try:
        target._ensure_buckets()
        # ASYMMETRIC SIGNATURES, and boto3 does not coerce: _write_attachment
        # takes a FILE OBJECT (it calls upload_fileobj, which raises
        # "Fileobj must implement read" on bytes), while _write_thumbnail and
        # _write_video_preview take raw bytes. read_attachment_bytes returns
        # bytes, so the attachment has to be wrapped.
        target._write_attachment(io.BytesIO(source), media.id, media.ext)
    except Exception as exc:
        app.logger.warning("offload: write failed for %s: %s", media.id, exc)
        return False, "write_failed"

    # Read back and compare. A PUT that returned 200 is not evidence the bytes
    # are retrievable -- that is exactly the assumption that makes a later
    # reclaim destructive.
    try:
        echo = target.read_attachment_bytes(media.id, media.ext)
    except Exception as exc:
        app.logger.warning("offload: verify read failed for %s: %s", media.id, exc)
        return False, "verify_unreadable"
    if _digest(echo) != _digest(source):
        app.logger.error("offload: VERIFY MISMATCH for media %s -- not marking offloaded", media.id)
        return False, "verify_mismatch"

    if include_derived:
        # Thumbs and previews are regenerable from the attachment, so a failure
        # here is logged and tolerated rather than failing the row.
        for reader, writer, label in (
            (primary.read_thumbnail_bytes, target._write_thumbnail, "thumb"),
            (primary.read_video_preview_bytes, target._write_video_preview, "preview"),
        ):
            try:
                data = reader(media.id)
                if data:
                    writer(data, media.id)
            except Exception as exc:
                app.logger.info("offload: %s for %s skipped (%s)", label, media.id, exc)

    return True, "ok"


def _pending_query(limit):
    """Media that is offload-ELIGIBLE, not merely un-offloaded.

    Publishing to the DHT is irreversible in practice: shards are encrypted and
    scattered across volunteer machines, and there is no recall. So nothing goes
    out until BOTH content gates have actually passed:

      1. BLOCKED-HASH: the object's sha256 must not appear in blocked_media_hash.
         Joined here rather than checked per-row so a banned file cannot slip
         through a race between the sweep and a fresh ban.

      2. NSFW: nsfw_score must be non-NULL and below the configured threshold.
         NULL means UNSCANNED, not safe -- treating it as safe would push every
         file that arrived while the classifier was down. Unscanned media is
         skipped and picked up on a later pass once media_rescan has scored it.

    overlay_blocked is excluded too: that is the manual "an admin blocked this"
    flag, and an admin decision must not be quietly replicated to volunteers.
    """
    from model.BlockedMediaHash import BlockedMediaHash
    from model.Media import Media
    from services.nsfw import threshold

    banned = db.session.query(BlockedMediaHash.sha256)

    return (
        db.session.query(Media)
        .filter(
            Media.dht_offloaded_at.is_(None),
            # Give up after MAX_ATTEMPTS so a permanently unreadable object
            # (pruned from the store) stops blocking the head of the queue.
            Media.dht_offload_attempts < MAX_ATTEMPTS,
            Media.overlay_blocked.is_(False),
            Media.nsfw_score.isnot(None),
            Media.nsfw_score < threshold(),
            db.or_(Media.sha256.is_(None), Media.sha256.notin_(banned)),
        )
        # NEWEST FIRST. Oldest-first left every new upload behind the entire
        # backlog -- over a day at 40 rows / 300s -- which is backwards: a
        # freshly posted file is both the most likely to be requested and the
        # one still occupying space we are trying to reclaim. It also meant
        # videos and audio never got reached, since they sit at higher ids than
        # the old scraped images. Dead rows still retire after MAX_ATTEMPTS, so
        # the tail drains regardless of which end is served first.
        .order_by(Media.id.desc())
        .limit(limit)
        .all()
    )


def eligibility_breakdown():
    """Why pending media is not moving, for the admin panel.

    Without this "pending: 6000" is indistinguishable from "6000 unscanned",
    "6000 blocked", or "the offload is broken".
    """
    from model.BlockedMediaHash import BlockedMediaHash
    from model.Media import Media
    from services.nsfw import threshold

    try:
        banned = db.session.query(BlockedMediaHash.sha256)
        base = db.session.query(db.func.count(Media.id)).filter(Media.dht_offloaded_at.is_(None))
        return {
            "pending_total": int(base.scalar() or 0),
            "unscanned": int(base.filter(Media.nsfw_score.is_(None)).scalar() or 0),
            "over_threshold": int(
                base.filter(Media.nsfw_score >= threshold()).scalar() or 0
            ),
            "admin_blocked": int(base.filter(Media.overlay_blocked.is_(True)).scalar() or 0),
            "banned_hash": int(base.filter(Media.sha256.in_(banned)).scalar() or 0),
            "nsfw_threshold": threshold(),
        }
    except Exception:
        db.session.rollback()
        app.logger.exception("offload: eligibility breakdown failed")
        return {}


def offload_batch(limit=25, dry_run=False):
    """Offload up to `limit` not-yet-offloaded objects. Returns a summary."""
    import datetime as _datetime

    summary = {"enabled": dht_write_enabled(), "examined": 0, "offloaded": 0,
               "failed": 0, "reasons": {}, "dry_run": bool(dry_run)}
    if not summary["enabled"]:
        return summary

    try:
        rows = _pending_query(limit)
    except Exception:
        db.session.rollback()
        app.logger.exception("offload: could not list pending media")
        return summary

    summary["examined"] = len(rows)
    for media in rows:
        if dry_run:
            continue
        ok, detail = offload_media(media)
        if ok:
            media.dht_offloaded_at = _datetime.datetime.utcnow()
            db.session.add(media)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                app.logger.exception("offload: could not mark media %s", media.id)
                summary["failed"] += 1
                continue
            summary["offloaded"] += 1
        else:
            summary["failed"] += 1
            summary["reasons"][detail] = summary["reasons"].get(detail, 0) + 1
            # Record the attempt so a dead row eventually drops out of the
            # queue instead of being retried forever at the head of it.
            media.dht_offload_attempts = int(media.dht_offload_attempts or 0) + 1
            db.session.add(media)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
    return summary


def progress():
    """{total, offloaded, pending, bytes_offloaded} for the admin panel."""
    from model.Media import Media

    try:
        total = db.session.query(db.func.count(Media.id)).scalar() or 0
        done = (
            db.session.query(db.func.count(Media.id))
            .filter(Media.dht_offloaded_at.isnot(None))
            .scalar()
            or 0
        )
    except Exception:
        db.session.rollback()
        app.logger.exception("offload: progress query failed")
        return {"enabled": dht_write_enabled(), "total": 0, "offloaded": 0, "pending": 0}
    return {
        "enabled": dht_write_enabled(),
        "endpoint": (app.config.get("DHT_S3_ENDPOINT") or "") if dht_write_enabled() else None,
        "total": int(total),
        "offloaded": int(done),
        "pending": int(total - done),
        "percent": round((done / total * 100.0), 1) if total else 0.0,
    }


# Continuous offload. Newly uploaded and newly scraped media becomes eligible
# the moment the NSFW classifier scores it, so this sweep is what makes offload
# ongoing rather than a one-time migration.
_SWEEP_INTERVAL_SECONDS = 300
_SWEEP_BATCH = 40


def start_storage_offload_sweep(flask_app):
    def _loop():
        import time as _time

        # Well after boot: the media pass and the NSFW rescan are both busy
        # early on, and competing with them for the connection pool is how the
        # startup lock pileups happened.
        _time.sleep(420)
        while True:
            try:
                with flask_app.app_context():
                    if not dht_write_enabled():
                        # Nothing to do and nothing to warn about repeatedly --
                        # an unconfigured DHT is a valid state.
                        _time.sleep(_SWEEP_INTERVAL_SECONDS)
                        continue
                    from services.singleton_worker import is_maintenance_leader

                    # Leader-gated: four workers offloading the same rows would
                    # duplicate encrypted writes and quadruple the shard churn.
                    if is_maintenance_leader():
                        result = offload_batch(limit=_SWEEP_BATCH)
                        if result.get("offloaded") or result.get("failed"):
                            flask_app.logger.info(
                                "offload sweep: %d offloaded, %d failed %s",
                                result["offloaded"], result["failed"],
                                result.get("reasons") or "",
                            )
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("storage offload sweep failed")
            _time.sleep(_SWEEP_INTERVAL_SECONDS)

    import shared as _shared

    _shared.spawn_native_thread(target=_loop, name="storage-offload-sweep", daemon=True)
