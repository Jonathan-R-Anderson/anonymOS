"""Put snapshot objects where the DHT can serve them.

The backend's S3 endpoint is the storage node's gateway, and that node's whole
job is putting bytes into the DHT and getting them back. So "publish to the DHT"
is not a new transport to build — it is the store the site already writes every
image through, addressed by hash instead of by upload id.

WHY A SEPARATE BUCKET
---------------------
Snapshot objects are immutable, expire on a schedule, and are garbage collected
as a set. Media is none of those. Mixing them would mean every retention rule
has to ask "but is this one a snapshot object?", and the first rule that forgets
to ask is the one that deletes a snapshot mid-outage.

WHAT PUTTING SOMETHING HERE DOES AND DOES NOT PROVE
---------------------------------------------------
A successful write means the gateway accepted the bytes. It does NOT mean the
object is replicated across N peers — the gateway does not report that, and at
the time of writing most peers in this network refuse shards outright ("node is
cache-only and does not host shards"), so a write that returns 200 may be held
in exactly one place.

So this module offers `readback`, which fetches an object again and checks it
hashes to its name. That proves retrievability, which is weaker than replication
and is what can actually be established from here. Confirming DISTINCT PEERS
needs the node's own DHT API and is deliberately not faked with an optimistic
count — a replication number nobody measured is worse than no number, because it
would be believed during the outage it was supposed to protect.
"""

from shared import app

BUCKET = "snapshots"


def enabled():
    """Whether an object store is configured at all."""
    return bool(app.config.get("S3_ENDPOINT"))


def _client():
    """A client for the storage node's S3 gateway.

    The TLS settings mirror model.Media.S3Storage exactly, and that is not
    incidental: the gateway presents a SELF-SIGNED certificate, so a client
    built with library defaults fails every request with
    CERTIFICATE_VERIFY_FAILED. Guessing a default here rather than reading the
    same configuration is how the first version of this silently stored nothing
    while reporting a published snapshot.
    """
    import boto3
    from botocore.client import Config

    ca_bundle = (app.config.get("S3_CA_BUNDLE") or "").strip()
    insecure = str(app.config.get("S3_INSECURE_TLS") or "").strip().lower()
    if insecure in ("1", "true", "yes"):
        verify = False
    elif ca_bundle:
        verify = ca_bundle
    else:
        verify = None

    # Newer botocore attaches its own checksum headers by default, which this
    # gateway rejects with XAmzContentSHA256Mismatch. Same treatment as
    # model.Media, for the same reason: every difference from the client that
    # already works against this endpoint is a difference that has to be
    # rediscovered by watching a failure.
    extra = {}
    try:
        Config(request_checksum_calculation="when_required")
        extra["request_checksum_calculation"] = "when_required"
        extra["response_checksum_validation"] = "when_required"
    except Exception:
        pass

    return boto3.client(
        "s3",
        endpoint_url=app.config["S3_ENDPOINT"],
        aws_access_key_id=app.config.get("S3_ACCESS_KEY"),
        aws_secret_access_key=app.config.get("S3_SECRET_KEY"),
        verify=verify,
        config=Config(
            **extra,
            s3={"addressing_style": "path"},
            # Bounded, so a stalled write cannot hold the build open. The
            # snapshot builder runs in the serving process; an unbounded S3 read
            # there is a request worker parked for a minute.
            connect_timeout=5,
            read_timeout=20,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )


def _bucket():
    prefix = app.config.get("S3_UUID_PREFIX") or ""
    return "%s%s" % (prefix, BUCKET)


def ensure_bucket(client=None):
    client = client or _client()
    try:
        client.head_bucket(Bucket=_bucket())
        return True
    except Exception:
        pass
    try:
        client.create_bucket(Bucket=_bucket())
        return True
    except Exception:
        app.logger.exception("snapshot: could not create the %s bucket", _bucket())
        return False


def put(digest, body, expires_at=None, client=None):
    """Store one object under its hash. Returns True on success."""
    client = client or _client()
    metadata = {"content-hash": digest}
    if expires_at:
        # Carried on the object so a storage node can expire it without holding
        # the manifest that referenced it.
        metadata["expires-at"] = str(int(expires_at))
    try:
        client.put_object(Bucket=_bucket(), Key=digest, Body=body,
                          Metadata=metadata)
        return True
    except Exception:
        app.logger.exception("snapshot: could not store %s in the object store",
                             digest[:12])
        return False


def get(digest, client=None):
    """Fetch one object, verifying it hashes to its name."""
    from services.snapshot import sha256_hex

    client = client or _client()
    try:
        response = client.get_object(Bucket=_bucket(), Key=digest)
        body = response["Body"].read()
    except Exception:
        return None
    if sha256_hex(body) != digest:
        # The store returned something that is not what was asked for. Content
        # addressing means this is detectable rather than trusted, which is the
        # entire reason the name is a hash.
        app.logger.error("snapshot: object store returned wrong bytes for %s",
                         digest[:12])
        return None
    return body


def readback(digests, client=None):
    """Fetch every object again. Returns (confirmed, missing).

    Run before a snapshot is activated. A write that returned success and a read
    that returns the right bytes are different claims, and only the second one
    means a reader can be served during an outage.
    """
    client = client or _client()
    confirmed, missing = 0, []
    for digest in digests:
        if get(digest, client=client) is not None:
            confirmed += 1
        else:
            missing.append(digest)
    return confirmed, missing


# Manifest keys. Kept out of the object namespace so a manifest can never
# collide with a content hash, and so listing one does not walk the other.
MANIFEST_PREFIX = "manifests/"
CURRENT_KEY = "current.json"


def put_manifest(sequence, body, client=None):
    """Store a manifest and move the current pointer. Pointer last, always.

    Two writes, in this order: the numbered manifest, then the pointer. A reader
    that catches the pair mid-update sees the OLD snapshot, never a pointer to a
    manifest that is not there yet.
    """
    client = client or _client()
    try:
        client.put_object(Bucket=_bucket(),
                          Key="%s%d.json" % (MANIFEST_PREFIX, int(sequence)),
                          Body=body, ContentType="application/json")
    except Exception:
        app.logger.exception("snapshot: could not store manifest %s in the DHT",
                             sequence)
        return False
    try:
        client.put_object(Bucket=_bucket(), Key=CURRENT_KEY, Body=body,
                          ContentType="application/json")
        return True
    except Exception:
        app.logger.exception("snapshot: could not move the DHT current pointer")
        return False


def current_manifest(client=None):
    """The manifest the DHT currently advertises, or None."""
    import json

    client = client or _client()
    try:
        response = client.get_object(Bucket=_bucket(), Key=CURRENT_KEY)
        return json.loads(response["Body"].read().decode("utf-8"))
    except Exception:
        return None
