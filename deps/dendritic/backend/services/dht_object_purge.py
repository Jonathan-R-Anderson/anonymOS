"""List what the storage DHT holds, purge ONE object out of it, RECALL the shards
that reached other peers, and say honestly how far each of those got.

READ THIS BEFORE TRUSTING THE WORD "PURGED"
===========================================
An object written to the DHT is encrypted, cut into 1 MiB chunks, and each chunk
is Reed-Solomon coded into 6 data + 3 parity shards which the node then PLACES ON
OTHER PEERS. Deleting the object through the gateway does local things only:

    storage-client/internal/store/store.go  Store.DeleteObject
      1. drops the manifest row from bolt;
      2. removeUnreferenced() unlinks this node's own shard FILES -- but only
         those no surviving manifest still points at, because shards are
         content-addressed (sha256 of the bytes) and therefore shared between
         identical objects;
      3. RetirePlacement() captures the holder list into a recall tombstone and
         only then drops the placement row.

Step 3 used to be a bare forgetPlacement(), which destroyed the holder list as
part of the delete -- so the instant after a purge, the shards were still on
peers and nothing anywhere could name which peers. That ordering is fixed, and
this module now calls the recall BEFORE the delete regardless, so the report is
about holders that were asked rather than holders that were forgotten.

WHAT RECALL IS, AND WHAT IT IS NOT
----------------------------------
`/syndichan/storage/1.0.0` now dispatches a fifth operation, `delete`, beside
have / get / pof-challenge / store. It is authorised by a COORDINATOR-SIGNED
REVOCATION: this site holds the ed25519 key every storage node already pins to
verify placement leases, and it signs a separate token type (different domain
prefix, different field set, mandatory recipient, ten-minute expiry) that names
exactly one shard on exactly one peer. A holder verifies the signature, the
binding and the expiry, refuses anything one of its own manifests still
references, unlinks the file and blocklists the shard id so the owner's own
replicate pass cannot push it straight back.

Three outcomes are possible per holder and they are NOT the same thing:

    deleted      the holder confirmed the bytes are gone
    refused      the holder answered and said no, with a reason
    unreachable  the holder never answered -- retried, never assumed gone

A holder that cannot be reached keeps its tombstone, and the node retries it in
the background -- backing off to a long interval once a holder has refused
repeatedly, which the report says out loud rather than looking stalled.
"Unreachable" is therefore a status, not a conclusion.

And a FOURTH thing is not any of those three: the node failing to read its own
recall ledger. That used to arrive here as an empty record with no error, so it
printed as "no confirmed remote holder" -- a settled fact standing in for a
number nobody knew. It now arrives with its own code and prints as unknown. On a
takedown page the difference between "nobody has it" and "I could not find out"
is the whole point of the page.

WHAT STILL CANNOT BE DONE
-------------------------
A holder that never comes back keeps its shard. Nothing can reach a disk that is
offline forever, and this page will keep saying so rather than rounding it to
"purged". Nor can an object be crypto-shredded: the content key is DERIVED from
one master secret by hardened BIP32 (services/content_keys.py), so destroying a
per-object key is not a thing that exists.

What remote shards ARE, meanwhile, is ciphertext their holders cannot read, in
pieces that need six of nine to mean anything.

READING THE LEDGER
------------------
The node exposes its placement ledger as S3 QUERY SUBRESOURCES on the same
gateway the site already talks to -- GET /?placement, GET /<bucket>?placement,
GET /<bucket>/<key>?placement, and POST /<bucket>/<key>?recall. All four demand
SigV4 explicitly (the gateway's public-read bypass is refused for them by name).
So shard and chunk counts here are OBSERVED where the ledger answers, and fall
back to arithmetic, clearly labelled, only when it does not.

WHY DELETE IS VERIFIED WITH A SECOND HEAD
-----------------------------------------
    func (s *Server) deleteObject(w http.ResponseWriter, bucket, key string) {
        _ = s.store.DeleteObject(bucket, key)
        w.WriteHeader(http.StatusNoContent)
    }

The gateway DISCARDS the error and always answers 204 (s3api/server.go:624). A
204 is therefore evidence that the request arrived, and evidence of nothing else.
Every layer here re-HEADs after deleting and reports what the HEAD found. The
recall route deliberately does NOT copy that shape: it returns a per-holder
report, because there is no single boolean that could hold one.
"""

import json
import math
import re

from shared import app, db


# Fixed at the node from config (storage-client/internal/config/config.go:536).
# Mirrored here only to derive a shard COUNT for the preview; nothing in this
# module acts on these numbers.
CHUNK_BYTES = 1 << 20
DATA_SHARDS = 6
PARITY_SHARDS = 3
SHARDS_PER_CHUNK = DATA_SHARDS + PARITY_SHARDS

# The buckets a syndichan deployment writes. A purge is refused for anything
# else: an unrecognised bucket in a destructive form is far more likely to be a
# typo than a real target, and "delete whatever the operator typed" is how the
# wrong thing goes at 2am.
KNOWN_BUCKETS = {
    "attachments": "user media (the origin object)",
    "thumbs": "generated thumbnails",
    "previews": "generated video hover previews",
    "snapshots": "site snapshots",
    "arcade": "published arcade content",
    "codeplay": "published codeplay content",
    "releases": "node release binaries",
    "stream-archives": "recorded live streams",
    "static": "site assets",
}

# Buckets whose objects the SITE ITSELF serves from fixed keys. Purging one does
# not corrupt anything, but it does remove a thing the site expects to be there,
# so the preview says so out loud.
SITE_CRITICAL_BUCKETS = {"static", "releases", "snapshots"}

_MEDIA_TARGET = re.compile(r"^media:(\d+)$", re.IGNORECASE)


class TargetError(ValueError):
    """The target could not be resolved to exactly one unambiguous thing."""


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

def parse_target(raw):
    """Normalise operator input into ONE unambiguous target.

    Accepted:
        media:123               -- a Media row and all three of its objects
        <bucket>/<key>          -- one object, e.g. arcade/index.html

    Returns a dict with a `canonical` string; that string is what the operator
    has to retype to confirm, so it must be stable and must round-trip.
    """
    text = (raw or "").strip()
    if not text:
        raise TargetError("Enter a target: either media:<id> or <bucket>/<key>.")

    match = _MEDIA_TARGET.match(text)
    if match:
        media_id = int(match.group(1))
        return {"kind": "media", "canonical": "media:%d" % media_id,
                "media_id": media_id, "bucket": None, "key": None}

    # A bare integer is ambiguous -- it could be a media id or a key -- so it is
    # refused rather than guessed at.
    if text.isdigit():
        raise TargetError(
            "Ambiguous target %r: write media:%s for the media object, or "
            "<bucket>/<key> for a raw object." % (text, text)
        )

    if "/" not in text:
        raise TargetError(
            "A raw object target needs a bucket: <bucket>/<key>. Known buckets: %s."
            % ", ".join(sorted(KNOWN_BUCKETS))
        )

    bucket, key = text.split("/", 1)
    bucket = bucket.strip().lower()
    key = key.strip().lstrip("/")
    if bucket not in KNOWN_BUCKETS:
        raise TargetError(
            "Unknown bucket %r. This deployment writes: %s."
            % (bucket, ", ".join(sorted(KNOWN_BUCKETS)))
        )
    if not key:
        raise TargetError("Missing object key after %r/." % bucket)
    if key.endswith("/") or key in (".", ".."):
        raise TargetError(
            "%r is a prefix, not an object. Purge deletes exactly one key at a "
            "time on purpose." % key
        )
    return {"kind": "object", "canonical": "%s/%s" % (bucket, key),
            "media_id": None, "bucket": bucket, "key": key}


def _media_objects(media):
    """The three keys one Media row owns, in the bucket layout S3Storage uses."""
    return [
        {"bucket": "attachments", "key": "%d.%s" % (media.id, media.ext),
         "role": "attachment"},
        {"bucket": "thumbs", "key": "%d.jpg" % media.id, "role": "thumbnail"},
        {"bucket": "previews", "key": "%d-v2.mp4" % media.id, "role": "video preview"},
    ]


def _resolve_objects(target):
    """(objects, media_row_or_None). Raises TargetError if a media id is unknown."""
    if target["kind"] != "media":
        return [dict(bucket=target["bucket"], key=target["key"], role="object")], None

    from model.Media import Media

    media = db.session.query(Media).filter(Media.id == target["media_id"]).one_or_none()
    if media is None:
        raise TargetError("No media row with id %d." % target["media_id"])
    return _media_objects(media), media


# --------------------------------------------------------------------------
# Stores
# --------------------------------------------------------------------------

def _dht_store():
    """The syndichan node's S3 gateway, or None when it is not configured or is
    the same endpoint as the primary (in which case there is no separate DHT to
    talk to and pretending otherwise would double-report one delete)."""
    from services.storage_offload import _DHTStorage, dht_write_enabled

    if not dht_write_enabled():
        return None
    try:
        return _DHTStorage.get()
    except Exception:
        app.logger.exception("dht purge: could not build the DHT gateway client")
        return None


def _primary_store():
    """The site's own object store, when it is S3-shaped. FolderStorage has no
    bucket/key namespace, so a raw object target does not apply to it."""
    from model.Media import S3Storage, storage

    return storage if isinstance(storage, S3Storage) else None


def _head(store, bucket, key):
    """{'present', 'size', 'object_id', 'error'} for one key.

    `object_id` is the gateway's ETag, which for the node IS the manifest's
    ObjectID -- the primary key of the placement ledger. It is the only ledger
    identifier reachable from outside the node, so it is recorded even though
    nothing here can look it up.
    """
    result = {"present": False, "size": None, "object_id": None, "error": None}
    if store is None:
        result["error"] = "not_configured"
        return result
    try:
        client = store._s3_client.meta.client
        response = client.head_object(Bucket=store._bucket_uuid + bucket, Key=key)
    except Exception as exc:
        from model.Media import _is_missing_storage_error

        if _is_missing_storage_error(exc):
            return result
        result["error"] = str(exc)[:300]
        return result
    result["present"] = True
    result["size"] = int(response.get("ContentLength") or 0)
    result["object_id"] = (response.get("ETag") or "").strip('"') or None
    return result


# --------------------------------------------------------------------------
# The placement ledger, over the gateway the site already speaks to
# --------------------------------------------------------------------------

_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _ledger_store():
    """The store whose node holds the ledger.

    In production S3_ENDPOINT and DHT_S3_ENDPOINT are the SAME node, so
    dht_write_enabled() is False and _dht_store() returns None -- correctly, for
    its purpose (there is no second store to double-report a delete against).
    The ledger does not care: it belongs to whichever of the two is a syndichan
    node, and that is the primary when they are the same.
    """
    return _dht_store() or _primary_store()


def _ledger_call(method, path, params=None, timeout=None):
    """One signed request to a non-S3 route on the node's gateway.

    boto3 has no operation for a custom query subresource, so the request is
    signed by hand -- but with the EXISTING client's signer, credentials, TLS
    settings and connection pool, so a placement call cannot end up trusting a
    different certificate or a different key than an object call does.

    Returns (parsed_json, error_string). Never raises: an unreadable ledger is a
    reportable state, not a crash on the admin page.
    """
    store = _ledger_store()
    if store is None:
        return None, "no syndichan node gateway is configured on this deployment"
    try:
        from botocore.awsrequest import AWSRequest
    except Exception:
        return None, "botocore is not available in this process"
    try:
        client = store._s3_client.meta.client
        url = (client.meta.endpoint_url or "").rstrip("/") + path
        if params:
            from urllib.parse import urlencode

            url += "?" + urlencode(params, doseq=True)
        request = AWSRequest(method=method, url=url, data=b"")
        request.headers["x-amz-content-sha256"] = _EMPTY_SHA256
        # Force a real body hash rather than UNSIGNED-PAYLOAD: the node accepts
        # UNSIGNED-PAYLOAD only over TLS or loopback, and this call must work on
        # both.
        try:
            request.context["payload_signing_enabled"] = True
        except Exception:
            pass
        client._request_signer.sign("SyndichanPlacement", request)
        response = client._endpoint.http_session.send(request.prepare())
    except Exception as exc:
        return None, str(exc)[:300]
    body = getattr(response, "content", b"") or b""
    status = int(getattr(response, "status_code", 0) or 0)
    if status >= 400:
        return None, "the node answered HTTP %d: %s" % (
            status, body[:200].decode("utf-8", "replace"))
    try:
        return json.loads(body.decode("utf-8")), None
    except Exception:
        return None, "the node's answer was not JSON"


def ledger_summary():
    """Whole-node headline: how many objects the ledger tracks and how they sit."""
    payload, error = _ledger_call("GET", "/", {"placement": ""})
    if error:
        return {"available": False, "error": error}
    payload = dict(payload or {})
    payload["available"] = True
    return payload


def _prefixed(bucket):
    store = _ledger_store()
    prefix = getattr(store, "_bucket_uuid", "") or "" if store is not None else ""
    return prefix + bucket


def list_placements(bucket, prefix="", marker="", limit=50):
    """One page of the ledger for one bucket.

    NOT derived from ListObjects: this is the placement ledger itself, so a row
    carries observed chunk/shard counts and the peers that confirmed each shard.
    It also includes objects whose manifest is already gone but whose shards are
    still being recalled, which a bucket listing could never show.
    """
    if bucket not in KNOWN_BUCKETS:
        raise TargetError(
            "Unknown bucket %r. This deployment writes: %s."
            % (bucket, ", ".join(sorted(KNOWN_BUCKETS))))
    params = {"placement": "", "limit": str(int(limit or 50))}
    if prefix:
        params["prefix"] = prefix
    if marker:
        params["marker"] = marker
    payload, error = _ledger_call("GET", "/" + _prefixed(bucket), params)
    if error:
        return {"available": False, "error": error, "bucket": bucket,
                "objects": [], "next_marker": ""}
    rows = list((payload or {}).get("objects") or [])
    for row in rows:
        # The canonical string the purge form accepts, so list-then-delete is one
        # click rather than a retype from a different vocabulary.
        row["canonical"] = "%s/%s" % (row.get("bucket") or bucket, row.get("key") or "")
        row["holders"] = sorted((row.get("holder_shards") or {}).items(),
                                key=lambda item: (-item[1], item[0]))
    return {"available": True, "bucket": bucket, "prefix": prefix,
            "objects": rows, "next_marker": (payload or {}).get("next_marker") or "",
            "truncated": bool((payload or {}).get("truncated"))}


def _is_absent(error):
    """A 404 from the ledger means 'no row for this key', which is an ANSWER.

    Distinguishing it from a transport failure matters: "the node says nothing
    was ever placed" and "the node could not be asked" look identical in a plain
    error string and mean opposite things to an operator deciding whether the
    bytes are still out there.
    """
    return "HTTP 404" in (error or "")


def object_placement(bucket, key):
    """The per-shard ledger row for one object: shard ids, sizes, holders."""
    payload, error = _ledger_call(
        "GET", "/%s/%s" % (_prefixed(bucket), key), {"placement": ""})
    if _is_absent(error):
        return {"available": True, "absent": True, "chunks": 0, "shard_count": 0,
                "distinct_holders": 0, "shards": [], "holders": [],
                "data_shards": DATA_SHARDS, "parity_shards": PARITY_SHARDS}
    if error:
        return {"available": False, "error": error}
    payload = dict(payload or {})
    payload["available"] = True
    payload["holders"] = sorted((payload.get("holder_shards") or {}).items(),
                                key=lambda item: (-item[1], item[0]))
    return payload


def recall_shards(bucket, key, shard_ids=None, reason=None):
    """Ask every recorded holder to drop shards of this object.

    shard_ids restricts it to specific shards -- the per-shard delete. Empty
    means the whole object.

    Returns the node's per-holder report, or an `available: False` dict. It never
    returns a single success boolean, because there is not one: holders that
    deleted, holders that refused with a reason, and holders that never answered
    are three true and different results.
    """
    params = {"recall": ""}
    if reason:
        params["reason"] = str(reason)[:200]
    wanted = [str(shard_id) for shard_id in (shard_ids or []) if shard_id]
    if wanted:
        params["shard"] = wanted
    payload, error = _ledger_call(
        "POST", "/%s/%s" % (_prefixed(bucket), key), params)
    if _is_absent(error):
        # The node has no ledger row for this key, so it never confirmed a
        # remote holder for it. That is a real answer, not a failure to ask.
        return {"available": True, "counts": {}, "shards": [], "outstanding": 0,
                "resolved": True}
    if error:
        return {"available": False, "error": error}
    payload = dict(payload or {})
    if payload.get("error"):
        # The CODE is carried, not just the sentence. The node distinguishes "I
        # asked the holders and something went wrong" from "I could not read my
        # own recall ledger", and the second one has to survive to the page: it
        # is the difference between a failed attempt and an unknown number of
        # peers still holding the bytes.
        return {"available": False, "code": str(payload["error"]),
                "error": payload.get("detail") or payload["error"]}
    payload["available"] = True
    return payload


def _recall_counts(report):
    counts = dict((report or {}).get("counts") or {})
    return {
        "deleted": int(counts.get("deleted") or 0),
        "absent": int(counts.get("absent") or 0),
        "refused": int(counts.get("refused") or 0),
        "unreachable": int(counts.get("unreachable") or 0),
        "pending": int(counts.get("pending") or 0),
    }


def _recall_layer(canonical, report):
    """Turn one recall report into the per-layer row the purge page prints.

    This replaces the blanket 'unreachable' the page used to print for every
    object in every outcome. That string was true when there was no delete verb;
    printing it now, while holders are actually being asked, would be a lie in
    the comfortable direction.

    THREE DIFFERENT ZEROES, AND ONLY ONE OF THEM IS A ZERO
    -----------------------------------------------------
    `no_holders` means the ledger was read and named nobody. `unavailable` means
    the node could not be asked. `ledger_unreadable` means the node answered and
    could not read its own tombstone -- so the holder count is UNKNOWN. All three
    used to render as the first one, because the node turned a failed ledger read
    into an empty record with no error, which arrived here as counts of zero and
    printed "the placement ledger recorded no confirmed remote holder" on the
    page an operator uses for takedowns.
    """
    if not report or not report.get("available"):
        detail = (report or {}).get("error") or "the node did not answer"
        if (report or {}).get("code") == "recall_ledger_unreadable":
            return _layer("remote_shard_holders", "ledger_unreadable",
                          "%s %s" % (RECALL_LEDGER_UNREADABLE, detail),
                          object=canonical, holders_known=False, holders=None,
                          holders_reason=REMOTE_HOLDERS_UNKNOWN)
        return _layer("remote_shard_holders", "unavailable",
                      "%s %s" % (RECALL_UNAVAILABLE, detail),
                      object=canonical, holders_known=False, holders=None,
                      holders_reason=REMOTE_HOLDERS_UNKNOWN)
    counts = _recall_counts(report)
    holders = sum(counts.values())
    if holders == 0:
        return _layer("remote_shard_holders", "no_holders",
                      "The placement ledger recorded no confirmed remote holder "
                      "for %s, so there was nothing on another peer to recall. "
                      "That is an observation from the ledger, not an assumption."
                      % canonical,
                      object=canonical, holders_known=True, holders=0, counts=counts)
    if counts["refused"] or counts["unreachable"] or counts["pending"]:
        status = "partial"
    else:
        status = "recalled"
    deferred = bool(report.get("deferred"))
    return _layer(
        "remote_shard_holders", status,
        "%d holder answer(s) for %s: %d deleted, %d already gone, %d refused, "
        "%d unreachable, %d still pending. Refused and unreachable holders keep "
        "their shards; the node retries them in the background and this page can "
        "be re-run.%s %s"
        % (holders, canonical, counts["deleted"], counts["absent"],
           counts["refused"], counts["unreachable"], counts["pending"],
           (" " + RECALL_DEFERRED) if deferred else "",
           REMOTE_SHARDS_RECALLABLE),
        object=canonical, holders_known=True, holders=holders, counts=counts,
        shards=(report.get("shards") or []), deferred=deferred,
        outstanding=int(report.get("outstanding") or 0))


def _shard_math(size_bytes):
    """Chunks and shards the node would have made for an object of this size.

    DERIVED, NOT OBSERVED. It is arithmetic on the stored length using the
    node's configured 1 MiB / 6+3, not a reading of the manifest -- the manifest
    is not exposed. It is right whenever the node runs the default geometry and
    wrong if an operator changed it, which is why the UI labels it as derived.
    """
    if not size_bytes:
        return {"chunks": 0, "shards": 0, "data_shards": DATA_SHARDS,
                "parity_shards": PARITY_SHARDS, "derived": True}
    chunks = int(math.ceil(float(size_bytes) / CHUNK_BYTES))
    return {"chunks": chunks, "shards": chunks * SHARDS_PER_CHUNK,
            "data_shards": DATA_SHARDS, "parity_shards": PARITY_SHARDS,
            "derived": True}


REMOTE_HOLDERS_UNKNOWN = (
    "The node's placement ledger could not be read for this object, so the number "
    "of peers holding its shards is not known from here. It is not zero -- it is "
    "unknown. (The ledger is served at GET <bucket>/<key>?placement on the node's "
    "S3 gateway; a failure here means that call did not answer, not that nothing "
    "was placed.)"
)

REMOTE_SHARDS_RECALLABLE = (
    "Shards already placed on other peers ARE recalled. The peer protocol carries "
    "a `delete` operation authorised by a coordinator-signed revocation naming one "
    "shard, the one holder that may honour it and the one origin that may present "
    "it, and each holder verifies it, refuses anything its own "
    "manifests still reference, unlinks the file and blocklists the shard id so it "
    "cannot be re-pushed. Every holder is reported separately as deleted, refused "
    "or unreachable. An unreachable holder is retried by the node in the "
    "background and is NEVER counted as gone."
)

RECALL_UNAVAILABLE = (
    "The node's recall endpoint could not be reached, so no holder was asked to "
    "drop anything. Shards already placed are untouched, and the node keeps its "
    "placement/recall ledger, so this can be retried."
)

RECALL_LEDGER_UNREADABLE = (
    "The node ANSWERED and could not read its own recall ledger for this object, "
    "so how many peers still hold its shards is UNKNOWN — it is not zero. This is "
    "not the same as 'nothing was ever placed': that answer comes from a ledger "
    "that was read. Treat the shards as still out there until a recall reports "
    "per holder, and check the node's metadata store."
)

RECALL_DEFERRED = (
    "The node has backed off to its long retry interval for this object, because "
    "its outstanding holders have answered and refused repeatedly. The tombstone "
    "stands and they are still retried — re-running this form asks them again "
    "immediately."
)

# Per-holder states, mirroring storage-client/internal/store/recall.go.
RECALL_TERMINAL = ("deleted", "absent")


# --------------------------------------------------------------------------
# Preview -- reads only. Nothing in this function deletes anything.
# --------------------------------------------------------------------------

def preview(raw_target):
    """What a purge of this target would touch. Purely read-only.

    Deliberately does the same resolution the execute path does, from the same
    canonical string, so that what is shown and what is deleted cannot drift.
    """
    target = parse_target(raw_target)
    objects, media = _resolve_objects(target)

    dht = _dht_store()
    primary = _primary_store()

    rows = []
    total_bytes = total_chunks = total_shards = present = 0
    total_holders = 0
    holders_known = True
    for entry in objects:
        dht_head = _head(dht, entry["bucket"], entry["key"])
        primary_head = _head(primary, entry["bucket"], entry["key"])
        # Shard geometry follows the DHT copy, which is the encrypted blob the
        # node actually coded. Falling back to the primary size would understate
        # it, since the primary holds plaintext.
        size = dht_head["size"] if dht_head["present"] else primary_head["size"]
        # OBSERVED first. The ledger knows exactly how many chunks and shards
        # this object was cut into and which peers confirmed each one; the
        # arithmetic below is only the fallback for when it cannot be read.
        placement = object_placement(entry["bucket"], entry["key"])
        if placement.get("available"):
            shards = {
                "chunks": int(placement.get("chunks") or 0),
                "shards": int(placement.get("shard_count") or 0),
                "data_shards": int(placement.get("data_shards") or DATA_SHARDS),
                "parity_shards": int(placement.get("parity_shards") or PARITY_SHARDS),
                "derived": False,
            }
            total_holders += int(placement.get("distinct_holders") or 0)
        else:
            shards = _shard_math(size)
            holders_known = False
        if dht_head["present"] or primary_head["present"]:
            present += 1
        if size:
            total_bytes += size
        total_chunks += shards["chunks"]
        total_shards += shards["shards"]
        rows.append({
            "bucket": entry["bucket"], "key": entry["key"], "role": entry["role"],
            "canonical": "%s/%s" % (entry["bucket"], entry["key"]),
            "dht": dht_head, "primary": primary_head, "shards": shards,
            "placement": placement,
            "site_critical": entry["bucket"] in SITE_CRITICAL_BUCKETS,
            "bucket_purpose": KNOWN_BUCKETS.get(entry["bucket"], ""),
        })

    warnings = []
    if dht is None:
        warnings.append(
            "No separate DHT gateway is configured (DHT_S3_ENDPOINT), so nothing "
            "can be deleted from the DHT by this page."
        )
    if not present:
        warnings.append(
            "Neither store currently holds any of these keys. A purge would "
            "delete no bytes; it would still blocklist the hash and clean up the "
            "database rows."
        )
    for row in rows:
        if row["site_critical"] and (row["dht"]["present"] or row["primary"]["present"]):
            warnings.append(
                "%s is in the '%s' bucket (%s) — the site serves this key from a "
                "fixed path and will 404 for it after the purge."
                % (row["canonical"], row["bucket"], row["bucket_purpose"])
            )

    result = {
        "target": target["canonical"],
        "kind": target["kind"],
        "objects": rows,
        "totals": {
            "objects": len(rows), "present": present, "bytes": total_bytes,
            "chunks": total_chunks, "shards": total_shards,
        },
        # Known when the ledger answered for EVERY object of the target. A
        # partial read is reported as unknown rather than as a smaller number:
        # an undercount here reads as "safer than it is".
        "remote_holders": {
            "known": holders_known,
            "count": total_holders if holders_known else None,
            "reason": None if holders_known else REMOTE_HOLDERS_UNKNOWN,
        },
        "remote_shards_recallable": True,
        "remote_shards_note": REMOTE_SHARDS_RECALLABLE,
        "warnings": warnings,
        "media": None,
    }

    if media is not None:
        result["media"] = {
            "id": media.id, "ext": media.ext, "sha256": media.sha256,
            "nsfw_score": media.nsfw_score,
            "offloaded": media.dht_offloaded_at is not None,
            "references": _references(media.id),
        }
    else:
        # A raw key can still BE a media object; saying so stops an operator
        # deleting the bytes and leaving a row pointing at them.
        result["media_hint"] = _media_for_key(target["bucket"], target["key"])
    return result


def _references(media_id):
    """Rows that would be left dangling if the object went and they did not."""
    from model.Post import Post

    out = {"posts": 0, "videos": 0, "examples": []}
    try:
        out["posts"] = int(
            db.session.query(db.func.count(Post.id))
            .filter(Post.media == media_id).scalar() or 0
        )
    except Exception:
        db.session.rollback()
    try:
        from model.Video import Video

        out["videos"] = int(
            db.session.query(db.func.count(Video.id))
            .filter(Video.media_id == media_id).scalar() or 0
        )
    except Exception:
        db.session.rollback()
    try:
        from model.Board import Board
        from model.Thread import Thread

        rows = (
            db.session.query(Post.id, Post.thread, Post.body, Board.uri)
            .join(Thread, Post.thread == Thread.id)
            .join(Board, Thread.board == Board.id)
            .filter(Post.media == media_id).limit(5).all()
        )
        out["examples"] = [
            {"post_id": r[0], "thread_id": r[1], "excerpt": (r[2] or "")[:120],
             "board": r[3] or ""} for r in rows
        ]
    except Exception:
        db.session.rollback()
    return out


def _media_for_key(bucket, key):
    """The Media row a raw attachment/thumb/preview key belongs to, if any."""
    if bucket not in ("attachments", "thumbs", "previews"):
        return None
    stem = key.split("/")[-1].split(".")[0].replace("-v2", "")
    if not stem.isdigit():
        return None
    from model.Media import Media

    try:
        media = db.session.query(Media).filter(Media.id == int(stem)).one_or_none()
    except Exception:
        db.session.rollback()
        return None
    if media is None:
        return None
    return {"id": media.id, "ext": media.ext,
            "note": "This key belongs to media #%d. Purging the raw key leaves "
                    "that row (and any post using it) pointing at bytes that are "
                    "gone. Use media:%d to purge the row too."
                    % (media.id, media.id)}


# --------------------------------------------------------------------------
# Execute
# --------------------------------------------------------------------------

def _layer(name, status, detail, **extra):
    row = {"layer": name, "status": status, "detail": detail}
    row.update(extra)
    return row


def _delete_from(store, label, bucket, key):
    """Delete one key from one store and VERIFY with a fresh HEAD.

    Returns (status, detail). The gateway answers 204 whether or not anything
    happened, so the HEAD is the only evidence there is.
    """
    before = _head(store, bucket, key)
    if store is None:
        return "not_configured", "%s is not configured on this deployment." % label
    if before["error"]:
        return "error", "could not read %s before deleting: %s" % (label, before["error"])
    if not before["present"]:
        return "absent", "%s did not hold %s/%s." % (label, bucket, key)
    try:
        store._s3_remove_key(bucket, key)
    except Exception as exc:
        from model.Media import _is_missing_storage_error

        if not _is_missing_storage_error(exc):
            app.logger.exception("dht purge: delete failed on %s for %s/%s",
                                 label, bucket, key)
            return "error", "%s refused the delete: %s" % (label, str(exc)[:200])
    after = _head(store, bucket, key)
    if after["present"]:
        return "still_present", (
            "%s answered the delete but still serves %s/%s. The gateway returns "
            "204 unconditionally, so this HEAD is what actually settles it."
            % (label, bucket, key)
        )
    if after["error"]:
        return "unverified", (
            "%s accepted the delete but the confirming HEAD failed (%s), so "
            "whether the object is gone is not established." % (label, after["error"])
        )
    return "deleted", "%s no longer holds %s/%s (confirmed by HEAD)." % (label, bucket, key)


def purge(raw_target, confirmation, reason=None, acting_slip_id=None,
          acting_wallet=None, acting_ip=None, delete_rows=True,
          blocklist_hash=True):
    """Purge one target. Writes an audit row whatever happens.

    `confirmation` must equal the canonical target string exactly. That is the
    whole gate: a checkbox can be hit by a mis-click, and a target that has to be
    retyped cannot be purged by one.

    Returns a result whose `layers` list reports each layer SEPARATELY. There is
    deliberately no single boolean: this operation reaches some layers and
    provably never reaches others, and one flag cannot say that.
    """
    from model.DhtPurgeAudit import record as record_audit

    try:
        target = parse_target(raw_target)
    except TargetError:
        # Audited before re-raising: reaching for the destructive button with a
        # target that does not resolve is still a thing that happened.
        record_audit(str(raw_target or "")[:512], "object", [], "refused",
                     reason=reason, acting_slip_id=acting_slip_id,
                     acting_wallet=acting_wallet, acting_ip=acting_ip)
        raise

    if (confirmation or "").strip() != target["canonical"]:
        layers = [_layer("confirmation", "refused",
                         "Typed confirmation did not match %r. Nothing was "
                         "touched." % target["canonical"])]
        record_audit(target["canonical"], target["kind"], layers, "refused",
                     reason=reason, acting_slip_id=acting_slip_id,
                     acting_wallet=acting_wallet, acting_ip=acting_ip)
        return {"target": target["canonical"], "kind": target["kind"],
                "outcome": "refused", "layers": layers, "objects": []}

    try:
        objects, media = _resolve_objects(target)
    except TargetError as exc:
        # A media id that no longer exists. Confirmation already matched, so
        # this is an attempted purge and gets a row of its own.
        record_audit(target["canonical"], target["kind"],
                     [_layer("target", "unresolved", str(exc))], "refused",
                     reason=reason, acting_slip_id=acting_slip_id,
                     acting_wallet=acting_wallet, acting_ip=acting_ip)
        raise

    dht = _dht_store()
    primary = _primary_store()

    layers = []
    object_reports = []
    deleted_anywhere = False
    errored = False

    recalled_anywhere = False
    for entry in objects:
        bucket, key = entry["bucket"], entry["key"]
        canonical = "%s/%s" % (bucket, key)
        before = _head(dht, bucket, key)
        placement = object_placement(bucket, key)
        if placement.get("available"):
            shards = {
                "chunks": int(placement.get("chunks") or 0),
                "shards": int(placement.get("shard_count") or 0),
                "data_shards": int(placement.get("data_shards") or DATA_SHARDS),
                "parity_shards": int(placement.get("parity_shards") or PARITY_SHARDS),
                "derived": False,
            }
        else:
            shards = _shard_math(before["size"])

        # RECALL FIRST, DELETE SECOND, and not for tidiness.
        #
        # The recall needs the placement row, which names the holders. The
        # delete retires that row into a tombstone -- so a recall afterwards
        # would still work, but a recall BEFORE means the report describes
        # holders that were asked while the ledger was whole, and it means a
        # failure to reach the node leaves the object intact rather than
        # deleted-and-unrecallable.
        recall = recall_shards(bucket, key, reason=(reason or "admin DHT purge"))
        counts = _recall_counts(recall) if recall.get("available") else {}
        if counts.get("deleted"):
            recalled_anywhere = True

        dht_status, dht_detail = _delete_from(dht, "the DHT gateway", bucket, key)
        primary_status, primary_detail = _delete_from(
            primary, "the primary object store", bucket, key
        )
        if dht_status == "deleted" or primary_status == "deleted":
            deleted_anywhere = True
        if dht_status in ("error", "still_present") or primary_status in ("error", "still_present"):
            errored = True

        layers.append(_layer("dht_gateway_object", dht_status, dht_detail,
                             object=canonical, size=before["size"],
                             object_id=before["object_id"]))
        layers.append(_layer("primary_store_object", primary_status, primary_detail,
                             object=canonical))

        if dht_status == "deleted":
            layers.append(_layer(
                "node_local_shards", "released",
                "The node unlinks its own shard files for %s as part of the "
                "delete, except any shard whose bytes are still referenced by "
                "another object (shards are content-addressed and shared). "
                "Roughly %d shard(s) across %d chunk(s), derived from the %s-byte "
                "stored object -- the node reports no count, so this is arithmetic, "
                "not an observation."
                % (canonical, shards["shards"], shards["chunks"], before["size"] or 0),
                object=canonical, shards=shards["shards"], chunks=shards["chunks"]))
            layers.append(_layer(
                "placement_ledger", "retired",
                "The node retired its placement row for %s: the holder list was "
                "captured into a recall tombstone first, so any holder that did "
                "not answer above is still named and will be retried. The row "
                "itself is gone, which is what stops the dispersal and repair "
                "passes re-placing shards of a deleted object."
                % canonical, object=canonical,
                outstanding=int((recall or {}).get("outstanding") or 0)))
        else:
            layers.append(_layer(
                "node_local_shards", "not_reached",
                "No object was deleted from the DHT gateway for %s, so no local "
                "shard was released." % canonical, object=canonical))

        # ALWAYS reported, on every object, in every outcome -- but now with
        # what each holder actually said.
        layers.append(_recall_layer(canonical, recall))

        object_reports.append({
            "canonical": canonical, "bucket": bucket, "key": key,
            "role": entry["role"], "size": before["size"],
            "object_id": before["object_id"], "shards": shards,
            "dht": dht_status, "primary": primary_status,
            "recall": recall, "recall_counts": counts,
        })

    layers.append(_read_cache_layer(media, target))
    layers.extend(_database_layers(media, target, delete_rows, blocklist_hash, reason,
                                   acting_slip_id))

    if any(l["status"] == "error" for l in layers) and not deleted_anywhere:
        outcome = "failed"
    elif deleted_anywhere:
        outcome = "purged"
    elif errored:
        outcome = "failed"
    else:
        outcome = "nothing_found"

    # Only true when a holder actually confirmed a deletion. Not "a recall was
    # attempted", not "the endpoint answered" -- the column exists so an
    # operator reading old rows can tell which purges reached the network, and
    # a generous reading of it would destroy that.
    record_audit(target["canonical"], target["kind"], layers, outcome,
                 reason=reason, acting_slip_id=acting_slip_id,
                 acting_wallet=acting_wallet, acting_ip=acting_ip,
                 remote_shards_recalled=recalled_anywhere)

    return {"target": target["canonical"], "kind": target["kind"],
            "outcome": outcome, "layers": layers, "objects": object_reports,
            "remote_shards_recalled": recalled_anywhere,
            "remote_shards_note": REMOTE_SHARDS_RECALLABLE}


# --------------------------------------------------------------------------
# Recall on its own -- per object or per shard, without deleting the object
# --------------------------------------------------------------------------

def recall(raw_target, confirmation, shard_ids=None, reason=None,
           acting_slip_id=None, acting_wallet=None, acting_ip=None):
    """Recall shards WITHOUT deleting the object.

    The per-shard delete the listing offers. Same retype-to-confirm gate as a
    purge, and audited the same way, because it destroys data on other people's
    machines even though the object survives here.

    Note what it does NOT do: the object still exists, so the node's dispersal
    pass will place fresh shards for it again -- on other peers, since the ones
    that honoured the recall blocklisted the shard id. That is stated in the
    layer rather than hidden, because an operator recalling one shard usually
    means "get it off THAT machine", not "make this object less durable".
    """
    from model.DhtPurgeAudit import record as record_audit

    target = parse_target(raw_target)
    if target["kind"] != "object":
        raise TargetError(
            "Recall works on one <bucket>/<key> object at a time; %s names a "
            "media row with several." % target["canonical"])
    if (confirmation or "").strip() != target["canonical"]:
        layers = [_layer("confirmation", "refused",
                         "Typed confirmation did not match %r. Nothing was "
                         "touched." % target["canonical"])]
        record_audit(target["canonical"], "object", layers, "refused",
                     reason=reason, acting_slip_id=acting_slip_id,
                     acting_wallet=acting_wallet, acting_ip=acting_ip)
        return {"target": target["canonical"], "outcome": "refused",
                "layers": layers}

    wanted = [s for s in (shard_ids or []) if s]
    report = recall_shards(target["bucket"], target["key"], wanted,
                           reason=(reason or "admin shard recall"))
    layers = [_recall_layer(target["canonical"], report)]
    counts = _recall_counts(report) if report.get("available") else {}
    if wanted:
        layers.append(_layer(
            "recall_scope", "per_shard",
            "Restricted to %d shard(s) of %s. The object itself was NOT deleted "
            "and its manifest is intact, so the node's dispersal pass will place "
            "replacement shards -- on different peers, because a holder that "
            "honours a recall also blocklists the shard id."
            % (len(wanted), target["canonical"]), shards=wanted))
    else:
        layers.append(_layer(
            "recall_scope", "whole_object",
            "Every recorded holder of every shard of %s was asked. The object "
            "itself was NOT deleted; use the purge form for that."
            % target["canonical"]))

    if not report.get("available"):
        outcome = "failed"
    elif counts.get("deleted"):
        outcome = "purged" if not (counts.get("refused") or counts.get("unreachable")) \
            else "partial"
    elif sum(counts.values()) == 0:
        outcome = "nothing_found"
    else:
        outcome = "partial"

    record_audit(target["canonical"], "object", layers, outcome,
                 reason=reason, acting_slip_id=acting_slip_id,
                 acting_wallet=acting_wallet, acting_ip=acting_ip,
                 remote_shards_recalled=bool(counts.get("deleted")))
    return {"target": target["canonical"], "kind": "object", "outcome": outcome,
            "layers": layers, "objects": [], "recall": report,
            "remote_shards_recalled": bool(counts.get("deleted")),
            "remote_shards_note": REMOTE_SHARDS_RECALLABLE}


def _read_cache_layer(media, target):
    """Evict the in-process read cache.

    Without this the site keeps serving a purged object from RAM: media_read
    checks cache.get() BEFORE the negative-cache flag, so marking it unavailable
    is not enough -- the bytes have to actually leave.
    """
    media_id = media.id if media is not None else None
    if media_id is None and target["kind"] == "object":
        hint = _media_for_key(target["bucket"], target["key"])
        media_id = hint["id"] if hint else None
    if media_id is None:
        return _layer("read_cache", "not_applicable",
                      "This target is not media, so nothing was cached for it.")
    try:
        from services.media_cache import cache

        store = cache()
        dropped = store.drop("attachment:%d" % media_id)
        store.mark_unavailable("attachment:%d" % media_id)
    except Exception as exc:
        app.logger.exception("dht purge: cache eviction failed for media %s", media_id)
        return _layer("read_cache", "error",
                      "Could not evict the in-process read cache (%s); this "
                      "worker may keep serving the bytes until it restarts."
                      % str(exc)[:150])
    return _layer(
        "read_cache", "evicted" if dropped else "not_cached",
        "Dropped attachment:%d from this worker's media cache and marked it "
        "unavailable. OTHER WORKERS AND CDN/browser caches are not reached by "
        "this and may keep serving the bytes until their entries expire."
        % media_id)


def _database_layers(media, target, delete_rows, blocklist_hash, reason,
                     acting_slip_id):
    """What happens to the rows that point at the object.

    THE RULE THIS ENFORCES: no row is left pointing at bytes that are gone
    without saying so. For a media target the referencing posts/videos and the
    Media row are deleted, so there is nothing dangling. For a raw key the rows
    are not touched -- and the layer says exactly which row is now dangling, so
    the operator can see it rather than discover it from a broken thumbnail.
    """
    layers = []
    if media is None:
        hint = None
        if target["kind"] == "object":
            hint = _media_for_key(target["bucket"], target["key"])
        if hint:
            layers.append(_layer(
                "database_rows", "left_dangling",
                "Media row #%d still exists and still references %s, whose bytes "
                "were just purged. Requests for it will now 404 (or fall back to "
                "a regenerated thumbnail). Purge media:%d to remove the row and "
                "the posts that embed it." % (hint["id"], target["canonical"], hint["id"]),
                media_id=hint["id"]))
        else:
            layers.append(_layer(
                "database_rows", "not_applicable",
                "No database row references this object key."))
        layers.append(_layer("hash_blocklist", "not_applicable",
                             "A raw object key has no recorded content hash to "
                             "blocklist."))
        return layers

    sha = media.sha256
    if blocklist_hash and sha:
        try:
            from model.BlockedMediaHash import block_media_hash

            block_media_hash(sha, reason=(reason or "admin DHT purge"),
                             created_by_slip_id=acting_slip_id)
            layers.append(_layer("hash_blocklist", "blocked",
                                 "sha256 %s is blocklisted: re-uploading these "
                                 "bytes is refused, and the offload sweep will "
                                 "never publish them again." % sha))
        except Exception as exc:
            db.session.rollback()
            app.logger.exception("dht purge: blocklist failed for media %s", media.id)
            layers.append(_layer("hash_blocklist", "error",
                                 "Could not blocklist %s (%s) -- these bytes can "
                                 "be re-uploaded." % (sha, str(exc)[:150])))
    elif not sha:
        layers.append(_layer("hash_blocklist", "skipped",
                             "This media row has no recorded sha256, so there is "
                             "nothing to blocklist and the same bytes could be "
                             "uploaded again."))
    else:
        layers.append(_layer("hash_blocklist", "skipped",
                             "Not requested. The same bytes can be re-uploaded."))

    if not delete_rows:
        layers.append(_layer(
            "database_rows", "left_dangling",
            "Row deletion was not requested. Media row #%d and %d post(s) still "
            "reference the purged object and will serve 404s."
            % (media.id, _references(media.id)["posts"]), media_id=media.id))
        return layers

    posts = videos = 0
    try:
        from model.Video import Video

        videos = db.session.query(Video).filter(
            Video.media_id == media.id).delete(synchronize_session=False)
    except Exception:
        db.session.rollback()
        app.logger.exception("dht purge: video delete failed for media %s", media.id)
    try:
        from model.Media import Media
        from model.Post import Post

        posts = db.session.query(Post).filter(
            Post.media == media.id).delete(synchronize_session=False)
        db.session.query(Media).filter(Media.id == media.id).delete(
            synchronize_session=False)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app.logger.exception("dht purge: row delete failed for media %s", media.id)
        layers.append(_layer(
            "database_rows", "error",
            "The object was purged but its rows could not be deleted (%s). Media "
            "row #%d still points at bytes that are gone." % (str(exc)[:150], media.id),
            media_id=media.id))
        return layers

    layers.append(_layer(
        "database_rows", "deleted",
        "Deleted media row #%d, %d post(s) and %d video row(s), so nothing is "
        "left pointing at the purged object." % (media.id, posts, videos),
        media_id=media.id, posts=posts, videos=videos))
    return layers
