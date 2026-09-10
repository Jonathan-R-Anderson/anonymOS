"""Manage editable codeplay content: seed from the bundled JSON, admin CRUD, and
publish a content-addressed snapshot of each collection to the DHT.

The DB (model.CodeplayContent) is the editable source of truth. A snapshot of
each collection is pushed to the storage DHT via the same node S3 gateway that
holds imageboard media, so the durable copy lives on the network. Publishing is
best-effort: a failure is logged and never blocks editing or serving content.
"""
import hashlib
import io
import json
import os

from shared import app, db
from model.CodeplayContent import (
    CodeplayContent, COLLECTIONS, build_collection, collection_counts, has_any, item_by_id,
)

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "codeplay")

# SiteSetting keys recording the published DHT snapshot (sha256) per collection.
_SNAPSHOT_KEY = "codeplay-dht-snapshot-%s"


def _invalidate_cache():
    """Drop services.codeplay's in-process content cache so edits show at once."""
    try:
        from services import codeplay as cp
        cp._CACHE.clear()
    except Exception:
        app.logger.exception("codeplay_content: cache invalidation failed")


def _extract(collection, payload, difficulty_override=None):
    """Pull the stable id + filter fields out of an item payload."""
    item_id = str(payload.get("id")) if payload.get("id") is not None else None
    category = str(payload.get("category") or "")
    difficulty = str(difficulty_override or payload.get("difficulty") or "")
    return item_id, category, difficulty


def seed_from_bundled(force=False):
    """Populate the table from backend/data/codeplay/*.json. No-op if the table
    already has rows (unless force=True, which tops up MISSING items only and
    never deletes admin edits). Returns {collection: added}."""
    if has_any() and not force:
        return {}
    added = {}
    for collection in COLLECTIONS:
        path = os.path.join(_DATA_DIR, "%s.json" % collection)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            app.logger.exception("codeplay_content: cannot read seed %s", path)
            continue
        existing = {
            row.item_id
            for row in db.session.query(CodeplayContent.item_id).filter(
                CodeplayContent.collection == collection
            )
        }
        pairs = []  # (item_id, category, difficulty, payload)
        if collection == "daily" and isinstance(data, dict):
            for diff, items in data.items():
                for it in (items or []):
                    iid, cat, _ = _extract(collection, it, difficulty_override=diff)
                    pairs.append(("%s-%s" % (diff, iid), cat, diff, it))
        elif isinstance(data, list):
            for it in data:
                iid, cat, diff = _extract(collection, it)
                pairs.append((iid, cat, diff, it))
        count = 0
        for position, (iid, cat, diff, payload) in enumerate(pairs):
            if not iid or iid in existing:
                continue
            db.session.add(CodeplayContent(
                collection=collection, item_id=iid, category=cat, difficulty=diff,
                payload=json.dumps(payload, ensure_ascii=False), position=position, active=True,
            ))
            count += 1
        if count:
            added[collection] = count
    db.session.commit()
    if added:
        _invalidate_cache()
    return added


def _next_position(collection):
    from sqlalchemy import func
    top = db.session.query(func.max(CodeplayContent.position)).filter(
        CodeplayContent.collection == collection
    ).scalar()
    return (top or 0) + 1


def add_item(collection, payload, difficulty=None):
    """Add an item to a collection. `payload` is the full item dict (must carry
    an `id`; for collections keyed by numeric id, any unique string works)."""
    if collection not in COLLECTIONS:
        raise ValueError("Unknown codeplay collection: %s" % collection)
    if not isinstance(payload, dict) or payload.get("id") in (None, ""):
        raise ValueError("Item needs an 'id'.")
    iid, cat, diff = _extract(collection, payload, difficulty_override=difficulty)
    row_key = ("%s-%s" % (diff, iid)) if collection == "daily" else iid
    exists = db.session.query(CodeplayContent.id).filter(
        CodeplayContent.collection == collection, CodeplayContent.item_id == row_key
    ).first()
    if exists:
        raise ValueError("An item with id %s already exists in %s." % (iid, collection))
    row = CodeplayContent(
        collection=collection, item_id=row_key, category=cat, difficulty=diff,
        payload=json.dumps(payload, ensure_ascii=False), position=_next_position(collection),
        active=True,
    )
    db.session.add(row)
    db.session.commit()
    _invalidate_cache()
    return row


def update_item(row_id, payload=None, active=None, position=None):
    row = item_by_id(row_id)
    if row is None:
        raise ValueError("No such content item.")
    if payload is not None:
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a JSON object.")
        payload.setdefault("id", row.item_id.split("-", 1)[-1] if row.collection == "daily" else row.item_id)
        _, cat, diff = _extract(row.collection, payload,
                                difficulty_override=(row.difficulty if row.collection == "daily" else None))
        row.payload = json.dumps(payload, ensure_ascii=False)
        row.category = cat
        if row.collection != "daily":
            row.difficulty = diff
    if active is not None:
        row.active = bool(active)
    if position is not None:
        try:
            row.position = int(position)
        except (TypeError, ValueError):
            pass
    db.session.commit()
    _invalidate_cache()
    return row


def delete_item(row_id):
    row = item_by_id(row_id)
    if row is None:
        return None
    collection = row.collection
    db.session.delete(row)
    db.session.commit()
    _invalidate_cache()
    return collection


# --- DHT snapshot publishing ------------------------------------------------

def _s3_client():
    """A boto3 client pointed at the node's S3 gateway (the DHT), configured like
    model.Media.S3Storage. Returns None if no endpoint is set."""
    endpoint = (app.config.get("DHT_S3_ENDPOINT") or app.config.get("S3_ENDPOINT") or "").strip()
    if not endpoint:
        return None
    import boto3
    from botocore.config import Config
    ca = (app.config.get("DHT_S3_CA_BUNDLE") or "").strip()
    insecure = str(app.config.get("DHT_S3_INSECURE_TLS") or "").strip().lower() in ("1", "true", "yes")
    verify = False if insecure else (ca or None)
    extra = {}
    try:
        Config(request_checksum_calculation="when_required")
        extra["request_checksum_calculation"] = "when_required"
        extra["response_checksum_validation"] = "when_required"
    except Exception:
        pass
    return boto3.client(
        "s3", endpoint_url=endpoint,
        aws_access_key_id=app.config.get("DHT_S3_ACCESS_KEY") or app.config.get("S3_ACCESS_KEY") or "",
        aws_secret_access_key=app.config.get("DHT_S3_SECRET_KEY") or app.config.get("S3_SECRET_KEY") or "",
        verify=verify,
        config=Config(**extra, s3={"addressing_style": "path"},
                      connect_timeout=5, read_timeout=120,
                      retries={"max_attempts": 2, "mode": "standard"}),
    )


_CODEPLAY_BUCKET = "codeplay"


# Above this, a collection is published as shards plus an index rather than one
# object. 4 MB is well under any single-object limit and small enough that a
# reader fetching one shard is not made to wait on the rest.
#
# The Edabit import took `problems` from 57 items to ~8,600, about 14 MB. One
# object that size is a bad citizen in a store other people host: it cannot be
# fetched partially, a single byte of drift invalidates all of it, and every
# node that wants any problem must carry every problem.
_SHARD_BYTES = 4 * 1024 * 1024


def _shard(items, limit=_SHARD_BYTES):
    """Split a collection into chunks that each stay under the size limit.

    Splits on item boundaries and never mid-item: a shard is independently
    parseable JSON, so a reader that fetched exactly one has usable content
    rather than a fragment it must reassemble before it can tell.
    """
    shards, current, size = [], [], 0
    for item in items:
        encoded = len(json.dumps(item, ensure_ascii=False)) + 1
        if current and size + encoded > limit:
            shards.append(current)
            current, size = [], 0
        current.append(item)
        size += encoded
    if current:
        shards.append(current)
    return shards or [[]]


def publish_to_dht():
    """Publish a snapshot of every collection to the DHT node gateway. Records the
    sha256 of each snapshot in a SiteSetting. Best-effort per collection; returns
    {collection: sha256} for those that published.

    A collection larger than _SHARD_BYTES is written as `<collection>/NNN.json`
    shards with `<collection>.json` as an INDEX naming them and their digests.
    Small collections keep the plain single-object form they always had, so
    nothing that reads them needs to know sharding exists until it meets a
    collection big enough to need it — and then the index tells it.

    The recorded sha256 is of the index in that case. That is the right thing to
    pin: it changes whenever any shard changes, so one digest still answers "is
    my copy current" for the whole collection.
    """
    client = _s3_client()
    if client is None:
        app.logger.info("codeplay_content: no S3/DHT endpoint; skipping publish")
        return {}
    prefix = (app.config.get("DHT_S3_UUID_PREFIX") or "").strip()
    bucket = (prefix + _CODEPLAY_BUCKET) if prefix else _CODEPLAY_BUCKET
    try:
        client.head_bucket(Bucket=bucket)
    except Exception:
        try:
            client.create_bucket(Bucket=bucket)
        except Exception:
            app.logger.exception("codeplay_content: cannot ensure bucket %s", bucket)
    from model.SiteSetting import set_setting
    published = {}
    for collection in COLLECTIONS:
        try:
            built = build_collection(collection)
            body = json.dumps(built, ensure_ascii=False, sort_keys=True).encode("utf-8")

            if len(body) <= _SHARD_BYTES or not isinstance(built, list):
                # Unchanged path. `daily` is a dict rather than a list and has
                # no natural shard boundary, so it is never split.
                digest = hashlib.sha256(body).hexdigest()
                client.put_object(Bucket=bucket, Key="%s.json" % collection, Body=body,
                                  ContentType="application/json")
            else:
                shards = _shard(built)
                index = {"collection": collection, "sharded": True,
                         "count": len(built), "shards": []}
                for number, chunk in enumerate(shards):
                    chunk_body = json.dumps(chunk, ensure_ascii=False,
                                            sort_keys=True).encode("utf-8")
                    key = "%s/%03d.json" % (collection, number)
                    client.put_object(Bucket=bucket, Key=key, Body=chunk_body,
                                      ContentType="application/json")
                    index["shards"].append({
                        "key": key,
                        "count": len(chunk),
                        "sha256": hashlib.sha256(chunk_body).hexdigest(),
                    })
                body = json.dumps(index, ensure_ascii=False, sort_keys=True).encode("utf-8")
                digest = hashlib.sha256(body).hexdigest()
                # Index LAST, so a reader never sees an index naming a shard
                # that has not been written yet.
                client.put_object(Bucket=bucket, Key="%s.json" % collection, Body=body,
                                  ContentType="application/json")
                app.logger.info("codeplay_content: %s published as %d shard(s), %d items",
                                collection, len(shards), len(built))

            set_setting(_SNAPSHOT_KEY % collection, digest)
            published[collection] = digest
        except Exception:
            app.logger.exception("codeplay_content: publish failed for %s", collection)
    if published:
        db.session.commit()
    return published


def status():
    """Admin summary: per-collection DB counts + last published DHT sha256."""
    from model.SiteSetting import get_setting
    counts = collection_counts()
    out = {}
    for collection in COLLECTIONS:
        out[collection] = {
            "count": counts.get(collection, 0),
            "dht_sha256": get_setting(_SNAPSHOT_KEY % collection, "") or None,
        }
    return out
