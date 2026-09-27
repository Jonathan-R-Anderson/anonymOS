"""Putting sealed submissions into the DHT, and proving they came back.

Same transport as everything else the site stores: `S3_ENDPOINT` is a storage
node's gateway, and that node encrypts, erasure-codes and distributes what it is
given. This module is the namespace, the versioning and the readback gate;
`services/snapshot_dht.py` is the model it follows.

WHY A DEDICATED BUCKET
----------------------
`snapshot_dht` makes the argument and it holds here: mixing object classes means
every retention rule has to ask "but is this one a report?", and the first rule
that forgets to ask is the one that deletes a complainant's submission during an
outage. Reports have their own retention policy, their own key, and their own
deletion path, so they get their own bucket.

WHAT THE KEY MAY CONTAIN
------------------------
    civil-rights-reports/<report-id>/v<n>

An unguessable id and an integer. No date, no category, no jurisdiction, no
kind -- a DHT key is visible to every node that routes for it, so anything
descriptive in the key is metadata published to strangers. The key deliberately
does not distinguish a civil-rights report from a press tip: the prefix is shared
so that the existence of a key says nothing about what sort of thing it is.

VERSIONS ARE APPEND-ONLY
------------------------
A correction writes v2 and leaves v1 in place. Two reasons: the audit trail
refers to versions and a reference to something that was overwritten is not
evidence of anything, and a complainant who adds detail should not be able to
silently rewrite what they first said -- nor should anyone else be able to on
their behalf.

WHAT A SUCCESSFUL WRITE PROVES, AND WHAT IT DOES NOT
----------------------------------------------------
Carried over from `snapshot_dht`, unchanged and load-bearing: a 200 from the
gateway means the gateway accepted the bytes. It does NOT mean the object is
replicated across peers -- the gateway does not report that, and at the time of
writing many peers refuse shards outright, so a write that succeeded may be held
in exactly one place.

`store()` therefore fetches the object back and verifies it before reporting
success. That proves RETRIEVABILITY, which is weaker than replication and is what
can actually be established from here. The user is told their report was received
and stored; they are not told it is durably replicated, because nobody here
knows that.
"""

import hashlib

from shared import app


BUCKET = "public-interest-reports"

# One prefix for every kind. See the module docstring: a key that announces it
# holds a press tip tells every routing node something about the person who sent
# it, and the site's own index already knows which kind it is.
KEY_PREFIX = "civil-rights-reports"


class ReportStorageError(Exception):
    """Storage did not complete. Never swallow this into a success path."""


def enabled():
    return bool(app.config.get("S3_ENDPOINT"))


def key_for(report_id, version=1):
    return "%s/%s/v%d" % (KEY_PREFIX, report_id, int(version))


def _client():
    """A client for the storage node's S3 gateway.

    Deliberately identical in configuration to `snapshot_dht._client` -- the
    gateway presents a self-signed certificate and rejects botocore's default
    checksum headers, and every difference from the client that already works
    against this endpoint is a difference somebody has to rediscover by watching
    a failure.
    """
    from services import snapshot_dht
    return snapshot_dht._client()


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
        app.logger.exception("reports: could not create the %s bucket", _bucket())
        return False


def store(report_id, blob, content_hash, version=1, expires_at=None, client=None):
    """Write a sealed submission and prove it reads back. Raises on any failure.

    Raising rather than returning False is the point. This is the one call whose
    failure must never be mistaken for success by a caller that forgot to check
    a return value -- the requirement is that a user is never told their report
    was submitted when it was not, and an exception is the only result that
    cannot be ignored by accident.

    Returns the key on success.
    """
    if not enabled():
        raise ReportStorageError("no object store is configured (S3_ENDPOINT unset)")

    client = client or _client()
    ensure_bucket(client)
    key = key_for(report_id, version)

    metadata = {"content-hash": content_hash}
    if expires_at:
        # Carried on the object so a node can expire it without holding any
        # index that refers to it.
        metadata["expires-at"] = str(int(expires_at))

    try:
        client.put_object(Bucket=_bucket(), Key=key, Body=blob, Metadata=metadata)
    except Exception as exc:
        # No report_id in the log line beyond the key, and never any payload.
        # Logs are the one place this data reliably leaks.
        app.logger.exception("reports: write failed for %s", key)
        raise ReportStorageError("could not write %s: %s" % (key, exc))

    # THE GATE. A write that returned success and a read that returns the right
    # bytes are different claims, and only the second one means the submission
    # can be recovered later.
    fetched = fetch(report_id, version=version, client=client)
    if fetched is None:
        raise ReportStorageError(
            "wrote %s but could not read it back; treating the submission as "
            "failed" % key
        )
    if hashlib.sha256(fetched).hexdigest() != content_hash:
        raise ReportStorageError(
            "read back %s but the bytes do not match the hash that was stored" % key
        )
    return key


def fetch(report_id, version=1, client=None):
    """Fetch one stored version, or None. Does not decrypt and does not verify.

    Verification belongs to `report_crypto.unseal`, which has the expected hash
    and the expected identity. Splitting them keeps this module ignorant of the
    key -- a transport that could decrypt would be a second place holding the
    ability to read reports.
    """
    client = client or _client()
    try:
        response = client.get_object(Bucket=_bucket(), Key=key_for(report_id, version))
        return response["Body"].read()
    except Exception:
        return None


def latest_version(report_id, client=None, ceiling=64):
    """The highest stored version, or 0 if none.

    Walks upward from 1 rather than listing: listing a prefix enumerates every
    version of a report to anyone who can reach the bucket, and this is called
    on a path where that is not needed. `ceiling` bounds it -- a report with 64
    corrections is a bug, not a use case.
    """
    client = client or _client()
    found = 0
    for version in range(1, ceiling + 1):
        try:
            client.head_object(Bucket=_bucket(), Key=key_for(report_id, version))
        except Exception:
            break
        found = version
    return found


def delete(report_id, version=None, client=None):
    """Remove stored versions. Returns the keys actually deleted.

    Used by retention expiry and by an operator deletion. Deleting the index row
    without this leaves ciphertext on volunteer disks that nobody can find and
    nobody will ever remove -- the worst of both outcomes, since the data
    survives and the ability to act on it does not.

    NOTE, and it is a real limit: removing an object through the gateway is a
    request to the storage layer, not a proof that every shard on every peer is
    gone. `services/dht_object_purge.py` is the path that recalls shards from
    holders, and a retention sweep that must actually erase should use it. This
    function is the gateway-level half.
    """
    client = client or _client()
    versions = [version] if version else range(1, (latest_version(report_id, client) or 0) + 1)
    removed = []
    for candidate in versions:
        key = key_for(report_id, candidate)
        try:
            client.delete_object(Bucket=_bucket(), Key=key)
            removed.append(key)
        except Exception:
            app.logger.exception("reports: could not delete %s", key)
    return removed


# --- evidence --------------------------------------------------------------

# The three artefacts an attachment becomes. See services/report_evidence.py for
# why one file is not enough: stripping metadata destroys the thing that proves a
# document genuine, so the untouched copy is kept as evidence, a scrubbed copy is
# what a reviewer reads, and the extracted metadata is kept as DATA.
VARIANT_ORIGINAL = "original"
VARIANT_SCRUBBED = "scrubbed"
VARIANT_MANIFEST = "manifest"

VARIANTS = (VARIANT_ORIGINAL, VARIANT_SCRUBBED, VARIANT_MANIFEST)


def evidence_key_for(report_id, index, variant):
    """civil-rights-reports/<report-id>/e<n>/<variant>

    Same namespace and the same discipline as the payload key: an unguessable
    report id, an integer, and a fixed word. No filename, no MIME type, no
    size -- a DHT key is visible to every node that routes for it, and an
    attachment called `bodycam-2026-03-04.mp4` in a key would describe the
    contents of an encrypted object to strangers.
    """
    if variant not in VARIANTS:
        raise ReportStorageError("unknown evidence variant %r" % variant)
    return "%s/%s/e%d/%s" % (KEY_PREFIX, report_id, int(index), variant)


def store_evidence(report_id, index, variant, blob, content_hash,
                   expires_at=None, client=None):
    """Write one artefact and prove it reads back. Raises on any failure.

    Deliberately the same readback gate as `store()`. An attachment that the
    gateway accepted and cannot return is not stored, and the submitter must not
    be told their documents arrived -- which for evidence is worse than for the
    written report, because a source who believes a document was delivered will
    not send it again.
    """
    if not enabled():
        raise ReportStorageError("no object store is configured (S3_ENDPOINT unset)")

    client = client or _client()
    ensure_bucket(client)
    key = evidence_key_for(report_id, index, variant)

    metadata = {"content-hash": content_hash}
    if expires_at:
        metadata["expires-at"] = str(int(expires_at))

    try:
        client.put_object(Bucket=_bucket(), Key=key, Body=blob, Metadata=metadata)
    except Exception as exc:
        # No filename in the log line, and never any content.
        app.logger.exception("reports: evidence write failed for %s", key)
        raise ReportStorageError("could not write %s: %s" % (key, exc))

    fetched = fetch_evidence(report_id, index, variant, client=client)
    if fetched is None:
        raise ReportStorageError(
            "wrote %s but could not read it back; treating the attachment as "
            "failed" % key)
    if hashlib.sha256(fetched).hexdigest() != content_hash:
        raise ReportStorageError(
            "read back %s but the bytes do not match the hash that was stored"
            % key)
    return key


def fetch_evidence(report_id, index, variant, client=None):
    """One artefact, or None. Does not decrypt."""
    client = client or _client()
    try:
        response = client.get_object(
            Bucket=_bucket(), Key=evidence_key_for(report_id, index, variant))
        return response["Body"].read()
    except Exception:
        return None


def delete_evidence(report_id, index_ceiling=64, client=None):
    """Remove every artefact of every attachment. Returns the keys deleted.

    Called by retention alongside the payload. An expiry that removed the report
    and left its attachments would leave the most sensitive part of a submission
    on volunteer disks with nothing pointing at it -- unfindable and therefore
    undeletable.
    """
    client = client or _client()
    removed = []
    for index in range(0, index_ceiling):
        found_any = False
        for variant in VARIANTS:
            key = evidence_key_for(report_id, index, variant)
            try:
                client.head_object(Bucket=_bucket(), Key=key)
            except Exception:
                continue
            try:
                client.delete_object(Bucket=_bucket(), Key=key)
                removed.append(key)
                found_any = True
            except Exception:
                app.logger.exception("reports: could not delete %s", key)
        # Attachment indexes are contiguous, so the first gap is the end. Walking
        # to the ceiling regardless would issue 192 HEADs for a report with one
        # attachment.
        if not found_any and index > 0:
            break
    return removed
