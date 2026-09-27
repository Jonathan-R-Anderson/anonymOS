"""Sealing a submission so the nodes that store it cannot read it.

The scheme is `services.content_keys` -- AES-256-GCM under a content key that is
ECIES-wrapped to a hardened BIP32 child of a master secret -- used with a
DIFFERENT master. This module is the key separation and the payload format; it
deliberately implements no cryptography of its own.

WHY A SEPARATE MASTER SECRET
----------------------------
`STORAGE_CONTENT_MASTER_SECRET` already decrypts every stored media object on
this site. Rooting reports in it would mean "authorised to read a civil-rights
complaint" and "holds the key that reads all site content" are the same
capability, so any compromise yielding one yields the other.

`services/snapshot_key.py` faced exactly this and refused the shortcut, for
reasons that apply here with more force: separate key, separate blast radius. It
also refuses to fall back to the origin key when unset, because a fallback
"would quietly undo the separation at exactly the moment somebody was in a
hurry" -- and the resulting deployment looks identical to a correct one.

So: `REPORT_CONTENT_MASTER_SECRET`, no fallback, and reports that cannot be
sealed rather than reports sealed under the wrong key. An intake that refuses to
accept a submission is a visible outage; an intake that accepts one and protects
it with the wrong key is a silent breach.

WHAT THE TWO INTEGRITY VALUES EACH PROVE
----------------------------------------
Both are needed and they answer different questions:

* the **AEAD tag**, inside the blob, proves the bytes decrypt to something we
  sealed -- a node that flips a byte produces a decryption failure, not
  plausible-looking wrong content. This is what makes silent modification by a
  malicious node detectable.
* the **content hash**, recorded in the index row, proves these are the bytes we
  sealed *for this report*. Without it, a node could serve report B's perfectly
  valid ciphertext in place of report A's and every cryptographic check inside
  the blob would pass.

The object id binds the ciphertext to `<report-id>/v<n>` through the AEAD's
additional data, so a payload cannot be replayed as a different report or as a
different version of the same one.
"""

import hashlib
import json
import os

from services import content_keys


ENV_MASTER = "REPORT_CONTENT_MASTER_SECRET"

# Bumped when the payload structure changes in a way an old reader cannot
# handle. Recorded on the index row so old payloads stay decodable.
SCHEMA_VERSION = 1


class ReportCryptoError(Exception):
    pass


def _secret():
    secret = (os.getenv(ENV_MASTER) or "").strip()
    if not secret:
        raise ReportCryptoError(
            "%s is not configured; submissions cannot be sealed. This does NOT "
            "fall back to the storage master by design -- see the module "
            "docstring." % ENV_MASTER
        )
    return secret


def enabled():
    """Whether reports can be sealed at all.

    Intake must check this BEFORE accepting anything from a person. Discovering
    the key is missing after collecting somebody's account of being assaulted
    means either dropping it or storing it unprotected, and both are worse than
    telling them up front that submissions are closed.
    """
    return bool((os.getenv(ENV_MASTER) or "").strip())


def generate_master_secret():
    """A fresh master seed as hex, for `REPORT_CONTENT_MASTER_SECRET`."""
    return content_keys.generate_master_secret()


def object_id_for(report_id, version=1):
    """The AEAD-bound identity of one stored version.

    Includes the version so a v1 ciphertext cannot be served as v2 -- versions
    are corrections, and a correction that can be silently rolled back is not a
    correction.
    """
    return "%s/v%d" % (report_id, int(version))


def canonical_payload(payload):
    """Deterministic bytes for a submission dict.

    Sorted keys and no incidental whitespace, so the same submission always
    hashes the same way. `ensure_ascii=False` keeps non-Latin text as UTF-8
    rather than escapes -- an account written in Arabic or Bengali should not
    triple in size on the way to storage.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def seal(report_id, payload, version=1):
    """Encrypt a submission. Returns (blob, content_hash).

    `content_hash` is over the CIPHERTEXT as it will be stored, because that is
    what a later reader can recompute without first being able to decrypt.
    """
    blob = content_keys.encrypt(
        object_id_for(report_id, version),
        canonical_payload(payload),
        secret=_secret(),
    )
    return blob, hashlib.sha256(blob).hexdigest()


def unseal(report_id, blob, version=1, expected_hash=None):
    """Decrypt a stored blob back to the submission dict.

    Two checks happen before any decryption, and both are necessary.

    `expected_hash`, when supplied, catches a substituted object without its
    contents ever being processed -- the caller learns "this is not the object
    we stored" rather than "this decrypted to something unexpected".

    The IDENTITY check is not optional and is easy to get wrong. `content_keys`
    takes the object id out of the blob and uses it as the AEAD's additional
    data, so the tag proves a blob is internally consistent and can never prove
    it is the blob that was asked for. Without comparing the embedded id against
    the expected one, another report's perfectly valid ciphertext decrypts
    happily when fetched under this report's key -- so a node that swapped two
    objects would be serving one complainant's account in place of another's,
    passing every cryptographic check.
    """
    if expected_hash:
        actual = hashlib.sha256(blob).hexdigest()
        if not _constant_time_equal(actual, expected_hash):
            raise ReportCryptoError(
                "content hash mismatch for %s: stored %s, fetched %s -- the "
                "object served is not the object recorded"
                % (report_id, expected_hash, actual)
            )

    want = object_id_for(report_id, version)
    try:
        got = content_keys.object_id_of(blob)
    except Exception as exc:
        raise ReportCryptoError("unreadable report blob for %s: %s" % (report_id, exc))
    if not _constant_time_equal(got, want):
        raise ReportCryptoError(
            "object identity mismatch: asked for %s, blob is sealed for %s"
            % (want, got)
        )

    plaintext = content_keys.decrypt(blob, secret=_secret())
    return json.loads(plaintext.decode("utf-8"))


def _constant_time_equal(a, b):
    import hmac as _hmac
    return _hmac.compare_digest(str(a), str(b))


def seal_bytes(object_id, raw):
    """Encrypt arbitrary bytes under an explicit object id. Returns (blob, hash).

    For evidence files, where the plaintext is not a JSON payload and must not
    be treated as one -- a 500 MB video does not round-trip through
    canonical_payload, and forcing it to would base64 it into memory twice.

    The caller supplies the object id, which is how three artefacts of the same
    attachment stay distinguishable: the AEAD binds the ciphertext to that id, so
    an original cannot be served in place of a scrubbed copy even though both
    belong to the same file. Ids look like `<report-id>/e<n>/<variant>`.
    """
    blob = content_keys.encrypt(object_id, raw, secret=_secret())
    return blob, hashlib.sha256(blob).hexdigest()


def unseal_bytes(object_id, blob, expected_hash=None):
    """Decrypt bytes sealed by `seal_bytes`.

    Same two checks as `unseal`, and for the same reasons: the hash catches a
    substituted object before its contents are processed, and the embedded id is
    compared against the expected one because `content_keys` takes the id FROM
    the blob and can therefore only prove self-consistency, never that this is
    the object that was asked for.
    """
    if expected_hash:
        actual = hashlib.sha256(blob).hexdigest()
        if not _constant_time_equal(actual, expected_hash):
            raise ReportCryptoError(
                "content hash mismatch for %s -- the object served is not the "
                "object recorded" % object_id)

    try:
        got = content_keys.object_id_of(blob)
    except Exception as exc:
        raise ReportCryptoError("unreadable blob for %s: %s" % (object_id, exc))
    if not _constant_time_equal(got, object_id):
        raise ReportCryptoError(
            "object identity mismatch: asked for %s, blob is sealed for %s"
            % (object_id, got))

    return content_keys.decrypt(blob, secret=_secret())
