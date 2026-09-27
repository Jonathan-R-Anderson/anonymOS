"""The key that signs emergency snapshots — deliberately not the origin key.

WHY A SECOND KEY
----------------
The origin signing key signs live responses, one at a time, inside a request.
This one signs a whole frozen copy of the public site, produced by a process
that crawls every eligible page and runs for minutes at a stretch.

Those are very different exposures. The snapshot publisher touches far more of
the system, runs unattended, and is the kind of thing that ends up on a build
host. If it held the origin key, compromising the least-guarded component would
yield the ability to sign LIVE responses — and a signature that proves only "an
attacker reached the build box" is worth nothing.

So: separate key, separate blast radius. A stolen publisher key can forge an
emergency snapshot, which is bad and bounded — readers see the snapshot banner,
the sequence is visible, and a revocation can pull it. It cannot forge the
page somebody is reading right now.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It does not fall back to the origin key when unset. A fallback would quietly
undo the separation above at exactly the moment somebody was in a hurry, and the
resulting deployment would look identical to a correct one.

No key configured means snapshots are built but unsigned, and an unsigned
snapshot is one no client will serve. That is the safe direction: a snapshot
nobody trusts is useless, while a snapshot signed by the wrong key is dangerous.
"""

import base64

from shared import app

# Domain separator. A snapshot manifest signature must never verify as anything
# else, and must never be produced by replaying an origin-object signature.
SNAPSHOT_PREFIX = b"syndichan-snapshot:v1"

CONFIG_PRIVATE = "SNAPSHOT_SIGNING_KEY"
CONFIG_PUBLIC = "SNAPSHOT_PUBLIC_KEY"


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(str(text or "").strip() + "===")


def _signing_key():
    """The private key, or None. Never leaves this module."""
    raw = (app.config.get(CONFIG_PRIVATE) or "").strip()
    if not raw:
        return None
    try:
        from nacl.signing import SigningKey

        seed = _unb64(raw)
        if len(seed) == 64:
            # libsodium secret keys carry the public half; the seed is the first
            # 32 bytes.
            seed = seed[:32]
        if len(seed) != 32:
            app.logger.error(
                "SNAPSHOT_SIGNING_KEY is not a 32-byte ed25519 seed; snapshots "
                "will be built unsigned and no client will serve them")
            return None
        return SigningKey(seed)
    except Exception:
        app.logger.exception("SNAPSHOT_SIGNING_KEY could not be loaded")
        return None


def enabled():
    return _signing_key() is not None


def public_key_b64():
    """The key clients pin for snapshots. Derived from the private half.

    Derived rather than configured separately for the same reason the origin key
    is: two independently-set halves can disagree, and a public key that does not
    match its signer is indistinguishable from an attack.
    """
    key = _signing_key()
    if key is None:
        return (app.config.get(CONFIG_PUBLIC) or "").strip() or None
    return _b64(bytes(key.verify_key))


def manifest_message(snapshot_id, sequence, root, created_at, expires_at, count):
    """Exactly the bytes signed for a snapshot manifest. Clients rebuild this.

    Every field that changes what the snapshot MEANS is covered:

      * `sequence`, or a valid old manifest could be replayed over a newer one;
      * `expires_at`, or an expired snapshot could be served forever;
      * `root`, which commits to every object;
      * `count`, so entries cannot be dropped from a manifest whose root still
        verifies for the ones that remain.
    """
    return b"\n".join([
        SNAPSHOT_PREFIX,
        str(snapshot_id or "").encode("ascii"),
        str(int(sequence or 0)).encode("ascii"),
        str(root or "").encode("ascii"),
        str(int(created_at or 0)).encode("ascii"),
        str(int(expires_at or 0)).encode("ascii"),
        str(int(count or 0)).encode("ascii"),
    ])


def sign_manifest(snapshot_id, sequence, root, created_at, expires_at, count):
    """Sign one snapshot. None when no publisher key is configured."""
    signer = _signing_key()
    if signer is None:
        return None
    message = manifest_message(snapshot_id, sequence, root, created_at,
                               expires_at, count)
    try:
        return _b64(signer.sign(message).signature)
    except Exception:
        app.logger.exception("could not sign snapshot %s", snapshot_id)
        return None


def verify_manifest(snapshot_id, sequence, root, created_at, expires_at, count,
                    signature_b64, public_b64=None):
    """Check a snapshot signature. Used by tests and by any in-process reader."""
    public = public_b64 or public_key_b64()
    if not public or not signature_b64:
        return False
    try:
        from nacl.signing import VerifyKey

        message = manifest_message(snapshot_id, sequence, root, created_at,
                                   expires_at, count)
        VerifyKey(_unb64(public)).verify(message, _unb64(signature_b64))
        return True
    except Exception:
        return False


def generate_key():
    """A fresh publisher keypair, for an operator setting this up.

    Deliberately not called at runtime: a key that regenerates itself invalidates
    every snapshot signed before it, which during an outage means no gateway can
    serve anything.
    """
    from nacl.signing import SigningKey

    key = SigningKey.generate()
    return _b64(bytes(key)), _b64(bytes(key.verify_key))
