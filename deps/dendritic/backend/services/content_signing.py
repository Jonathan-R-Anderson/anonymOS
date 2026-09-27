"""Origin signatures: proving bytes came from syndichan, not from a gateway.

A volunteer gateway is transport. Whether the bytes it hands a reader are the
bytes this server published is a question mathematics answers — so this module
signs content here, at the origin, and gateways never hold the key.

WHAT IS SIGNED, AND WHY IT IS NOT A "RELEASE"
---------------------------------------------
The obvious design is the one every static site uses: a build emits a manifest
of every file, the origin signs the Merkle root, clients verify against it.
That works for CSS and JavaScript and it is used for exactly those here.

It does not work for a thread. /thread/123 changes the moment somebody replies,
so a manifest covering "the site" would be invalid before it finished being
written, and signing a release per post means re-signing the world every few
seconds. So dynamic objects are signed INDIVIDUALLY:

    signature = Ed25519( "syndichan-object:v1" || key || version || sha256(body) )

The version is what makes this worth anything. Without it, a gateway that kept
an old signed copy could serve it forever and every signature would still
verify — "stale but authentic" is a real attack, and monotonicity is the only
thing that stops it. Clients remember the highest version they have seen for a
key and refuse anything lower.

THE KEY
-------
Ed25519, to match node identities and PoF receipts: one signature scheme in the
system rather than three. The private key lives in configuration
(ORIGIN_SIGNING_KEY) and is never written to the database, never sent to a
gateway, and never logged.

It is deliberately NOT the deploy key. If whatever can deploy can also sign,
then a signature proves only that an attacker used the build system, which is
the property this whole mechanism is supposed to provide.

When no key is configured every function here degrades to "unsigned" rather
than raising. An origin that cannot sign should still serve — the failure mode
is content nobody can verify, which is where the site is today, not an outage.
"""

import base64
import hashlib

from shared import app

# Domain separator. A signature over a thread body must not be replayable as a
# signature over anything else, and prefixing the purpose is the cheapest way
# to guarantee that.
OBJECT_PREFIX = b"syndichan-object:v1"
MANIFEST_PREFIX = b"syndichan-manifest:v1"

CONFIG_PRIVATE = "ORIGIN_SIGNING_KEY"
CONFIG_PUBLIC = "ORIGIN_PUBLIC_KEY"


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(str(text or "").strip() + "=" * (-len(str(text or "").strip()) % 4))


def sha256_hex(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def _signing_key():
    """The private key, or None. Never returned to a caller outside this module."""
    raw = (app.config.get(CONFIG_PRIVATE) or "").strip()
    if not raw:
        return None
    try:
        from nacl.signing import SigningKey

        seed = _unb64(raw)
        if len(seed) == 64:
            # A 64-byte value is the libsodium secret key (seed + public half).
            seed = seed[:32]
        if len(seed) != 32:
            app.logger.error("ORIGIN_SIGNING_KEY is not a 32-byte ed25519 seed; "
                             "content will be served unsigned")
            return None
        return SigningKey(seed)
    except Exception:
        app.logger.exception("ORIGIN_SIGNING_KEY could not be loaded")
        return None


def enabled():
    return _signing_key() is not None


def public_key_b64():
    """The public key clients pin, base64. None when signing is off.

    Derived from the private key rather than configured separately: two
    independently-set halves can disagree, and a public key that does not match
    the signer is indistinguishable from an attack.
    """
    key = _signing_key()
    if key is None:
        configured = (app.config.get(CONFIG_PUBLIC) or "").strip()
        return configured or None
    return _b64(bytes(key.verify_key))


def object_message(key, version, body_hash):
    """Exactly the bytes signed for one object. Clients rebuild this."""
    return b"\n".join([
        OBJECT_PREFIX,
        str(key).encode("utf-8"),
        str(int(version)).encode("ascii"),
        str(body_hash).encode("ascii"),
    ])


def sign_object(key, version, body):
    """Sign one addressable object.

    Returns {hash, version, signature} or None when signing is disabled — the
    caller serves the content either way, so this must never raise on a request
    path.
    """
    signer = _signing_key()
    if signer is None:
        return None
    body_hash = sha256_hex(body)
    try:
        signature = signer.sign(object_message(key, version, body_hash)).signature
    except Exception:
        app.logger.exception("could not sign object %s", key)
        return None
    return {"hash": body_hash, "version": int(version), "signature": _b64(signature)}


def verify_object(key, version, body, signature_b64, public_b64=None):
    """Verify a signature the way a client would.

    Present here so the server can check its own output in tests, and so there
    is one implementation of the rule rather than one per language that drifts.
    """
    public = public_b64 or public_key_b64()
    if not public or not signature_b64:
        return False
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        VerifyKey(_unb64(public)).verify(
            object_message(key, version, sha256_hex(body)), _unb64(signature_b64))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
    except Exception:
        app.logger.exception("verification failed for %s", key)
        return False


# ----------------------------------------------------------------- merkle tree

def merkle_root(leaf_hashes):
    """Root over ordered leaves, as hex.

    Duplicating the last node on an odd level is the well-known CVE-2012-2459
    shape in Bitcoin, where two different trees produce one root. Here the leaf
    ORDER and COUNT are fixed by a signed manifest that lists them, so a
    second preimage would have to change the manifest too — and the manifest is
    what is signed. Documented rather than worked around, because a reader who
    recognises the pattern deserves to know it was considered.
    """
    if not leaf_hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(leaf_hashes, index):
    """The sibling path proving leaf `index` belongs to the root.

    Each step is {hash, side}; `side` says whether the sibling goes on the left
    or the right, because a client that guesses will verify half the time and
    that is worse than failing.
    """
    if index < 0 or index >= len(leaf_hashes):
        return []
    level = [bytes.fromhex(h) for h in leaf_hashes]
    path = []
    position = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        pair = position ^ 1
        path.append({"hash": level[pair].hex(),
                     "side": "right" if pair > position else "left"})
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
        position //= 2
    return path


def verify_merkle(leaf_hash, path, root):
    current = bytes.fromhex(leaf_hash)
    for step in path or []:
        sibling = bytes.fromhex(step["hash"])
        current = (hashlib.sha256(sibling + current).digest()
                   if step.get("side") == "left"
                   else hashlib.sha256(current + sibling).digest())
    return current.hex() == root


def sign_manifest(root, released_at, count):
    """Sign a static release. Only the root is signed; per-file proofs come
    from the tree, which is why a release of ten thousand files costs one
    signature rather than ten thousand."""
    signer = _signing_key()
    if signer is None:
        return None
    message = b"\n".join([
        MANIFEST_PREFIX,
        str(root).encode("ascii"),
        str(int(released_at)).encode("ascii"),
        str(int(count)).encode("ascii"),
    ])
    try:
        return _b64(signer.sign(message).signature)
    except Exception:
        app.logger.exception("could not sign manifest %s", root)
        return None


def generate_key():
    """A fresh keypair, for an operator setting this up. Returns (seed_b64,
    public_b64). Deliberately not called anywhere at runtime: a key that
    regenerates itself invalidates every signature that came before it."""
    from nacl.signing import SigningKey

    key = SigningKey.generate()
    return _b64(bytes(key)), _b64(bytes(key.verify_key))
