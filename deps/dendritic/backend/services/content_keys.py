"""Coordinator-rooted content encryption (Bitcoin-style BIP32 master key).

The server holds ONE master secret (`STORAGE_CONTENT_MASTER_SECRET`). From it we
derive, exactly the way a Bitcoin wallet does, a **hardened** child keypair per
object (secp256k1, BIP32 CKDpriv). Because the derivation is deterministic from
the master, the server can reproduce any object's key and therefore unlock any
content it has ever stored -- ultimate control. Because the children are
*hardened*, handing one child's material to a worker never exposes the master or
any sibling -- access control.

Storage nodes only ever hold the ciphertext this module produces; they cannot
read it. An object is:

    K            = random 32-byte content key
    ciphertext   = AES-256-GCM(K, plaintext)
    K is ECIES-wrapped to the object's child public key Q_i:
        e        = ephemeral secp256k1 key,  R = e*G
        S        = ECDH(e, Q_i)
        kek      = HKDF-SHA256(S)
        wrappedK = AES-256-GCM(kek, K)

so the on-disk blob carries {object_id, R, wrappedK, content ciphertext} and
nothing else. The server recovers K with the child PRIVATE key d_i
(S = ECDH(d_i, R)); to let a specific worker run one lab it re-seals K to that
worker's Curve25519 "content key" with a libsodium sealed box (PyNaCl), which the
Go worker opens with `nacl/box.OpenAnonymous`.

This module is deliberately self-contained and side-effect free so it can be unit
tested without a database or network.
"""

import base64
import hashlib
import hmac
import os

import nacl.public
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# secp256k1 group order.
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_CURVE = ec.SECP256K1()
_HARDENED = 0x80000000
# A fixed purpose level so this hierarchy never collides with any other use of
# the same master. 'S' for Syndichan.
_PURPOSE = 0x53
_ECIES_INFO = b"syndichan-content-ecies-v1"
_MAGIC = b"SCE1"  # Syndichan Content Encryption, format 1
_ENV = "STORAGE_CONTENT_MASTER_SECRET"

# Parsed master cached by the exact secret string it came from, so a rotated
# secret is picked up without a restart and tests can set the env freely.
_cache = {}


class ContentKeyError(Exception):
    """Raised when the content master is missing or a blob is malformed."""


def _decode_secret(value):
    value = (value or "").strip()
    if not value:
        raise ContentKeyError("%s is not configured" % _ENV)
    # Even-length all-hex -> raw seed bytes; otherwise base64 (padded or not).
    if len(value) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in value):
        return bytes.fromhex(value)
    return base64.b64decode(value + "=" * (-len(value) % 4))


def _master(secret=None):
    """(k, chain_code) for a master seed, or raise if unset.

    `secret` lets a caller root a SEPARATE key tree from the same
    implementation -- civil-rights reports do this so that the key which reads
    every stored media object is not also the key which reads a complainant's
    name and address. Passing None keeps the historical behaviour of reading
    STORAGE_CONTENT_MASTER_SECRET, so every existing caller is unaffected.

    There is deliberately no fallback the other way: a caller that passes an
    empty secret gets an error, not the storage master. A fallback would
    silently undo the separation at exactly the moment somebody was in a hurry,
    and the resulting deployment would look identical to a correct one.
    """
    if secret is None:
        secret = os.getenv(_ENV) or ""
    cached = _cache.get(secret)
    if cached is not None:
        return cached
    seed = _decode_secret(secret)
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(digest[:32], "big")
    chain_code = digest[32:]
    if k == 0 or k >= _N:
        raise ContentKeyError("invalid content master seed")
    result = (k, chain_code)
    _cache[secret] = result
    return result


def enabled(secret=None):
    if secret is None:
        secret = os.getenv(_ENV) or ""
    return bool((secret or "").strip())


def generate_master_secret():
    """A fresh 32-byte master seed as hex -- for `STORAGE_CONTENT_MASTER_SECRET`."""
    return os.urandom(32).hex()


def _ckd_priv(k_par, c_par, index):
    """BIP32 hardened child key derivation (secp256k1). index must be hardened."""
    if index < _HARDENED:
        raise ContentKeyError("only hardened derivation is used")
    data = b"\x00" + k_par.to_bytes(32, "big") + index.to_bytes(4, "big")
    digest = hmac.new(c_par, data, hashlib.sha512).digest()
    il = int.from_bytes(digest[:32], "big")
    if il >= _N:
        # ~2^-127; BIP32 says skip to the next index. Not worth the branch for
        # our label-derived indices -- surface it instead of silently diverging.
        raise ContentKeyError("degenerate child key; pick another object id")
    k_child = (il + k_par) % _N
    if k_child == 0:
        raise ContentKeyError("degenerate child key; pick another object id")
    return k_child, digest[32:]


def _path_for(object_id):
    """A hardened BIP32 path derived from the object id: m/purpose'/i0'/../i3'.

    Four 31-bit hardened levels are taken from SHA-256(object_id) -- 124 bits, so
    collisions between distinct objects are cryptographically negligible.
    """
    digest = hashlib.sha256(object_id.encode("utf-8")).digest()
    path = [_PURPOSE | _HARDENED]
    for j in range(4):
        chunk = int.from_bytes(digest[j * 4:(j + 1) * 4], "big") & 0x7FFFFFFF
        path.append(chunk | _HARDENED)
    return path


def _child_scalar(object_id, secret=None):
    k, chain_code = _master(secret)
    for index in _path_for(object_id):
        k, chain_code = _ckd_priv(k, chain_code, index)
    return k


def _child_private_key(object_id, secret=None):
    return ec.derive_private_key(_child_scalar(object_id, secret), _CURVE)


def _hkdf(shared):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=_ECIES_INFO
    ).derive(shared)


def encrypt(object_id, plaintext, secret=None):
    """Encrypt `plaintext` for `object_id`. Returns the opaque storage blob.

    ECIES-wraps a fresh content key to the object's child public key, so only the
    master (server) -- or a worker the server explicitly grants -- can recover it.

    `secret` selects the key tree; see `_master`.
    """
    child_pub = _child_private_key(object_id, secret).public_key()
    ephemeral = ec.generate_private_key(_CURVE)
    r = ephemeral.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    shared = ephemeral.exchange(ec.ECDH(), child_pub)
    kek = _hkdf(shared)

    content_key = os.urandom(32)
    aad = object_id.encode("utf-8")
    wrap_nonce = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(wrap_nonce, content_key, aad)
    content_nonce = os.urandom(12)
    ciphertext = AESGCM(content_key).encrypt(content_nonce, plaintext, aad)
    return _pack(object_id, r, wrap_nonce, wrapped, content_nonce, ciphertext)


def is_encrypted_blob(blob):
    """True if `blob` is one of our content-encryption blobs (starts with SCE1)."""
    return bool(blob) and bytes(memoryview(blob)[:4]) == _MAGIC


def object_id_of(blob):
    """The object id a blob was sealed for, without decrypting it.

    `decrypt` takes the id FROM the blob and uses it as the AEAD's additional
    data, so the tag can only ever confirm the blob is self-consistent -- it can
    never tell a caller "this is not the object you asked for". A caller that
    fetched a blob by name and needs to know it got the right one has to compare
    the embedded id against the name it asked for, and this is how.
    """
    return _unpack(blob)[0]


def recover_key(blob, secret=None):
    """The raw 32-byte content key for a blob (server only; holds the master).

    Used to grant a worker access to one object. The caller must protect it: it
    is the plaintext key, and anything that gets it can decrypt that object."""
    return _recover_key(blob, secret)


def _recover_key(blob, secret=None):
    """Recover the content key K from a blob using the master (server only)."""
    object_id, r, wrap_nonce, wrapped, _content_nonce, _ct = _unpack(blob)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, r)
    shared = _child_private_key(object_id, secret).exchange(ec.ECDH(), peer)
    kek = _hkdf(shared)
    return AESGCM(kek).decrypt(wrap_nonce, wrapped, object_id.encode("utf-8"))


def decrypt(blob, secret=None):
    """Decrypt a storage blob back to plaintext (server, holds the master)."""
    object_id, r, wrap_nonce, wrapped, content_nonce, ct = _unpack(blob)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, r)
    shared = _child_private_key(object_id, secret).exchange(ec.ECDH(), peer)
    kek = _hkdf(shared)
    aad = object_id.encode("utf-8")
    content_key = AESGCM(kek).decrypt(wrap_nonce, wrapped, aad)
    return AESGCM(content_key).decrypt(content_nonce, ct, aad)


def seal_for_worker(blob, worker_content_pubkey):
    """Re-seal a blob's content key to a worker's Curve25519 content key.

    `worker_content_pubkey` is the raw 32-byte X25519 key the worker advertises
    in its DHT WorkerRecord. Returns a base64 libsodium sealed box the Go worker
    opens with nacl/box.OpenAnonymous. Only the master can produce this, and only
    the named worker can open it -- that is the access-control grant.
    """
    if isinstance(worker_content_pubkey, str):
        worker_content_pubkey = base64.b64decode(
            worker_content_pubkey + "=" * (-len(worker_content_pubkey) % 4)
        )
    if len(worker_content_pubkey) != 32:
        raise ContentKeyError("worker content key must be 32 bytes")
    content_key = _recover_key(blob)
    sealed = nacl.public.SealedBox(nacl.public.PublicKey(worker_content_pubkey)).encrypt(
        content_key
    )
    return base64.b64encode(sealed).decode("ascii")


def _pack(object_id, r, wrap_nonce, wrapped, content_nonce, ciphertext):
    oid = object_id.encode("utf-8")
    if len(oid) > 0xFFFF or len(wrapped) > 0xFFFF:
        raise ContentKeyError("object id or wrapped key too large")
    return b"".join([
        _MAGIC,
        len(oid).to_bytes(2, "big"), oid,
        r,                                    # 33-byte compressed ephemeral point
        wrap_nonce,                           # 12
        len(wrapped).to_bytes(2, "big"), wrapped,
        content_nonce,                        # 12
        ciphertext,                           # remainder
    ])


def _unpack(blob):
    try:
        view = memoryview(blob)
        if bytes(view[:4]) != _MAGIC:
            raise ContentKeyError("not a content blob")
        pos = 4
        oid_len = int.from_bytes(view[pos:pos + 2], "big"); pos += 2
        object_id = bytes(view[pos:pos + oid_len]).decode("utf-8"); pos += oid_len
        r = bytes(view[pos:pos + 33]); pos += 33
        wrap_nonce = bytes(view[pos:pos + 12]); pos += 12
        wrapped_len = int.from_bytes(view[pos:pos + 2], "big"); pos += 2
        wrapped = bytes(view[pos:pos + wrapped_len]); pos += wrapped_len
        content_nonce = bytes(view[pos:pos + 12]); pos += 12
        ciphertext = bytes(view[pos:])
    except ContentKeyError:
        raise
    except Exception as exc:
        raise ContentKeyError("malformed content blob") from exc
    if len(r) != 33 or len(wrap_nonce) != 12 or len(content_nonce) != 12:
        raise ContentKeyError("truncated content blob")
    return object_id, r, wrap_nonce, wrapped, content_nonce, ciphertext
