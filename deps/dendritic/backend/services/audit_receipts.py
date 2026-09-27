"""Signing and weighing audit receipts.

An audit receipt is a claim about somebody else's machine, sent to an open
endpoint. Two questions follow, and conflating them is the mistake this module
exists to prevent:

    who SENT this?          ->  a signature over a canonical message  (checkable)
    whose word is it WORTH? ->  whether that key is a registered node (policy)

The first is cryptography and is answered here. The second is policy and is
answered here too, but separately and conservatively: a signature proves a
report was not forged in someone else's name. It proves nothing about whether
that someone should be believed.

WHY A BROWSER SIGNATURE IS WORTH LITTLE, AND WHY IT IS STILL WORTH HAVING
------------------------------------------------------------------------
A browser can generate a thousand keys as easily as one, so signing buys no
sybil resistance from readers. What it does buy:

  * a report cannot be filed in another observer's name, so one observer's
    record cannot be poisoned by someone else;
  * an observer is provably the same across reports, which is what makes
    "distinct observers" mean anything at all.

A VALIDATOR signature is different in kind. It is made with a node's persistent
Ed25519 identity -- the same key that registered with the controller and carries
a reputation -- so it is attributable to an operator with something to lose.
That is why only validator receipts are eligible for quorum, and why claiming
`observer_kind="validator"` without a signature from a registered node key is
demoted rather than believed.
"""

import base64
import hashlib

RECEIPT_PREFIX = b"syndichan-audit:v1"

KIND_CLIENT = "client"
KIND_VALIDATOR = "validator"


def receipt_message(gateway, object_key, version, object_hash, result):
    """The exact bytes an observer signs.

    Every field that gives the report meaning is covered. Leaving any of them
    out would let a signature be lifted from one observation and replayed onto
    another -- a genuine "pass" for one object becoming a forged "mismatch"
    for a different one, in the same observer's name.
    """
    return b"\n".join([
        RECEIPT_PREFIX,
        str(gateway or "").encode("utf-8"),
        str(object_key or "").encode("utf-8"),
        str(int(version or 0)).encode("ascii"),
        str(object_hash or "").encode("ascii"),
        str(result or "").encode("ascii"),
    ])


def _decode(value):
    """Base64, tolerant of missing padding and of the URL-safe alphabet."""
    text = str(value or "").strip().replace("-", "+").replace("_", "/")
    if not text:
        return None
    try:
        return base64.b64decode(text + "===")
    except Exception:
        return None


# libp2p PublicKey protobuf: field 1 = Ed25519, field 2 = the 32 raw bytes.
_PROTOBUF_PREFIX = b"\x08\x01\x12\x20"


def _public_key(value):
    """The raw 32-byte Ed25519 key, whichever encoding arrived.

    Both forms genuinely circulate in this system: a node's /gateway/identity
    publishes the protobuf-wrapped key, while registration stores the raw one as
    hex. Accepting only one would reject honest receipts from whichever half of
    the codebase was not consulted, and the failure would look like a bad
    signature rather than an encoding mismatch.
    """
    raw = _decode(value)
    if raw is None:
        return None
    if len(raw) == 36 and raw.startswith(_PROTOBUF_PREFIX):
        return raw[len(_PROTOBUF_PREFIX):]
    return raw if len(raw) == 32 else None


def verify_signature(public_key_b64, signature_b64, message):
    """True when this key really signed this message. Never raises."""
    key = _public_key(public_key_b64)
    signature = _decode(signature_b64)
    if not key or not signature or len(signature) != 64:
        return False
    try:
        from nacl.signing import VerifyKey

        VerifyKey(key).verify(message, signature)
        return True
    except Exception:
        return False


def observer_id(public_key_b64):
    """A stable, short identifier derived FROM the key.

    Derived rather than self-chosen so a signed report's identity cannot be
    anything other than the key that signed it. A self-declared id next to a
    signature would let one key file reports under many names, and "distinct
    observers" -- the only number here that resists a single loud source --
    would stop meaning anything.
    """
    key = _public_key(public_key_b64)
    if not key:
        return ""
    return hashlib.sha256(key).hexdigest()[:32]


def classify(claimed_kind, public_key_b64, signature_b64, message,
             registered_node_keys=None):
    """Decide what a report actually is: ``(kind, observer, verified)``.

    A claim of "validator" is only honoured when the signature verifies AND the
    signing key belongs to a node the network has registered. Anything else is
    demoted to a client report rather than refused, because a demoted report is
    still an observation, while a refused one is evidence thrown away.
    """
    verified = bool(public_key_b64) and verify_signature(
        public_key_b64, signature_b64, message)
    if not verified:
        return KIND_CLIENT, "", False

    identity = observer_id(public_key_b64)
    if claimed_kind == KIND_VALIDATOR:
        known = registered_node_keys or set()
        # The node's registered identity is its raw Ed25519 key in hex; the
        # receipt carries the same key base64-encoded. One key, two encodings.
        raw = _public_key(public_key_b64)
        if raw and raw.hex() in known:
            return KIND_VALIDATOR, identity, True
        # Signed, but by a key nobody has registered. Worth keeping as an
        # observation; not worth the weight a validator carries.
        return KIND_CLIENT, identity, True
    return KIND_CLIENT, identity, True
