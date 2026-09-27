"""Turn a gateway's advertised name into a key that can be checked.

An audit receipt names the gateway it is about. If that name is only a string,
the record fills with gateways nobody ever ran: anyone can POST a thousand
invented names and "gateways seen" becomes fiction that later corroboration has
to wade through.

It does not have to be a string. The controller accepts a registration only when
the peer ID matches the Ed25519 key that signed it (see
``gateway-controller/backend/security.py``), so a peer ID *is* a public key in
another encoding. Ed25519 keys are short enough that libp2p embeds them in the
peer ID rather than hashing them, which is the reason this direction works at
all: the key can be read back out.

That gives three questions, deliberately kept apart:

    is this a well-formed identity?  ->  decodes to an Ed25519 key   (certain)
    is it a gateway that registered? ->  ask the controller          (current)
    did it serve honest bytes?       ->  audit receipts              (statistical)

The first is answered here, the second in ``services/gateway_registry.py``, the
third by the audit table. Neither of the first two implies the third, and the
value of separating them is that a forged name never reaches the stage where
somebody has to judge its behaviour.

WHY THIS BINDS AUDITS TO REPUTATION
-----------------------------------
A node signs its PoF registration with the same ``p2p.key`` it uses as its
libp2p identity (``internal/facilitation/register.go`` hex-encodes exactly the
key ``internal/gateway/identity.go`` loads). So a peer ID converted to hex is
the ``p2p_public_key`` that ``services/reputation.py`` already scores. One
operator, one key, one record — rather than a translation table that can
disagree with itself about who somebody is.
"""

# Bitcoin alphabet: no 0, O, I or l, because those are the pairs a human
# transcribing a key gets wrong.
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: value for value, char in enumerate(ALPHABET)}

# libp2p PublicKey protobuf: field 1 = Ed25519 key type, field 2 = 32 raw bytes.
_PROTOBUF_PREFIX = b"\x08\x01\x12\x20"
# Identity multihash: code 0x00, then length 0x24 (36 bytes of protobuf). Codec
# 0x00 means "the digest is the value itself", which is why an Ed25519 peer ID
# is reversible and an RSA one is not.
_IDENTITY_MULTIHASH = b"\x00\x24"
_EXPECTED_LENGTH = len(_IDENTITY_MULTIHASH) + 36

# The origin serving its own content is not a gateway and has no peer ID. It is
# named rather than left blank so an observation always has a subject.
ORIGIN = "origin"


def b58decode(text):
    """Base58 (Bitcoin alphabet). Returns None on anything malformed.

    None rather than an exception because every caller here is handling
    attacker-supplied input, and a decoder that raises turns "somebody sent
    junk" into a 500.
    """
    if not text:
        return None
    number = 0
    for char in text:
        value = _INDEX.get(char)
        if value is None:
            return None
        number = number * 58 + value
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    # Leading '1's encode leading zero bytes, which the integer cannot carry.
    padding = len(text) - len(text.lstrip("1"))
    return b"\x00" * padding + body


def ed25519_key(identity):
    """The 32-byte public key inside a peer ID, or None if it is not one."""
    raw = b58decode(str(identity or "").strip())
    if raw is None or len(raw) != _EXPECTED_LENGTH:
        return None
    if not raw.startswith(_IDENTITY_MULTIHASH + _PROTOBUF_PREFIX):
        return None
    return raw[len(_IDENTITY_MULTIHASH) + len(_PROTOBUF_PREFIX):]


def node_key_hex(identity):
    """The peer ID as the hex key PoF registration and reputation already use.

    This is the whole point of the module: it is the same key, so an audit and a
    storage receipt land on the same node instead of on two records that happen
    to describe one machine.
    """
    key = ed25519_key(identity)
    return key.hex() if key else None


def is_identity(value):
    """True for a real peer ID, or for the origin naming itself."""
    text = normalize(value)
    return text == ORIGIN or ed25519_key(text) is not None


def normalize(value):
    """Trim whitespace. Deliberately does NOT change case.

    Base58 is case-sensitive — ``12D3KooW…`` and ``12d3koow…`` are different
    strings and only one of them decodes. Lower-casing an identity destroys it
    rather than normalising it, so the only thing folded here is the one literal
    name that is not a key.
    """
    text = str(value or "").strip()
    return ORIGIN if text.lower() == ORIGIN else text


def short(identity):
    """A form fit for a log line or a table cell, without pretending to be one."""
    text = normalize(identity)
    return text if len(text) <= 16 else text[:16] + "…"
