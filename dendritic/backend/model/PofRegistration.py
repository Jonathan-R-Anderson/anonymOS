"""Self-service node registration for Proof-of-Facilitation.

A node POSTs a signed registration; it is queued here and submitted on-chain in
one batched transaction. Nodes do not wait for a human to approve them
individually — the operator's only job is paying gas for the batch, because
somebody has to and no paymaster is deployed.

**Why this endpoint demands an ed25519 proof.** `NodeRegistry.registerWithSig`
recovers the WALLET from its signature, but nothing in it proves the caller
holds the node's p2p private key — and a node's p2p public key is its libp2p
peer id, broadcast to the whole network. Since `p2pKeyUsed` makes registration
first-come-first-served, anyone who sees a peer id could bind it to their own
wallet and collect that node's earnings. Requiring the p2p key to sign the
binding closes that on this path. It does NOT close it on-chain: the contract
remains callable directly. See the note in doc/ and the roadmap.
"""

import datetime

from shared import db

STATUS_PENDING = "pending"
STATUS_SUBMITTED = "submitted"
STATUS_FAILED = "failed"

# What the node signs with its ed25519 p2p key. Versioned so the format can
# change without old signatures silently validating against a new meaning.
PROOF_PREFIX = "syndichan-pof-register:v1"


class PofRegistration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Hex of the raw 32-byte ed25519 public key. This is the identity: node_id
    # is keccak256 of it, which the console computes when submitting (the
    # runtime has no keccak).
    p2p_public_key = db.Column(db.String(64), nullable=False, unique=True, index=True)
    wallet = db.Column(db.String(42), nullable=False)
    capabilities = db.Column(db.BigInteger, nullable=False, default=0)
    endpoint_commitment = db.Column(db.String(66), nullable=False, default="")
    nonce = db.Column(db.BigInteger, nullable=False, default=0)
    # secp256k1 signature over the contract's registrationDigest, verified
    # on-chain by registerWithSig — not here, since the runtime cannot ecrecover.
    sig_v = db.Column(db.Integer, nullable=False, default=0)
    sig_r = db.Column(db.String(66), nullable=False, default="")
    sig_s = db.Column(db.String(66), nullable=False, default="")
    # ed25519 proof that the p2p key consented to this wallet binding.
    p2p_proof = db.Column(db.String(128), nullable=False, default="")

    status = db.Column(db.String(16), nullable=False, default=STATUS_PENDING, index=True)
    tx_hash = db.Column(db.String(80), nullable=True)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    submitted_at = db.Column(db.DateTime, nullable=True)


def proof_message(wallet, capabilities, endpoint_commitment, nonce):
    """The exact bytes the p2p key signs.

    Includes the wallet, so a captured proof cannot be replayed to bind the same
    node to a different payout address — which is the whole attack it exists to
    stop.
    """
    return "\n".join((
        PROOF_PREFIX,
        (wallet or "").lower(),
        str(int(capabilities)),
        (endpoint_commitment or "").lower(),
        str(int(nonce)),
    )).encode("utf-8")


def verify_p2p_proof(p2p_public_key_hex, proof_hex, wallet, capabilities, endpoint_commitment, nonce):
    """True when `proof` is a valid ed25519 signature by that p2p key."""
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:  # pragma: no cover - PyNaCl ships in the image
        return False
    try:
        key = VerifyKey(bytes.fromhex(p2p_public_key_hex))
        key.verify(
            proof_message(wallet, capabilities, endpoint_commitment, nonce),
            bytes.fromhex(proof_hex),
        )
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def pending_registrations(limit=200):
    return (
        db.session.query(PofRegistration)
        .filter(PofRegistration.status == STATUS_PENDING)
        .order_by(PofRegistration.created_at.asc())
        .limit(limit)
        .all()
    )


def registration_for_key(p2p_public_key_hex):
    return (
        db.session.query(PofRegistration)
        .filter(PofRegistration.p2p_public_key == p2p_public_key_hex)
        .one_or_none()
    )


def mark_submitted(record_id, tx_hash):
    record = db.session.query(PofRegistration).filter(PofRegistration.id == record_id).one_or_none()
    if record is None:
        return None
    record.status = STATUS_SUBMITTED
    record.tx_hash = (tx_hash or "")[:80]
    record.submitted_at = datetime.datetime.utcnow()
    record.error = None
    return record


def mark_failed(record_id, message):
    record = db.session.query(PofRegistration).filter(PofRegistration.id == record_id).one_or_none()
    if record is None:
        return None
    # Stays queued rather than being written off: most failures are transient
    # (gas, nonce, an RPC blip) and a node that already signed should not have
    # to notice and sign again.
    record.status = STATUS_PENDING
    record.error = (message or "")[:2000]
    return record


PAYOUT_PREFIX = "syndichan-pof-payout:v1"


class PofPayout(db.Model):
    """Where a node's rewards go, as declared and signed by that node.

    Separate from PofRegistration because the two change on different clocks:
    registration happens once, while an operator may re-point their payout
    address at any time — and must be able to without re-registering.
    """

    id = db.Column(db.Integer, primary_key=True)
    p2p_public_key = db.Column(db.String(64), nullable=False, unique=True, index=True)
    payout = db.Column(db.String(42), nullable=False)
    # Higher wins. Without it, which declaration takes effect would depend on
    # arrival order, which the node cannot control.
    sequence = db.Column(db.BigInteger, nullable=False, default=0)
    signature = db.Column(db.String(128), nullable=False, default="")
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow,
                           onupdate=datetime.datetime.utcnow)


def payout_message(payout, sequence):
    """The exact bytes the node signs. Must match facilitation.PayoutMessage."""
    return "\n".join((
        PAYOUT_PREFIX,
        (payout or "").strip().lower(),
        str(int(sequence)),
    )).encode("utf-8")


def verify_payout_declaration(p2p_public_key_hex, payout, sequence, signature_hex):
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:  # pragma: no cover
        return False
    try:
        VerifyKey(bytes.fromhex(p2p_public_key_hex)).verify(
            payout_message(payout, sequence), bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def payout_for_key(p2p_public_key_hex):
    return (
        db.session.query(PofPayout)
        .filter(PofPayout.p2p_public_key == p2p_public_key_hex)
        .one_or_none()
    )


def all_payouts(limit=2000):
    return db.session.query(PofPayout).limit(limit).all()
