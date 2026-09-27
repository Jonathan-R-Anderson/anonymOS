package channel

// Keys, and what signs what.
//
// THE DECISION THIS FILE MAKES
// ----------------------------
// A routing node must sign UNATTENDED. Forwarding payments while its operator
// sleeps is the entire job, so there is a hot key on the machine and no amount
// of hardware-wallet discipline changes that. What can be changed is HOW MUCH
// that key is worth stealing.
//
// So the channel key is DERIVED from the node's seed under its own domain, and
// is deliberately not the payout key. One leaked hot key then costs what is
// committed to open channels — bounded by RouterConfig.TotalCommittedMax — and
// not the address the operator's earnings accumulate in. Deriving both from one
// secret, or worse using one key for both, collapses that distinction and makes
// a routing compromise a total one.
//
// WHY THE ENCODING IS CANONICAL AND LENGTH-PREFIXED
// -------------------------------------------------
// A balance proof is a signature over channel state. If two different states
// can produce the same signed bytes, one signature authorises both — and a
// counterparty picks whichever suits them. Concatenating fields without lengths
// is exactly how that happens: channel "ab" nonce 1 and channel "a" nonce "b1"
// serialise identically. Every field here is length-prefixed for that reason,
// not for tidiness.

import (
	"errors"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	domainChannelKey   = "syndichan/channel/signing-key/v1"
	domainBalanceProof = "syndichan/channel/balance-proof/v1"
)

var (
	ErrNotSigned    = errors.New("channel: balance proof carries no signature")
	ErrBadSignature = errors.New("channel: balance proof signature does not verify")
	ErrNoKey        = errors.New("channel: no channel signing key")
)

// Key is the node's channel-signing identity.
type Key struct {
	priv *secp256k1.PrivateKey
}

// DeriveKey produces the channel key from the node's seed.
//
// Domain-separated, so this key cannot be recovered from the payout key or vice
// versa even though both descend from the same seed. That separation is the
// whole point: see the file comment.
func DeriveKey(nodeSeed [32]byte) *Key {
	material := derive(domainChannelKey, nodeSeed[:])
	return &Key{priv: secp256k1.PrivKeyFromBytes(material[:])}
}

// PublicKey is what a counterparty verifies against, compressed.
func (k *Key) PublicKey() []byte {
	if k == nil || k.priv == nil {
		return nil
	}
	return k.priv.PubKey().SerializeCompressed()
}

// proofDigest is the canonical bytes a balance proof signs over.
//
// Includes the channel, nonce and BOTH balances. Omitting either balance would
// let a counterparty reuse a signature across states that differ only in the
// direction value moved — which is the state that matters.
func proofDigest(ch ChannelID, nonce uint64, outbound, inbound Amount) [32]byte {
	return derive(domainBalanceProof,
		[]byte(ch),
		uint64Bytes(nonce),
		amountBytes(outbound),
		amountBytes(inbound),
	)
}

// SignBalance produces a counter-signable balance proof.
func (k *Key) SignBalance(ch ChannelID, nonce uint64, outbound, inbound Amount) (BalanceProof, error) {
	if k == nil || k.priv == nil {
		return BalanceProof{}, ErrNoKey
	}
	digest := proofDigest(ch, nonce, outbound, inbound)
	sig := ecdsa.Sign(k.priv, digest[:])
	return BalanceProof{
		Channel:   ch,
		Nonce:     nonce,
		Signature: sig.Serialize(),
	}, nil
}

// VerifyBalance checks a peer's proof against their public key.
//
// The caller supplies the balances it believes the proof covers. That is
// deliberate: a proof that carried its own balances would be verifying itself,
// and a peer could sign a state the local node never agreed to and have it
// check out.
func VerifyBalance(peerPubKey []byte, proof BalanceProof, outbound, inbound Amount) error {
	if len(proof.Signature) == 0 {
		return ErrNotSigned
	}
	pub, err := secp256k1.ParsePubKey(peerPubKey)
	if err != nil {
		return ErrBadSignature
	}
	sig, err := ecdsa.ParseDERSignature(proof.Signature)
	if err != nil {
		return ErrBadSignature
	}
	digest := proofDigest(proof.Channel, proof.Nonce, outbound, inbound)
	if !sig.Verify(digest[:], pub) {
		return ErrBadSignature
	}
	return nil
}

// Signer is what a backend needs from the wallet. An interface so a backend can
// be handed a hardware-backed signer for the on-chain operations while the hot
// key handles balance proofs — the split the roadmap's key table describes.
type Signer interface {
	PublicKey() []byte
	SignBalance(ch ChannelID, nonce uint64, outbound, inbound Amount) (BalanceProof, error)
}

var _ Signer = (*Key)(nil)
