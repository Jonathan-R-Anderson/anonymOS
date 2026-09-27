package aggregator

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

// This is the "verification, not self-report" core: a provider signs a receipt
// for work it did, independently-selected witnesses countersign the same receipt
// hash, and the aggregator only counts a receipt once the provider signature is
// valid and enough distinct witnesses have attested. Node identities are the
// node's Ed25519 p2p key; a node id is keccak256(pubkey), matching NodeRegistry.

func be64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

// CanonicalReceiptHash is the deterministic keccak256 over a receipt's fields in
// a fixed order — exactly what the provider and every witness sign.
func CanonicalReceiptHash(r ServiceReceipt) [32]byte {
	buf := make([]byte, 0, 200)
	buf = append(buf, r.ProviderNodeID[:]...)
	buf = append(buf, r.VerifierNodeID[:]...)
	buf = append(buf, byte(r.ServiceType))
	buf = append(buf, r.JobID[:]...)
	buf = append(buf, r.ChallengeHash[:]...)
	buf = append(buf, r.ResultHash[:]...)
	buf = append(buf, be64(r.Epoch)...)
	buf = append(buf, be64(r.StartedAt)...)
	buf = append(buf, be64(r.CompletedAt)...)
	buf = append(buf, be64(r.Quantity)...)
	buf = append(buf, be32(r.Quality)...)
	buf = append(buf, be64(r.Nonce)...)
	return keccak(buf)
}

// NodeIDOf is keccak256(ed25519 public key) — the on-chain node id.
func NodeIDOf(pub ed25519.PublicKey) [32]byte { return keccak([]byte(pub)) }

// WitnessAttestation is one witness's signature over a receipt hash.
type WitnessAttestation struct {
	Pub ed25519.PublicKey `json:"pub"`
	Sig []byte            `json:"sig"`
}

// SignedReceipt is a receipt plus the provider signature and witness attestations.
// JSON tags mirror the node's facilitation.SignedReceipt exactly. Without them
// a node's upload decodes into an empty struct — no error, just a receipt that
// verifies against nothing and is silently dropped at settlement.
type SignedReceipt struct {
	Receipt     ServiceReceipt       `json:"receipt"`
	ProviderPub ed25519.PublicKey    `json:"provider_pub"`
	ProviderSig []byte               `json:"provider_sig"`
	Witnesses   []WitnessAttestation `json:"witnesses"`
}

// SignReceipt produces a signature over the canonical receipt hash.
func SignReceipt(priv ed25519.PrivateKey, r ServiceReceipt) []byte {
	h := CanonicalReceiptHash(r)
	return ed25519.Sign(priv, h[:])
}

var (
	ErrProviderMismatch   = errors.New("aggregator: provider pubkey does not match ProviderNodeID")
	ErrProviderSig        = errors.New("aggregator: invalid provider signature")
	ErrWitnessSelf        = errors.New("aggregator: provider cannot witness its own receipt")
	ErrWitnessThreshold   = errors.New("aggregator: insufficient valid witnesses")
	ErrWitnessNotSelected = errors.New("aggregator: no attestations from the selected witness set")
)

// ValidateReceipt verifies the provider signature and counts distinct, valid,
// independent witness attestations against minWitnesses. A witness that is the
// provider itself is a hard error (collusion signal); duplicate witness ids are
// counted once.
func ValidateReceipt(sr SignedReceipt, minWitnesses int) error {
	h := CanonicalReceiptHash(sr.Receipt)
	if NodeIDOf(sr.ProviderPub) != sr.Receipt.ProviderNodeID {
		return ErrProviderMismatch
	}
	if !ed25519.Verify(sr.ProviderPub, h[:], sr.ProviderSig) {
		return ErrProviderSig
	}
	seen := make(map[[32]byte]bool)
	valid := 0
	for _, w := range sr.Witnesses {
		id := NodeIDOf(w.Pub)
		if id == sr.Receipt.ProviderNodeID {
			return ErrWitnessSelf
		}
		if seen[id] {
			continue
		}
		if ed25519.Verify(w.Pub, h[:], w.Sig) {
			seen[id] = true
			valid++
		}
	}
	if valid < minWitnesses {
		return ErrWitnessThreshold
	}
	return nil
}

// ValidateAttested is ValidateReceipt with the check that actually matters:
// attestations only count if they come from the witness set the protocol DREW
// for this claim. Counting any signature (ValidateReceipt) lets a provider bring
// its own friends, which makes attestation self-reported and worthless — see
// SelectWitnesses. Callers derive `selected` from the epoch randomness with
// SelectWitnesses and pass the m-of-n rule from ThresholdFor.
//
// A short selection (fewer candidates than t.Of) is rejected rather than
// silently settled against a smaller quorum.
func ValidateAttested(sr SignedReceipt, selected map[[32]byte]bool, t Threshold) error {
	if len(selected) < t.Of {
		return ErrWitnessThreshold
	}
	h := CanonicalReceiptHash(sr.Receipt)
	if NodeIDOf(sr.ProviderPub) != sr.Receipt.ProviderNodeID {
		return ErrProviderMismatch
	}
	if !ed25519.Verify(sr.ProviderPub, h[:], sr.ProviderSig) {
		return ErrProviderSig
	}
	seen := make(map[[32]byte]bool)
	valid, offSet := 0, 0
	for _, w := range sr.Witnesses {
		id := NodeIDOf(w.Pub)
		if id == sr.Receipt.ProviderNodeID {
			return ErrWitnessSelf
		}
		if seen[id] {
			continue
		}
		if !ed25519.Verify(w.Pub, h[:], w.Sig) {
			continue
		}
		seen[id] = true
		if selected[id] {
			valid++
		} else {
			offSet++
		}
	}
	if valid < t.Need {
		// Distinguish "not enough witnesses" from "witnesses nobody asked for":
		// the latter is a collusion signal worth surfacing, not a shortfall.
		if valid == 0 && offSet > 0 {
			return ErrWitnessNotSelected
		}
		return ErrWitnessThreshold
	}
	return nil
}
