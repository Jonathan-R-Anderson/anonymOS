package facilitation

import (
	"crypto/ed25519"
	"encoding/binary"
)

// Service receipts — the node's half of the Proof-of-Facilitation ledger.
//
// The aggregator lives in a DIFFERENT repository and a different Go module, so
// this file cannot import its types; it re-implements the canonical encoding.
// That is a real hazard: if the two encodings ever drift by a single byte, every
// receipt this node signs hashes to something the aggregator will not recognise,
// and the node silently earns nothing while appearing to work perfectly.
//
// TestCanonicalReceiptHashGoldenVector pins the shared vector so the drift fails
// a test here instead of failing silently in production. The same vector is
// pinned on the aggregator side.

// ServiceType is the receipt's service INDEX (0..6), matching the aggregator's
// ServiceType ordering. It is deliberately not the same number as the CapXxx
// bitmask above: NodeRegistry stores capabilities as bits (1<<n), receipts carry
// the index (n). Confusing the two would attribute work to the wrong service.
type ServiceType uint8

const (
	ServiceDHT ServiceType = iota
	ServiceGateway
	ServiceStorage
	ServiceLoadBalance
	ServiceDockerWorker
	ServiceDockerController
	ServiceWitness
)

// CapabilityBit maps a service index to its NodeRegistry capability bit.
func (s ServiceType) CapabilityBit() uint64 { return uint64(1) << uint64(s) }

// ServiceReceipt is one rewarded, witness-attested action. Field ORDER here is
// part of the wire contract: the canonical hash is a flat concatenation, so
// reordering fields changes every hash.
type ServiceReceipt struct {
	ProviderNodeID [32]byte
	VerifierNodeID [32]byte
	ServiceType    ServiceType
	JobID          [32]byte
	ChallengeHash  [32]byte
	ResultHash     [32]byte
	Epoch          uint64
	StartedAt      uint64
	CompletedAt    uint64
	Quantity       uint64
	Quality        uint32
	Nonce          uint64
}

func be64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

// CanonicalReceiptHash is keccak256 over the fields in a fixed order — exactly
// what the provider and every witness sign, and exactly what the aggregator
// recomputes. Big-endian throughout; no length prefixes, no padding.
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
	var out [32]byte
	copy(out[:], keccak256(buf))
	return out
}

// SignReceipt signs the canonical hash with the node's Ed25519 p2p key — the
// same key whose keccak256 is the node id, so the signature and the claimed
// identity cannot be separated.
func SignReceipt(priv ed25519.PrivateKey, r ServiceReceipt) []byte {
	h := CanonicalReceiptHash(r)
	return ed25519.Sign(priv, h[:])
}

// VerifyReceiptSignature checks a signature against the canonical hash.
func VerifyReceiptSignature(pub ed25519.PublicKey, r ServiceReceipt, sig []byte) bool {
	h := CanonicalReceiptHash(r)
	return ed25519.Verify(pub, h[:], sig)
}

// WitnessAttestation is one witness's signature over a receipt hash.
type WitnessAttestation struct {
	Pub ed25519.PublicKey `json:"pub"`
	Sig []byte            `json:"sig"`
}

// SignedReceipt is what the node persists and hands to the aggregator: the
// receipt, the provider's signature, and whatever attestations have arrived.
type SignedReceipt struct {
	Receipt     ServiceReceipt       `json:"receipt"`
	ProviderPub ed25519.PublicKey    `json:"provider_pub"`
	ProviderSig []byte               `json:"provider_sig"`
	Witnesses   []WitnessAttestation `json:"witnesses"`
}

// NewSignedReceipt builds and signs a receipt for work this node performed.
func NewSignedReceipt(pub ed25519.PublicKey, priv ed25519.PrivateKey, r ServiceReceipt) SignedReceipt {
	r.ProviderNodeID = NodeID(pub)
	return SignedReceipt{
		Receipt:     r,
		ProviderPub: pub,
		ProviderSig: SignReceipt(priv, r),
	}
}

// Hash is the receipt's canonical hash — its identity for storage and dedup.
func (s SignedReceipt) Hash() [32]byte { return CanonicalReceiptHash(s.Receipt) }

// AddWitness records an attestation, ignoring duplicates from the same witness
// and refusing one from the provider itself (self-witnessing is rejected
// outright by the aggregator, so a receipt carrying one is worthless).
func (s *SignedReceipt) AddWitness(pub ed25519.PublicKey, sig []byte) bool {
	id := NodeID(pub)
	if id == s.Receipt.ProviderNodeID {
		return false
	}
	for _, w := range s.Witnesses {
		if NodeID(w.Pub) == id {
			return false
		}
	}
	// Verify before storing: an attestation that does not check out is worse
	// than none, because it makes a receipt look settleable when it is not.
	h := s.Hash()
	if !ed25519.Verify(pub, h[:], sig) {
		return false
	}
	s.Witnesses = append(s.Witnesses, WitnessAttestation{Pub: pub, Sig: sig})
	return true
}
