package facilitation

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// goldenReceipt is the shared cross-module vector. The identical struct is
// hashed on the aggregator side; both must produce goldenHash.
func goldenReceipt() ServiceReceipt {
	var provider, verifier, job, challenge, result [32]byte
	for i := 0; i < 32; i++ {
		provider[i] = byte(i)
		verifier[i] = byte(0x40 + i)
		job[i] = byte(0x80 + i)
		challenge[i] = byte(0xC0 + i)
		result[i] = byte(0xE0 - i)
	}
	return ServiceReceipt{
		ProviderNodeID: provider, VerifierNodeID: verifier,
		ServiceType: ServiceStorage, JobID: job,
		ChallengeHash: challenge, ResultHash: result,
		Epoch: 1234567890, StartedAt: 1700000000, CompletedAt: 1700000123,
		Quantity: 987654321, Quality: 4242, Nonce: 42,
	}
}

// Produced by proof-of-facilitation/aggregator's CanonicalReceiptHash.
const goldenHash = "76a75cf1dc27ff24c1827a1b8cc21cd354bdb1c7200e41c89ab677902a554bc7"

// The whole integration rests on this. storage-client and the aggregator are
// separate repositories and separate Go modules, so nothing but this vector
// stops the two encodings drifting apart — and drift would not look like a
// crash. The node would keep signing receipts, the aggregator would silently
// recognise none of them, and the operator would just never get paid.
func TestCanonicalReceiptHashGoldenVector(t *testing.T) {
	got := CanonicalReceiptHash(goldenReceipt())
	if hex.EncodeToString(got[:]) != goldenHash {
		t.Fatalf("canonical receipt hash drifted from the aggregator\n got: %s\nwant: %s\n"+
			"Field order, field widths and endianness must match "+
			"proof-of-facilitation/aggregator/attest.go exactly.",
			hex.EncodeToString(got[:]), goldenHash)
	}
}

// Every field must feed the hash: a field the hash ignores is a field an
// attacker can rewrite after signing.
func TestEveryFieldChangesTheHash(t *testing.T) {
	base := CanonicalReceiptHash(goldenReceipt())
	mutations := map[string]func(*ServiceReceipt){
		"ProviderNodeID": func(r *ServiceReceipt) { r.ProviderNodeID[0] ^= 1 },
		"VerifierNodeID": func(r *ServiceReceipt) { r.VerifierNodeID[0] ^= 1 },
		"ServiceType":    func(r *ServiceReceipt) { r.ServiceType = ServiceGateway },
		"JobID":          func(r *ServiceReceipt) { r.JobID[31] ^= 1 },
		"ChallengeHash":  func(r *ServiceReceipt) { r.ChallengeHash[7] ^= 1 },
		"ResultHash":     func(r *ServiceReceipt) { r.ResultHash[3] ^= 1 },
		"Epoch":          func(r *ServiceReceipt) { r.Epoch++ },
		"StartedAt":      func(r *ServiceReceipt) { r.StartedAt++ },
		"CompletedAt":    func(r *ServiceReceipt) { r.CompletedAt++ },
		"Quantity":       func(r *ServiceReceipt) { r.Quantity++ },
		"Quality":        func(r *ServiceReceipt) { r.Quality++ },
		"Nonce":          func(r *ServiceReceipt) { r.Nonce++ },
	}
	for name, mutate := range mutations {
		r := goldenReceipt()
		mutate(&r)
		if CanonicalReceiptHash(r) == base {
			t.Errorf("%s does not affect the canonical hash — it could be altered after signing", name)
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sr := NewSignedReceipt(pub, priv, ServiceReceipt{
		ServiceType: ServiceStorage, Epoch: 9, Quantity: 100, Quality: 1,
	})
	if sr.Receipt.ProviderNodeID != NodeID(pub) {
		t.Fatal("provider node id not derived from the signing key")
	}
	if !VerifyReceiptSignature(sr.ProviderPub, sr.Receipt, sr.ProviderSig) {
		t.Fatal("own signature does not verify")
	}
	// Tampering after signing must break the signature.
	bad := sr.Receipt
	bad.Quantity = 1_000_000
	if VerifyReceiptSignature(sr.ProviderPub, bad, sr.ProviderSig) {
		t.Fatal("signature still valid after the quantity was rewritten")
	}
}

func TestAddWitnessRules(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sr := NewSignedReceipt(pub, priv, ServiceReceipt{ServiceType: ServiceDHT, Epoch: 3, Quantity: 5})
	h := sr.Hash()

	// A witness that is the provider is refused: the aggregator treats
	// self-witnessing as a hard error, so storing one poisons the receipt.
	if sr.AddWitness(pub, ed25519.Sign(priv, h[:])) {
		t.Fatal("provider accepted as its own witness")
	}

	wpub, wpriv, _ := ed25519.GenerateKey(nil)
	if !sr.AddWitness(wpub, ed25519.Sign(wpriv, h[:])) {
		t.Fatal("valid witness rejected")
	}
	if sr.AddWitness(wpub, ed25519.Sign(wpriv, h[:])) {
		t.Fatal("same witness counted twice")
	}
	// A signature over the wrong thing must not be stored.
	bpub, bpriv, _ := ed25519.GenerateKey(nil)
	if sr.AddWitness(bpub, ed25519.Sign(bpriv, []byte("something else"))) {
		t.Fatal("invalid witness signature accepted")
	}
	if len(sr.Witnesses) != 1 {
		t.Fatalf("expected exactly 1 witness, got %d", len(sr.Witnesses))
	}
}

// The receipt's service INDEX and NodeRegistry's capability BIT are different
// numbers; mixing them up would credit work to the wrong service.
func TestCapabilityBitMapping(t *testing.T) {
	cases := map[ServiceType]uint64{
		ServiceDHT:              CapDHT,
		ServiceGateway:          CapGateway,
		ServiceStorage:          CapStorage,
		ServiceLoadBalance:      CapLoadBalance,
		ServiceDockerWorker:     CapDockerWorker,
		ServiceDockerController: CapDockerController,
		ServiceWitness:          CapWitness,
	}
	for svc, want := range cases {
		if got := svc.CapabilityBit(); got != want {
			t.Errorf("service %d: bit %d, want %d", svc, got, want)
		}
	}
}

// The node id vector, pinned identically in the aggregator. SHA3-256 and legacy
// Keccak-256 share an output size, so a wrong-but-plausible id would otherwise
// pass unnoticed and make every receipt unattributable.
const goldenNodeID = "8ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd2d"

func TestNodeIDGoldenVector(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	got := NodeID(pub)
	if hex.EncodeToString(got[:]) != goldenNodeID {
		t.Fatalf("node id drifted from the aggregator\n got: %s\nwant: %s",
			hex.EncodeToString(got[:]), goldenNodeID)
	}
}
