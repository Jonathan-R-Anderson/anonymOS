package aggregator

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"testing"
)

func newNode() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func TestValidateReceiptWitnessThreshold(t *testing.T) {
	ppub, ppriv := newNode()
	w1pub, w1priv := newNode()
	w2pub, w2priv := newNode()
	w3pub, w3priv := newNode()

	r := ServiceReceipt{ProviderNodeID: NodeIDOf(ppub), ServiceType: ServiceStorage, Epoch: 1, Quantity: 10, Quality: 1}
	sr := SignedReceipt{
		Receipt: r, ProviderPub: ppub, ProviderSig: SignReceipt(ppriv, r),
		Witnesses: []WitnessAttestation{
			{Pub: w1pub, Sig: SignReceipt(w1priv, r)},
			{Pub: w2pub, Sig: SignReceipt(w2priv, r)},
		},
	}
	if err := ValidateReceipt(sr, 2); err != nil {
		t.Fatalf("2-of-3 should pass: %v", err)
	}
	if err := ValidateReceipt(sr, 3); err != ErrWitnessThreshold {
		t.Fatalf("expected threshold error, got %v", err)
	}

	// A provider that witnesses its own receipt is rejected outright.
	self := sr
	self.Witnesses = append([]WitnessAttestation{{Pub: ppub, Sig: SignReceipt(ppriv, r)}}, sr.Witnesses...)
	if err := ValidateReceipt(self, 1); err != ErrWitnessSelf {
		t.Fatalf("expected self-witness error, got %v", err)
	}

	// Tampering the receipt after signing invalidates the provider signature.
	bad := sr
	bad.Receipt.Quantity = 999
	if err := ValidateReceipt(bad, 1); err != ErrProviderSig {
		t.Fatalf("expected provider-sig error on tamper, got %v", err)
	}
	_ = w3pub
	_ = w3priv

	// Provider pubkey that doesn't hash to the claimed node id.
	wrong := sr
	wrong.ProviderPub = w1pub
	if err := ValidateReceipt(wrong, 1); err != ErrProviderMismatch {
		t.Fatalf("expected provider-mismatch, got %v", err)
	}
}

func TestScoreProportionalAndCapped(t *testing.T) {
	a := nodeID(0xA1)
	b := nodeID(0xB2)
	receipts := []ServiceReceipt{
		{ProviderNodeID: a, ServiceType: ServiceStorage, Quantity: 60, Quality: 1},
		{ProviderNodeID: b, ServiceType: ServiceStorage, Quantity: 40, Quality: 1},
	}
	recipients := map[[32]byte][20]byte{a: addr(0xA1), b: addr(0xB2)}
	var split [7]uint16
	split[ServiceStorage] = 10000 // whole budget to storage this epoch
	budget := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))

	rows := Score(receipts, Policy{EpochBudget: budget, SplitBps: split, PerNodeCapBps: 0}, recipients)
	got := map[[32]byte]*big.Int{}
	for _, r := range rows {
		got[r.NodeID] = r.Amount
	}
	want := func(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }
	if got[a].Cmp(want(60)) != 0 || got[b].Cmp(want(40)) != 0 {
		t.Fatalf("proportional split wrong: A=%s B=%s", got[a], got[b])
	}

	// Cap node A at 50% of the epoch.
	capped := Score(receipts, Policy{EpochBudget: budget, SplitBps: split, PerNodeCapBps: 5000}, recipients)
	for _, r := range capped {
		if r.NodeID == a && r.Amount.Cmp(want(50)) != 0 {
			t.Fatalf("A should be capped at 50, got %s", r.Amount)
		}
	}
}
