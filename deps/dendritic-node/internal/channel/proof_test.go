package channel

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func capableProver() ProofCapabilities {
	return ProofCapabilities{
		Aggregation: true, TrustedSetup: false, OnChainVerifier: true,
		BrowserProving: true, System: "halo2",
	}
}

func TestNullProverRefusesEverything(t *testing.T) {
	var p ProofAdapter = NullProver{}
	ctx := context.Background()
	if _, _, err := p.ProvePrivateTransfer(ctx, Witness{}); !errors.Is(err, ErrNoProver) {
		t.Errorf("Prove: %v", err)
	}
	if err := p.VerifyPrivateTransfer(ctx, nil, PublicInputs{}); !errors.Is(err, ErrNoProver) {
		t.Errorf("Verify: %v", err)
	}
	if _, err := p.ProveAggregate(ctx, nil); !errors.Is(err, ErrNoProver) {
		t.Errorf("Aggregate: %v", err)
	}
	if p.Capabilities().System != "" {
		t.Error("the null prover named a proving system")
	}
}

// Both halves are configured independently, so the combination is what decides
// whether privacy is real. A private-capable channel with no prover must not
// advertise private payments.
func TestPrivatePaymentsNeedBothHalves(t *testing.T) {
	if SupportsPrivatePayments(full(), ProofCapabilities{}) {
		t.Error("claimed private payments with no prover")
	}
	if SupportsPrivatePayments(Capabilities{}, capableProver()) {
		t.Error("claimed private payments with a null channel backend")
	}
	if !SupportsPrivatePayments(full(), capableProver()) {
		t.Error("refused private payments when both halves support them")
	}
}

// A prover that cannot prove in a browser cannot serve viewers without taking
// their witness — and taking the witness is refused outright, so that
// combination is simply not private payments.
func TestNoBrowserProvingIsNotPrivatePayments(t *testing.T) {
	p := capableProver()
	p.BrowserProving = false
	if SupportsPrivatePayments(full(), p) {
		t.Error("claimed private payments with a prover viewers cannot run")
	}
}

// Streaming is a different claim from tipping. Without aggregation a stream
// costs one proof per voucher, which is not a slower feature but another one.
func TestStreamingNeedsAggregationSeparately(t *testing.T) {
	p := capableProver()
	if !SupportsPrivateStreaming(full(), p) {
		t.Fatal("refused streaming when everything supports it")
	}
	p.Aggregation = false
	if SupportsPrivateStreaming(full(), p) {
		t.Error("claimed private streaming without proof aggregation")
	}
	// One-off private payments must still be fine without aggregation.
	if !SupportsPrivatePayments(full(), p) {
		t.Error("aggregation was wrongly required for one-off payments")
	}
}

// An inconsistent channel backend poisons the whole combination — the same rule
// MayClaim follows, and for the same reason.
func TestInconsistentChannelBackendBlocksPrivatePayments(t *testing.T) {
	c := full()
	c.AdaptorSignatures = false // ConfidentialRecipient now impossible
	if SupportsPrivatePayments(c, capableProver()) {
		t.Error("claimed private payments on an inconsistent channel backend")
	}
}

// PublicInputs is the privacy boundary: every field is visible to every
// verifier forever. This pins the set so adding one is a deliberate act with a
// failing test attached, not a convenience someone slipped in.
func TestPublicInputsStaysMinimal(t *testing.T) {
	allowed := map[string]bool{
		"NoteTreeRoot": true, "Nullifiers": true, "OutputCommitments": true,
		"FeeCommitment": true, "RouteCommitment": true, "AssetCommitment": true,
		"ExpiresAt": true, "VerifyingKeyID": true, "ProtocolVersion": true,
	}
	typ := reflect.TypeOf(PublicInputs{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("PublicInputs gained %q — every public field is visible to "+
				"every verifier forever; add it deliberately or not at all", name)
		}
	}
}

// The witness must never contain something that belongs in public inputs, and
// must contain the secrets. A field moving between the two is a privacy change
// disguised as a refactor.
func TestWitnessHoldsTheSecrets(t *testing.T) {
	typ := reflect.TypeOf(Witness{})
	required := []string{"InputValues", "InputBlindings", "SpendingKey", "OutputValues"}
	present := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		present[typ.Field(i).Name] = true
	}
	for _, name := range required {
		if !present[name] {
			t.Errorf("Witness lost %q — it must stay private", name)
		}
	}
	// And nothing in the witness may be named like a public input.
	for i := 0; i < typ.NumField(); i++ {
		if strings.Contains(typ.Field(i).Name, "Nullifier") {
			t.Errorf("Witness field %q looks like a published value", typ.Field(i).Name)
		}
	}
}
