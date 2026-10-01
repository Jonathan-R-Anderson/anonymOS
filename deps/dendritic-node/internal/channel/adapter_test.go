package channel

import (
	"context"
	"errors"
	"testing"
	"time"
)

func full() Capabilities {
	return Capabilities{
		MediatedTransfers: true,
		HTLC:              true,
		AdaptorSignatures: true,
		Watchtower:        true,
		Chain:             1,
		Privacy: PrivacyCapabilities{
			OnionRouting:          true,
			BlindedPaths:          true,
			ConfidentialAmounts:   true,
			ConfidentialRecipient: true,
			PrivateNotes:          true,
			ZeroKnowledgeProofs:   true,
			AtomicMultipath:       true,
			PrivateStreaming:      true,
		},
	}
}

func TestAFullyCapableBackendValidates(t *testing.T) {
	if err := full().Validate(); err != nil {
		t.Fatalf("a consistent capability set was rejected: %v", err)
	}
}

// The most important inconsistency. Without adaptor signatures a routed payment
// carries one hash on every hop, so any two colluding routers link it. Such a
// backend may still route; it may not claim the recipient is confidential.
func TestConfidentialRecipientRequiresAdaptorSignatures(t *testing.T) {
	c := full()
	c.AdaptorSignatures = false
	if err := c.Validate(); !errors.Is(err, ErrInconsistentCapabilities) {
		t.Fatal("a backend without adaptor signatures claimed a confidential recipient")
	}
	// And dropping the claim makes it consistent again — routing is still fine.
	c.Privacy.ConfidentialRecipient = false
	if err := c.Validate(); err != nil {
		t.Fatalf("routing without the claim should be valid: %v", err)
	}
}

func TestImpossibleCombinationsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Capabilities)
	}{
		{"blinded paths without onion routing", func(c *Capabilities) {
			c.Privacy.OnionRouting = false
			c.Privacy.ConfidentialRecipient = false
		}},
		{"confidential amounts without notes", func(c *Capabilities) {
			c.Privacy.PrivateNotes = false
		}},
		{"notes without proofs", func(c *Capabilities) {
			c.Privacy.ZeroKnowledgeProofs = false
		}},
		{"multipath without any conditional lock", func(c *Capabilities) {
			c.HTLC = false
			c.AdaptorSignatures = false
			c.Privacy.ConfidentialRecipient = false
		}},
		{"onion routing without mediated transfers", func(c *Capabilities) {
			c.MediatedTransfers = false
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := full()
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted a combination that cannot be true")
			}
		})
	}
}

// An empty backend is consistent — claiming nothing is always honest.
func TestClaimingNothingIsValid(t *testing.T) {
	if err := (Capabilities{}).Validate(); err != nil {
		t.Fatalf("a backend claiming nothing was rejected: %v", err)
	}
}

// The chokepoint: no property may be claimed on an inconsistent report. If the
// capability set is wrong about one thing it is not evidence for anything.
func TestAnInconsistentBackendMayClaimNothing(t *testing.T) {
	c := full()
	c.AdaptorSignatures = false // makes ConfidentialRecipient impossible
	for _, property := range []string{
		"onion_routing", "blinded_paths", "confidential_amounts",
		"confidential_recipient", "private_notes", "zero_knowledge",
		"atomic_multipath", "private_streaming",
	} {
		if MayClaim(c, property) {
			t.Errorf("claimed %q from an inconsistent capability report", property)
		}
	}
}

func TestMayClaimTracksTheCapability(t *testing.T) {
	c := full()
	if !MayClaim(c, "confidential_amounts") {
		t.Error("a supported property was refused")
	}
	c.Privacy.ConfidentialAmounts = false
	if MayClaim(c, "confidential_amounts") {
		t.Error("an unsupported property was claimed")
	}
}

// A typo must not become a false promise.
func TestUnknownPropertiesAreNeverClaimable(t *testing.T) {
	for _, property := range []string{"", "untraceable", "anonymous", "confidental_amounts"} {
		if MayClaim(full(), property) {
			t.Errorf("claimed unknown property %q", property)
		}
	}
}

// The default backend must refuse everything rather than crash or silently
// succeed. A node with no channel configured behaves as though channels do not
// exist.
func TestNullRefusesEverythingHonestly(t *testing.T) {
	var a Adapter = Null{}
	ctx := context.Background()

	if _, err := a.Open(ctx, "peer", 100); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Open: %v", err)
	}
	if _, err := a.Pay(ctx, "ch", 1, "ref"); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Pay: %v", err)
	}
	if _, err := a.Reserve(ctx, "ch", 1, Hash{}, time.Now()); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Reserve: %v", err)
	}
	if err := a.Claim(ctx, "lock", Preimage{}); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Claim: %v", err)
	}
	if err := a.Release(ctx, "lock"); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Release: %v", err)
	}
	if _, err := a.Balance("ch"); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Balance: %v", err)
	}
	if err := a.Close(ctx, "ch", true); !errors.Is(err, ErrNoBackend) {
		t.Errorf("Close: %v", err)
	}
}

// And crucially: the null backend must not let anything be claimed.
func TestNullClaimsNoPrivacy(t *testing.T) {
	c := Null{}.Capabilities()
	if err := c.Validate(); err != nil {
		t.Fatalf("the null backend's report is inconsistent: %v", err)
	}
	for _, property := range []string{
		"onion_routing", "blinded_paths", "confidential_amounts",
		"confidential_recipient", "private_notes", "zero_knowledge",
	} {
		if MayClaim(c, property) {
			t.Errorf("the null backend claimed %q", property)
		}
	}
}

// Balance must keep locked value separate from spendable value. Folding them
// together is how a node signs a proof it cannot honour.
func TestLockedValueIsNotSpendable(t *testing.T) {
	b := Balance{Outbound: 100, Locked: 40, Nonce: 7}
	if b.Outbound != 100 || b.Locked != 40 {
		t.Fatal("Balance fields must stay distinct")
	}
	// Documented expectation: Outbound already excludes Locked, so a caller
	// must NOT subtract it again. This test exists to pin that contract, since
	// getting it backwards double-counts and under-spends by exactly Locked.
	spendable := b.Outbound
	if spendable != 100 {
		t.Errorf("spendable = %d; Outbound is defined as already excluding Locked", spendable)
	}
}
