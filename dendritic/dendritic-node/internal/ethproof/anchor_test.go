package ethproof

// The trust anchor gate — roadmap P12-5.
//
// The most important test here asserts that header verification FAILS. Until a
// light client exists, a system that could not tell Ethereum from a fabrication
// must say so rather than proceed.

import (
	"errors"
	"strings"
	"testing"
)

const alchemy = "https://eth-mainnet.g.alchemy.com/v2/key"

// THE GATE.
func TestHeaderVerificationFailsWithoutASyncCommitteeAnchor(t *testing.T) {
	v := &HeaderVerifier{ChainID: 1, Endpoint: alchemy}
	if err := v.VerifyHeader(BlockHeader{Number: "0x1"}); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("VerifyHeader returned %v, want ErrNoTrustAnchor", err)
	}
	// An operator pin is real but narrow, and must not satisfy the gate.
	if err := v.SetAnchor(Anchor{
		Kind: AnchorOperator, Source: "checked by hand against three explorers",
		BlockNumber: 25_737_778, BlockHash: "0xabc",
	}); err != nil {
		t.Fatalf("SetAnchor: %v", err)
	}
	if v.Anchor().Trustworthy() {
		t.Error("an operator pin claimed to establish canonicality")
	}
	if err := v.VerifyHeader(BlockHeader{Number: "0x1"}); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("an operator pin opened the gate: %v", err)
	}
}

// The circularity that would move the trust boundary without shrinking it.
func TestAnAnchorFromTheSameProviderIsRefused(t *testing.T) {
	v := &HeaderVerifier{ChainID: 1, Endpoint: alchemy}
	err := v.SetAnchor(Anchor{
		Kind:   AnchorSyncCommittee,
		Source: "https://eth-mainnet.g.alchemy.com/v2/otherkey",
	})
	if !errors.Is(err, ErrAnchorNotIndependent) {
		t.Fatalf("SetAnchor returned %v, want ErrAnchorNotIndependent", err)
	}
	if !strings.Contains(err.Error(), "alchemy.com") {
		t.Errorf("the refusal does not name the shared provider: %v", err)
	}
}

func TestAnIndependentAnchorIsAccepted(t *testing.T) {
	v := &HeaderVerifier{ChainID: 1, Endpoint: alchemy}
	if err := v.SetAnchor(Anchor{
		Kind: AnchorSyncCommittee, Source: "https://beaconstate.info",
		Note: "checkpoint sync provider, unrelated to the execution RPC",
	}); err != nil {
		t.Fatalf("an independent anchor was refused: %v", err)
	}
	if !v.Anchor().Trustworthy() {
		t.Error("a sync-committee anchor did not read as trustworthy")
	}
}

func TestAnAnchorMustSayWhereItCameFrom(t *testing.T) {
	v := &HeaderVerifier{ChainID: 1, Endpoint: alchemy}
	if err := v.SetAnchor(Anchor{Kind: AnchorSyncCommittee}); err == nil {
		t.Fatal("an anchor with no source was accepted")
	}
	if err := v.SetAnchor(Anchor{}); err == nil {
		t.Fatal("an anchor with no kind was accepted")
	}
}

// Linkage is a consistency check and must never be mistaken for security. This
// test exists to pin the distinction: it passes for a chain that is entirely
// fabricated, which is exactly why VerifyHeader does not consult it.
func TestChainLinkageIsOnlyAConsistencyCheck(t *testing.T) {
	// A wholly invented pair. Post-merge this costs nothing to produce.
	parent := BlockHeader{Number: "0x64", Hash: "0xaaaa"}
	child := BlockHeader{Number: "0x65", ParentHash: "0xAAAA"}

	if !ChainAt(parent, child) {
		t.Fatal("linkage did not recognise a linked pair")
	}
	// ...and the gate still refuses, because linkage proves nothing about
	// which chain this is.
	v := &HeaderVerifier{ChainID: 1, Endpoint: alchemy}
	if err := v.VerifyHeader(child); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("a linked fabrication passed the gate: %v", err)
	}
}

func TestLinkageRejectsAGap(t *testing.T) {
	parent := BlockHeader{Number: "0x64", Hash: "0xaaaa"}
	for _, bad := range []BlockHeader{
		{Number: "0x66", ParentHash: "0xaaaa"}, // skips a height
		{Number: "0x65", ParentHash: "0xbbbb"}, // wrong parent
		{Number: "0x65"},                       // no parent at all
	} {
		if ChainAt(parent, bad) {
			t.Errorf("linkage accepted %+v", bad)
		}
	}
}
