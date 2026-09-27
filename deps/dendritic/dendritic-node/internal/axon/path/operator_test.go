package path

import (
	"context"
	"fmt"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// owned is `relay` plus a verified on-chain owner.
func owned(t *testing.T, id string, a, b int, asn uint32, owner byte) Relay {
	t.Helper()
	r := relay(t, id, a, b, asn)
	var o peer.OperatorID
	for i := range o {
		o[i] = owner
	}
	r.Ann.Operator, r.Ann.OperatorSource = o, peer.OperatorSourceChain
	return r
}

// TestT12b1SameOwnerNeverShareAPath is T12b.1.
//
// The population is the case §7.2 describes and the reason the rung exists:
// 60 relays, every one in its own /16 and its own AS, so prefix and ASN
// diversity are trivially satisfiable — and only THREE owners. Without the
// operator rung every path passes; with it, no path may repeat an owner.
func TestT12b1SameOwnerNeverShareAPath(t *testing.T) {
	var cands []Relay
	for i := 0; i < 60; i++ {
		cands = append(cands, owned(t, fmt.Sprintf("r%03d", i), i, 1, uint32(1+i), byte(1+i%3)))
	}
	s := selector(cands, seeded(31))
	ctx := context.Background()

	for i := 0; i < 5000; i++ {
		p, rep, err := s.SelectPath(ctx, 3, Default(), WeightPolicy{})
		if err != nil {
			t.Fatalf("selection %d: %v", i, err)
		}
		if rep.DistinctOperators != 3 {
			t.Fatalf("report says %d distinct operators, want 3", rep.DistinctOperators)
		}
		if rep.OperatorUnavailable != 0 {
			t.Fatalf("%d candidates had no verified owner", rep.OperatorUnavailable)
		}
		seen := map[peer.OperatorID]bool{}
		for _, hop := range p {
			if seen[hop.Ann.Operator] {
				t.Fatalf("T12b.1 violated: owner %s holds two hops of one path", hop.Ann.Operator)
			}
			seen[hop.Ann.Operator] = true
		}
	}

	// Four hops with three owners is impossible, and must FAIL rather than
	// quietly return a path with a repeated owner.
	if _, _, err := s.SelectPath(ctx, 4, Default(), WeightPolicy{}); err != ErrNoPath {
		t.Fatalf("4 hops across 3 owners gave %v, want ErrNoPath", err)
	}
}

// TestT12b2UnverifiableOwnerIsReported is T12b.2.
//
// A pool where nobody's owner is verifiable still produces paths — that is the
// conservative rule from T12b.4 — but the report must say the rung was never
// applied. A caller reading only "3 hops, no error" would otherwise record a
// distinct-operator guarantee that was satisfied by ignorance.
func TestT12b2UnverifiableOwnerIsReported(t *testing.T) {
	// Nobody verified.
	plain := population(t, 60, 20)
	_, rep, err := selector(plain, seeded(41)).SelectPath(context.Background(), 3, Default(), WeightPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OperatorUnavailable != 60 {
		t.Fatalf("T12b.2 violated: %d of 60 unverifiable owners reported", rep.OperatorUnavailable)
	}
	if rep.DistinctOperators != 0 {
		t.Fatalf("unverified owners counted as %d distinct operators", rep.DistinctOperators)
	}

	// Half verified: the count must be exact, not a boolean.
	var mixed []Relay
	for i := 0; i < 60; i++ {
		if i%2 == 0 {
			mixed = append(mixed, owned(t, fmt.Sprintf("m%03d", i), i, 1, uint32(1+i), byte(1+i%7)))
		} else {
			mixed = append(mixed, relay(t, fmt.Sprintf("m%03d", i), i, 1, uint32(1+i)))
		}
	}
	_, rep, err = selector(mixed, seeded(42)).SelectPath(context.Background(), 3, Default(), WeightPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OperatorUnavailable != 30 {
		t.Fatalf("mixed pool reported %d unverifiable, want 30", rep.OperatorUnavailable)
	}
	if rep.DistinctOperators != 7 {
		t.Fatalf("mixed pool reported %d distinct operators, want 7", rep.DistinctOperators)
	}
}

// TestOperatorRungSurvivesAChainOutage is P12b's named failure mode.
//
// Every operator becoming unknown at once must WIDEN the admissible set, never
// collapse it. The test asserts the direction: a pool that could build paths
// with owners known can still build them with owners lost.
func TestOperatorRungSurvivesAChainOutage(t *testing.T) {
	var withOwners []Relay
	for i := 0; i < 30; i++ {
		withOwners = append(withOwners, owned(t, fmt.Sprintf("r%03d", i), i, 1, uint32(1+i), byte(1+i%5)))
	}
	lost := make([]Relay, len(withOwners))
	copy(lost, withOwners)
	for i := range lost {
		lost[i].Ann.Operator = peer.OperatorUnknown
		lost[i].Ann.OperatorSource = peer.OperatorSourceNone
	}
	ctx := context.Background()

	if _, _, err := selector(withOwners, seeded(51)).SelectPath(ctx, 3, Default(), WeightPolicy{}); err != nil {
		t.Fatalf("with owners known: %v", err)
	}
	_, rep, err := selector(lost, seeded(51)).SelectPath(ctx, 3, Default(), WeightPolicy{})
	if err != nil {
		t.Fatalf("a chain outage made path selection impossible: %v", err)
	}
	if rep.OperatorUnavailable != len(lost) {
		t.Fatalf("outage reported %d unavailable of %d", rep.OperatorUnavailable, len(lost))
	}
}

// TestUnknownOperatorPolicyIsBothReadings covers the §8.7-vs-P12b ruling.
//
// Both readings are implemented because both are correct about a different
// situation; see UnknownOperatorPolicy. What must never happen is that one is
// silently in force while a caller believes the other, so the two are tested
// against the SAME pool and must give opposite answers.
func TestUnknownOperatorPolicyIsBothReadings(t *testing.T) {
	// 60 relays, distinct /16s and distinct ASes, NOBODY registered.
	cands := population(t, 60, 60)
	ctx := context.Background()

	// P12b's reading (default): unknowns are mutually distinct, so paths build.
	distinct := Default()
	if _, _, err := selector(cands, seeded(61)).SelectPath(ctx, 3, distinct, WeightPolicy{}); err != nil {
		t.Fatalf("default policy could not build a path on an unregistered network: %v", err)
	}

	// §8.7's reading: every unregistered relay is one operator, so at most one
	// may appear -- and a 3-hop path is therefore impossible. This is the cost
	// of the stricter rule, and it is the reason it is not the default.
	collapse := Default()
	collapse.UnknownOperators = UnknownOperatorsCollapse
	if _, _, err := selector(cands, seeded(61)).SelectPath(ctx, 3, collapse, WeightPolicy{}); err != ErrNoPath {
		t.Fatalf("collapse policy built a 3-hop path from 60 unknown operators: %v", err)
	}
	// One hop is still fine under collapse: the rule caps unknowns per path at
	// one, it does not exclude them.
	if _, _, err := selector(cands, seeded(61)).SelectPath(ctx, 1, collapse, WeightPolicy{}); err != nil {
		t.Fatalf("collapse policy refused even a single unknown-operator hop: %v", err)
	}

	// With owners verified, the two policies agree -- the disagreement is only
	// ever about the unknown case.
	var known []Relay
	for i := 0; i < 60; i++ {
		known = append(known, owned(t, fmt.Sprintf("k%03d", i), i, 1, uint32(1+i), byte(1+i%9)))
	}
	for name, c := range map[string]DiversityConstraint{"distinct": distinct, "collapse": collapse} {
		if _, _, err := selector(known, seeded(62)).SelectPath(ctx, 3, c, WeightPolicy{}); err != nil {
			t.Fatalf("%s policy failed on a fully registered network: %v", name, err)
		}
	}
}
