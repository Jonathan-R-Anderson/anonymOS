package peer

import (
	"net/netip"
	"strings"
	"testing"
)

func seed(id, addr, op string) BootstrapPeer {
	return BootstrapPeer{NodeID: id, Addr: netip.MustParseAddr(addr), Operator: op}
}

func hasCode(ws []PartitionWarning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

// TestAdversarialBootstrapIsDetected is T3.5: an adversarial bootstrap set is
// detected and a partition warning is emitted rather than the node proceeding
// silently.
func TestAdversarialBootstrapIsDetected(t *testing.T) {
	// The canonical hostile shape: every seed in one /24, one declared
	// operator, and nothing in common with what this node knew before.
	seeds := []BootstrapPeer{
		seed("evil-1", "203.0.113.1", "acme"),
		seed("evil-2", "203.0.113.2", "acme"),
		seed("evil-3", "203.0.113.3", "acme"),
		seed("evil-4", "203.0.113.4", "acme"),
	}
	prior := []string{"honest-a", "honest-b", "honest-c"}

	audit := AuditBootstrap(nil, seeds, prior)

	if !audit.Partitioned(SeverityCritical) {
		t.Fatalf("T3.5 violated: adversarial bootstrap set produced no critical warning: %+v", audit.Warnings)
	}
	for _, code := range []string{"single-prefix", "single-operator", "disjoint-from-prior-view"} {
		if !hasCode(audit.Warnings, code) {
			t.Errorf("missing indicator %q; got %v", code, audit.Warnings)
		}
	}
	if audit.DistinctPrefixes != 1 {
		t.Errorf("DistinctPrefixes = %d, want 1", audit.DistinctPrefixes)
	}
	// The warning must be legible to an operator, not just a boolean.
	joined := strings.Join(func() (s []string) {
		for _, w := range audit.Warnings {
			s = append(s, w.String())
		}
		return
	}(), "\n")
	if !strings.Contains(joined, "203.0.113.0/24") {
		t.Errorf("warning text does not name the offending prefix:\n%s", joined)
	}
}

// TestHealthyBootstrapProducesNoCriticalWarning is the control: a set spread
// across distinct /24s with a prior-view overlap must not be flagged critical,
// or the check is a klaxon nobody will listen to.
func TestHealthyBootstrapProducesNoCriticalWarning(t *testing.T) {
	seeds := []BootstrapPeer{
		seed("a", "198.51.100.1", "op-a"),
		seed("b", "203.0.113.9", "op-b"),
		seed("c", "192.0.2.30", "op-c"),
		seed("d", "198.18.7.4", "op-d"),
	}
	audit := AuditBootstrap(nil, seeds, []string{"a", "z"})
	if audit.Partitioned(SeverityCritical) {
		t.Fatalf("healthy bootstrap set flagged critical: %+v", audit.Warnings)
	}
	if audit.DistinctPrefixes != 4 {
		t.Fatalf("DistinctPrefixes = %d, want 4", audit.DistinctPrefixes)
	}
	// The ASN gap must be reported, not silently passed over: for IPv4 seeds
	// no ASN resolves, so AS-concentration was never actually checked.
	if !hasCode(audit.Warnings, "asn-unavailable") {
		t.Errorf("IPv4-only seed set did not report the unchecked ASN constraint: %v", audit.Warnings)
	}
}

// TestTooFewSeedsIsCritical: below the floor there is nothing to cross-check.
func TestTooFewSeedsIsCritical(t *testing.T) {
	audit := AuditBootstrap(nil, []BootstrapPeer{seed("only", "198.51.100.1", "")}, nil)
	if !hasCode(audit.Warnings, "too-few-seeds") {
		t.Fatalf("single-seed bootstrap not flagged: %v", audit.Warnings)
	}
	if !audit.Partitioned(SeverityCritical) {
		t.Fatal("single-seed bootstrap was not critical")
	}
}

// TestDuplicateSeedIdentitiesFlagged: four addresses, one identity, is one
// vantage point pretending to be four.
func TestDuplicateSeedIdentitiesFlagged(t *testing.T) {
	seeds := []BootstrapPeer{
		seed("same", "198.51.100.1", ""),
		seed("same", "203.0.113.9", ""),
		seed("same", "192.0.2.30", ""),
	}
	audit := AuditBootstrap(nil, seeds, nil)
	if !hasCode(audit.Warnings, "duplicate-seed-identity") {
		t.Fatalf("duplicate identities not flagged: %v", audit.Warnings)
	}
}

// TestOperatorASNTableDetectsSingleAS: with an operator-supplied IPv4 ASN
// table, seeds spread across distinct /24s inside one AS are still one
// operator's network -- the case prefix distinctness alone misses.
func TestOperatorASNTableDetectsSingleAS(t *testing.T) {
	a := &Annotator{ASNv4: []PrefixASN{
		{Prefix: netip.MustParsePrefix("203.0.112.0/22"), ASN: 64500},
	}}
	seeds := []BootstrapPeer{
		seed("a", "203.0.112.1", ""),
		seed("b", "203.0.113.1", ""),
		seed("c", "203.0.114.1", ""),
	}
	audit := AuditBootstrap(a, seeds, nil)
	if audit.DistinctPrefixes != 3 {
		t.Fatalf("DistinctPrefixes = %d, want 3 (prefix check alone sees diversity)", audit.DistinctPrefixes)
	}
	if !hasCode(audit.Warnings, "single-asn") {
		t.Fatalf("three distinct /24s inside one AS were not flagged: %v", audit.Warnings)
	}
}

// TestDiscoveryThatNeverWidensIsFlagged: the seed list can look fine and the
// resulting view still be a partition.
func TestDiscoveryThatNeverWidensIsFlagged(t *testing.T) {
	seeds := []BootstrapPeer{
		seed("a", "198.51.100.1", ""),
		seed("b", "203.0.113.9", ""),
		seed("c", "192.0.2.30", ""),
	}
	discovered := []PeerEntry{{NodeID: "a"}, {NodeID: "b"}, {NodeID: "c"}}
	ws := AuditDiscovered(seeds, discovered)
	if !hasCode(ws, "no-peers-beyond-seeds") {
		t.Fatalf("a view consisting only of the seeds was not flagged: %v", ws)
	}
}

// TestDiscoveryInOnePrefixIsFlagged: seeds spread out, everything they
// introduced concentrated.
func TestDiscoveryInOnePrefixIsFlagged(t *testing.T) {
	seeds := []BootstrapPeer{seed("a", "198.51.100.1", ""), seed("b", "203.0.113.9", "")}
	mk := func(id, addr string) PeerEntry {
		ann, err := Annotate(netip.MustParseAddr(addr))
		if err != nil {
			t.Fatal(err)
		}
		return PeerEntry{NodeID: id, Annotations: []Annotation{ann}}
	}
	discovered := []PeerEntry{
		mk("x", "203.0.113.10"), mk("y", "203.0.113.11"),
		mk("z", "203.0.113.12"), mk("w", "203.0.113.13"),
	}
	ws := AuditDiscovered(seeds, discovered)
	if !hasCode(ws, "discovered-single-prefix") {
		t.Fatalf("a single-prefix discovered set was not flagged: %v", ws)
	}
}
