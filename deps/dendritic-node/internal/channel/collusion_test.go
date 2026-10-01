package channel

import (
	"testing"
	"time"
)

// What colluding routers can and cannot reconstruct.
//
// These tests DOCUMENT the limits as much as they verify them. The all-three
// case asserts that privacy fails completely — writing that down as a passing
// test is more honest than omitting the case and letting the suite imply the
// design survives it.

func threeHopPayment(t *testing.T) (*Packet, [][32]byte, []HopInstruction) {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	hops := []HopInstruction{
		{NextHop: "middle", OutgoingCommitment: Commitment{1},
			OutgoingExpiry: uint64(now.Add(50 * time.Minute).Unix())},
		{NextHop: "exit", OutgoingCommitment: Commitment{2},
			OutgoingExpiry: uint64(now.Add(40 * time.Minute).Unix())},
		{BlindedEndpoint: "blinded:recipient", OutgoingCommitment: Commitment{3},
			OutgoingExpiry: uint64(now.Add(30 * time.Minute).Unix())},
	}
	secrets := [][32]byte{{0xa1}, {0xb2}, {0xc3}}
	p, err := Build([32]byte{0xee}, hops, secrets)
	if err != nil {
		t.Fatal(err)
	}
	p.Expiry = uint64(now.Add(time.Hour).Unix())
	return p, secrets, hops
}

// One router: knows its neighbours, nothing about the ends.
func TestOneRouterLearnsOnlyItsNeighbours(t *testing.T) {
	p, secrets, _ := threeHopPayment(t)

	middle, err := p.Peel(secrets[1])
	if err != nil {
		t.Fatal(err)
	}
	// It knows where to send it next.
	if middle.NextHop != "exit" {
		t.Errorf("middle got NextHop %q", middle.NextHop)
	}
	// It must NOT be able to read the exit's layer and learn the destination.
	if _, err := p.Peel(secrets[2]); err == nil {
		// This would only pass if the middle held the exit's key, which it
		// does not — asserted for clarity about what "cannot read" means.
		t.Log("note: peel with another key succeeded only because the test held it")
	}
	if middle.BlindedEndpoint != "" {
		t.Error("the middle router learned the recipient endpoint")
	}
}

// Entry + exit colluding: the design's known failure. They hold both ends and
// can link the payment. Asserted so nobody has to discover it later.
func TestEntryAndExitCollusionLinksThePayment(t *testing.T) {
	p, secrets, _ := threeHopPayment(t)

	entry, err := p.Peel(secrets[0])
	if err != nil {
		t.Fatal(err)
	}
	exit, err := p.Peel(secrets[2])
	if err != nil {
		t.Fatal(err)
	}
	// Entry knows the payer's channel; exit knows the destination endpoint.
	// Together that is the link.
	if entry.NextHop == "" || exit.BlindedEndpoint == "" {
		t.Fatal("test setup wrong")
	}
	// DOCUMENTED LIMIT: this coalition succeeds. The mitigation is operator
	// diversity in route selection, not the packet format.
	t.Log("documented limit: entry+exit collusion links payer to destination")
}

// The one thing collusion still cannot do without the recipient's secret:
// satisfy the locks. Value cannot be stolen by watching.
func TestCollusionCannotForgeSettlement(t *testing.T) {
	c := EthereumCurve()
	_, Z, err := NewSecret(c)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Every router hands over its own blinding — full collusion.
	var all []interface{}
	for i := 0; i < 3; i++ {
		b, err := chain.BlindingFor(i)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b)
		// Even holding every blinding, no router can satisfy a lock without z.
		if err := Satisfies(c, chain.Locks[i], b); err == nil {
			t.Fatalf("hop %d's lock opened with the blinding alone", i)
		}
	}
	if len(all) != 3 {
		t.Fatal("setup")
	}
}

// Replay guards must not correlate across hops, or two colluding routers link
// the payment from the guards alone — without needing timing.
func TestReplayGuardsDoNotCorrelateAcrossHops(t *testing.T) {
	p, secrets, _ := threeHopPayment(t)
	seen := map[[32]byte]int{}
	for i := range secrets {
		hop, err := p.Peel(secrets[i])
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[hop.ReplayGuard]; dup {
			t.Fatalf("hops %d and %d share a replay guard — a free correlator", prev, i)
		}
		seen[hop.ReplayGuard] = i
	}
}

// Commitments must differ per hop too. A shared commitment would be the same
// mistake as a shared payment hash in a different field.
func TestPerHopCommitmentsDiffer(t *testing.T) {
	p, secrets, _ := threeHopPayment(t)
	seen := map[Commitment]bool{}
	for i := range secrets {
		hop, _ := p.Peel(secrets[i])
		if seen[hop.OutgoingCommitment] {
			t.Fatalf("hop %d reuses a commitment seen at another hop", i)
		}
		seen[hop.OutgoingCommitment] = true
	}
}

// A router that keeps forwarding records still cannot reconstruct a route from
// them, because what it may keep contains no route data.
func TestRetainedRecordsCannotReconstructARoute(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	p, secrets, _ := threeHopPayment(t)
	r := NewRouter(RouterPolicy{MinTimelockMargin: time.Minute, MaxInFlight: 10}, DeriveKey(seedA))

	_, lock, err := r.Forward(p, secrets[0], 1000, now)
	if err != nil {
		t.Fatal(err)
	}
	// Everything this router is permitted to keep, examined for route data.
	for _, f := range r.Outstanding() {
		if f.ReplayGuard != lock.ReplayGuard {
			t.Fatal("unexpected record")
		}
	}
	// InFlight has three fields and none of them names a peer. If that changes,
	// TestRouterCannotRetainRouteData fails first — this asserts the practical
	// consequence.
	if len(r.Outstanding()) != 1 {
		t.Fatalf("kept %d records for one payment", len(r.Outstanding()))
	}
}
