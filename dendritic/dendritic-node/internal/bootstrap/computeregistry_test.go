package bootstrap

import (
	"testing"
	"time"
)

var rgNow = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func liveDoc() Document {
	d := doc()
	d.ExpiresAt = rgNow.Add(20 * time.Minute)
	return d
}

func TestRegistryHoldsReachablePeersOnly(t *testing.T) {
	r := NewComputeRegistry()
	r.Update(liveDoc(), rgNow)
	for _, p := range r.Candidates("cpu", false, rgNow) {
		if !p.Reachable() {
			t.Fatal("an unreachable peer became a candidate")
		}
	}
}

// THE staleness rule. Acting on an expired listing dispatches confidently to
// peers that may be long gone, and the failure reads as "compute is broken"
// rather than "my directory is old".
func TestExpiredListingYieldsNoCandidates(t *testing.T) {
	r := NewComputeRegistry()
	r.Update(liveDoc(), rgNow)
	if len(r.Candidates("cpu", false, rgNow)) == 0 {
		t.Fatal("a live listing yielded nothing")
	}
	after := rgNow.Add(time.Hour)
	if got := r.Candidates("cpu", false, after); got != nil {
		t.Fatalf("an expired listing yielded %d candidates", len(got))
	}
	if !r.Stale(after) {
		t.Error("an expired registry did not report itself stale")
	}
}

// A registry that has never been updated must not look healthy.
func TestUnrefreshedRegistryIsStale(t *testing.T) {
	r := NewComputeRegistry()
	if !r.Stale(rgNow) {
		t.Fatal("a registry that never fetched anything reported fresh")
	}
	if got := r.Candidates("cpu", false, rgNow); got != nil {
		t.Fatal("an empty registry produced candidates")
	}
}

// Refresh REPLACES. Merging would build a list that only grows, so a node that
// left months ago stays a candidate forever and every dispatch to it wastes a
// round trip over I2P.
func TestRefreshReplacesRatherThanAccumulates(t *testing.T) {
	r := NewComputeRegistry()
	r.Update(liveDoc(), rgNow)
	before := len(r.Candidates("cpu", false, rgNow))

	shrunk := Document{
		Compute:   []ComputePeer{{NodeID: "cpu1", Destination: "d1", CPU: true}},
		ExpiresAt: rgNow.Add(20 * time.Minute),
	}
	r.Update(shrunk, rgNow)
	after := r.Candidates("cpu", false, rgNow)
	if len(after) >= before {
		t.Fatalf("refresh accumulated: %d then %d", before, len(after))
	}
	if len(after) != 1 || after[0].NodeID != "cpu1" {
		t.Fatalf("registry did not replace: %v", ids(after))
	}
}

// Two nodes holding the same document must derive the same candidate order, or
// a disputed placement cannot be re-derived.
func TestCandidateOrderIsReproducible(t *testing.T) {
	a, b := NewComputeRegistry(), NewComputeRegistry()
	d := liveDoc()
	a.Update(d, rgNow)
	// Same peers, opposite order in the document.
	reversed := d
	reversed.Compute = append([]ComputePeer(nil), d.Compute...)
	for i, j := 0, len(reversed.Compute)-1; i < j; i, j = i+1, j-1 {
		reversed.Compute[i], reversed.Compute[j] = reversed.Compute[j], reversed.Compute[i]
	}
	b.Update(reversed, rgNow)

	x, y := a.Candidates("cpu", false, rgNow), b.Candidates("cpu", false, rgNow)
	if len(x) != len(y) {
		t.Fatalf("different counts: %d vs %d", len(x), len(y))
	}
	for i := range x {
		if x[i].NodeID != y[i].NodeID {
			t.Fatalf("order differs at %d: %s vs %s", i, x[i].NodeID, y[i].NodeID)
		}
	}
}

// The summary is counts, never a peer list: a node UI showing every peer would
// publish the network's membership to anyone who opened it.
func TestSummaryReportsCountsNotPeers(t *testing.T) {
	r := NewComputeRegistry()
	r.Update(liveDoc(), rgNow)
	s := r.Summarise(rgNow)
	if s.Total != 4 || s.MicroVM != 2 {
		t.Fatalf("summary = %+v", s)
	}
	if s.Expired {
		t.Error("a live registry reported expired")
	}
}
