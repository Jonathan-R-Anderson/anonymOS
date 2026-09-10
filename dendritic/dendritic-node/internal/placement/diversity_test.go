package placement

import (
	"fmt"
	"testing"
)

// T12.2 — "the same holds for shard placement, which is the half that regresses
// silently."
//
// It regresses silently because a placement that co-locates two shards still
// works: reads succeed, writes succeed, the dashboard shows nine shards placed.
// The defect appears only when the shared domain fails, and by then the object
// is gone. Nothing short of a test on the assignment itself catches it.

func shards(n int, size int64) []Shard {
	out := make([]Shard, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Shard{ID: fmt.Sprintf("s%d", i), Index: i, Size: size})
	}
	return out
}

// TestT122NoTwoShardsShareAFailureDomain is T12.2.
//
// Nine peers, so distinct-PEER is trivially satisfiable — and only three /24s.
// The old guarantee places all nine; the domain guarantee places three and
// leaves six unplaced, because an unplaced shard is a visible deficit and a
// co-located one is a durability claim that is quietly false.
func TestT122NoTwoShardsShareAFailureDomain(t *testing.T) {
	var cands []Candidate
	for i := 0; i < 9; i++ {
		cands = append(cands, Candidate{
			PeerID:    fmt.Sprintf("p%d", i),
			FreeBytes: 1 << 30,
			Domains:   []string{fmt.Sprintf("p:10.%d.0.0/24", i%3)},
		})
	}
	got := Plan(shards(9, 1<<20), cands, 1)

	if len(got) != 3 {
		t.Fatalf("placed %d shards across 3 failure domains, want 3", len(got))
	}
	seen := map[string]bool{}
	byPeer := map[string][]string{}
	for _, c := range cands {
		byPeer[c.PeerID] = c.Domains
	}
	for _, a := range got {
		for _, k := range byPeer[a.Peer] {
			if seen[k] {
				t.Fatalf("T12.2 violated: two shards of one chunk in domain %s", k)
			}
			seen[k] = true
		}
	}

	// The control: without domains, the same nine peers take all nine shards.
	// If this ever placed fewer, the constraint would be firing on peers that
	// declare nothing, and dispersal would stop on a network with no
	// annotations at all.
	for i := range cands {
		cands[i].Domains = nil
	}
	if got := Plan(shards(9, 1<<20), cands, 1); len(got) != 9 {
		t.Fatalf("unannotated peers placed %d of 9 shards", len(got))
	}
}

// TestT122OperatorRungInPlacement is P12b's MaxPerOperatorInReplicaSet = 1.
//
// Nine peers in nine distinct /24s and nine distinct ASes — every address-level
// rung satisfied — owned by three people. §7.2's point, in the storage layer.
func TestT122OperatorRungInPlacement(t *testing.T) {
	var cands []Candidate
	for i := 0; i < 9; i++ {
		cands = append(cands, Candidate{
			PeerID:    fmt.Sprintf("p%d", i),
			FreeBytes: 1 << 30,
			Domains: []string{
				fmt.Sprintf("p:10.%d.0.0/24", i),
				fmt.Sprintf("a:%d", 64512+i),
				fmt.Sprintf("o:0x%02x", i%3),
			},
		})
	}
	got := Plan(shards(9, 1<<20), cands, 1)
	if len(got) != 3 {
		t.Fatalf("placed %d shards across 3 operators, want 3", len(got))
	}
	owners := map[string]bool{}
	for _, a := range got {
		var idx int
		fmt.Sscanf(a.Peer, "p%d", &idx)
		o := fmt.Sprintf("o:0x%02x", idx%3)
		if owners[o] {
			t.Fatalf("two shards of one chunk owned by %s", o)
		}
		owners[o] = true
	}
}

// TestExistingHoldersReserveTheirDomains checks the half that is easy to miss.
//
// A repair pass sees a chunk with some shards already placed. If the domains of
// the EXISTING holders are not reserved, the repair happily adds a new shard in
// a domain that already holds one, and every repair makes the chunk slightly
// less survivable while reporting success.
func TestExistingHoldersReserveTheirDomains(t *testing.T) {
	cands := []Candidate{
		{PeerID: "old", FreeBytes: 1 << 30, Domains: []string{"p:10.0.0.0/24"}},
		{PeerID: "same", FreeBytes: 1 << 30, Domains: []string{"p:10.0.0.0/24"}},
		{PeerID: "other", FreeBytes: 1 << 30, Domains: []string{"p:10.9.0.0/24"}},
	}
	sh := []Shard{
		{ID: "a", Index: 0, Size: 1 << 20, Holders: []string{"old"}},
		{ID: "b", Index: 1, Size: 1 << 20},
	}
	got := Plan(sh, cands, 1)
	if len(got) != 1 {
		t.Fatalf("planned %d assignments, want 1", len(got))
	}
	if got[0].Peer != "other" {
		t.Fatalf("repair placed on %s, which shares a /24 with the existing holder", got[0].Peer)
	}
}

// TestDomainsUnavailableIsCounted is the storage layer's honesty report.
func TestDomainsUnavailableIsCounted(t *testing.T) {
	cands := []Candidate{
		{PeerID: "a", Domains: []string{"p:10.0.0.0/24"}},
		{PeerID: "b"},
		{PeerID: "c"},
	}
	if n := DomainsUnavailable(cands); n != 2 {
		t.Fatalf("DomainsUnavailable = %d, want 2", n)
	}
}
