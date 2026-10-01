package placement

import "testing"

const gib = int64(1) << 30

// EQUAL BYTES, NOT EQUAL PERCENTAGE. This is the choice the whole feature turns
// on, so it is pinned directly: a big node and a small node converge on the same
// absolute occupancy, not on the same fraction of themselves.
//
// Balancing by percentage would send the 200 GB node ten times what it sends
// the 20 GB one, concentrating the network on the machines whose loss costs
// most -- and durability here is counted in DISTINCT HOLDERS, where the small
// volunteer buys a holder-slot just as cheaply.
func TestLevellingTargetsEqualBytesNotEqualPercentages(t *testing.T) {
	level := LevelPools([]Pool{
		{PeerID: "big", Used: 100 * gib, Capacity: 200 * gib},
		{PeerID: "small", Used: 0, Capacity: 20 * gib},
		{PeerID: "middling", Used: 20 * gib, Capacity: 80 * gib},
	})
	// 120 GiB over three nodes is 40 GiB each, except "small" cannot exceed its
	// 20 GiB capacity: it pins there and the remaining 100 GiB is shared by two.
	if level.Target != 50*gib {
		t.Fatalf("target %d bytes, want %d (100 GiB shared by the two uncapped nodes)",
			level.Target, 50*gib)
	}
	for _, node := range level.Nodes {
		switch node.PeerID {
		case "big":
			if node.Role != RoleSource {
				t.Fatalf("the 200 GB node at 100 GiB is %q against a 50 GiB target", node.Role)
			}
		case "small":
			if node.Target != 20*gib {
				t.Fatalf("the 20 GB node's target is %d, want its own capacity", node.Target)
			}
			if node.Role != RoleSink {
				t.Fatalf("the empty 20 GB node is %q, want a sink: a small pool fills FIRST", node.Role)
			}
		case "middling":
			if node.Role != RoleSink {
				t.Fatalf("a node 30 GiB under target is %q", node.Role)
			}
		}
	}
	// The percentage answer would be the opposite ranking: "big" at 50% is
	// fuller than "middling" at 25%, so a percentage-balancing plan would move
	// bytes ONTO the 200 GB node from the 80 GB one. Nothing here does that.
	for _, node := range level.Nodes {
		if node.PeerID == "big" && node.Delta <= 0 {
			t.Fatal("the largest node came out as a sink; this is percentage balancing")
		}
	}
}

// A node at its configured capacity leaves the levelling set rather than
// becoming a permanent deficit nothing can close.
func TestAFullNodeIsPinnedToItsCapacity(t *testing.T) {
	level := LevelPools([]Pool{
		{PeerID: "full", Used: 10 * gib, Capacity: 10 * gib},
		{PeerID: "roomy-a", Used: 40 * gib, Capacity: 500 * gib},
		{PeerID: "roomy-b", Used: 0, Capacity: 500 * gib},
	})
	for _, node := range level.Nodes {
		if node.PeerID != "full" {
			continue
		}
		if node.Target != 10*gib {
			t.Fatalf("a full node's target is %d, want its capacity %d", node.Target, 10*gib)
		}
		if node.Role != RoleBalanced {
			t.Fatalf("a node at exactly its capacity is %q; it can neither shed usefully nor take more",
				node.Role)
		}
	}
}

// The deadband is what stops two nodes a megabyte apart trading shards forever.
func TestTheDeadbandLeavesNearlyLevelNodesAlone(t *testing.T) {
	level := LevelPools([]Pool{
		{PeerID: "a", Used: 21 * gib, Capacity: 500 * gib},
		{PeerID: "b", Used: 19 * gib, Capacity: 500 * gib},
	})
	if level.Target != 20*gib {
		t.Fatalf("target %d, want %d", level.Target, 20*gib)
	}
	if len(level.Sources()) != 0 || len(level.Sinks()) != 0 {
		t.Fatalf("nodes 1 GiB either side of a 20 GiB target (2 GiB band) produced %d source(s) and %d sink(s)",
			len(level.Sources()), len(level.Sinks()))
	}
	// And a difference that is genuinely worth moving is still seen.
	level = LevelPools([]Pool{
		{PeerID: "a", Used: 30 * gib, Capacity: 500 * gib},
		{PeerID: "b", Used: 10 * gib, Capacity: 500 * gib},
	})
	if len(level.Sources()) != 1 || len(level.Sinks()) != 1 {
		t.Fatalf("a 20 GiB gap produced %d source(s) and %d sink(s)",
			len(level.Sources()), len(level.Sinks()))
	}
}

// On a nearly empty network ten percent of the target is a few kilobytes, and
// without a floor the fleet would churn over nothing.
func TestTheDeadbandHasAFloorOnASmallNetwork(t *testing.T) {
	level := LevelPools([]Pool{
		{PeerID: "a", Used: 40 << 20, Capacity: 500 * gib},
		{PeerID: "b", Used: 0, Capacity: 500 * gib},
	})
	if len(level.Sources()) != 0 || len(level.Sinks()) != 0 {
		t.Fatalf("a 40 MiB difference produced %d source(s) and %d sink(s); the floor is %d bytes",
			len(level.Sources()), len(level.Sinks()), MinLevelMove)
	}
}

// A peer with no capacity record is UNKNOWN, not empty. Counting it as empty
// would aim every surplus byte at whichever volunteer runs an older build.
func TestPeersWithNoCapacityRecordAreNotInTheLevellingSet(t *testing.T) {
	level := LevelPools([]Pool{
		{PeerID: "known", Used: 40 * gib, Capacity: 500 * gib},
		{PeerID: "silent"},
	})
	if len(level.Nodes) != 1 || level.Nodes[0].PeerID != "known" {
		t.Fatalf("the levelling set is %#v; a peer with no capacity record must be absent, not empty",
			level.Nodes)
	}
	if len(level.Sinks()) != 0 {
		t.Fatal("a peer that never reported was treated as an empty sink")
	}
}

// WithoutHolder describes the arrangement a move would leave behind, so the
// durability question is asked with the same primitives that answer it
// everywhere else.
func TestWithoutHolderDropsOnlyThatPeersCopyOfThatShard(t *testing.T) {
	shards := []Shard{
		{ID: "aa", Index: 0, Holders: []string{"p1", "p2"}},
		{ID: "bb", Index: 1, Holders: []string{"p1"}},
	}
	after := WithoutHolder(shards, "aa", "p1")
	if len(after[0].Holders) != 1 || after[0].Holders[0] != "p2" {
		t.Fatalf("shard aa now has holders %v, want only p2", after[0].Holders)
	}
	if len(after[1].Holders) != 1 || after[1].Holders[0] != "p1" {
		t.Fatalf("shard bb lost a holder it was not asked about: %v", after[1].Holders)
	}
	if len(shards[0].Holders) != 2 {
		t.Fatal("WithoutHolder mutated the caller's snapshot")
	}
	if DistinctHolders(after) != 2 {
		t.Fatalf("distinct holders after the projection is %d, want 2", DistinctHolders(after))
	}
}
