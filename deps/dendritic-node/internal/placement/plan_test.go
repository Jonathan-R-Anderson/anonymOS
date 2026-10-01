package placement

import (
	"fmt"
	"testing"
)

func chunkOf(count int, size int64) []Shard {
	shards := make([]Shard, count)
	for i := range shards {
		shards[i] = Shard{ID: fmt.Sprintf("shard-%02d", i), Index: i, Size: size}
	}
	return shards
}

func peers(count int) []Candidate {
	out := make([]Candidate, count)
	for i := range out {
		out[i] = Candidate{PeerID: fmt.Sprintf("peer-%02d", i), FreeBytes: int64(1_000_000 + i)}
	}
	return out
}

// THE property. Two shards of one chunk on one node means losing that node
// costs two of the three parity shards, so 6+3 silently becomes 6+1.
func TestPlanNeverPutsTwoShardsOfAChunkOnOneNode(t *testing.T) {
	for _, peerCount := range []int{1, 2, 3, 5, 8, 9, 12} {
		t.Run(fmt.Sprintf("%d-peers", peerCount), func(t *testing.T) {
			assignments := Plan(chunkOf(9, 175_000), peers(peerCount), 1)
			seen := map[string]string{}
			for _, assignment := range assignments {
				if previous, clash := seen[assignment.Peer]; clash {
					t.Fatalf("%s was given shard %s and shard %s of the same chunk",
						assignment.Peer, previous, assignment.ShardID)
				}
				seen[assignment.Peer] = assignment.ShardID
			}
			// Fewer peers than shards must yield FEWER assignments, never
			// doubled-up ones: an unplaced shard is a visible deficit the repair
			// loop retires, a doubled-up shard is a false durability claim.
			want := peerCount
			if want > 9 {
				want = 9
			}
			if len(assignments) != want {
				t.Fatalf("planned %d assignments for %d peers, want %d",
					len(assignments), peerCount, want)
			}
		})
	}
}

// A peer already holding a shard of the chunk must not be handed another one,
// which is the case repair hits: it re-places regenerated shards while the
// surviving holders are still in the ledger.
func TestPlanExcludesPeersAlreadyHoldingASibling(t *testing.T) {
	shards := chunkOf(9, 1000)
	shards[0].Holders = []string{"peer-00"}
	shards[1].Holders = []string{"peer-01"}
	shards[2].Holders = []string{"peer-02"}

	assignments := Plan(shards, peers(9), 1)
	if len(assignments) != 6 {
		t.Fatalf("planned %d assignments, want the 6 shards that have no holder", len(assignments))
	}
	for _, assignment := range assignments {
		switch assignment.Peer {
		case "peer-00", "peer-01", "peer-02":
			t.Fatalf("%s already holds a shard of this chunk", assignment.Peer)
		}
		if assignment.ShardIndex < 3 {
			t.Fatalf("shard %d already had a holder and was planned again", assignment.ShardIndex)
		}
	}
}

// A peer that cannot fit the shard is skipped rather than tried and failed.
// Zero free space means "unknown" (a connected peer with no capacity record),
// which stays usable so a young network with an empty directory still disperses.
func TestPlanSkipsPeersWithoutRoomButKeepsUnknownCapacity(t *testing.T) {
	candidates := []Candidate{
		{PeerID: "full", FreeBytes: 10},
		{PeerID: "unknown", FreeBytes: 0},
		{PeerID: "roomy", FreeBytes: 1 << 30},
	}
	assignments := Plan(chunkOf(3, 1_000_000), candidates, 1)
	if len(assignments) != 2 {
		t.Fatalf("planned %d assignments, want 2", len(assignments))
	}
	for _, assignment := range assignments {
		if assignment.Peer == "full" {
			t.Fatal("planned a shard onto a peer with 10 bytes free")
		}
	}
}

// Emptiest-first, so writes spread toward nodes with room instead of refilling
// whichever peer answered first.
func TestPlanPrefersTheEmptiestPeer(t *testing.T) {
	candidates := []Candidate{
		{PeerID: "small", FreeBytes: 1 << 20},
		{PeerID: "large", FreeBytes: 1 << 40},
	}
	assignments := Plan(chunkOf(1, 1000), candidates, 1)
	if len(assignments) != 1 || assignments[0].Peer != "large" {
		t.Fatalf("planned %#v, want the shard on the peer with the most room", assignments)
	}
}

// RemotelyRecoverable answers "can the chunk be decoded off this node AT ALL",
// which is counted in distinct shard INDEXES: two copies of index 4 rebuild
// nothing one copy does not. It is NOT the durability question -- see
// TestSurvivingIndexesIsBoundedByHolders -- because it says nothing about how
// many machines have to fail before the answer changes.
func TestRemotelyRecoverableCountsDistinctIndexes(t *testing.T) {
	shards := chunkOf(9, 1000)
	for i := 0; i < 5; i++ {
		shards[i].Holders = []string{fmt.Sprintf("peer-%02d", i)}
	}
	if RemotelyRecoverable(shards, 6) {
		t.Fatal("5 remote indexes of a 6+3 object claimed to be recoverable")
	}
	shards[5].Holders = []string{"peer-05"}
	if !RemotelyRecoverable(shards, 6) {
		t.Fatal("6 remote indexes of a 6+3 object should be recoverable")
	}
	if got := DistinctHolders(shards); got != 6 {
		t.Fatalf("DistinctHolders = %d, want 6", got)
	}
}

// The property the durability metric has to have: nine indexes placed says
// nothing on its own, and everything once you ask how many machines they are
// on. Same nine placements, three arrangements, three different answers.
func TestSurvivingIndexesIsBoundedByHolders(t *testing.T) {
	onePeer := chunkOf(9, 1000)
	for i := range onePeer {
		onePeer[i].Holders = []string{"peer-00"}
	}
	if got := RemoteIndexCount(onePeer); got != 9 {
		t.Fatalf("RemoteIndexCount = %d, want the 9 that make the old metric wrong", got)
	}
	if got := SurvivingIndexes(onePeer, 1); got != 0 {
		t.Fatalf("SurvivingIndexes after one loss = %d, want 0: it was all on one machine", got)
	}
	if SurvivesHolderLosses(onePeer, 6, 1) {
		t.Fatal("nine shards on one peer claimed to survive that peer going away")
	}

	spread := chunkOf(9, 1000)
	for i := range spread {
		spread[i].Holders = []string{fmt.Sprintf("peer-%02d", i)}
	}
	if got := SurvivingIndexes(spread, 3); got != 6 {
		t.Fatalf("SurvivingIndexes after three losses = %d, want the 6 that decode", got)
	}
	if !SurvivesHolderLosses(spread, 6, 3) {
		t.Fatal("nine shards on nine peers should tolerate the three losses parity pays for")
	}
	if SurvivesHolderLosses(spread, 6, 4) {
		t.Fatal("6+3 claimed to survive four simultaneous losses")
	}

	// Nine indexes on six peers, four of them on one: the count of placements is
	// unchanged and the object is one machine away from undecodable.
	lumpy := chunkOf(9, 1000)
	for i := range lumpy {
		if i < 4 {
			lumpy[i].Holders = []string{"peer-00"}
			continue
		}
		lumpy[i].Holders = []string{fmt.Sprintf("peer-%02d", i)}
	}
	if got := DistinctHolders(lumpy); got != 6 {
		t.Fatalf("DistinctHolders = %d, want 6", got)
	}
	if got := SurvivingIndexes(lumpy, 1); got != 5 {
		t.Fatalf("SurvivingIndexes after one loss = %d, want 5: one short of a decode", got)
	}
	if SurvivesHolderLosses(lumpy, 6, 1) {
		t.Fatal("a chunk with four of nine shards on one peer claimed to survive its loss")
	}
}

// Several holders per index is the case the exact search exists for: a peer
// leaving costs nothing while another peer still has the same index, and a
// count of "indexes minus the biggest holder" would call this fatal.
func TestSurvivingIndexesCreditsIndexesHeldTwice(t *testing.T) {
	shards := chunkOf(9, 1000)
	for i := range shards {
		shards[i].Holders = []string{"peer-a", "peer-b"}
	}
	if got := SurvivingIndexes(shards, 1); got != 9 {
		t.Fatalf("SurvivingIndexes after one loss = %d, want 9: every index has a second holder", got)
	}
	if got := SurvivingIndexes(shards, 2); got != 0 {
		t.Fatalf("SurvivingIndexes after two losses = %d, want 0: there were only two machines", got)
	}
}

// Plan refuses to CREATE co-location but cannot undo it, and a chunk that
// arrives crowded is fully placed -- so an ordinary plan has nothing to do and
// the object would stay under-replicated forever with no move that improves it.
func TestCrowdedChunkGetsItsSurplusIndexesASecondHolder(t *testing.T) {
	shards := chunkOf(9, 1000)
	for i := range shards {
		if i < 4 {
			shards[i].Holders = []string{"peer-crowded"}
			continue
		}
		shards[i].Holders = []string{fmt.Sprintf("peer-%02d", i)}
	}
	replanned := WithoutCrowdedHolders(shards)
	unplaced := 0
	for i, shard := range replanned {
		if len(shard.Holders) == 0 {
			unplaced++
			continue
		}
		if i >= 4 && shard.Holders[0] != fmt.Sprintf("peer-%02d", i) {
			t.Fatalf("shard %d lost its own holder", i)
		}
	}
	if unplaced != 3 {
		t.Fatalf("%d shards look unplaced, want the 3 surplus ones on peer-crowded", unplaced)
	}
	// The ledger is untouched: the crowded peer is still a holder and still
	// serves reads.
	if len(shards[1].Holders) != 1 || shards[1].Holders[0] != "peer-crowded" {
		t.Fatal("WithoutCrowdedHolders mutated the chunk it was given")
	}

	assignments := Plan(replanned, peers(12), 1)
	if len(assignments) != 3 {
		t.Fatalf("planned %d assignments, want a fresh holder for each surplus index", len(assignments))
	}
	for _, assignment := range assignments {
		if assignment.Peer == "peer-crowded" {
			t.Fatal("the surplus index was planned back onto the peer that was already crowded")
		}
	}
	// And the arrangement it produces is the one that survives a loss.
	for _, assignment := range assignments {
		shards[assignment.ShardIndex].Holders = append(shards[assignment.ShardIndex].Holders, assignment.Peer)
	}
	if !SurvivesHolderLosses(shards, 6, 1) {
		t.Fatal("after re-placing the surplus indexes the chunk still dies with one node")
	}
}

// A chunk of uniform bytes produces several indexes with the SAME content
// address, and a peer holding those bytes holds all of them. That is not
// crowding, and re-sending the same shard id elsewhere buys nothing.
func TestAliasedShardsAreNotTreatedAsCrowding(t *testing.T) {
	shards := make([]Shard, 6)
	for i := range shards {
		shards[i] = Shard{ID: "same-bytes", Index: i, Size: 1000, Holders: []string{"peer-00"}}
	}
	for i, shard := range WithoutCrowdedHolders(shards) {
		if len(shard.Holders) != 1 {
			t.Fatalf("index %d of an all-identical chunk was called surplus", i)
		}
	}
}
