package store

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// heldByPeer gives every shard of an object one confirmed holder, and puts the
// named peer on one of them -- the arrangement a drain has to unpick.
func drainableObject(t *testing.T, storage *Store, key string, seed int64, holders int) ObjectPlacement {
	t.Helper()
	manifest, err := storage.PutObject("dispersal", key, "application/octet-stream",
		bytes.NewReader(distinctBytes(seed, 200<<10)))
	if err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range row.Shards {
		for copyIndex := 0; copyIndex < holders; copyIndex++ {
			peerID := fmt.Sprintf("peer-%d-%d", shard.ShardIndex, copyIndex)
			if err := storage.ConfirmShardHolder(manifest.ObjectID, shard.ShardID, peerID); err != nil {
				t.Fatal(err)
			}
		}
	}
	fresh, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	return *fresh
}

// A DRAIN MUST RESUME WHERE IT LEFT OFF, ACROSS A RESTART.
//
// A drain of a full node is hours of work, and the operator running it is by
// definition about to restart or power down machines. If the position were held
// in memory, every restart would start again at the top of the bolt bucket:
// the same first objects would be re-examined forever and the tail of the ledger
// would never be reached, so a drain could run all week and leave shards on the
// machine somebody then unplugged.
//
// The position is ObjectPlacement.LastDrain, its own clock, written by
// MarkDrainAttempt. Here the store is CLOSED and REOPENED from the same
// directory between the two passes, which is the restart.
//
// Reverted to prove it fails: the `row.LastDrain = time.Now()` assignment in
// MarkDrainAttempt. The reopened store then hands back the object that was
// already attempted, and the second object is never reached.
func TestADrainResumesAfterARestart(t *testing.T) {
	dir := t.TempDir()
	storage, err := Open(dir, 6, 3, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateBucket("dispersal"); err != nil {
		t.Fatal(err)
	}
	first := drainableObject(t, storage, "first.bin", 41, 1)
	second := drainableObject(t, storage, "second.bin", 42, 1)
	leaving := map[string]bool{"peer-0-0": true}

	queued, err := storage.DrainCandidates(leaving, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 2 {
		t.Fatalf("the queue offered %d object(s) with a shard on the retiring peer, want 2", len(queued))
	}
	// One pass gets through the first object and the process ends there.
	if err := storage.MarkDrainAttempt(first.ObjectID); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	// THE RESTART.
	storage, err = Open(dir, 6, 3, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })

	resumed, err := storage.DrainCandidates(leaving, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed) != 1 || resumed[0].ObjectID != second.ObjectID {
		ids := make([]string, 0, len(resumed))
		for _, row := range resumed {
			ids = append(ids, row.ObjectID[:12])
		}
		t.Fatalf("after a restart the drain offered %v; it must continue with the object it never reached (%s), not repeat %s",
			ids, second.ObjectID[:12], first.ObjectID[:12])
	}

	// And a drain is a SCHEDULE, not a terminal state: once the cooldown has
	// elapsed the first object comes back, because a shard that could not move
	// this hour may well move next hour and an object dropped for good would be
	// one nobody ever counts again.
	both, err := storage.DrainCandidates(leaving, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(both) != 2 {
		t.Fatalf("with the cooldown elapsed the drain offered %d object(s), want both back", len(both))
	}
	// Least recently attempted first, so the one that has never been looked at
	// leads and the one already attempted follows. That ordering is what stops a
	// stuck object monopolising every pass.
	if both[0].ObjectID != second.ObjectID || both[1].ObjectID != first.ObjectID {
		t.Fatalf("the drain queue is not least-recently-attempted first: it offered %s then %s",
			both[0].ObjectID[:12], both[1].ObjectID[:12])
	}
}

// AN UNDER-REPLICATED OBJECT IS QUEUED FOR A DRAIN, AND THIS IS THE DELIBERATE
// OPPOSITE OF THE LEVELLING QUEUE.
//
// RebalanceCandidates drops it, correctly: tidying an object that still owes the
// network a holder is work taken from the loop trying to make it whole. A drain
// cannot afford the same rule. The holder is LEAVING whether or not anything is
// done about it, so an object that is already short is precisely the one the
// operator has to be told about before they reach for the power switch. It still
// will not be moved -- the mover's per-chunk durability gate refuses that and
// reports it -- but it has to reach the mover to be reported at all.
//
// Reverted to prove it fails: adding `if row.UnderReplicated() { return nil }` to
// DrainCandidates, the way the levelling queue has it. The short object then
// vanishes from the drain entirely and its shards are never counted or reported.
func TestTheDrainQueueIncludesAnUnderReplicatedObject(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "thin.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(43, 200<<10)))
	if err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	// Three of nine shards placed, one of them on the retiring peer: under the
	// decode threshold, so under any durability claim.
	for i, shard := range row.Shards {
		if i >= 3 {
			break
		}
		if err := storage.ConfirmShardHolder(manifest.ObjectID, shard.ShardID,
			fmt.Sprintf("thin-peer-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	thin, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !thin.UnderReplicated() {
		t.Fatalf("setup: three holders of nine shards reports durable: %#v", thin)
	}
	leaving := map[string]bool{"thin-peer-0": true}

	queued, err := storage.DrainCandidates(leaving, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range queued {
		if candidate.ObjectID == thin.ObjectID {
			found = true
		}
	}
	if !found {
		t.Fatal("an under-replicated object with a shard on a retiring node was not queued for the drain; its shards would leave with the machine and nothing would ever say so")
	}

	// The levelling queue still refuses it, so the two queues have not quietly
	// become one rule.
	levelled, err := storage.RebalanceCandidates(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range levelled {
		if candidate.ObjectID == thin.ObjectID {
			t.Fatal("the levelling queue took an under-replicated object; draining and levelling must not share a queue policy")
		}
	}
}

// The remaining count is what an operator acts on, so it counts what is THERE
// rather than what a pass happened to look at.
func TestShardsRecordedOnCountsTheWholeLedger(t *testing.T) {
	storage := openProductionShapedStore(t)
	first := drainableObject(t, storage, "first.bin", 44, 1)
	drainableObject(t, storage, "second.bin", 45, 1)

	// The object is several chunks long, so the peer holding shard index 0 holds
	// one shard PER CHUNK. The count is of shards, not of indexes, because a
	// shard is what has to be moved.
	perObject := len(first.ChunkIndexes())
	if perObject < 2 {
		t.Fatalf("setup: expected a multi-chunk object, got %d chunk(s)", perObject)
	}
	remaining, err := storage.ShardsRecordedOn(map[string]bool{"peer-0-0": true})
	if err != nil {
		t.Fatal(err)
	}
	if remaining.Objects != 2 || remaining.Shards != 2*perObject {
		t.Fatalf("remaining is %#v; the peer holds %d shard(s) of each of two objects",
			remaining, perObject)
	}
	if remaining.Bytes <= 0 {
		t.Fatalf("remaining reports %d bytes on a peer holding %d shards", remaining.Bytes, remaining.Shards)
	}

	// Dropping the holder is what a completed move does to the ledger.
	for _, shard := range first.Shards {
		for _, holder := range shard.Holders {
			if holder == "peer-0-0" {
				if err := storage.DropShardHolder(first.ObjectID, shard.ShardID, holder); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	after, err := storage.ShardsRecordedOn(map[string]bool{"peer-0-0": true})
	if err != nil {
		t.Fatal(err)
	}
	if after.Objects != 1 || after.Shards != perObject {
		t.Fatalf("after one object's shards moved off, remaining is %#v, want one object and %d shard(s)",
			after, perObject)
	}
	if none, err := storage.ShardsRecordedOn(nil); err != nil || none.Shards != 0 {
		t.Fatalf("counting an empty leaving-set gave %#v, %v", none, err)
	}
}

// The draining node's own number is the one the operator standing at the machine
// trusts, and it must come from what is on the disk rather than from what any
// owner believes.
func TestHeldForOthersCountsShardsHeldForOtherPeers(t *testing.T) {
	storage := openTestStore(t)
	held, err := storage.HeldForOthers()
	if err != nil {
		t.Fatal(err)
	}
	if held.Shards != 0 {
		t.Fatalf("a fresh store reports holding %d shard(s) for other peers", held.Shards)
	}

	value := distinctBytes(46, 4096)
	shardID := digest(value)
	if err := storage.PutRemoteShard(RemoteShard{
		ID: shardID, ObjectID: stringOfByte('a', 64), Size: int64(len(value)),
	}, value); err != nil {
		t.Fatal(err)
	}
	held, err = storage.HeldForOthers()
	if err != nil {
		t.Fatal(err)
	}
	if held.Shards != 1 || held.Bytes != int64(len(value)) {
		t.Fatalf("holding one 4 KiB shard for another peer reports %#v", held)
	}

	// A local object of this node's own is NOT counted: it is not somebody
	// else's shard to be recalled, and counting it would mean the number never
	// reaches zero and the operator is never told they may switch off.
	if _, err := storage.PutObject("local", "own.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(47, 200<<10))); err == nil {
		held, err = storage.HeldForOthers()
		if err != nil {
			t.Fatal(err)
		}
		if held.Shards != 1 {
			t.Fatalf("this node's own object was counted as held for other peers: %#v", held)
		}
	}
}
