package store

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// levelledObject writes a 6+3 object and gives every shard `holders` distinct
// confirmed peers, which is how a durable object looks in the ledger.
func levelledObject(t *testing.T, storage *Store, key string, holders int) ObjectPlacement {
	t.Helper()
	manifest, err := storage.PutObject("dispersal", key, "application/octet-stream",
		bytes.NewReader(distinctBytes(31, 200<<10)))
	if err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	// One distinct peer per shard index, so no peer holds two shards of a
	// chunk -- the arrangement everything downstream assumes.
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

// LEVELLING IS THE LOWEST-PRIORITY MOVER, and this is where that is enforced
// first: an object that still owes the network a holder never enters the queue.
// Getting it to the durability threshold beats tidying the pools it sits on.
//
// Reverted to prove it fails: the UnderReplicated check in RebalanceCandidates.
// The under-replicated object is then queued for levelling.
func TestRebalanceQueueSkipsAnUnderReplicatedObject(t *testing.T) {
	storage := openProductionShapedStore(t)
	durable := levelledObject(t, storage, "durable.bin", 1)
	if durable.UnderReplicated() {
		t.Fatalf("setup: nine shards on nine distinct peers reports under-replicated: %#v", durable)
	}

	// The second object gets holders for only three of its nine shards, which
	// is under the decode threshold and therefore under any durability claim.
	manifest, err := storage.PutObject("dispersal", "thin.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(32, 200<<10)))
	if err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
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

	queued, err := storage.RebalanceCandidates(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range queued {
		if candidate.ObjectID == thin.ObjectID {
			t.Fatal("an under-replicated object was queued for levelling; it belongs to dispersal until it reaches the threshold")
		}
	}
	if len(queued) != 1 || queued[0].ObjectID != durable.ObjectID {
		t.Fatalf("the queue holds %d object(s); want only the durable one", len(queued))
	}
}

// An object with nothing on any peer has nothing to level.
func TestRebalanceQueueSkipsAnObjectWithNoRemoteHolder(t *testing.T) {
	storage := openProductionShapedStore(t)
	if _, err := storage.PutObject("dispersal", "local.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(33, 200<<10))); err != nil {
		t.Fatal(err)
	}
	queued, err := storage.RebalanceCandidates(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 0 {
		t.Fatalf("queued %d object(s) with no remote holder to move", len(queued))
	}
}

// THE COOLDOWN IS PERSISTED, and on its OWN clock.
//
// Persisted because an in-memory cooldown resets on every crash loop, which is
// when a storm is least affordable -- the same reasoning RepairStored already
// follows. On its own clock because stamping the shared LastAttempt would push
// the object's next REPAIR audit six hours out every time the lowest-priority
// mover glanced at it.
func TestRebalanceCooldownIsPersistedAndDoesNotDelayRepair(t *testing.T) {
	storage := openProductionShapedStore(t)
	row := levelledObject(t, storage, "cooling.bin", 1)

	before, err := storage.AuditCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 {
		t.Fatalf("setup: the repair audit sees %d object(s), want 1", len(before))
	}

	if err := storage.MarkRebalanceAttempt(row.ObjectID); err != nil {
		t.Fatal(err)
	}
	queued, err := storage.RebalanceCandidates(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 0 {
		t.Fatal("an object levelled a moment ago is already back in the levelling queue")
	}

	// The repair audit is untouched: it has its own clock and its own cooldown.
	after, err := storage.LoadObjectPlacement(row.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.LastAttempt.IsZero() {
		t.Fatal("levelling stamped the placement clock repair rate-limits itself with")
	}
	audits, err := storage.AuditCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 {
		t.Fatalf("the repair audit now sees %d object(s); levelling delayed it", len(audits))
	}

	// And it survives a restart, which is the whole reason it is in bolt.
	path := storage.dir
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, 6, 3, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	queued, err = reopened.RebalanceCandidates(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 0 {
		t.Fatal("the levelling cooldown was forgotten across a restart, so a crash loop could level in a tight loop")
	}
}

// A chunk with exactly the threshold number of holders offers nothing to move.
func TestOnlyChunksWithDurabilityMarginAreMovable(t *testing.T) {
	storage := openProductionShapedStore(t)
	row := levelledObject(t, storage, "margin.bin", 1)
	threshold := DurableRemoteHolders(row.DataShards, row.ParityShards)

	for _, chunkIndex := range row.ChunkIndexes() {
		if !row.ChunkHasDurabilityMargin(chunkIndex) {
			t.Fatalf("chunk %d of a fully dispersed object reports no margin", chunkIndex)
		}
	}

	// Drop holders until the first chunk sits on exactly the threshold.
	chunk := row.ChunkIndexes()[0]
	for {
		fresh, err := storage.LoadObjectPlacement(row.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		shards := fresh.PlacementSnapshot(chunk)
		holders := map[string]bool{}
		for _, shard := range shards {
			for _, holder := range shard.Holders {
				holders[holder] = true
			}
		}
		if len(holders) <= threshold {
			if len(holders) != threshold {
				t.Fatalf("dropped past the threshold: %d holders, want %d", len(holders), threshold)
			}
			if fresh.ChunkHasDurabilityMargin(chunk) {
				t.Fatalf("a chunk on exactly %d holders claims a durability margin", threshold)
			}
			for holder := range holders {
				if len(fresh.MovableChunkShards(chunk, holder)) != 0 {
					t.Fatal("an at-threshold chunk offered a shard for levelling")
				}
			}
			return
		}
		for _, shard := range shards {
			if len(shard.Holders) > 0 {
				if err := storage.DropShardHolder(row.ObjectID, shard.ID, shard.Holders[0]); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
	}
}

// The mover's memory of its own recalls expires, and it fails OPEN: refusing
// forever would quietly shrink the candidate set, which is the bug the scoped
// recall refusal was written to replace.
func TestMovedAwayMemoryIsScopedAndExpires(t *testing.T) {
	storage := openProductionShapedStore(t)
	const objectID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	shardID := objectID
	other := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	if storage.ShardMovedAwayFrom(objectID, shardID, "peer-a") {
		t.Fatal("an untouched shard reports as recently moved")
	}
	if err := storage.NoteShardMovedAway(objectID, shardID, "peer-a"); err != nil {
		t.Fatal(err)
	}
	if !storage.ShardMovedAwayFrom(objectID, shardID, "peer-a") {
		t.Fatal("the move was not remembered")
	}
	// Scoped to the peer, the shard and the object, exactly like the refusal it
	// mirrors on the holder.
	if storage.ShardMovedAwayFrom(objectID, shardID, "peer-b") {
		t.Fatal("one peer's refusal was applied to another peer")
	}
	if storage.ShardMovedAwayFrom(objectID, other, "peer-a") {
		t.Fatal("one shard's refusal was applied to another shard")
	}
	if storage.ShardMovedAwayFrom(other, shardID, "peer-a") {
		t.Fatal("one object's refusal was applied to another object")
	}

	// An elapsed deadline is not a refusal. Written straight into bolt because
	// the TTL is six hours and a test must not sleep through it.
	expired := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if err := storage.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDenied).Put(movedAwayKey(objectID, shardID, "peer-a"), []byte(expired))
	}); err != nil {
		t.Fatal(err)
	}
	if storage.ShardMovedAwayFrom(objectID, shardID, "peer-a") {
		t.Fatal("an elapsed refusal still blocks placement; refusing forever is the bug this replaced")
	}
}
