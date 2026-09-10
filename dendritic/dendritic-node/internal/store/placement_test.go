package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// openProductionShapedStore uses the real 6+3 layout, because the durability
// arithmetic only means anything at the numbers production runs.
func openProductionShapedStore(t *testing.T) *Store {
	t.Helper()
	storage, err := Open(t.TempDir(), 6, 3, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.CreateBucket("dispersal"); err != nil {
		t.Fatal(err)
	}
	return storage
}

// A write must succeed with nobody to send shards to -- the network is
// frequently empty and refusing uploads until it is not would be worse than
// storing one copy. What must NOT happen is the object claiming a durability it
// does not have.
func TestWriteWithZeroPeersSucceedsAndIsMarkedUnderReplicated(t *testing.T) {
	storage := openProductionShapedStore(t)
	// No distributor is set, which is exactly the peerless case: nothing will
	// ever be asked to place a shard.
	content := distinctBytes(11, 300<<10)
	manifest, err := storage.PutObject("dispersal", "lonely.bin", "application/octet-stream",
		bytes.NewReader(content))
	if err != nil {
		t.Fatalf("a write with no peers must still succeed: %v", err)
	}

	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatalf("the write was not enrolled in the placement ledger: %v", err)
	}
	if !row.UnderReplicated() {
		t.Fatal("an object with zero remote holders claimed to be durable")
	}
	if row.FullyDispersed() {
		t.Fatal("an object with zero remote holders claimed to be fully dispersed")
	}
	if got := row.WeakestChunk(); got != 0 {
		t.Fatalf("WeakestChunk = %d, want 0 remote shard indexes", got)
	}
	for _, shard := range row.Shards {
		if len(shard.Holders) != 0 {
			t.Fatalf("shard %s claims holders %v with no peers in existence",
				shard.ShardID, shard.Holders)
		}
		if !shard.Local {
			t.Fatalf("shard %s is not recorded as local, but local disk is the only copy", shard.ShardID)
		}
	}

	summary, err := storage.PlacementStatus()
	if err != nil {
		t.Fatal(err)
	}
	if summary.Objects != 1 || summary.UnderReplicated != 1 || summary.LocalOnly != 1 ||
		summary.FullyDispersed != 0 {
		t.Fatalf("summary %#v does not report the object as local-only and under-replicated", summary)
	}

	// And it is queued for dispersal, durably, so a later peer gets it.
	candidates, err := storage.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].ObjectID != manifest.ObjectID {
		t.Fatalf("under-replicated object is not in the dispersal queue: %#v", candidates)
	}

	// The bytes are still readable from the one copy that exists.
	var recovered bytes.Buffer
	if _, err := storage.GetObject("dispersal", "lonely.bin", &recovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("locally stored object did not read back")
	}
}

// The durability threshold: SEVEN distinct peers is where the promise becomes
// true for 6+3. Six is the decode threshold and therefore exactly zero
// redundancy -- lose any one of those six and the remote copies stop being an
// object -- and "a node drops out" is the event the whole feature is for.
func TestDurabilityThresholdIsDataShardsPlusOneHolders(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "threshold.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(12, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) != 1 {
		t.Fatalf("expected a single chunk, got %d", len(manifest.Chunks))
	}
	if got := DurableRemoteHolders(6, 3); got != 7 {
		t.Fatalf("DurableRemoteHolders(6,3) = %d, want 7", got)
	}
	holderOf := func(index int) string { return fmt.Sprintf("peer-%02d", index) }
	for index, ref := range manifest.Chunks[0].Shards {
		row, err := storage.LoadObjectPlacement(manifest.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		if want := index >= DurableRemoteHolders(6, 3); row.UnderReplicated() == want {
			t.Fatalf("with %d distinct holders UnderReplicated()=%v", index, row.UnderReplicated())
		}
		if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID, holderOf(index)); err != nil {
			t.Fatal(err)
		}
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if row.UnderReplicated() || !row.FullyDispersed() {
		t.Fatalf("all nine shards placed on nine distinct peers should be durable and complete: %#v", row)
	}
	// A holder dropping out takes the object below the full-dispersal target,
	// which is the signal repair keys off.
	if err := storage.DropShardHolder(manifest.ObjectID,
		manifest.Chunks[0].Shards[0].ID, holderOf(0)); err != nil {
		t.Fatal(err)
	}
	row, _ = storage.LoadObjectPlacement(manifest.ObjectID)
	if row.FullyDispersed() {
		t.Fatal("an object that lost a holder still claims full dispersal")
	}
	if row.WeakestChunk() != 8 {
		t.Fatalf("WeakestChunk = %d after one holder left, want 8 distinct holders", row.WeakestChunk())
	}
	// Eight of nine on eight distinct peers still survives one loss with six
	// indexes left, so it is under the completion target but not under-replicated.
	if row.UnderReplicated() {
		t.Fatal("eight shards on eight distinct peers was reported as under-replicated")
	}
}

// CO-LOCATION IS NOT DURABILITY.
//
// Nine shards, one peer. Every shard has a confirmed holder and every index is
// off this node, so an index-counting metric reports 9 of 9 and retires the
// object -- with the whole of it sitting on a single machine whose loss takes
// the object with it. Durability is bounded by the number of DISTINCT HOLDERS,
// never by the number of placed indexes.
func TestOneHolderOfEveryShardIsNotDurable(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "hoarded.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(50, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID, "the-only-peer"); err != nil {
				t.Fatal(err)
			}
		}
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.UnderReplicated() {
		t.Fatal("an object whose every shard sits on ONE peer was reported as durable")
	}
	if row.FullyDispersed() {
		t.Fatal("an object whose every shard sits on ONE peer was reported as fully dispersed")
	}
	if got := row.WeakestChunk(); got != 1 {
		t.Fatalf("WeakestChunk = %d, want 1: one holder is the object's whole redundancy", got)
	}

	// The consequence that makes it fatal rather than cosmetic: a retired object
	// is one no pass will ever look at again.
	candidates, err := storage.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].ObjectID != manifest.ObjectID {
		t.Fatalf("a co-located object is not in the dispersal queue: %#v", candidates)
	}
	summary, err := storage.PlacementStatus()
	if err != nil {
		t.Fatal(err)
	}
	if summary.UnderReplicated != 1 || summary.FullyDispersed != 0 {
		t.Fatalf("summary %#v calls a single-holder object dispersed", summary)
	}
}

// Two holders for nine shards is the same failure one step along, and the
// threshold has to catch every arrangement below dataShards+1 distinct peers.
func TestDurabilityCountsHoldersNotPlacedIndexes(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "lumpy.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(51, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) != 1 {
		t.Fatalf("expected a single chunk, got %d", len(manifest.Chunks))
	}
	shards := manifest.Chunks[0].Shards
	// Six peers, nine shards: peer-0 takes four of them. Six distinct indexes are
	// remote and every index is placed, but losing peer-0 costs four of nine and
	// leaves five -- one short of a decode.
	holders := []string{"peer-0", "peer-0", "peer-0", "peer-0", "peer-1", "peer-2", "peer-3", "peer-4", "peer-5"}
	for i, ref := range shards {
		if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID, holders[i]); err != nil {
			t.Fatal(err)
		}
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.UnderReplicated() {
		t.Fatal("nine indexes over six peers, four on one, was reported as durable")
	}
	if row.FullyDispersed() {
		t.Fatal("a chunk that cannot survive one node loss was reported as fully dispersed")
	}
	if got := row.WeakestChunk(); got != 6 {
		t.Fatalf("WeakestChunk = %d, want the 6 distinct holders", got)
	}
}

// Reconstruction from EXACTLY dataShards, with nothing local at all: this is
// what a read looks like once shards genuinely live on other nodes.
func TestReadReconstructsFromExactlySixRemoteShards(t *testing.T) {
	storage := openProductionShapedStore(t)
	content := distinctBytes(13, 40<<10)
	manifest, err := storage.PutObject("dispersal", "remote.bin", "application/octet-stream",
		bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) != 1 {
		t.Fatalf("expected a single chunk, got %d", len(manifest.Chunks))
	}

	// Stash every shard, then wipe local disk: the node now holds none of them.
	elsewhere := map[string][]byte{}
	for _, ref := range manifest.Chunks[0].Shards {
		value, err := storage.ReadShard(ref.ID)
		if err != nil {
			t.Fatal(err)
		}
		elsewhere[ref.ID] = value
		if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
			t.Fatal(err)
		}
	}

	// The "network" serves exactly six of the nine, chosen to include parity so
	// the decode is a real reconstruction and not a concatenation.
	servable := map[string]bool{}
	for _, index := range []int{0, 1, 2, 3, 7, 8} {
		servable[manifest.Chunks[0].Shards[index].ID] = true
	}
	var mu sync.Mutex
	var served []string
	storage.SetShardFetcher(func(_ context.Context, shardID string, _ []string) ([]byte, error) {
		if !servable[shardID] {
			return nil, errors.New("holder is gone")
		}
		mu.Lock()
		served = append(served, shardID)
		mu.Unlock()
		return elsewhere[shardID], nil
	})

	var recovered bytes.Buffer
	if _, err := storage.GetObject("dispersal", "remote.bin", &recovered); err != nil {
		t.Fatalf("six of nine shards must reconstruct the object: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("object reconstructed from six remote shards does not match")
	}
	mu.Lock()
	count := len(served)
	mu.Unlock()
	if count != 6 {
		t.Fatalf("fetched %d shards to decode a 6+3 chunk, want exactly 6", count)
	}
}

// And five is not "almost": Reed-Solomon decodes from dataShards or from
// nothing, so a read must fail rather than emit a short object.
func TestReadFailsWithFiveOfNineShards(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "short.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(14, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := map[string][]byte{}
	for _, ref := range manifest.Chunks[0].Shards {
		value, _ := storage.ReadShard(ref.ID)
		elsewhere[ref.ID] = value
		if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	servable := map[string]bool{}
	for _, index := range []int{0, 1, 2, 3, 4} {
		servable[manifest.Chunks[0].Shards[index].ID] = true
	}
	storage.SetShardFetcher(func(_ context.Context, shardID string, _ []string) ([]byte, error) {
		if !servable[shardID] {
			return nil, errors.New("holder is gone")
		}
		return elsewhere[shardID], nil
	})
	var out bytes.Buffer
	if _, err := storage.GetObject("dispersal", "short.bin", &out); err == nil {
		t.Fatal("a read with five of nine shards must fail, not return partial bytes")
	}
}

// A read that is fully served locally must not touch the network at all -- the
// common case, and the one where a stray fetch costs an I2P round trip.
func TestReadDoesNotFetchWhenSixShardsAreLocal(t *testing.T) {
	storage := openProductionShapedStore(t)
	content := distinctBytes(15, 40<<10)
	manifest, err := storage.PutObject("dispersal", "local.bin", "application/octet-stream",
		bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	// Drop the three parity shards: six data shards remain, which is exactly
	// enough and must be recognised as enough.
	for _, ref := range manifest.Chunks[0].Shards[6:] {
		if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	var fetches int
	storage.SetShardFetcher(func(context.Context, string, []string) ([]byte, error) {
		fetches++
		return nil, errors.New("should not have been called")
	})
	var recovered bytes.Buffer
	if _, err := storage.GetObject("dispersal", "local.bin", &recovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("object did not read back from six local shards")
	}
	if fetches != 0 {
		t.Fatalf("made %d network fetches with a local quorum in hand", fetches)
	}
}

// The read path passes the ledger's holders to the fetcher, so a miss goes
// straight to a node that confirmed the bytes instead of searching every peer
// that ever connected.
func TestReadPassesRecordedHoldersToTheFetcher(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "hinted.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(16, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	ref := manifest.Chunks[0].Shards[0]
	if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID, "peer-holding-it"); err != nil {
		t.Fatal(err)
	}
	// Four shards away, so five local copies remain: below the six-shard quorum,
	// which is the only condition under which the network is consulted at all.
	elsewhere := map[string][]byte{}
	for _, gone := range manifest.Chunks[0].Shards[:4] {
		value, err := storage.ReadShard(gone.ID)
		if err != nil {
			t.Fatal(err)
		}
		elsewhere[gone.ID] = value
		if err := os.Remove(storage.shardPath(gone.ID)); err != nil {
			t.Fatal(err)
		}
	}
	hinted := make(chan []string, 9)
	storage.SetShardFetcher(func(_ context.Context, shardID string, hints []string) ([]byte, error) {
		if shardID == ref.ID {
			hinted <- hints
		}
		value, ok := elsewhere[shardID]
		if !ok {
			return nil, errors.New("not available")
		}
		return value, nil
	})
	var out bytes.Buffer
	if _, err := storage.GetObject("dispersal", "hinted.bin", &out); err != nil {
		t.Fatal(err)
	}
	select {
	case hints := <-hinted:
		if len(hints) != 1 || hints[0] != "peer-holding-it" {
			t.Fatalf("fetcher was given hints %v, want the recorded holder", hints)
		}
	default:
		t.Fatal("the missing shard was never offered to the fetcher")
	}
}

// Objects that predate the ledger are enrolled, so the backlog on the running
// node becomes visible instead of invisible.
func TestEnrolMissingPlacementsPicksUpPreLedgerObjects(t *testing.T) {
	storage := openProductionShapedStore(t)
	var ids []string
	for i := 0; i < 3; i++ {
		manifest, err := storage.PutObject("dispersal", string(rune('a'+i))+".bin",
			"application/octet-stream", bytes.NewReader(distinctBytes(int64(20+i), 8<<10)))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, manifest.ObjectID)
		if err := storage.forgetPlacement(manifest.ObjectID); err != nil {
			t.Fatal(err)
		}
	}
	enrolled, pending, err := storage.EnrolMissingPlacements(2)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled != 2 || pending != 1 {
		t.Fatalf("enrolled %d with %d pending, want 2 and 1", enrolled, pending)
	}
	enrolled, pending, err = storage.EnrolMissingPlacements(10)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled != 1 || pending != 0 {
		t.Fatalf("second pass enrolled %d with %d pending, want 1 and 0", enrolled, pending)
	}
	for _, id := range ids {
		if _, err := storage.LoadObjectPlacement(id); err != nil {
			t.Fatalf("object %s was never enrolled: %v", id, err)
		}
	}
}

// A deleted object must leave the queue, or the pass spends forever trying to
// place shards of something that no longer exists.
func TestDeletingAnObjectForgetsItsPlacement(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "gone.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(21, 8<<10)))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.DeleteObject("dispersal", "gone.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.LoadObjectPlacement(manifest.ObjectID); err == nil {
		t.Fatal("the placement row outlived the object")
	}
	candidates, err := storage.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("deleted object is still queued for dispersal: %#v", candidates)
	}
}

// The queue must rotate. An object attempted a moment ago stands aside so the
// next one is tried, otherwise a handful of undispersable objects starve
// everything behind them.
func TestDispersalQueueRotatesOnCooldown(t *testing.T) {
	storage := openProductionShapedStore(t)
	var ids []string
	for i := 0; i < 3; i++ {
		manifest, err := storage.PutObject("dispersal", "q"+string(rune('a'+i))+".bin",
			"application/octet-stream", bytes.NewReader(distinctBytes(int64(30+i), 8<<10)))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, manifest.ObjectID)
	}
	first, err := storage.DispersalCandidates(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("queue returned %d candidates, want 1", len(first))
	}
	if err := storage.MarkPlacementAttempt(first[0].ObjectID); err != nil {
		t.Fatal(err)
	}
	second, err := storage.DispersalCandidates(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 {
		t.Fatalf("queue returned %d candidates on the second pass, want 1", len(second))
	}
	if second[0].ObjectID == first[0].ObjectID {
		t.Fatal("the queue handed back the object it had just attempted; the rest would starve")
	}
	_ = ids
}

// Repair must audit objects that currently look perfect, because "fully
// dispersed" is a record of the past and a holder going away is the event
// repair exists to catch. The dispersal queue is right to skip them; the audit
// queue must not.
func TestAuditQueueIncludesHealthyObjectsThatDispersalSkips(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "healthy.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(40, 8<<10)))
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID,
				"peer-"+ref.ID[:6]); err != nil {
				t.Fatal(err)
			}
		}
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.FullyDispersed() {
		t.Fatal("test setup did not reach full dispersal")
	}
	dispersal, err := storage.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dispersal) != 0 {
		t.Fatalf("dispersal queue still holds a fully dispersed object: %#v", dispersal)
	}
	audit, err := storage.AuditCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 || audit[0].ObjectID != manifest.ObjectID {
		t.Fatal("a fully dispersed object is never audited, so a lost holder would go unnoticed")
	}
}

// The last gate in front of a push. The planner refuses to co-locate, but a
// plan is a snapshot and placement rounds overlap, so the question is asked
// again against the ledger immediately before the bytes go out.
func TestHoldsSiblingShardSeesTheRestOfTheChunk(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "sibling.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(52, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	shards := manifest.Chunks[0].Shards
	if err := storage.ConfirmShardHolder(manifest.ObjectID, shards[0].ID, "peer-a"); err != nil {
		t.Fatal(err)
	}
	if !storage.HoldsSiblingShard(manifest.ObjectID, shards[1].ID, "peer-a") {
		t.Fatal("a peer already holding shard 0 was cleared to take shard 1 of the same chunk")
	}
	if storage.HoldsSiblingShard(manifest.ObjectID, shards[1].ID, "peer-b") {
		t.Fatal("a peer holding nothing was refused")
	}
	// Not a sibling of itself: a retry, or a content-addressed shard shared with
	// another object, must still be confirmable on the peer that has it.
	if storage.HoldsSiblingShard(manifest.ObjectID, shards[0].ID, "peer-a") {
		t.Fatal("the shard's own holder was treated as co-location")
	}
}

// Consecutive is the whole of the word: one answer wipes the record, so a
// holder that is unreachable one evening a month never accumulates its way to
// eviction.
func TestHolderSilencesAreConsecutiveAndSurviveARewrite(t *testing.T) {
	storage := openProductionShapedStore(t)
	content := distinctBytes(53, 40<<10)
	manifest, err := storage.PutObject("dispersal", "silence.bin", "application/octet-stream",
		bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	shard := manifest.Chunks[0].Shards[0]
	if err := storage.ConfirmShardHolder(manifest.ObjectID, shard.ID, "peer-a"); err != nil {
		t.Fatal(err)
	}
	for want := 1; want <= 2; want++ {
		got, err := storage.NoteHolderSilence(manifest.ObjectID, shard.ID, "peer-a")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("silence count %d after %d unanswered audits, want %d", got, want, want)
		}
	}
	// A restart must not hand a long-silent holder a clean slate, so the count
	// survives the manifest being written again.
	if _, err := storage.PutObject("dispersal", "silence.bin", "application/octet-stream",
		bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if got := row.HolderSilences(shard.ID, "peer-a"); got != 2 {
		t.Fatalf("silence count is %d after a rewrite, want the 2 it had earned", got)
	}
	if err := storage.NoteHolderAnswered(manifest.ObjectID, shard.ID, "peer-a"); err != nil {
		t.Fatal(err)
	}
	row, _ = storage.LoadObjectPlacement(manifest.ObjectID)
	if got := row.HolderSilences(shard.ID, "peer-a"); got != 0 {
		t.Fatalf("silence count is %d after the holder answered, want 0", got)
	}
	// And a holder that is dropped takes its count with it: coming back means
	// starting from zero, not one probe from eviction.
	if _, err := storage.NoteHolderSilence(manifest.ObjectID, shard.ID, "peer-a"); err != nil {
		t.Fatal(err)
	}
	if err := storage.DropShardHolder(manifest.ObjectID, shard.ID, "peer-a"); err != nil {
		t.Fatal(err)
	}
	row, _ = storage.LoadObjectPlacement(manifest.ObjectID)
	if got := row.HolderSilences(shard.ID, "peer-a"); got != 0 {
		t.Fatalf("a dropped holder left a silence count of %d behind", got)
	}
	// A peer that is not a holder cannot accumulate silences at all.
	if got, err := storage.NoteHolderSilence(manifest.ObjectID, shard.ID, "peer-stranger"); err != nil || got != 0 {
		t.Fatalf("NoteHolderSilence for a non-holder returned %d, %v", got, err)
	}
}
