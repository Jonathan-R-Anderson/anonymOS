package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func openRecallStore(t *testing.T) *Store {
	t.Helper()
	storage, err := Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	return storage
}

// THE ORDERING BUG. DeleteObject ended with forgetPlacement, which erased the
// only record anywhere of which peers hold shards of the object -- so the moment
// after a purge, the shards existed and nothing could name their holders. The
// holder list must be captured BEFORE the ledger row goes.
func TestDeleteObjectCapturesHoldersBeforeForgetting(t *testing.T) {
	storage := openRecallStore(t)
	if err := storage.CreateBucket("recall"); err != nil {
		t.Fatal(err)
	}
	manifest, err := storage.PutObject("recall", "object.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{3, 1, 4, 1, 5}, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(row.Shards) == 0 {
		t.Fatal("the object was stored with no shards")
	}
	const holder = "12D3KooWGRUts8ZckKrhVePMWnwLKrDMbYrgvXvJVwFHhPHu3EXV"
	for _, shard := range row.Shards {
		if err := storage.ConfirmShardHolder(manifest.ObjectID, shard.ShardID, holder); err != nil {
			t.Fatal(err)
		}
	}

	if err := storage.DeleteObject("recall", "object.bin"); err != nil {
		t.Fatal(err)
	}

	// The placement row is gone, as it must be: otherwise the dispersal and
	// repair queues would keep re-placing shards of a deleted object.
	if _, err := storage.LoadObjectPlacement(manifest.ObjectID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the placement row survived the delete: %v", err)
	}
	// But the holders did not vanish with it.
	record, err := storage.LoadRecall(manifest.ObjectID)
	if err != nil {
		t.Fatalf("the delete destroyed the holder list: %v", err)
	}
	if len(record.Shards) != len(row.Shards) {
		t.Fatalf("captured %d shards, the object had %d", len(record.Shards), len(row.Shards))
	}
	if record.Resolved() {
		t.Fatal("a freshly captured recall claims every holder has already answered")
	}
	for _, shard := range record.Shards {
		if len(shard.Holders) != 1 || shard.Holders[0].PeerID != holder {
			t.Fatalf("shard %s captured holders %#v", shard.ShardID, shard.Holders)
		}
		if shard.Holders[0].State != RecallPending {
			t.Fatalf("shard %s starts in state %q, not pending", shard.ShardID, shard.Holders[0].State)
		}
	}
}

// An object that never reached a peer has nothing to recall, and must not leave
// a tombstone the recall pass would then chase forever.
func TestDeleteWithoutHoldersLeavesNoTombstone(t *testing.T) {
	storage := openRecallStore(t)
	if err := storage.CreateBucket("recall"); err != nil {
		t.Fatal(err)
	}
	manifest, err := storage.PutObject("recall", "local.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{9}, 3000)))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.DeleteObject("recall", "local.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.LoadRecall(manifest.ObjectID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a purely local object left a recall tombstone: %v", err)
	}
}

// Shards are content-addressed, so two objects with identical chunk bytes are
// literally the same file. A holder must refuse to honour a revocation for bytes
// one of its OWN manifests still needs, or accepting one owner's delete silently
// destroys another object.
func TestDeleteRemoteShardRefusesShardAnotherManifestNeeds(t *testing.T) {
	storage := openRecallStore(t)
	if err := storage.CreateBucket("held"); err != nil {
		t.Fatal(err)
	}
	manifest, err := storage.PutObject("held", "mine.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{2, 7, 1, 8}, 3000)))
	if err != nil {
		t.Fatal(err)
	}
	shardID := manifest.Chunks[0].Shards[0].ID

	removed, err := storage.DeleteRemoteShard("", shardID)
	if !errors.Is(err, ErrShardStillReferenced) {
		t.Fatalf("expected a referenced-shard refusal, got removed=%v err=%v", removed, err)
	}
	if _, err := storage.ReadShard(shardID); err != nil {
		t.Fatalf("a refused recall removed the bytes anyway: %v", err)
	}
	// And the refusal must not poison the denylist: the node still owns this
	// object and has to be able to serve and repair it.
	if storage.IsRejected("shard", shardID) {
		t.Fatal("a refused recall blocklisted a shard the node still needs")
	}
}

// The remote_shards row is keyed by shard id alone and carries ONE object id, so
// a peer cannot tell whether a second owner is depending on the same bytes. A
// revocation naming a different object than the row is refused rather than
// guessed at.
func TestDeleteRemoteShardRefusesAnotherOwnersShard(t *testing.T) {
	storage := openRecallStore(t)
	value := bytes.Repeat([]byte("shared bytes"), 40)
	digest := sha256.Sum256(value)
	shardID := hex.EncodeToString(digest[:])
	held := stringOfByte('a', 64)
	other := stringOfByte('b', 64)
	if err := storage.PutRemoteShard(RemoteShard{
		ID: shardID, ObjectID: held, Size: int64(len(value)),
	}, value); err != nil {
		t.Fatal(err)
	}

	if _, err := storage.DeleteRemoteShard(other, shardID); !errors.Is(err, ErrShardHeldForAnotherObject) {
		t.Fatalf("expected an other-object refusal, got %v", err)
	}
	if _, err := storage.ReadShard(shardID); err != nil {
		t.Fatalf("a refused recall removed another owner's shard: %v", err)
	}

	// The rightful owner's revocation is honoured, and the shard is blocklisted
	// so the owner's own replicate pass cannot push it straight back.
	removed, err := storage.DeleteRemoteShard(held, shardID)
	if err != nil || !removed {
		t.Fatalf("the rightful revocation was not honoured: removed=%v err=%v", removed, err)
	}
	if _, err := storage.ReadShard(shardID); err == nil {
		t.Fatal("the shard file survived an honoured revocation")
	}
	if !storage.RecallRefused(held, shardID) {
		t.Fatal("an honoured revocation left no refusal entry, so the next " +
			"replicate pass would restore the shard")
	}
	if storage.IsRejected("shard", shardID) {
		t.Fatal("a recall wrote a PERMANENT moderation rejection; that poisons " +
			"the content address for every other object, forever")
	}
	if err := storage.PutRemoteShard(RemoteShard{
		ID: shardID, ObjectID: held, Size: int64(len(value)),
	}, value); err == nil {
		t.Fatal("a recalled shard was accepted again")
	}
}

// Deleting a shard that is not here is a terminal, honest answer -- the owner can
// stop chasing this peer for it -- and is reported differently from a deletion.
func TestDeleteRemoteShardOnAbsentShard(t *testing.T) {
	storage := openRecallStore(t)
	removed, err := storage.DeleteRemoteShard(stringOfByte('c', 64), stringOfByte('d', 64))
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("a shard that was never here was reported as removed")
	}
}

// Recapturing must resume, not restart: a purge retried after some holders have
// already confirmed must not put those holders back to pending and re-ask them.
//
// The payload is deliberately constant bytes, which erasure-code into IDENTICAL
// data shards -- the same shard id appearing several times in one object. An
// answer has to land on every entry carrying that id, or the duplicates stay
// pending and the tombstone never resolves.
func TestCaptureRecallPreservesAnswers(t *testing.T) {
	storage := openRecallStore(t)
	if err := storage.CreateBucket("resume"); err != nil {
		t.Fatal(err)
	}
	manifest, err := storage.PutObject("resume", "object.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{6}, 3000)))
	if err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	const holder = "12D3KooWGRUts8ZckKrhVePMWnwLKrDMbYrgvXvJVwFHhPHu3EXV"
	first := row.Shards[0].ShardID
	for _, shard := range row.Shards {
		if err := storage.ConfirmShardHolder(manifest.ObjectID, shard.ShardID, holder); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := storage.CaptureRecall(manifest.ObjectID, "first"); err != nil {
		t.Fatal(err)
	}
	if err := storage.RecordRecallOutcome(manifest.ObjectID, first, holder,
		RecallDeleted, "confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.CaptureRecall(manifest.ObjectID, "second"); err != nil {
		t.Fatal(err)
	}
	record, err := storage.LoadRecall(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range record.Shards {
		if shard.ShardID != first {
			continue
		}
		if shard.Holders[0].State != RecallDeleted {
			t.Fatalf("recapture reset a confirmed holder to %q", shard.Holders[0].State)
		}
	}
}

// The listing is the other half of the ask: the site could not see the ledger at
// all, so the admin page printed "?" for holders and derived shard counts by
// arithmetic. Counts here must be OBSERVED.
func TestListPlacementsReportsObservedShardsAndHolders(t *testing.T) {
	storage := openRecallStore(t)
	if err := storage.CreateBucket("listing"); err != nil {
		t.Fatal(err)
	}
	manifest, err := storage.PutObject("listing", "a/one.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{1, 2, 3}, 5000)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.PutObject("listing", "b/two.bin", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte{4, 5, 6}, 5000))); err != nil {
		t.Fatal(err)
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	const holder = "12D3KooWGRUts8ZckKrhVePMWnwLKrDMbYrgvXvJVwFHhPHu3EXV"
	if err := storage.ConfirmShardHolder(manifest.ObjectID, row.Shards[0].ShardID, holder); err != nil {
		t.Fatal(err)
	}

	listing, err := storage.ListPlacements("listing", "a/", "", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Objects) != 1 {
		t.Fatalf("prefix filter returned %d objects", len(listing.Objects))
	}
	view := listing.Objects[0]
	if view.ObjectID != manifest.ObjectID || !view.ObjectPresent {
		t.Fatalf("unexpected listing row %#v", view)
	}
	if view.ShardCount != len(row.Shards) || view.Chunks != len(row.ChunkIndexes()) {
		t.Fatalf("listing reported %d shards / %d chunks, ledger has %d / %d",
			view.ShardCount, view.Chunks, len(row.Shards), len(row.ChunkIndexes()))
	}
	if view.PlainSize != manifest.PlainSize {
		t.Fatalf("listing reported size %d, manifest says %d", view.PlainSize, manifest.PlainSize)
	}
	if view.DistinctHolders != 1 || view.HolderShards[holder] != 1 {
		t.Fatalf("holder rollup is %#v", view.HolderShards)
	}
	if !view.UnderReplicated {
		t.Fatal("an object with one holder of one shard is not under-replicated?")
	}

	// Paging returns a marker rather than an offset, because bolt keys are
	// object ids and an offset into a hash ordering means nothing.
	page, err := storage.ListPlacements("listing", "", "", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Objects) != 1 || page.NextMarker == "" {
		t.Fatalf("first page %#v", page)
	}
	next, err := storage.ListPlacements("listing", "", page.NextMarker, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Objects) != 1 || next.Objects[0].ObjectID == page.Objects[0].ObjectID {
		t.Fatalf("second page repeated or skipped: %#v", next)
	}
}

func stringOfByte(char byte, count int) string {
	value := make([]byte, count)
	for i := range value {
		value[i] = char
	}
	return string(value)
}
