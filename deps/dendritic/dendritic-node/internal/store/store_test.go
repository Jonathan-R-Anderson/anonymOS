package store

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
)

// distinctBytes returns deterministic pseudo-random content, so that shards of
// different objects are genuinely different and never dedup into one another.
func distinctBytes(seed int64, size int) []byte {
	buf := make([]byte, size)
	rand.New(rand.NewSource(seed)).Read(buf)
	return buf
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	storage, err := Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.CreateBucket("test-bucket"); err != nil {
		t.Fatal(err)
	}
	return storage
}

func TestErasureRoundTripWithTwoMissingShards(t *testing.T) {
	storage := openTestStore(t)
	// The node stores opaque bytes and does not encrypt (content arrives already
	// ciphertext from the coordinator). Use bytes that look like content, drop
	// the parity shards, and confirm Reed-Solomon reconstructs them exactly.
	content := bytes.Repeat([]byte("opaque ciphertext bytes the node cannot read\n"), 5000)
	manifest, err := storage.PutObject("test-bucket", "folder/file.txt", "text/plain", bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ObjectID == "" || len(manifest.Chunks) < 2 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards[:manifest.ParityShards] {
			if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	var recovered bytes.Buffer
	if _, err := storage.GetObject("test-bucket", "folder/file.txt", &recovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("recovered bytes differ from stored bytes")
	}
}

func TestTamperedShardIsRejected(t *testing.T) {
	storage := openTestStore(t)
	manifest, err := storage.PutObject("test-bucket", "file.bin", "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4}, 1000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]
	for _, ref := range chunk.Shards[:manifest.ParityShards+1] {
		if err := os.WriteFile(storage.shardPath(ref.ID), bytes.Repeat([]byte{0xff}, ref.Size), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if _, err := storage.GetObject("test-bucket", "file.bin", &output); err == nil {
		t.Fatal("expected reconstruction failure after too many corrupt shards")
	}
}

func TestRejectRemovesAndDeniesObject(t *testing.T) {
	storage := openTestStore(t)
	manifest, err := storage.PutObject("test-bucket", "reject.bin", "application/octet-stream", bytes.NewReader([]byte("reject me")))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.RejectAndRemove("object", manifest.ObjectID); err != nil {
		t.Fatal(err)
	}
	if !storage.IsRejected("object", manifest.ObjectID) {
		t.Fatal("object ID was not denied")
	}
	if _, err := storage.HeadObject("test-bucket", "reject.bin"); !os.IsNotExist(err) {
		t.Fatalf("object metadata remains: %v", err)
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			if _, err := os.Stat(storage.shardPath(ref.ID)); !os.IsNotExist(err) {
				t.Fatalf("shard %s remains after rejection", ref.ID)
			}
		}
	}
	// Rejection removes shards through removeUnreferenced, so it must give the
	// bytes back to the usage counter as well.
	used, err := storage.UsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if used != 0 {
		t.Fatalf("usage is %d bytes after rejecting the only object, want 0", used)
	}
}

// TestWritingManyShardsDoesNotWalkTheTree pins the property the fix is for:
// storing new shards must not measure the shard tree. ensureCapacity used to
// call UsedBytes() -- a filepath.Walk over every stored shard -- once per new
// shard, inside the global allocation lock, which is what made unique writes
// slow enough to outlive the client's socket timeout.
func TestWritingManyShardsDoesNotWalkTheTree(t *testing.T) {
	storage := openTestStore(t)
	walksBefore := storage.walkCount()

	shardSizes := make(map[string]int64)
	for i := 0; i < 8; i++ {
		manifest, err := storage.PutObject(
			"test-bucket", fmt.Sprintf("object-%d.bin", i), "application/octet-stream",
			bytes.NewReader(distinctBytes(int64(i)+1, 200<<10)),
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range manifest.Chunks {
			for _, ref := range chunk.Shards {
				shardSizes[ref.ID] = int64(ref.Size)
			}
		}
	}
	if len(shardSizes) < 100 {
		t.Fatalf("test wrote only %d distinct shards; it is not exercising the path", len(shardSizes))
	}
	if walks := storage.walkCount() - walksBefore; walks != 0 {
		t.Fatalf("writing %d distinct shards performed %d tree walks, want 0", len(shardSizes), walks)
	}

	var expected int64
	for _, size := range shardSizes {
		expected += size
	}
	used, err := storage.UsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if used != expected {
		t.Fatalf("cached usage is %d bytes, want %d", used, expected)
	}
	if walks := storage.walkCount() - walksBefore; walks != 0 {
		t.Fatalf("UsedBytes performed %d tree walks, want 0: polling callers must be cheap", walks)
	}
	// The cheap counter still has to agree with the expensive truth.
	measured, err := storage.measureUsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if measured != used {
		t.Fatalf("counter says %d bytes, disk says %d", used, measured)
	}
}

func TestUsedBytesTracksWritesAndDeletes(t *testing.T) {
	storage := openTestStore(t)
	if used, err := storage.UsedBytes(); err != nil || used != 0 {
		t.Fatalf("fresh store reports %d bytes (err %v), want 0", used, err)
	}
	if _, err := storage.PutObject(
		"test-bucket", "keep.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(11, 128<<10)),
	); err != nil {
		t.Fatal(err)
	}
	kept, err := storage.UsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.PutObject(
		"test-bucket", "drop.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(12, 128<<10)),
	); err != nil {
		t.Fatal(err)
	}
	both, err := storage.UsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if both <= kept {
		t.Fatalf("usage did not grow for the second object: %d then %d", kept, both)
	}

	if err := storage.DeleteObject("test-bucket", "drop.bin"); err != nil {
		t.Fatal(err)
	}
	after, err := storage.UsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if after != kept {
		t.Fatalf("usage is %d bytes after deleting the second object, want %d", after, kept)
	}
	measured, err := storage.measureUsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if measured != after {
		t.Fatalf("counter says %d bytes after a delete, disk says %d", after, measured)
	}

	if err := storage.DeleteObject("test-bucket", "keep.bin"); err != nil {
		t.Fatal(err)
	}
	if empty, err := storage.UsedBytes(); err != nil || empty != 0 {
		t.Fatalf("usage is %d bytes (err %v) after deleting everything, want 0", empty, err)
	}
}

// TestConcurrentWritersOfOneShardCountItOnce covers the accounting race opened
// up by writing outside the allocation lock: several writers of the same
// content-addressed shard all see it absent, all rename identical bytes onto
// the same name, and exactly one of them may charge for it.
func TestConcurrentWritersOfOneShardCountItOnce(t *testing.T) {
	storage := openTestStore(t)
	value := distinctBytes(99, 32<<10)
	id := digest(value)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := storage.writeShard(id, value); err != nil {
				t.Errorf("writeShard: %v", err)
			}
		}()
	}
	wg.Wait()

	used, err := storage.UsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if used != int64(len(value)) {
		t.Fatalf("16 writers of one shard accounted for %d bytes, want %d", used, len(value))
	}
	measured, err := storage.measureUsedBytes()
	if err != nil {
		t.Fatal(err)
	}
	if measured != used {
		t.Fatalf("counter says %d bytes, disk says %d", used, measured)
	}
}

func TestExpectedDigestMismatchNeverPublishesObject(t *testing.T) {
	storage := openTestStore(t)
	_, err := storage.PutObjectVerified(
		"test-bucket", "bad.bin", "application/octet-stream",
		bytes.NewReader([]byte("actual")), string(make([]byte, 64)),
	)
	if err != ErrDigestMismatch {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}
	if _, err := storage.HeadObject("test-bucket", "bad.bin"); !os.IsNotExist(err) {
		t.Fatalf("mismatched object was published: %v", err)
	}
}

func TestCapacityChoicePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	storage, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	const chosen = int64(3 << 30)
	if err := storage.SetCapacity(chosen); err != nil {
		t.Fatal(err)
	}
	if storage.Capacity() != chosen {
		t.Fatalf("capacity is %d, want %d", storage.Capacity(), chosen)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Capacity() != chosen {
		t.Fatalf("persisted capacity is %d, want %d", reopened.Capacity(), chosen)
	}
}

func TestBucketPolicyPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	storage, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateBucket("public-media"); err != nil {
		t.Fatal(err)
	}
	policy := []byte(`{"Statement":[{"Effect":"Allow"}]}`)
	if err := storage.SetBucketPolicy("public-media", policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.BucketPolicy("public-media")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, policy) {
		t.Fatalf("persisted policy is %q, want %q", got, policy)
	}
}
