package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// coordinatorStub is the signing authority a test stands in for, and the record
// of what was asked of it. The counts matter to the levelling tests: "the source
// was never asked to delete" is only observable as "no delete token was ever
// minted for it", so the stub has to be able to say.
type coordinatorStub struct {
	key ed25519.PrivateKey
	mu  sync.Mutex
	// revocations counts delete tokens issued, by (shard, recipient).
	revocations []revocationRequestShard
	// gate, when non-nil, holds every revocation request until it is closed, so
	// a test can park one move mid-flight and watch what another one does.
	gate chan struct{}
	// hit is signalled once per revocation request, buffered so nothing blocks
	// on a test that is not listening.
	hit chan struct{}
}

func (c *coordinatorStub) revocationsIssued() []revocationRequestShard {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]revocationRequestShard(nil), c.revocations...)
}

func (c *coordinatorStub) hold() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gate = make(chan struct{})
}

func (c *coordinatorStub) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gate != nil {
		close(c.gate)
		c.gate = nil
	}
}

// stubCoordinator signs whatever lease or revocation is asked for, so a test
// exercises placement and levelling rather than the coordinator.
func stubCoordinator(t *testing.T, nodes ...*Node) *coordinatorStub {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.coordKey = publicKey
	}
	stub := &coordinatorStub{key: privateKey, hit: make(chan struct{}, 64)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request leaseRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxHeaderBytes)).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lease := Lease{
			Version: 1, ObjectID: request.ObjectID, ShardID: request.ShardID,
			Size: request.Size, Recipient: request.Recipient,
			ExpiresAt: time.Now().Unix() + 300,
		}
		lease.Signature = base64.RawStdEncoding.EncodeToString(
			ed25519.Sign(privateKey, leaseMessage(lease)),
		)
		_ = json.NewEncoder(w).Encode(lease)
	}))
	t.Cleanup(server.Close)
	previous := leaseURL
	leaseURL = server.URL
	t.Cleanup(func() { leaseURL = previous })

	revocations := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request revocationRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stub.mu.Lock()
		stub.revocations = append(stub.revocations, request.Shards...)
		gate := stub.gate
		stub.mu.Unlock()
		select {
		case stub.hit <- struct{}{}:
		default:
		}
		if gate != nil {
			<-gate
		}
		var issued revocationResponse
		for _, entry := range request.Shards {
			nonce := make([]byte, 16)
			_, _ = rand.Read(nonce)
			revocation := Revocation{
				Version: 1, ObjectID: request.ObjectID, ShardID: entry.ShardID,
				Recipient: entry.Recipient,
				// Taken from the body the node signed, exactly as the real
				// coordinator takes it from the authenticated requester.
				Requester: request.Requester,
				IssuedAt:  time.Now().Unix(), ExpiresAt: time.Now().Unix() + 600,
				Nonce: base64.RawURLEncoding.EncodeToString(nonce),
			}
			revocation.Signature = base64.RawStdEncoding.EncodeToString(
				ed25519.Sign(privateKey, revocationMessage(revocation)),
			)
			issued.Revocations = append(issued.Revocations, revocation)
		}
		_ = json.NewEncoder(w).Encode(issued)
	}))
	t.Cleanup(revocations.Close)
	previousRevocation := revocationURL
	revocationURL = revocations.URL
	t.Cleanup(func() { revocationURL = previousRevocation })
	return stub
}

// varyingBytes is deterministic pseudo-random content. Uniform content matters:
// shards are content-addressed, so a chunk of identical bytes produces IDENTICAL
// data shards that dedup into one file on disk, and a test that deletes "two
// shards" would delete one.
func varyingBytes(seed int64, size int) []byte {
	buf := make([]byte, size)
	mathrand.New(mathrand.NewSource(seed)).Read(buf)
	return buf
}

// shardFileOf is where the store keeps a shard on disk. Spelled out here rather
// than exported from the store: tests need to simulate a lost shard, production
// code has no business unlinking one.
func shardFileOf(dir, shardID string) string {
	return filepath.Join(dir, "storage", "shards", shardID[:2], shardID)
}

func openTestNode(t *testing.T, ctx context.Context, dataShards, parityShards int) (*Node, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	storage, err := store.Open(dir+"/storage", dataShards, parityShards, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, storage,
		log.New(io.Discard, "", 0), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	return node, storage, dir
}

// THE REQUIREMENT. Losing one node must cost at most one shard per chunk.
//
// The old distributor used `peers[shardNumber%len(peers)]`, which gives distinct
// holders only by accident when there happen to be at least as many peers as
// shards. This asserts the property directly, end to end over real libp2p hosts:
// every shard of the chunk landed, and no host holds two of them.
func TestDispersalPutsEachShardOfAChunkOnADistinctNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, _ := openTestNode(t, ctx, dataShards, parityShards)

	targets := make([]*Node, 0, dataShards+parityShards)
	stores := make([]*store.Store, 0, dataShards+parityShards)
	for i := 0; i < dataShards+parityShards; i++ {
		node, storage, _ := openTestNode(t, ctx, dataShards, parityShards)
		targets = append(targets, node)
		stores = append(stores, storage)
	}
	stubCoordinator(t, append([]*Node{source}, targets...)...)
	for _, target := range targets {
		if err := source.host.Connect(ctx, peer.AddrInfo{
			ID: target.host.ID(), Addrs: target.host.Addrs(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := sourceStore.CreateBucket("spread"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("spread", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(1, 8000)))
	if err != nil {
		t.Fatal(err)
	}
	result := source.DisperseObject(ctx, *manifest)
	if result.Placed != len(manifest.Chunks)*(dataShards+parityShards) {
		t.Fatalf("placed %d shards, want %d", result.Placed,
			len(manifest.Chunks)*(dataShards+parityShards))
	}
	if !result.Durable || !result.Complete {
		t.Fatalf("dispersal onto %d distinct peers reported %#v", len(targets), result)
	}

	// What the peers actually hold, measured from their own disks rather than
	// from the sender's opinion.
	for _, chunk := range manifest.Chunks {
		holdersOfChunk := map[int]int{}
		for _, ref := range chunk.Shards {
			carriers := 0
			for index, storage := range stores {
				value, err := storage.ReadShard(ref.ID)
				if err != nil {
					continue
				}
				expected, err := sourceStore.ReadShard(ref.ID)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(value, expected) {
					t.Fatalf("node %d stored different bytes for shard %s", index, ref.ID[:12])
				}
				carriers++
				holdersOfChunk[index]++
			}
			if carriers == 0 {
				t.Fatalf("shard %d of chunk %d reached no peer at all", ref.Index, chunk.Index)
			}
		}
		for index, count := range holdersOfChunk {
			if count > 1 {
				t.Fatalf("node %d holds %d shards of chunk %d; one node loss would cost %d of %d parity",
					index, count, chunk.Index, count, parityShards)
			}
		}
	}

	// And the ledger agrees, because repair and the read path both key off it.
	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if row.UnderReplicated() || !row.FullyDispersed() {
		t.Fatalf("ledger reports %#v after a complete dispersal", row)
	}
	for _, chunkIndex := range row.ChunkIndexes() {
		seen := map[string]string{}
		for _, shard := range row.PlacementSnapshot(chunkIndex) {
			if len(shard.Holders) != 1 {
				t.Fatalf("shard %d of chunk %d has holders %v, want exactly one",
					shard.Index, chunkIndex, shard.Holders)
			}
			if previous, clash := seen[shard.Holders[0]]; clash {
				t.Fatalf("ledger puts shards %s and %s of chunk %d on the same node",
					previous, shard.ID[:12], chunkIndex)
			}
			seen[shard.Holders[0]] = shard.ID[:12]
		}
	}
}

// With fewer peers than shards, the honest outcome is fewer placements and an
// object that still says it is under-replicated -- not shards stacked two to a
// host under a durability claim that does not hold.
func TestDispersalWithTooFewPeersRefusesToDoubleUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, _ := openTestNode(t, ctx, dataShards, parityShards)
	targetA, storeA, _ := openTestNode(t, ctx, dataShards, parityShards)
	targetB, storeB, _ := openTestNode(t, ctx, dataShards, parityShards)
	stubCoordinator(t, source, targetA, targetB)
	for _, target := range []*Node{targetA, targetB} {
		if err := source.host.Connect(ctx, peer.AddrInfo{
			ID: target.host.ID(), Addrs: target.host.Addrs(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sourceStore.CreateBucket("cramped"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("cramped", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(2, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	result := source.DisperseObject(ctx, *manifest)
	if result.Placed != 2 {
		t.Fatalf("placed %d shards on 2 peers, want 2", result.Placed)
	}
	if result.Unassignable != 3 {
		t.Fatalf("reported %d unassignable shards, want the 3 with nowhere distinct to go",
			result.Unassignable)
	}
	if result.Durable {
		t.Fatal("2 of 3 data shards off-node was reported as durable; it cannot be decoded")
	}
	for name, storage := range map[string]*store.Store{"A": storeA, "B": storeB} {
		held := 0
		for _, ref := range manifest.Chunks[0].Shards {
			if _, err := storage.ReadShard(ref.ID); err == nil {
				held++
			}
		}
		if held > 1 {
			t.Fatalf("peer %s holds %d shards of one chunk", name, held)
		}
	}
}

// Repair is triggered by the periodic pass, by a dispersal that finds a chunk
// short, and by overlapping runs of either; shard ids are shared between objects
// because shards are content-addressed. Two concurrent repairs of one shard
// would regenerate the same bytes twice, take two coordinator leases, and race
// into the ledger.
func TestRepairDoesNotRunTwiceForTheSameShardConcurrently(t *testing.T) {
	node := &Node{repairing: make(map[string]struct{})}
	const shardID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	const racers = 64
	var (
		start   sync.WaitGroup
		done    sync.WaitGroup
		mu      sync.Mutex
		granted int
		inside  int
		peak    int
	)
	start.Add(1)
	for i := 0; i < racers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			if !node.beginRepair(shardID) {
				return
			}
			mu.Lock()
			granted++
			inside++
			if inside > peak {
				peak = inside
			}
			mu.Unlock()
			// Hold the slot long enough that a broken gate would overlap.
			time.Sleep(time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			node.endRepair(shardID)
		}()
	}
	start.Done()
	done.Wait()

	if peak > 1 {
		t.Fatalf("%d goroutines repaired the same shard at once", peak)
	}
	if granted == 0 {
		t.Fatal("no goroutine was ever allowed to repair the shard")
	}
	// The slot is released, so a later pass can repair it again.
	if !node.beginRepair(shardID) {
		t.Fatal("the repair slot was never released")
	}
	node.endRepair(shardID)

	// A different shard is never blocked by an in-flight repair of another.
	if !node.beginRepair(shardID) {
		t.Fatal("could not claim the first shard")
	}
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if !node.beginRepair(other) {
		t.Fatal("an unrelated shard was blocked by another shard's repair")
	}
	if node.beginRepair(shardID) {
		t.Fatal("the same shard was claimed twice")
	}
	node.endRepair(shardID)
	node.endRepair(other)
}

// The other half of the user's request: when a node drops out, the pieces it
// held are rebuilt from the survivors.
func TestRepairRebuildsShardsLostWithAHolder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, sourceDir := openTestNode(t, ctx, dataShards, parityShards)
	if err := sourceStore.CreateBucket("repair"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("repair", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(3, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]

	// Two shards are gone: the holder that had them is gone and the local copies
	// went with a disk. Three survive, which is exactly dataShards.
	lost := chunk.Shards[:2]
	originals := map[string][]byte{}
	for _, ref := range lost {
		value, err := sourceStore.ReadShard(ref.ID)
		if err != nil {
			t.Fatal(err)
		}
		originals[ref.ID] = value
		if err := os.Remove(shardFileOf(sourceDir, ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	for _, ref := range lost {
		if _, err := sourceStore.ReadShard(ref.ID); err == nil {
			t.Fatal("test setup did not actually remove the shard")
		}
	}

	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	budget := 16
	restored, err := source.restoreChunkBytes(ctx, *manifest, chunk.Index,
		row.PlacementSnapshot(chunk.Index), &budget)
	if err != nil {
		t.Fatal(err)
	}
	if restored != 2 {
		t.Fatalf("rebuilt %d shards, want 2", restored)
	}
	if budget != 14 {
		t.Fatalf("repair budget is %d, want it charged for 2 shards", budget)
	}
	for _, ref := range lost {
		rebuilt, err := sourceStore.ReadShard(ref.ID)
		if err != nil {
			t.Fatalf("shard %s was not rebuilt: %v", ref.ID[:12], err)
		}
		if !bytes.Equal(rebuilt, originals[ref.ID]) {
			t.Fatalf("rebuilt shard %s differs from the original", ref.ID[:12])
		}
	}
}

// The storm brake. A netsplit makes every holder unreachable at once, so an
// unbudgeted repair would try to rebuild the whole catalogue at the moment the
// network can least carry it.
func TestRepairBudgetCapsShardsRebuiltInOnePass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, sourceDir := openTestNode(t, ctx, dataShards, parityShards)
	if err := sourceStore.CreateBucket("budget"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("budget", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(4, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]
	for _, ref := range chunk.Shards[:2] {
		if err := os.Remove(shardFileOf(sourceDir, ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	budget := 1
	restored, err := source.restoreChunkBytes(ctx, *manifest, chunk.Index,
		row.PlacementSnapshot(chunk.Index), &budget)
	if err != nil {
		t.Fatal(err)
	}
	if restored != 1 || budget != 0 {
		t.Fatalf("rebuilt %d shards with %d budget left; the cap did not hold", restored, budget)
	}
}

// Fewer than dataShards survivors is a lost chunk, and repair must say so
// rather than write out whatever Reconstruct returns.
func TestRepairRefusesToRebuildBelowDataShards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, sourceDir := openTestNode(t, ctx, dataShards, parityShards)
	if err := sourceStore.CreateBucket("lost"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("lost", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(5, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]
	for _, ref := range chunk.Shards[:3] {
		if err := os.Remove(shardFileOf(sourceDir, ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	budget := 16
	if _, err := source.restoreChunkBytes(ctx, *manifest, chunk.Index,
		row.PlacementSnapshot(chunk.Index), &budget); err == nil {
		t.Fatal("repair claimed to rebuild a chunk with 2 of 3 data shards surviving")
	}
}

// dispersedObject stands up a source node and `targets` peers, connects them
// all, and writes one object. Returned so the placement tests below can talk
// about "the peer holding shard 3" rather than about indexes into a slice.
type dispersedObject struct {
	source      *Node
	sourceStore *store.Store
	sourceDir   string
	nodes       map[string]*Node
	stores      map[string]*store.Store
	manifest    *store.Manifest
	coordinator *coordinatorStub
}

func disperseOnto(t *testing.T, ctx context.Context, targets, dataShards, parityShards int,
	bucket string, seed int64) *dispersedObject {
	t.Helper()
	source, sourceStore, sourceDir := openTestNode(t, ctx, dataShards, parityShards)
	out := &dispersedObject{
		source: source, sourceStore: sourceStore, sourceDir: sourceDir,
		nodes: map[string]*Node{}, stores: map[string]*store.Store{},
	}
	all := []*Node{source}
	for i := 0; i < targets; i++ {
		node, storage, _ := openTestNode(t, ctx, dataShards, parityShards)
		out.nodes[node.host.ID().String()] = node
		out.stores[node.host.ID().String()] = storage
		all = append(all, node)
	}
	out.coordinator = stubCoordinator(t, all...)
	for _, target := range all[1:] {
		if err := source.host.Connect(ctx, peer.AddrInfo{
			ID: target.host.ID(), Addrs: target.host.Addrs(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sourceStore.CreateBucket(bucket); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject(bucket, "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(seed, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) != 1 {
		t.Fatalf("expected a single chunk, got %d", len(manifest.Chunks))
	}
	out.manifest = manifest
	return out
}

// coLocation reports the peers holding more than one shard of the chunk,
// measured from the peers' own disks rather than from the sender's opinion.
func (d *dispersedObject) coLocation(t *testing.T) map[string]int {
	t.Helper()
	held := map[string]int{}
	for _, ref := range d.manifest.Chunks[0].Shards {
		for id, storage := range d.stores {
			if _, err := storage.ReadShard(ref.ID); err == nil {
				held[id]++
			}
		}
	}
	for id, count := range held {
		if count == 1 {
			delete(held, id)
		} else {
			t.Logf("peer %s holds %d shards of one chunk", id[:12], count)
		}
	}
	return held
}

// CRITICAL: two placement rounds running at once must not undo the planner.
//
// placement.Plan cannot put two shards of a chunk on one peer, but that holds
// for ONE call: the PUT-time distributor, the replicate pass and the repair
// pass are three goroutines that all place shards for the same object, and two
// of them overlapping each plan from a ledger the other has not written to yet.
// Their candidate lists are ranked by advertised free space, so any change
// between the rounds permutes the ranking and the second round sends shard 4 to
// the peer the first round is sending shard 0 to.
func TestConcurrentPlacementRoundsNeverCoLocateAChunk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := disperseOnto(t, ctx, dataShards+parityShards, dataShards, parityShards, "race", 7)

	// The same peers, ranked in OPPOSITE orders: one round's first choice is the
	// other's last. This is a capacity record refreshing between two passes, not
	// a contrivance -- free space is exactly what the ranking is made of.
	var ids []string
	for id := range fixture.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ascending := make([]placement.Candidate, len(ids))
	descending := make([]placement.Candidate, len(ids))
	for i, id := range ids {
		ascending[i] = placement.Candidate{PeerID: id, FreeBytes: int64(1<<30 + (len(ids) - i))}
		descending[i] = placement.Candidate{PeerID: id, FreeBytes: int64(1<<30 + i)}
	}

	read := func(shardID string) ([]byte, error) { return fixture.sourceStore.ReadShard(shardID) }
	var start sync.WaitGroup
	var done sync.WaitGroup
	var mu sync.Mutex
	placed := 0
	start.Add(1)
	for _, candidates := range [][]placement.Candidate{ascending, descending} {
		done.Add(1)
		go func(candidates []placement.Candidate) {
			defer done.Done()
			start.Wait()
			result := fixture.source.placeShards(ctx, fixture.manifest.ObjectID, candidates, read)
			mu.Lock()
			placed += result.Placed
			mu.Unlock()
		}(candidates)
	}
	start.Done()
	done.Wait()

	if doubled := fixture.coLocation(t); len(doubled) > 0 {
		t.Fatalf("%d peer(s) ended up holding two shards of one chunk; losing one costs %d of %d parity",
			len(doubled), 2, parityShards)
	}
	if placed != dataShards+parityShards {
		t.Fatalf("two rounds placed %d shards between them, want each of the %d shards once",
			placed, dataShards+parityShards)
	}
	row, err := fixture.sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, shard := range row.PlacementSnapshot(0) {
		if len(shard.Holders) != 1 {
			t.Fatalf("shard %d has holders %v, want exactly one", shard.Index, shard.Holders)
		}
		seen[shard.Holders[0]]++
	}
	for holder, count := range seen {
		if count > 1 {
			t.Fatalf("the ledger records %s as holding %d shards of one chunk", holder[:12], count)
		}
	}
	if row.UnderReplicated() || !row.FullyDispersed() {
		t.Fatalf("ledger reports %#v after the object was fully placed", row)
	}
}

// holderOfShard returns the recorded holder of a shard, and fails if there is
// not exactly one.
func holderOfShard(t *testing.T, storage *store.Store, objectID, shardID string) string {
	t.Helper()
	row, err := storage.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range row.Shards {
		if shard.ShardID != shardID {
			continue
		}
		if len(shard.Holders) != 1 {
			t.Fatalf("shard %s has holders %v, want exactly one", shardID[:12], shard.Holders)
		}
		return shard.Holders[0]
	}
	t.Fatalf("shard %s is not in the ledger", shardID[:12])
	return ""
}

func recordsHolder(t *testing.T, storage *store.Store, objectID, shardID, peerID string) bool {
	t.Helper()
	row, err := storage.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range row.Shards {
		if shard.ShardID != shardID {
			continue
		}
		for _, holder := range shard.Holders {
			if holder == peerID {
				return true
			}
		}
	}
	return false
}

// THE OTHER HALF OF THE REQUIREMENT: "when a node drops out the missing pieces
// are reconstructed".
//
// A node that drops out does not answer "no", it says nothing at all, so the
// audit has to reach a verdict from silence. This drives the whole loop --
// audit, drop, rebuild, re-place -- against a peer whose process is gone,
// rather than deleting a file and calling the rebuild directly.
func TestUnreachableHolderIsDroppedAcrossAuditsAndItsShardRebuilt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	// One peer more than the chunk has shards, so the regenerated shard has
	// somewhere to go that is not already holding a sibling.
	fixture := disperseOnto(t, ctx, dataShards+parityShards+1, dataShards, parityShards, "dropout", 8)
	source, sourceStore := fixture.source, fixture.sourceStore

	result := source.DisperseObject(ctx, *fixture.manifest)
	if result.Placed != dataShards+parityShards || !result.Complete {
		t.Fatalf("setup dispersal reported %#v", result)
	}

	victimShard := fixture.manifest.Chunks[0].Shards[0]
	victimPeer := holderOfShard(t, sourceStore, fixture.manifest.ObjectID, victimShard.ID)
	// The node goes away. Not "answers no", not "refuses": gone.
	if err := fixture.nodes[victimPeer].Close(); err != nil {
		t.Fatalf("could not stop the holder: %v", err)
	}
	// And the local copy goes with a disk, so the shard has to be REBUILT rather
	// than merely re-sent.
	if err := os.Remove(shardFileOf(fixture.sourceDir, victimShard.ID)); err != nil {
		t.Fatal(err)
	}

	for audit := 1; audit <= 3; audit++ {
		// Audits are hours apart in production, so the two-minute candidate cache
		// has always expired between them.
		source.candidateMu.Lock()
		source.candidateCache, source.candidateAt = nil, time.Time{}
		source.candidateMu.Unlock()

		row, err := sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		budget := 16
		source.repairObject(ctx, *row, &budget)

		stillRecorded := recordsHolder(t, sourceStore, fixture.manifest.ObjectID, victimShard.ID, victimPeer)
		switch {
		case audit < 3 && !stillRecorded:
			t.Fatalf("a holder was evicted after %d unanswered audit(s); a reboot would cost a node every shard it holds",
				audit)
		case audit == 3 && stillRecorded:
			t.Fatal("a holder unreachable across three consecutive audits is still in the ledger, so its shard is never rebuilt")
		}
	}

	rebuilt, err := sourceStore.ReadShard(victimShard.ID)
	if err != nil {
		t.Fatalf("the shard of the node that dropped out was never rebuilt: %v", err)
	}
	replacement := holderOfShard(t, sourceStore, fixture.manifest.ObjectID, victimShard.ID)
	if replacement == victimPeer {
		t.Fatal("the shard was re-placed on the node that dropped out")
	}
	storage, known := fixture.stores[replacement]
	if !known {
		t.Fatalf("shard re-placed on unknown peer %s", replacement)
	}
	value, err := storage.ReadShard(victimShard.ID)
	if err != nil {
		t.Fatalf("the new holder does not actually have the shard: %v", err)
	}
	if !bytes.Equal(value, rebuilt) {
		t.Fatal("the new holder stored different bytes")
	}
	if doubled := fixture.coLocation(t); len(doubled) > 0 {
		t.Fatalf("repair put two shards of one chunk on %d peer(s)", len(doubled))
	}
	row, err := sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if row.UnderReplicated() || !row.FullyDispersed() {
		t.Fatalf("after repair the object still reports %#v", row)
	}
}

// The other side of the same judgement: silence is only evidence about a holder
// when this node is demonstrably able to reach the others. With most holders
// unreachable the likely fault is local, and an audit that "repaired" its way
// through a netsplit would forget where the object lives and then rebuild and
// re-push the whole catalogue as the peers come back.
func TestAuditDropsNothingWhenMostHoldersAreSilent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := disperseOnto(t, ctx, dataShards+parityShards, dataShards, parityShards, "netsplit", 9)
	source, sourceStore := fixture.source, fixture.sourceStore
	if result := source.DisperseObject(ctx, *fixture.manifest); !result.Complete {
		t.Fatalf("setup dispersal reported %#v", result)
	}

	before, err := sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	// Three of the five holders go dark at once -- the shape of a netsplit, or
	// of an I2P tunnel this node lost rather than three machines dying.
	silenced := 0
	for _, shard := range before.Shards {
		if silenced == 3 {
			break
		}
		if err := fixture.nodes[shard.Holders[0]].Close(); err != nil {
			t.Fatal(err)
		}
		silenced++
	}

	for audit := 0; audit < 5; audit++ {
		row, err := sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		source.auditHolders(ctx, *row)
	}

	after, err := sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range before.Shards {
		for _, holder := range shard.Holders {
			if !recordsHolder(t, sourceStore, fixture.manifest.ObjectID, shard.ShardID, holder) {
				t.Fatalf("five audits during a netsplit forgot that %s holds shard %s",
					holder[:12], shard.ShardID[:12])
			}
			if count := after.HolderSilences(shard.ShardID, holder); count != 0 {
				t.Fatalf("holder %s carries %d silences out of a netsplit; it would be two probes from eviction",
					holder[:12], count)
			}
		}
	}
}

// A chunk can arrive at this code already co-located -- a ledger row written
// before the property was enforced, two objects sharing a content-addressed
// shard, or a placement round from an older build. Every shard has a holder, so
// the pass has nothing obvious left to do; the object must not simply sit there
// being counted as under-replicated forever.
func TestAlreadyCoLocatedObjectIsSpreadByTheNextPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := disperseOnto(t, ctx, dataShards+parityShards, dataShards, parityShards, "crowded", 11)
	source, sourceStore := fixture.source, fixture.sourceStore

	// One peer is recorded as holding the entire chunk. Nine of nine placed,
	// zero machines of redundancy.
	var crowded string
	for id := range fixture.nodes {
		if crowded == "" || id < crowded {
			crowded = id
		}
	}
	for _, ref := range fixture.manifest.Chunks[0].Shards {
		if err := sourceStore.ConfirmShardHolder(fixture.manifest.ObjectID, ref.ID, crowded); err != nil {
			t.Fatal(err)
		}
	}
	row, err := sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.UnderReplicated() || row.FullyDispersed() {
		t.Fatalf("setup: a single-holder object reports %#v", row)
	}

	result := source.DisperseObject(ctx, *fixture.manifest)
	if result.Placed == 0 {
		t.Fatal("a fully placed but co-located object was left exactly as it was")
	}
	row, err = sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if row.UnderReplicated() {
		t.Fatalf("still under-replicated after a pass over a co-located object: %#v", row)
	}
	// Measured from the peers' own disks: the pieces really did move.
	elsewhere := 0
	for id, storage := range fixture.stores {
		if id == crowded {
			continue
		}
		for _, ref := range fixture.manifest.Chunks[0].Shards {
			if _, err := storage.ReadShard(ref.ID); err == nil {
				elsewhere++
			}
		}
	}
	if elsewhere < dataShards {
		t.Fatalf("only %d shard(s) reached a second machine, want at least %d", elsewhere, dataShards)
	}
}
