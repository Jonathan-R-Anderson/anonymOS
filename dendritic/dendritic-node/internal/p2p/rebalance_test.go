package p2p

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// LEVELLING MOVES REAL BYTES OFF REAL DISKS, so these tests are about what the
// mover REFUSES to do. Each one was checked by reverting the guard it names and
// watching it fail: a levelling test that passes with the guard removed has
// tested that the code runs, not that the invariant holds.

const (
	// A pool big enough that the deadband (10%, floored at 64 MiB) is a
	// meaningful number rather than the floor.
	testPoolCapacity = 100 << 30
	testPoolTarget   = 20 << 30
)

// levelling is the fixture: an object dispersed over real hosts, plus a handle
// on who holds what.
type levelling struct {
	*dispersedObject
	holders map[string]string // shard id -> the peer the ledger records
	idle    []string          // peers holding nothing of the chunk
}

func levelledFixture(t *testing.T, ctx context.Context, peers, dataShards, parityShards int, seed int64) *levelling {
	t.Helper()
	fixture := disperseOnto(t, ctx, peers, dataShards, parityShards, "level", seed)
	result := fixture.source.DisperseObject(ctx, *fixture.manifest)
	if result.Placed == 0 {
		t.Fatalf("setup: nothing was dispersed (%#v)", result)
	}
	out := &levelling{dispersedObject: fixture, holders: map[string]string{}}
	row, err := fixture.sourceStore.LoadObjectPlacement(fixture.manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	busy := map[string]bool{}
	for _, shard := range row.Shards {
		for _, holder := range shard.Holders {
			out.holders[shard.ShardID] = holder
			busy[holder] = true
		}
	}
	for id := range fixture.nodes {
		if !busy[id] {
			out.idle = append(out.idle, id)
		}
	}
	sort.Strings(out.idle)
	return out
}

// pools describes the fleet to the mover: everyone at the target, except the
// named source (fat) and the named sinks (empty).
//
// The source's surplus is chosen so the MEAN is still exactly the target --
// (k+1) times the target when k nodes hold nothing -- so every other node comes
// out balanced rather than accidentally a sink. A test whose "balanced" nodes
// are quietly sinks would let a co-locating move find a destination anyway and
// would prove nothing.
func (l *levelling) pools(source string, sinks ...string) []placement.Pool {
	thin := map[string]bool{}
	for _, id := range sinks {
		thin[id] = true
	}
	var out []placement.Pool
	for id := range l.nodes {
		pool := placement.Pool{PeerID: id, Used: testPoolTarget, Capacity: testPoolCapacity}
		switch {
		case id == source:
			pool.Used = int64(len(thin)+1) * testPoolTarget
		case thin[id]:
			pool.Used = 0
		}
		out = append(out, pool)
	}
	return out
}

func mustPeer(t *testing.T, id string) peer.ID {
	t.Helper()
	decoded, err := peer.Decode(id)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// heldBy counts the shards of the chunk a peer has on its own disk, which is
// the only measurement that cannot be faked by the sender's opinion.
func (l *levelling) heldBy(t *testing.T, peerID string) int {
	t.Helper()
	return l.heldByOf(t, peerID, l.manifest)
}

func (l *levelling) heldByOf(t *testing.T, peerID string, manifest *store.Manifest) int {
	t.Helper()
	storage := l.stores[peerID]
	if storage == nil {
		t.Fatalf("no store for peer %s", peerID)
	}
	count := 0
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			if _, err := storage.ReadShard(ref.ID); err == nil {
				count++
			}
		}
	}
	return count
}

// shardOn returns the shard the ledger says this peer holds.
func (l *levelling) shardOn(t *testing.T, peerID string) string {
	t.Helper()
	for shardID, holder := range l.holders {
		if holder == peerID {
			return shardID
		}
	}
	t.Fatalf("peer %s holds no shard of the chunk", peerID[:12])
	return ""
}

// A MOVE MUST NEVER CO-LOCATE.
//
// The only thin peer on offer here is one that ALREADY holds a shard of the
// chunk. A mover that picks the emptiest sink and sends -- the obvious
// implementation, and the one the old round-robin distributor effectively was --
// puts two shards of one chunk on one machine, which turns two tolerable losses
// into one. The destination has to come from placement.Plan, whose exclusion set
// is every peer holding any shard of the chunk.
//
// Reverted to prove it fails: choosing the destination as `(*sinks)[0].PeerID`
// instead of from Plan. The shard then lands on the sibling holder.
func TestALevellingMoveNeverLandsOnAPeerHoldingASibling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 21)

	// Two peers that both hold a shard of the one chunk: one fat, one thin.
	var holders []string
	for _, holder := range fixture.holders {
		holders = append(holders, holder)
	}
	sort.Strings(holders)
	if len(holders) < 2 {
		t.Fatalf("setup: expected several holders, got %v", holders)
	}
	source, sibling := holders[0], holders[1]
	before := fixture.heldBy(t, sibling)

	report := fixture.source.rebalanceWith(ctx, fixture.pools(source, sibling))

	if report.Moved != 0 {
		t.Fatalf("moved %d shard(s) when the only sink already held a sibling", report.Moved)
	}
	if report.NoDestination != 1 {
		t.Fatalf("report says %#v; want exactly one shard with nowhere distinct to go", report)
	}
	if after := fixture.heldBy(t, sibling); after != before {
		t.Fatalf("the sibling holder went from %d shard(s) of the chunk to %d: one node loss now costs two of %d parity",
			before, after, parityShards)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted for a move that never happened: %#v", issued)
	}
}

// A CHUNK AT EXACTLY THE DURABILITY THRESHOLD IS NOT LEVELLED.
//
// Here the chunk sits on exactly DurableRemoteHolders peers: durable, and with
// nothing to spare. The move itself would be safe in the ordinary case, because
// the destination is confirmed before the source is dropped -- but a crash, a
// coordinator outage or a refused delete in that window leaves an arrangement
// nobody re-checks until the next audit, and tidying is never worth an object's
// last margin.
//
// Reverted to prove it fails: `>` to `>=` in ChunkHasDurabilityMargin. The
// at-threshold chunk is then moved.
func TestAChunkAtExactlyTheDurabilityThresholdIsNotLevelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 22)
	objectID := fixture.manifest.ObjectID
	threshold := store.DurableRemoteHolders(dataShards, parityShards)

	// One holder leaves, the way an audit records it leaving, until the chunk
	// sits on exactly the threshold: durable, and with nothing to spare.
	for _, ref := range fixture.manifest.Chunks[0].Shards {
		row, err := fixture.sourceStore.LoadObjectPlacement(objectID)
		if err != nil {
			t.Fatal(err)
		}
		if placement.DistinctHolders(row.PlacementSnapshot(0)) <= threshold {
			break
		}
		holder := fixture.holders[ref.ID]
		if holder == "" {
			continue
		}
		if err := fixture.sourceStore.DropShardHolder(objectID, ref.ID, holder); err != nil {
			t.Fatal(err)
		}
		delete(fixture.holders, ref.ID)
	}
	row, err := fixture.sourceStore.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	holders := placement.DistinctHolders(row.PlacementSnapshot(0))
	if holders != threshold {
		t.Fatalf("setup produced %d holders, need exactly the threshold %d", holders, threshold)
	}
	if row.UnderReplicated() {
		t.Fatalf("setup: the object must be durable, not under-replicated: %#v", row)
	}
	if len(fixture.idle) == 0 {
		t.Fatal("setup: no idle peer to act as a sink")
	}
	source := ""
	for _, holder := range fixture.holders {
		source = holder
		break
	}
	sink := fixture.idle[0]

	report := fixture.source.rebalanceWith(ctx, fixture.pools(source, sink))

	if report.Moved != 0 {
		t.Fatalf("levelled a chunk sitting on exactly %d holders, the durability threshold", threshold)
	}
	if report.SkippedNoMargin != 1 {
		t.Fatalf("report says %#v; want the chunk skipped for having no durability margin", report)
	}
	if held := fixture.heldBy(t, sink); held != 0 {
		t.Fatalf("the sink received %d shard(s) from an at-threshold chunk", held)
	}
}

// COPY, THEN DELETE. NEVER THE REVERSE.
//
// The destination here acknowledges the store frame and keeps nothing -- a
// holder that lies, or a disk that failed between the ack and the flush. The
// ledger therefore believes the copy landed. The only thing standing between
// that lie and a lost shard is the follow-up `have`: an acknowledgement is a
// sentence, a probe is an observation, and nothing is deleted on the strength of
// the former.
//
// Reverted to prove it fails: the PeerHasShard verification in moveShard. The
// source is then asked to delete on the destination's word, a delete token is
// minted, and the shard leaves the only peer that actually had it.
func TestTheSourceIsNotAskedToDeleteUntilTheDestinationIsVerified(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 23)
	if len(fixture.idle) == 0 {
		t.Fatal("setup: no idle peer to act as a sink")
	}
	sink := fixture.idle[0]
	source := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	shardID := fixture.shardOn(t, source)

	// The sink accepts every store and keeps nothing, and answers `have`
	// honestly -- the realistic failure, and the one the probe exists to catch.
	lyingSink(t, fixture.nodes[sink])

	report := fixture.source.rebalanceWith(ctx, fixture.pools(source, sink))

	if report.Moved != 0 {
		t.Fatalf("counted %d move(s) onto a destination that kept nothing", report.Moved)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted before the copy was verified: %#v", issued)
	}
	if _, err := fixture.stores[source].ReadShard(shardID); err != nil {
		t.Fatalf("the source no longer has shard %s: the only copy was deleted against an unverified destination",
			shardID[:12])
	}
	if !recordsHolder(t, fixture.sourceStore, fixture.manifest.ObjectID, shardID, source) {
		t.Fatal("the ledger stopped recording the source as a holder although nothing was deleted")
	}
	// And the ledger does not carry the destination's lie forward: it
	// acknowledged the store, answered `have` with no, and was un-recorded.
	if recordsHolder(t, fixture.sourceStore, fixture.manifest.ObjectID, shardID, sink) {
		t.Fatal("the ledger still names a destination that answered `have` with no; the chunk reads one machine more durable than it is")
	}
}

// INSIDE THE DEADBAND, NOTHING MOVES.
//
// Every node here is off the target by 1.5 GiB against a 2 GiB band. Without a
// deadband those differences are "work": two nodes a megabyte apart trade shards
// forever, and every trade costs a lease, a revocation and two I2P round trips.
//
// Reverted to prove it fails: LevelDeadband set to 0. The 1.5 GiB differences
// then exceed the remaining floor and the mover starts trading.
func TestNodesInsideTheDeadbandProduceNoMoves(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 24)

	// Alternating 1.5 GiB above and below a 20 GiB target: a real difference,
	// well inside the 10% band, and well outside the 64 MiB floor.
	const drift = 3 << 29 // 1.5 GiB
	var pools []placement.Pool
	var ids []string
	for id := range fixture.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i, id := range ids {
		used := int64(testPoolTarget - drift)
		if i%2 == 0 {
			used = testPoolTarget + drift
		}
		pools = append(pools, placement.Pool{PeerID: id, Used: used, Capacity: testPoolCapacity})
	}

	report := fixture.source.rebalanceWith(ctx, pools)

	if !report.Deadbanded {
		t.Fatalf("report says %#v; every node is within the deadband of the target", report)
	}
	if report.Moved != 0 || report.Sources != 0 || report.Sinks != 0 {
		t.Fatalf("a fleet inside the deadband produced %d move(s), %d source(s) and %d sink(s)",
			report.Moved, report.Sources, report.Sinks)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted while every node was balanced: %#v", issued)
	}
}

// AN UNDER-REPLICATED OBJECT IS NEVER LEVELLED -- NOT EVEN ITS HEALTHY CHUNKS.
//
// The object here is several chunks long. One chunk has lost two holders and is
// under the threshold; the others are untouched and have margin to spare. That
// separation is the point: the guard is about the OBJECT, because while any part
// of it is short the whole object is a dispersal problem, and spending leases
// and I2P round trips tidying its healthy chunks is work taken from the loop
// that is trying to make it whole. With a single-chunk object the object guard
// and the per-chunk margin guard cannot be told apart, and a test that cannot
// tell them apart cannot show either one is load-bearing.
//
// It drives rebalanceObject DIRECTLY, past the queue, because the queue has its
// own test (store: TestRebalanceQueueSkipsAnUnderReplicatedObject) and the two
// guards must each hold on their own.
//
// Reverted to prove it fails: the UnderReplicated re-check in rebalanceObject.
// A healthy chunk of the short object is then levelled.
func TestAnUnderReplicatedObjectIsSkippedByTheMover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 25)

	// A second, multi-chunk object over the same peers.
	manifest, err := fixture.sourceStore.PutObject("level", "wide.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(251, 300<<10)))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) < 2 {
		t.Fatalf("setup: expected several chunks, got %d", len(manifest.Chunks))
	}
	if result := fixture.source.DisperseObject(ctx, *manifest); result.Placed == 0 {
		t.Fatalf("setup: nothing was dispersed (%#v)", result)
	}
	objectID := manifest.ObjectID

	// Chunk 0 loses two holders, the way an audit records them leaving.
	row, err := fixture.sourceStore.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	dropped := 0
	for _, shard := range row.PlacementSnapshot(0) {
		if dropped >= 2 || len(shard.Holders) == 0 {
			continue
		}
		if err := fixture.sourceStore.DropShardHolder(objectID, shard.ID, shard.Holders[0]); err != nil {
			t.Fatal(err)
		}
		dropped++
	}
	row, err = fixture.sourceStore.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.UnderReplicated() {
		t.Fatalf("setup: the object is still durable after dropping two holders of chunk 0")
	}
	// And a LATER chunk is untouched, so there is real work the mover is
	// choosing not to do.
	healthy := -1
	for _, chunkIndex := range row.ChunkIndexes() {
		if chunkIndex != 0 && row.ChunkHasDurabilityMargin(chunkIndex) {
			healthy = chunkIndex
			break
		}
	}
	if healthy < 0 {
		t.Fatal("setup: no healthy chunk with margin to level")
	}
	source := row.PlacementSnapshot(healthy)[0].Holders[0]

	// The sink is a peer holding nothing of that chunk.
	sink := ""
	for id := range fixture.nodes {
		if id == source {
			continue
		}
		clash := false
		for _, shard := range row.PlacementSnapshot(healthy) {
			for _, holder := range shard.Holders {
				if holder == id {
					clash = true
				}
			}
		}
		if !clash {
			sink = id
			break
		}
	}
	if sink == "" {
		t.Fatal("setup: no peer free of chunk", healthy)
	}
	before := fixture.heldByOf(t, sink, manifest)

	surplus := map[string]int64{source: testPoolTarget}
	deficit := map[string]int64{sink: testPoolTarget}
	sinks := []placement.Candidate{{PeerID: sink, FreeBytes: testPoolCapacity, Capacity: testPoolCapacity}}
	budget := rebalanceShardsPerPass
	var report RebalanceReport
	fixture.source.rebalanceObject(ctx, objectID, surplus, deficit, &sinks, &budget, &report)

	if report.Moved != 0 {
		t.Fatalf("levelled a healthy chunk of an under-replicated object: %#v", report)
	}
	if report.SkippedUnderReplicated != 1 {
		t.Fatalf("report says %#v; want the object skipped for being under-replicated", report)
	}
	if after := fixture.heldByOf(t, sink, manifest); after != before {
		t.Fatalf("the sink went from %d to %d shard(s) of an under-replicated object", before, after)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted against an under-replicated object: %#v", issued)
	}
}

// THE MOVER CANNOT RUN CONCURRENTLY WITH ITSELF FOR ONE OBJECT.
//
// Two rounds planning from the same ledger is how a chunk gets co-located by
// two moves that were each individually correct: round one is copying shard 0 to
// the peer round two has just decided to send shard 1 to, and neither ever saw
// the other's holder. Levelling takes the object's placement gate for the WHOLE
// move -- copy, verify and delete -- and not merely for the copy, because a
// recall that lands while another round is placing a sibling is the same race
// with the pieces moving the other way.
//
// The coordinator is parked mid-move here: the first mover is inside its
// revocation request and holding the gate. If a second mover can run, it reaches
// its own revocation request, and the stub sees two.
//
// Reverted to prove it fails: the `defer n.lockPlacement(objectID)()` at the top
// of rebalanceObject. The second mover then walks straight through.
func TestTheMoverCannotRunConcurrentlyWithItselfForOneObject(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 26)
	if len(fixture.idle) == 0 {
		t.Fatal("setup: no idle peer to act as a sink")
	}
	sink := fixture.idle[0]
	source := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	objectID := fixture.manifest.ObjectID

	fixture.coordinator.hold()
	t.Cleanup(fixture.coordinator.release)

	// Each round gets its OWN pass arithmetic: two passes never overlap in
	// production (RebalanceStored runs them one at a time), so sharing the maps
	// here would manufacture a data race the code cannot have and hide the one
	// under test.
	round := func() (chan struct{}, *RebalanceReport) {
		done := make(chan struct{})
		report := &RebalanceReport{}
		surplus := map[string]int64{source: testPoolTarget}
		deficit := map[string]int64{sink: testPoolTarget}
		sinks := []placement.Candidate{{PeerID: sink, FreeBytes: testPoolCapacity, Capacity: testPoolCapacity}}
		budget := rebalanceShardsPerPass
		go func() {
			defer close(done)
			fixture.source.rebalanceObject(ctx, objectID, surplus, deficit, &sinks, &budget, report)
		}()
		return done, report
	}

	first, _ := round()
	select {
	case <-fixture.coordinator.hit:
	case <-time.After(30 * time.Second):
		t.Fatal("the first mover never reached the coordinator")
	}

	second, _ := round()
	select {
	case <-second:
		t.Fatal("a second levelling round ran for the same object while the first was mid-move")
	case <-fixture.coordinator.hit:
		t.Fatal("a second delete token was requested for an object already being levelled")
	case <-time.After(3 * time.Second):
		// Blocked on the gate, which is the whole point.
	}

	fixture.coordinator.release()
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			t.Fatal("a levelling round never finished after the coordinator was released")
		}
	}
}

// The happy path, so the refusals above are not the only thing under test: a
// shard really does leave the fat node and land on the thin one, the ledger says
// so, and the chunk is no less durable afterwards.
func TestLevellingMovesAShardOffTheFatNodeAndDeletesTheSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 27)
	if len(fixture.idle) == 0 {
		t.Fatal("setup: no idle peer to act as a sink")
	}
	sink := fixture.idle[0]
	source := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	shardID := fixture.shardOn(t, source)
	objectID := fixture.manifest.ObjectID

	before, err := fixture.sourceStore.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	durableBefore := placement.DistinctHolders(before.PlacementSnapshot(0))

	report := fixture.source.rebalanceWith(ctx, fixture.pools(source, sink))

	if report.Moved != 1 {
		t.Fatalf("report says %#v; want exactly one shard moved", report)
	}
	if _, err := fixture.stores[sink].ReadShard(shardID); err != nil {
		t.Fatalf("the destination does not have shard %s: %v", shardID[:12], err)
	}
	if _, err := fixture.stores[source].ReadShard(shardID); err == nil {
		t.Fatalf("the source still has shard %s; a move that only copies is not a move", shardID[:12])
	}
	after, err := fixture.sourceStore.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	if recordsHolder(t, fixture.sourceStore, objectID, shardID, source) {
		t.Fatal("the ledger still names the source as a holder of a shard it deleted")
	}
	if !recordsHolder(t, fixture.sourceStore, objectID, shardID, sink) {
		t.Fatal("the ledger does not name the destination as a holder")
	}
	if got := placement.DistinctHolders(after.PlacementSnapshot(0)); got != durableBefore {
		t.Fatalf("distinct holders went from %d to %d across a move", durableBefore, got)
	}
	if after.UnderReplicated() {
		t.Fatalf("the object is under-replicated after a level: %#v", after)
	}
	// And the mover remembers its own recall, so nothing tries to place the
	// shard back on a peer that is refusing it for the next six hours.
	if !fixture.sourceStore.ShardMovedAwayFrom(objectID, shardID, source) {
		t.Fatal("the move was not recorded, so placement will offer the shard back to the peer it was taken from")
	}
	if err := fixture.source.placeOne(ctx, objectID, shardID, mustPeer(t, source),
		func(string) ([]byte, error) { return nil, io.EOF }); err != errRecentlyMovedAway {
		t.Fatalf("placing the shard back on the source returned %v, want %v", err, errRecentlyMovedAway)
	}
}

// lyingSink makes a peer accept every store frame, keep nothing, and answer
// `have` honestly.
func lyingSink(t *testing.T, node *Node) {
	t.Helper()
	node.host.SetStreamHandler(ProtocolID, func(stream network.Stream) {
		defer stream.Close()
		reader := bufio.NewReader(stream)
		var header requestHeader
		if err := readJSONFrame(reader, &header); err != nil {
			return
		}
		switch header.Operation {
		case "store":
			_ = writeJSONFrame(stream, responseHeader{OK: true})
			_, _ = io.CopyN(io.Discard, reader, header.Size)
			// The lie: acknowledged, never written.
			_ = writeJSONFrame(stream, responseHeader{OK: true})
		case "have":
			_ = writeJSONFrame(stream, responseHeader{OK: true, Present: false})
		default:
			_ = writeJSONFrame(stream, responseHeader{Error: "unsupported operation"})
		}
	})
}

// The shared rate limit is a real counter, not a comment: repair's movements
// consume the same window the mover draws on, and the mover is the one that gets
// refused.
func TestRepairAndLevellingShareOneShardMoveBudget(t *testing.T) {
	budget := newShardMoveBudget()
	budget.limit = 4
	now := time.Now()
	budget.now = func() time.Time { return now }

	if !budget.allow() {
		t.Fatal("a fresh window refused the first move")
	}
	budget.record(3)
	if budget.allow() {
		t.Fatal("levelling was allowed a move after repair spent the window")
	}
	now = now.Add(moveWindow + time.Second)
	if !budget.allow() {
		t.Fatal("the window never rolled over")
	}
}
