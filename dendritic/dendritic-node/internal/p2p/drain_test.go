package p2p

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// DRAINING TAKES A HOLDER AWAY. Every test here is therefore about what the
// drain REFUSES to do, and each was checked by reverting the guard it names and
// watching it fail -- a drain test that passes with the guard removed has tested
// that the code runs, not that the machine is safe to switch off.

// stallReasons is the report's refusals, for asserting on.
func stallReasons(report DrainReport) []string {
	var out []string
	for _, stall := range report.Stalls {
		out = append(out, stall.Reason)
	}
	return out
}

// A DRAINING NODE IS NOT A DESTINATION.
//
// This is the half of the feature that is easy to leave out, because a drain
// that only MOVES shards looks like it works: the retiring node empties, and
// meanwhile dispersal is filling it back up from the other end. The peer is
// dropped from the candidate set that dispersal, repair and levelling all share,
// and the filter has to be on BOTH tiers of that set -- a retiring node stays up
// and stays CONNECTED for the whole drain, so the connected-peers fallback is
// exactly the path that would let it back in.
//
// Reverted to prove it fails: the `n.isDraining(id)` check in the connected-peer
// tier of storageCandidates. The retiring peer is then handed shards of the new
// object while it is trying to leave.
func TestADrainingNodeIsNotChosenForNewPlacements(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 31)

	// A peer that has proved it will accept shards -- it holds one already -- so
	// its absence from the next object cannot be explained by it being unusable.
	retiring := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	if retiring == "" {
		t.Fatal("setup: no holder to retire")
	}
	fixture.source.markDraining(retiring)

	manifest, err := fixture.sourceStore.PutObject("level", "after-drain.bin",
		"application/octet-stream", bytes.NewReader(varyingBytes(131, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.source.DisperseObject(ctx, *manifest)

	if result.Placed != dataShards+parityShards {
		t.Fatalf("placed %d of %d shards with one peer retiring; the rest of the fleet should have absorbed it (%#v)",
			result.Placed, dataShards+parityShards, result)
	}
	if held := fixture.heldByOf(t, retiring, manifest); held != 0 {
		t.Fatalf("the retiring node was given %d shard(s) of an object written after it announced it was leaving",
			held)
	}
	row, err := fixture.sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range row.Shards {
		for _, holder := range shard.Holders {
			if holder == retiring {
				t.Fatalf("the ledger records the retiring node as a holder of shard %s", shard.ShardID[:12])
			}
		}
	}
	// And it is not merely absent from one plan: the candidate set itself no
	// longer offers it, which is what makes repair and levelling decline too.
	for _, candidate := range fixture.source.storageCandidates(ctx) {
		if candidate.PeerID == retiring {
			t.Fatal("the retiring node is still in the candidate set; repair and levelling would keep offering it shards")
		}
	}
}

// NOTHING IS RECALLED FROM A RETIRING NODE UNTIL THE REPLACEMENT IS CONFIRMED.
//
// The destination here acknowledges the store frame and keeps nothing -- a peer
// that lies, or a disk that failed between the acknowledgement and the flush.
// The ledger therefore believes the copy landed, and the retiring node is about
// to be switched off. The only thing between that lie and a lost shard is the
// follow-up `have`: an acknowledgement is a sentence, a probe is an observation,
// and a drain must not delete on the strength of the former even though the
// source is leaving anyway.
//
// Reverted to prove it fails: the PeerHasShard verification in moveShard. A
// delete token is then minted and the shard leaves the only peer that had it.
func TestADrainDoesNotRecallUntilTheReplacementIsConfirmed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 32)
	if len(fixture.idle) == 0 {
		t.Fatal("setup: no idle peer to receive the shard")
	}
	// The only peer that can take the shard without holding a sibling.
	sink := fixture.idle[0]
	retiring := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	shardID := fixture.shardOn(t, retiring)
	lyingSink(t, fixture.nodes[sink])

	report := fixture.source.drainWith(ctx, []string{retiring})

	if report.Moved != 0 {
		t.Fatalf("counted %d move(s) onto a destination that kept nothing", report.Moved)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted against a retiring node before the copy was verified: %#v", issued)
	}
	if _, err := fixture.stores[retiring].ReadShard(shardID); err != nil {
		t.Fatalf("shard %s is gone from the retiring node: the only copy was deleted against an unverified destination",
			shardID[:12])
	}
	if !recordsHolder(t, fixture.sourceStore, fixture.manifest.ObjectID, shardID, retiring) {
		t.Fatal("the ledger stopped recording the retiring node as a holder although nothing was deleted")
	}
	if recordsHolder(t, fixture.sourceStore, fixture.manifest.ObjectID, shardID, sink) {
		t.Fatal("the ledger still names a destination that answered `have` with no; the chunk reads one machine more durable than it is")
	}
	// And the operator is told, rather than left to infer it from a move count.
	if report.Unmovable == 0 {
		t.Fatalf("report says %#v; a shard that could not leave must be reported, not merely not counted", report)
	}
	if report.Remaining.Shards == 0 {
		t.Fatal("the report says nothing is left on the retiring node while its shard is still on its disk")
	}
}

// A SHARD THAT CANNOT BE RE-PLACED IS LEFT ALONE AND REPORTED, NOT DROPPED.
//
// Every peer here already holds a sibling of the chunk -- the fleet is exactly
// as large as the chunk is wide -- so there is nowhere distinct for the retiring
// node's shard to go. The tempting shortcut is that the machine is leaving
// anyway, so recall it and let repair sort it out afterwards; that trades a
// machine which is still up and still serving for a chunk that is one holder
// weaker immediately. The other tempting shortcut is to send it to a peer
// holding a sibling, which turns two tolerable losses into one.
//
// Reverted to prove it fails: choosing the destination as `destinations[0]`
// instead of from placement.Plan. The shard then lands on a sibling holder and
// the chunk is co-located.
func TestAShardWithNowhereToGoStaysPutAndIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	// Exactly as many peers as the chunk has shards: every peer holds one.
	fixture := levelledFixture(t, ctx, dataShards+parityShards, dataShards, parityShards, 33)
	if len(fixture.idle) != 0 {
		t.Fatalf("setup: expected every peer to hold a shard, %d are idle", len(fixture.idle))
	}
	retiring := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	shardID := fixture.shardOn(t, retiring)
	before := map[string]int{}
	for id := range fixture.nodes {
		before[id] = fixture.heldBy(t, id)
	}

	report := fixture.source.drainWith(ctx, []string{retiring})

	if report.Moved != 0 {
		t.Fatalf("moved %d shard(s) when every peer already held a sibling of the chunk", report.Moved)
	}
	if report.Unmovable != 1 || len(report.Stalls) != 1 {
		t.Fatalf("report says %#v; want exactly one shard reported unmovable", report)
	}
	if report.Stalls[0].Reason != drainReasonNoDestination {
		t.Fatalf("the shard was reported as %q, want the no-destination reason", report.Stalls[0].Reason)
	}
	if report.Stalls[0].ShardID != shardID || report.Stalls[0].Peer != retiring {
		t.Fatalf("the report names shard %s on %s; want %s on %s",
			report.Stalls[0].ShardID[:12], report.Stalls[0].Peer[:12], shardID[:12], retiring[:12])
	}
	if _, err := fixture.stores[retiring].ReadShard(shardID); err != nil {
		t.Fatalf("shard %s was dropped from the retiring node with nowhere else to put it: %v",
			shardID[:12], err)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted for a shard that had nowhere to go: %#v", issued)
	}
	for id, count := range before {
		if after := fixture.heldBy(t, id); after != count {
			t.Fatalf("peer %s went from %d to %d shard(s) of one chunk; a drain co-located it",
				id[:12], count, after)
		}
	}
	// The remaining count still sees it, which is what stops "no moves this pass"
	// reading as "safe to switch off".
	if report.Remaining.Shards == 0 {
		t.Fatal("the report says nothing is left on the retiring node while an unmovable shard sits on it")
	}
}

// AN UNDER-REPLICATED CHUNK IS NOT DRAINED, AND SAYS WHY.
//
// The chunk here is below the durability threshold, so there is no arrangement
// in which moving a shard off it can be PROVEN not to weaken it: the count after
// the move is the count before, and the count before is already short. Repair
// owns the object until it is durable again, and the drain's job is to say so
// rather than to spend a lease and a transfer discovering it at the delete.
//
// Reverted to prove it fails: the `!row.ChunkIsDurable(chunkIndex)` guard in
// drainChunk. The mover then copies the shard to the sink -- a real transfer,
// against an object repair is trying to rescue -- before the delete is refused,
// and the report calls it a failure rather than an unmovable remainder with a
// reason an operator can act on.
func TestAnUnderReplicatedChunkIsNotDrainedAndIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 34)
	if len(fixture.idle) == 0 {
		t.Fatal("setup: no idle peer to receive the shard")
	}
	sink := fixture.idle[0]
	objectID := fixture.manifest.ObjectID

	// Holders leave, the way an audit records them leaving, until the chunk is
	// under the threshold -- but one retiring holder is kept.
	retiring := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	threshold := store.DurableRemoteHolders(dataShards, parityShards)
	for _, ref := range fixture.manifest.Chunks[0].Shards {
		row, err := fixture.sourceStore.LoadObjectPlacement(objectID)
		if err != nil {
			t.Fatal(err)
		}
		if placement.DistinctHolders(row.PlacementSnapshot(0)) < threshold {
			break
		}
		holder := fixture.holders[ref.ID]
		if holder == "" || holder == retiring {
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
	if row.ChunkIsDurable(0) {
		t.Fatalf("setup: the chunk is still durable after dropping holders: %#v", row)
	}
	shardID := fixture.shardOn(t, retiring)

	report := fixture.source.drainWith(ctx, []string{retiring})

	if report.Moved != 0 {
		t.Fatalf("drained a shard off an under-replicated chunk: %#v", report)
	}
	if report.Unmovable == 0 || !containsReason(stallReasons(report), drainReasonUnderReplicated) {
		t.Fatalf("report says %#v; want the shard reported unmovable because the chunk is under-replicated", report)
	}
	if held := fixture.heldBy(t, sink); held != 0 {
		t.Fatalf("the sink received %d shard(s) of an under-replicated chunk; the copy should never have been attempted",
			held)
	}
	if _, err := fixture.stores[retiring].ReadShard(shardID); err != nil {
		t.Fatalf("shard %s left the retiring node although the chunk could not afford it: %v", shardID[:12], err)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted against an under-replicated chunk: %#v", issued)
	}
}

// A DRAIN DOES NOT STARVE REPAIR.
//
// Repair and the movers share one window counter. Repair RECORDS its movements
// against it and is never refused -- it is restoring durability, and a drain
// that could push it aside would let "somebody wants to unplug a machine" outrank
// "an object is one disk from gone". The drain asks, and is refused as soon as
// the window is spent. That priority order is a counter, not a comment.
//
// Reverted to prove it fails: the `n.shardMoves.allow()` check in drainChunk.
// The drain then moves shards through a window repair has already spent.
func TestADrainIsRefusedWhenRepairHasSpentTheSharedBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 35)
	if len(fixture.idle) == 0 {
		t.Fatal("setup: no idle peer to receive the shard")
	}
	sink := fixture.idle[0]
	retiring := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	shardID := fixture.shardOn(t, retiring)

	// A half hour of heavy repair, recorded exactly as repairObject records it.
	fixture.source.shardMoves.record(movesPerWindow)

	report := fixture.source.drainWith(ctx, []string{retiring})

	if report.Moved != 0 {
		t.Fatalf("the drain moved %d shard(s) through a window repair had already spent", report.Moved)
	}
	if !report.BudgetExhausted {
		t.Fatalf("report says %#v; the pass must say the shared budget ended it, not imply there was nothing to do", report)
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted with the shared budget spent: %#v", issued)
	}
	if _, err := fixture.stores[retiring].ReadShard(shardID); err != nil {
		t.Fatalf("shard %s left the retiring node although no move was allowed: %v", shardID[:12], err)
	}
	if held := fixture.heldBy(t, sink); held != 0 {
		t.Fatalf("the sink received %d shard(s) with the shared budget spent", held)
	}
	// The window is still spent afterwards, so the drain has not quietly topped
	// itself up on the way past.
	if fixture.source.shardMoves.allow() {
		t.Fatal("the shared window is no longer spent after a refused drain pass")
	}
}

// The other direction of the same rule: a drain spending the whole window can
// never refuse REPAIR a move.
//
// Repair records against the counter and is never asked for permission -- there
// is no path by which the budget can say no to it -- and that is the priority
// order expressed as an API rather than as a comment. A drain is refused as soon
// as the window is spent, so an hour of heavy draining costs some tidying and
// costs the loop that keeps objects alive nothing.
func TestADrainCanNeverRefuseRepairAMove(t *testing.T) {
	budget := newShardMoveBudget()
	budget.limit = 2
	now := time.Now()
	budget.now = func() time.Time { return now }

	if !budget.allow() || !budget.allow() {
		t.Fatal("a fresh window refused the drain its first two moves")
	}
	if budget.allow() {
		t.Fatal("the drain was allowed a move past the shared limit")
	}
	// Repair moves anyway, and overspends the window doing it.
	budget.record(8)
	if budget.allow() {
		t.Fatal("the drain got a move after repair had overspent the window")
	}
	now = now.Add(moveWindow + time.Second)
	if !budget.allow() {
		t.Fatal("the window never rolled over, so a drain would stall forever after one busy half hour")
	}
}

// THE HAPPY PATH, INCLUDING THE ONE PLACE DRAINING DELIBERATELY DIFFERS FROM
// LEVELLING.
//
// The chunk sits on EXACTLY the durability threshold. Levelling refuses those --
// tidying is never worth an object's last margin (see
// TestAChunkAtExactlyTheDurabilityThresholdIsNotLevelled). A drain must move
// them, because the margin is not being spent, it is walking out of the building
// on a machine that is about to be switched off, and refusing to act would
// guarantee the loss the rule exists to prevent.
//
// Copy-then-delete is what makes that safe: the chunk goes threshold ->
// threshold+1 -> threshold and never dips.
func TestADrainMovesAChunkSittingAtExactlyTheDurabilityThreshold(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 36)
	objectID := fixture.manifest.ObjectID
	threshold := store.DurableRemoteHolders(dataShards, parityShards)

	retiring := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	for _, ref := range fixture.manifest.Chunks[0].Shards {
		row, err := fixture.sourceStore.LoadObjectPlacement(objectID)
		if err != nil {
			t.Fatal(err)
		}
		if placement.DistinctHolders(row.PlacementSnapshot(0)) <= threshold {
			break
		}
		holder := fixture.holders[ref.ID]
		if holder == "" || holder == retiring {
			continue
		}
		if err := fixture.sourceStore.DropShardHolder(objectID, ref.ID, holder); err != nil {
			t.Fatal(err)
		}
		delete(fixture.holders, ref.ID)
	}
	before, err := fixture.sourceStore.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	if got := placement.DistinctHolders(before.PlacementSnapshot(0)); got != threshold {
		t.Fatalf("setup produced %d holders, need exactly the threshold %d", got, threshold)
	}
	if before.UnderReplicated() {
		t.Fatalf("setup: the object must be durable, not under-replicated: %#v", before)
	}
	if before.ChunkHasDurabilityMargin(0) {
		t.Fatal("setup: the chunk has margin to spare, so this is the levelling case and not the draining one")
	}
	shardID := fixture.shardOn(t, retiring)

	report := fixture.source.drainWith(ctx, []string{retiring})

	if report.Moved != 1 {
		t.Fatalf("report says %#v; want the at-threshold shard moved off the retiring node", report)
	}
	if _, err := fixture.stores[retiring].ReadShard(shardID); err == nil {
		t.Fatalf("shard %s is still on the retiring node; a drain that only copies is not a drain", shardID[:12])
	}
	if recordsHolder(t, fixture.sourceStore, objectID, shardID, retiring) {
		t.Fatal("the ledger still names the retiring node as a holder of a shard it deleted")
	}
	after, err := fixture.sourceStore.LoadObjectPlacement(objectID)
	if err != nil {
		t.Fatal(err)
	}
	if got := placement.DistinctHolders(after.PlacementSnapshot(0)); got != threshold {
		t.Fatalf("distinct holders went from %d to %d across a drain of an at-threshold chunk", threshold, got)
	}
	if after.UnderReplicated() {
		t.Fatalf("the object is under-replicated after a drain: %#v", after)
	}
	if report.Remaining.Shards != 0 {
		t.Fatalf("the report still records %d shard(s) on a node it has emptied", report.Remaining.Shards)
	}
	if report.Unmovable != 0 {
		t.Fatalf("report says %#v; nothing should be unmovable here", report)
	}

	// And the pass is resumable rather than repeated: the object's drain clock
	// was stamped, so an immediately following pass does not re-examine it.
	again := fixture.source.drainWith(ctx, []string{retiring})
	if again.Examined != 0 {
		t.Fatalf("the next pass re-examined %d object(s) inside the cooldown; a restart loop would never reach the rest of the ledger",
			again.Examined)
	}
}

// A drain with nowhere at all to send says so, rather than reporting the same
// zero as a drain with nothing to do. Only one of those means the machine can be
// switched off.
func TestADrainWithNoCandidatesSaysSo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 37)

	// Every peer is retiring at once, so there is no destination anywhere.
	var everyone []string
	for id := range fixture.nodes {
		everyone = append(everyone, id)
	}
	sort.Strings(everyone)

	report := fixture.source.drainWith(ctx, everyone)

	if !report.NoCandidates {
		t.Fatalf("report says %#v; with every peer retiring the pass must say it had nowhere to send anything", report)
	}
	if report.Moved != 0 {
		t.Fatalf("moved %d shard(s) with no destination on the network", report.Moved)
	}
	if report.Remaining.Shards == 0 {
		t.Fatal("the report claims nothing is left while every shard sits on a retiring peer")
	}
	if issued := fixture.coordinator.revocationsIssued(); len(issued) != 0 {
		t.Fatalf("a delete token was minted with nowhere to move anything: %#v", issued)
	}
}

// A RETIRING NODE REFUSES SHARDS ITSELF, and does not stop answering anything
// else.
//
// The advertisement is the polite mechanism and it is not sufficient on its own:
// it has a ten-minute TTL, an owner running an older build ignores the field,
// and there is a window between the operator setting the flag and the next
// publication. The refusal in the handler is the guarantee. What it must NOT do
// is refuse "get", "have" or "delete" -- those are exactly what a drain runs on.
//
// Reverted to prove it fails: the `n.draining.Load()` branch in handleStream's
// "store" case. The shard is then accepted onto a disk about to be switched off.
func TestARetiringNodeRefusesNewShardsButStillServesTheDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 38)
	retiring := fixture.holders[fixture.manifest.Chunks[0].Shards[0].ID]
	shardID := fixture.shardOn(t, retiring)
	fixture.nodes[retiring].SetDraining(true)

	// "have" and "get" keep working: the owner fetches the bytes from here to
	// copy them elsewhere, and probes for them afterwards.
	target := mustPeer(t, retiring)
	has, err := fixture.source.PeerHasShard(ctx, target, shardID)
	if err != nil || !has {
		t.Fatalf("a retiring node stopped answering `have` (%v, %v); the drain cannot verify anything", has, err)
	}
	if _, err := fixture.source.FetchShard(ctx, shardID, []string{retiring}); err != nil {
		t.Fatalf("a retiring node stopped serving `get`: %v; its shards could never be copied off it", err)
	}

	// A store frame is refused, and refused with a message the candidate logic
	// recognises as an answered no rather than as an unreachable peer.
	manifest, err := fixture.sourceStore.PutObject("level", "refused.bin",
		"application/octet-stream", bytes.NewReader(varyingBytes(138, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	newShard := manifest.Chunks[0].Shards[0].ID
	err = fixture.source.placeOne(ctx, manifest.ObjectID, newShard, target,
		func(id string) ([]byte, error) { return fixture.sourceStore.ReadShard(id) })
	if err == nil {
		t.Fatal("a retiring node accepted a new shard")
	}
	if !strings.Contains(err.Error(), "draining") {
		t.Fatalf("the refusal was %q; it must name draining so an operator reading a log knows why", err)
	}
	if !answeredNo(err) {
		t.Fatal("the draining refusal is not recognised as an answered no, so a peer that ignores the advertisement would keep offering shards forever")
	}
	if _, err := fixture.stores[retiring].ReadShard(newShard); err == nil {
		t.Fatal("the retiring node stored a shard it had refused")
	}
}

// A peer that says it is draining is believed for as long as its record would
// have been, and no longer -- so a node that changes its mind, or whose record
// simply ages out, is an ordinary peer again without anybody intervening.
func TestTheDrainingMemoryExpiresWithTheRecord(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	fixture := levelledFixture(t, ctx, dataShards+parityShards+1, dataShards, parityShards, 39)
	var someone string
	for id := range fixture.nodes {
		if someone == "" || id < someone {
			someone = id
		}
	}
	if fixture.source.isDraining(someone) {
		t.Fatal("a peer that has said nothing is treated as draining")
	}
	fixture.source.markDraining(someone)
	if !fixture.source.isDraining(someone) {
		t.Fatal("a peer that announced it was retiring was not remembered")
	}
	// A failed DHT lookup -- which is routine -- must not un-drain it.
	fixture.source.storageCandidates(ctx)
	if !fixture.source.isDraining(someone) {
		t.Fatal("a candidate refresh that found no records forgot that a peer was retiring; it would go straight back into every placement")
	}
	// Age the record out the way time would.
	fixture.source.drainingMu.Lock()
	fixture.source.drainingUntil[someone] = time.Now().Add(-time.Second)
	fixture.source.drainingMu.Unlock()
	if fixture.source.isDraining(someone) {
		t.Fatal("a stale draining record is still believed; a peer that stopped draining could never rejoin the fleet")
	}
}

func containsReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}
