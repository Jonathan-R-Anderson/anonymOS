package p2p

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// LEVELLING THE POOLS: THE MOVER
// ==============================
// Placement picks the emptiest advertised peer and never revisits the decision.
// A node that joined early accumulates, a node that joined tonight stays nearly
// empty, and two peers were already refusing shards with "storage capacity
// exceeded" while six machines sat almost idle. Nothing rebalanced.
//
// This is the loop that does, and it is the LOWEST priority mover in the
// system: dispersal is racing to give an object its first remote copy, repair is
// restoring one that a dead node took away, and levelling is tidying. Every
// design decision below follows from that ranking.
//
// WHO MOVES WHAT
// --------------
// The mover runs on the OWNER of an object, not on the fat node. Only the owner
// has the placement ledger, so only the owner knows which peer holds a sibling
// of the chunk; only the owner can obtain a revocation, because the coordinator
// signs delete tokens for authorised origins; and only the owner can COPY before
// it deletes, because it is the one that can confirm the copy landed. A fat
// volunteer holds shard ids and nothing else -- it cannot tell which of its
// shards belong to the same chunk, so it could not shed one safely if it tried.
//
// The owner's own local copies are deliberately out of scope. Levelling here
// moves shards between REMOTE holders; draining a node's own disk is the
// operator-leaving case (roadmap phase 2b step 4), which is the same machinery
// with a target of zero and a different set of questions about what happens to
// the last copy.
//
// THE ORDER OF OPERATIONS IS THE WHOLE FEATURE
// --------------------------------------------
//	1. copy the shard to the destination and get the destination's confirmation;
//	2. VERIFY the copy with a fresh `have`, because a confirmation is a sentence
//	   and a probe is an observation;
//	3. re-read the ledger and prove the chunk is still durable with the source
//	   dropped;
//	4. only then mint a revocation and ask the source to delete;
//	5. and only credit the delete once the holder's claim has been re-checked,
//	   which recallFromPeer already does.
//
// A crash anywhere in that sequence leaves the shard on at least one peer, and
// usually on two. A duplicate is the safe direction; the reverse order has a
// window in which the only copy is in flight.

const (
	// rebalanceInterval is the levelling cadence: slower than repair's half
	// hour, because occupancy changes over days and a mover that runs often
	// enough to notice a megabyte is a mover that thrashes.
	rebalanceInterval = 1 * time.Hour
	// rebalanceObjectsPerPass and rebalanceShardsPerPass bound one pass. Small
	// on purpose: converging a fleet is not urgent, and every move costs the
	// coordinator a revocation, the lease service a lease, and two peers an I2P
	// round trip each. Eight shards an hour still shifts gigabytes a week.
	rebalanceObjectsPerPass = 8
	rebalanceShardsPerPass  = 8
	// rebalanceCooldown is the minimum gap between levelling passes over the
	// same object, persisted in the ledger (ObjectPlacement.LastRebalance) for
	// the reason repairCooldown is: an in-memory cooldown resets in a crash
	// loop, which is when a storm is least affordable. A day, because an object
	// that has just been levelled is by definition no longer the fleet's problem.
	rebalanceCooldown = 24 * time.Hour
	// moveWindow and movesPerWindow are the rate limit levelling SHARES with
	// repair. Both subsystems move shards for different reasons and both draw on
	// the same coordinator; unbounded they fight over the leases placement needs.
	//
	// Repair records its movements here but is never refused -- it is restoring
	// durability, and a new failure mode in that path would be a worse bug than
	// anything levelling can cause. Levelling is refused as soon as the window is
	// spent, so a half hour of heavy repair simply means no levelling. That IS
	// the priority order, expressed as a shared counter rather than as a comment.
	moveWindow      = 30 * time.Minute
	movesPerWindow  = 64
	rebalanceDialTO = 2 * time.Minute
)

// errCopyUnverified means the destination acknowledged the shard but a fresh
// probe did not find it. Nothing is deleted on the strength of an unverified
// copy: unknown must not collapse into the outcome we were hoping for.
var errCopyUnverified = errors.New("the destination did not confirm the shard on a follow-up probe")

// errWouldWeakenChunk means dropping the source would leave the chunk below the
// durability threshold, so the delete half of the move is refused and the
// duplicate stands.
var errWouldWeakenChunk = errors.New("dropping the source would take the chunk under the durability threshold")

// shardMoveBudget is the window counter repair and levelling share.
type shardMoveBudget struct {
	mu     sync.Mutex
	spent  int
	since  time.Time
	limit  int
	window time.Duration
	// now is a test hook, so a test can age the window without sleeping.
	now func() time.Time
}

func newShardMoveBudget() *shardMoveBudget {
	return &shardMoveBudget{limit: movesPerWindow, window: moveWindow, now: time.Now}
}

// record accounts for movements this node made for a higher-priority reason.
// Never refuses; the caller has already done the work.
func (b *shardMoveBudget) record(count int) {
	if b == nil || count <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	b.spent += count
}

// allow claims one movement for levelling, or refuses because the window is
// spent. A nil budget allows everything, so a Node assembled without one (only
// tests do that) is not silently frozen.
func (b *shardMoveBudget) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	if b.spent >= b.limit {
		return false
	}
	b.spent++
	return true
}

func (b *shardMoveBudget) roll() {
	now := b.now()
	if b.since.IsZero() || now.Sub(b.since) >= b.window {
		b.since, b.spent = now, 0
	}
}

// RebalanceReport is what one levelling pass did, and what it decided not to do.
// The refusals are reported as loudly as the moves: a mover that cannot be
// observed is indistinguishable from a mover that is not running, which is
// exactly how five faults survived unnoticed in this subsystem.
type RebalanceReport struct {
	// Target is the byte count every node in the levelling set should hold.
	Target int64
	// Pools is how many peers had a usable occupancy figure.
	Pools   int
	Sources int
	Sinks   int
	// Examined is how many objects the pass looked at.
	Examined int
	Moved    int
	Bytes    int64
	// SkippedUnderReplicated counts objects that were not levelled because they
	// still owe the network a holder. Getting them to threshold beats levelling.
	SkippedUnderReplicated int
	// SkippedNoMargin counts chunks left alone because they sit at (or below)
	// the durability threshold, with no margin to spend on tidying.
	SkippedNoMargin int
	// NoDestination counts shards that had somewhere to leave and nowhere
	// distinct to go -- every thin peer already held a sibling of that chunk.
	NoDestination int
	Failed        int
	// BudgetExhausted records that the shared rate limit, not the absence of
	// work, ended the pass.
	BudgetExhausted bool
	// Deadbanded is true when every node was within the deadband of the target,
	// which is the healthy steady state and must not read as a failure.
	Deadbanded bool
}

// RebalanceStored levels the pools in the background.
func (n *Node) RebalanceStored(ctx context.Context) {
	for {
		timer := time.NewTimer(rebalanceInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		n.rebalanceOnce(ctx)
	}
}

func (n *Node) rebalanceOnce(ctx context.Context) {
	if len(n.host.Network().Peers()) == 0 {
		return
	}
	report := n.rebalanceWith(ctx, n.storagePools(ctx))
	switch {
	case report.Pools == 0:
		n.logger.Printf("rebalance: no peer published a usable occupancy figure; nothing to level against")
	case report.Deadbanded:
		n.logger.Printf(
			"rebalance: %d pool(s) all within %.0f%% of the %d-byte target; nothing to move",
			report.Pools, placement.LevelDeadband*100, report.Target)
	default:
		n.logger.Printf(
			"rebalance: target %d bytes across %d pool(s), %d source(s) and %d sink(s); "+
				"moved %d shard(s) (%d bytes) over %d object(s) "+
				"[skipped %d under-replicated, %d chunk(s) with no durability margin, %d with nowhere distinct to go, %d failed, budget-exhausted=%t]",
			report.Target, report.Pools, report.Sources, report.Sinks,
			report.Moved, report.Bytes, report.Examined,
			report.SkippedUnderReplicated, report.SkippedNoMargin,
			report.NoDestination, report.Failed, report.BudgetExhausted)
	}
}

// storagePools is the levelling set: every peer that published a capacity
// record, plus this node.
//
// MEASURED, NOT LEDGERED. A peer's occupancy is Capacity-FreeBytes from the
// record it publishes about its own disk, and this node's is store.UsedBytes(),
// which is reconciled against a walk of the shard tree. Summing the placement
// ledger by holder would be easy and wrong: the ledger records what peers
// confirmed, disk records what is there, and they diverge on exactly the events
// that create a levelling problem -- a delete that failed, a shard an operator
// removed by hand, a peer holding bytes for somebody else's objects too.
//
// A peer with no capacity record is absent from the set rather than counted as
// empty. Reading "has not reported" as "holds nothing" would aim every surplus
// byte at whichever volunteer merely runs an older build.
func (n *Node) storagePools(ctx context.Context) []placement.Pool {
	var pools []placement.Pool
	for _, record := range n.occupancyRecords(ctx) {
		if record.Capacity <= 0 {
			continue
		}
		if record.Draining || n.isDraining(record.NodeID) {
			// A retiring node is not part of the fleet this target describes. Its
			// bytes are on their way back to everyone else, so counting them would
			// set a mean the remaining machines cannot hold once they arrive, and
			// counting its capacity would set one they are all permanently behind.
			// The drain empties it; levelling must not also be trying to.
			continue
		}
		used := record.Capacity - record.FreeBytes
		if used < 0 {
			used = 0
		}
		pools = append(pools, placement.Pool{
			PeerID: record.NodeID, Used: used, Capacity: record.Capacity,
		})
	}
	if len(pools) == 0 {
		return nil
	}
	// This node counts toward the mean even though it is never a source or a
	// sink here: leaving it out would compute the target over everyone else and
	// make the rest of the fleet look fat by exactly this node's share.
	if used, err := n.store.UsedBytes(); err == nil && n.store.Capacity() > 0 {
		pools = append(pools, placement.Pool{
			PeerID: n.host.ID().String(), Used: used, Capacity: n.store.Capacity(),
		})
	}
	return pools
}

// rebalanceWith runs one pass against a given view of the fleet's occupancy.
//
// The pools are a parameter rather than discovered inside, for the same reason
// placeShards takes its candidates: the levelling arithmetic and the invariants
// under it are testable without standing up a DHT that publishes capacity.
func (n *Node) rebalanceWith(ctx context.Context, pools []placement.Pool) RebalanceReport {
	level := placement.LevelPools(pools)
	report := RebalanceReport{Target: level.Target, Pools: len(level.Nodes)}
	if len(level.Nodes) == 0 {
		return report
	}
	self := n.host.ID().String()

	// surplus/deficit are the pass's own running arithmetic. Without them a
	// single pass would empty its whole budget into the first thin peer and
	// overshoot it past the target, which the next pass would then have to
	// undo -- the ping-pong the deadband exists to prevent, reintroduced from
	// inside one pass.
	surplus := map[string]int64{}
	for _, source := range level.Sources() {
		if source.PeerID == self {
			// This node cannot shed its own local copies through this path; see
			// the file header on why draining is a separate feature.
			continue
		}
		surplus[source.PeerID] = source.Delta
	}
	// A sink has to be a peer this node would write to at all. The pools above
	// deliberately include peers the candidate list drops -- a peer refusing with
	// "capacity exceeded" belongs in the mean, and is usually a source -- but
	// offering a shard to a peer that is refusing everything would spend a lease
	// to be told no.
	writable := map[string]bool{}
	for _, candidate := range n.storageCandidates(ctx) {
		writable[candidate.PeerID] = true
	}
	deficit := map[string]int64{}
	var sinks []placement.Candidate
	for _, sink := range level.Sinks() {
		if sink.PeerID == self || !writable[sink.PeerID] {
			continue
		}
		deficit[sink.PeerID] = -sink.Delta
		sinks = append(sinks, placement.Candidate{
			PeerID: sink.PeerID, FreeBytes: sink.Headroom(), Capacity: sink.Capacity,
		})
	}
	report.Sources, report.Sinks = len(surplus), len(sinks)
	if len(surplus) == 0 || len(sinks) == 0 {
		// Either everyone is inside the deadband, or the only fat node is this
		// one, or there is nowhere with room. All three are "nothing to do", and
		// the healthy steady state is the first.
		report.Deadbanded = len(level.Sources()) == 0 && len(level.Sinks()) == 0
		return report
	}

	rows, err := n.store.RebalanceCandidates(rebalanceObjectsPerPass, rebalanceCooldown)
	if err != nil {
		n.logger.Printf("rebalance: cannot read the placement ledger: %v", err)
		return report
	}
	budget := rebalanceShardsPerPass
	for _, row := range rows {
		if ctx.Err() != nil || budget <= 0 || report.BudgetExhausted {
			break
		}
		if len(sinks) == 0 || len(surplus) == 0 {
			// Every sink has taken its share for this pass, or every source has
			// shed its surplus. Either way the pass has converged as far as it
			// is allowed to; the next one recomputes from measured usage.
			break
		}
		report.Examined++
		n.rebalanceObject(ctx, row.ObjectID, surplus, deficit, &sinks, &budget, &report)
	}
	return report
}

// rebalanceObject moves what it may off the fat holders of ONE object.
func (n *Node) rebalanceObject(
	ctx context.Context,
	objectID string,
	surplus, deficit map[string]int64,
	sinks *[]placement.Candidate,
	budget *int,
	report *RebalanceReport,
) {
	// The object's placement gate, taken for the WHOLE move and not just the
	// copy. This is what stops two levelling passes -- or a levelling pass and
	// the dispersal or repair round that also place this object's shards --
	// planning from the same ledger and then each writing a holder the other
	// never saw. A mover that recalled a shard while another round was placing
	// its sibling could co-locate a chunk that neither round would have
	// co-located on its own.
	//
	// Taken BEFORE the ledger is read, for the same reason placeShards takes it
	// before reading: a plan computed outside the lock is a plan about a past.
	defer n.lockPlacement(objectID)()

	_ = n.store.MarkRebalanceAttempt(objectID)
	row, err := n.store.LoadObjectPlacement(objectID)
	if err != nil {
		return
	}
	// Re-asked under the lock. The queue was read once at the top of the pass
	// and a holder can drop out while the pass is still running; levelling an
	// object that has since fallen under the threshold would spend the margin
	// repair is about to need.
	if row.UnderReplicated() {
		report.SkippedUnderReplicated++
		return
	}

	for _, chunkIndex := range row.ChunkIndexes() {
		if ctx.Err() != nil || *budget <= 0 || len(*sinks) == 0 || len(surplus) == 0 {
			return
		}
		// Re-read per chunk rather than working from one snapshot: the previous
		// chunk's move changed the holder lists this one plans against.
		fresh, err := n.store.LoadObjectPlacement(objectID)
		if err != nil {
			return
		}
		moved, err := n.rebalanceChunk(ctx, *fresh, chunkIndex, surplus, deficit, sinks, report)
		if report.BudgetExhausted {
			// The shared window is spent. Every remaining chunk would ask and be
			// refused, so stop asking.
			return
		}
		if err != nil {
			continue
		}
		if moved {
			*budget--
		}
	}
}

// rebalanceChunk moves at most ONE shard of one chunk.
//
// One, because every move changes the arrangement the next decision depends on:
// the destination becomes a holder, the source stops being one, and both pools
// move. Draining a whole chunk in one pass would be planning four moves from one
// snapshot, which is how a mover co-locates a chunk it was trying to spread.
func (n *Node) rebalanceChunk(
	ctx context.Context,
	row store.ObjectPlacement,
	chunkIndex int,
	surplus, deficit map[string]int64,
	sinks *[]placement.Candidate,
	report *RebalanceReport,
) (bool, error) {
	shards := row.PlacementSnapshot(chunkIndex)
	if len(shards) == 0 || !holdsForSomeSource(shards, surplus) {
		// Nothing of this chunk sits on a node the pass considers fat.
		return false, nil
	}
	if !row.ChunkHasDurabilityMargin(chunkIndex) {
		report.SkippedNoMargin++
		return false, nil
	}
	source, shard, ok := pickSurplusShard(row, chunkIndex, surplus)
	if !ok {
		return false, nil
	}

	// THE DESTINATION IS CHOSEN BY THE PLANNER, not by picking the emptiest
	// sink. Plan is the one place that knows a peer holding a sibling of this
	// chunk may not take another shard of it, and a second implementation of
	// that rule is a second chance to get it wrong. The shard being moved is
	// presented as unplaced -- its current holder removed -- while every sibling
	// keeps its holders, so Plan's exclusion set is exactly "everyone who holds
	// any of this chunk", which is what has to be avoided.
	view := placement.WithoutHolder(shards, shard.ID, source)
	var destination string
	for _, assignment := range placement.Plan(view, *sinks, 1) {
		if assignment.ShardID == shard.ID {
			destination = assignment.Peer
			break
		}
	}
	if destination == "" {
		report.NoDestination++
		return false, nil
	}
	if destination == source {
		return false, nil
	}
	if deficit[destination] < shard.Size {
		return false, nil
	}
	if !n.shardMoves.allow() {
		report.BudgetExhausted = true
		return false, errors.New("shared shard-move budget is spent")
	}

	if err := n.moveShard(ctx, row, shard, source, destination); err != nil {
		report.Failed++
		n.logger.Printf("rebalance: shard %s of %s did not move from %s to %s: %v",
			shortID(shard.ID), shortID(row.ObjectID), shortID(source), shortID(destination), err)
		return false, err
	}
	report.Moved++
	report.Bytes += shard.Size

	surplus[source] -= shard.Size
	if surplus[source] < placement.MinLevelMove {
		delete(surplus, source)
	}
	deficit[destination] -= shard.Size
	filled := deficit[destination] < placement.MinLevelMove
	if filled {
		delete(deficit, destination)
	}
	remaining := make([]placement.Candidate, 0, len(*sinks))
	for _, candidate := range *sinks {
		if candidate.PeerID != destination {
			remaining = append(remaining, candidate)
			continue
		}
		if filled {
			// It has taken its share for this pass. Dropping it here is what
			// stops one pass emptying its whole budget into the first thin peer
			// and overshooting it past the target.
			continue
		}
		candidate.FreeBytes -= shard.Size
		remaining = append(remaining, candidate)
	}
	*sinks = remaining
	n.logger.Printf("rebalance: moved shard %s of %s off %s onto %s (%d bytes)",
		shortID(shard.ID), shortID(row.ObjectID), shortID(source), shortID(destination), shard.Size)
	return true, nil
}

// pickSurplusShard chooses which shard leaves, from the fattest source holding
// one, and only from a chunk that has durability margin to spare.
func pickSurplusShard(
	row store.ObjectPlacement, chunkIndex int, surplus map[string]int64,
) (string, placement.Shard, bool) {
	best, bestSurplus := "", int64(0)
	for holder, over := range surplus {
		// Deterministic on ties: map iteration order is random, and two passes
		// over the same fleet should reach the same decision.
		if over < bestSurplus || (over == bestSurplus && holder >= best) {
			continue
		}
		if len(row.MovableChunkShards(chunkIndex, holder)) == 0 {
			continue
		}
		best, bestSurplus = holder, over
	}
	if best == "" {
		return "", placement.Shard{}, false
	}
	movable := row.MovableChunkShards(chunkIndex, best)
	// The largest shard of the chunk, so a fixed budget of moves sheds as many
	// bytes as it can. Shards of one chunk are near-identical in size, so this
	// is mostly a tie-break; it is deterministic, which matters more.
	chosen := movable[0]
	for _, shard := range movable[1:] {
		if shard.Size > chosen.Size || (shard.Size == chosen.Size && shard.ID < chosen.ID) {
			chosen = shard
		}
	}
	return best, chosen, true
}

// holdsForSomeSource reports whether any shard of the chunk sits on a peer the
// pass considers fat -- which is what tells "nothing here to move" apart from
// "something here, but no margin to move it".
func holdsForSomeSource(shards []placement.Shard, surplus map[string]int64) bool {
	for _, shard := range shards {
		for _, holder := range shard.Holders {
			if _, fat := surplus[holder]; fat {
				return true
			}
		}
	}
	return false
}

// moveShard is COPY, VERIFY, PROVE, THEN DELETE. In that order, every time.
//
// Shared with the drain (drain.go), which is this same move with the source's
// target set to zero. The two callers differ in WHICH shard leaves and in what
// they do when it cannot; the order of operations that makes a move safe is one
// implementation, because a second one is a second chance to get it wrong.
func (n *Node) moveShard(
	ctx context.Context, row store.ObjectPlacement,
	shard placement.Shard, source, destination string,
) error {
	target, err := peer.Decode(destination)
	if err != nil {
		return err
	}
	from, err := peer.Decode(source)
	if err != nil {
		return err
	}
	if target == n.host.ID() || from == n.host.ID() {
		return errors.New("this mover does not move a shard to or from this node")
	}

	// 1. COPY. The bytes come from local disk when this node still has them and
	//    from the source holder otherwise -- levelling must not need the owner to
	//    be holding a full copy of everything it once placed. They are not
	//    written to local disk on the way through: the point of the exercise is
	//    to move bytes, not to accumulate them here.
	read := func(shardID string) ([]byte, error) {
		if value, err := n.store.ReadShard(shardID); err == nil {
			return value, nil
		}
		fetchCtx, cancel := context.WithTimeout(ctx, rebalanceDialTO)
		defer cancel()
		return n.FetchShard(fetchCtx, shardID, shard.Holders)
	}
	// placeOne re-asks the ledger for a sibling on the target immediately before
	// sending, records the holder only on the peer's acknowledgement, and skips
	// the transfer entirely if the peer already has the bytes -- which is also
	// how a move interrupted between the copy and the delete resumes: the next
	// pass finds the destination already holding the shard, costs one small
	// frame, and goes on to the delete it never got to.
	if err := n.placeOne(ctx, row.ObjectID, shard.ID, target, read); err != nil {
		return err
	}

	// 2. VERIFY, on a fresh stream. The acknowledgement is a sentence written by
	//    the party we are about to rely on; `have` is an observation. This is the
	//    same standard recallFromPeer applies to a deletion claim, applied to the
	//    copy -- and it is the difference between "the ledger says two peers have
	//    it" and "two peers have it" at the moment the delete is authorised.
	has, err := n.PeerHasShard(ctx, target, shard.ID)
	if err != nil {
		// UNKNOWN, not "no". A probe that could not be delivered says nothing
		// about the destination's disk -- the same distinction the repair audit
		// refuses to blur -- so the ledger is left exactly as it is and nothing
		// is deleted. The next pass asks again.
		return errCopyUnverified
	}
	if !has {
		// ANSWERED no, having just acknowledged the store. The ledger now names
		// a holder that does not hold, which overstates the chunk's durability
		// by one machine; the mover found that out and must not leave it.
		_ = n.store.DropShardHolder(row.ObjectID, shard.ID, destination)
		return errCopyUnverified
	}

	// 3. PROVE. Re-read the ledger -- not the snapshot the plan came from -- and
	//    check that the destination is recorded and that the chunk survives the
	//    source being dropped. Anything can have changed while the copy was in
	//    flight: an audit may have dropped another holder, a repair round may
	//    have re-placed a sibling.
	fresh, err := n.store.LoadObjectPlacement(row.ObjectID)
	if err != nil {
		return err
	}
	chunkIndex, found := fresh.ChunkIndexOfShard(shard.ID)
	if !found {
		return errors.New("the shard left the ledger while it was being copied")
	}
	if !fresh.HolderOfShard(shard.ID, destination) {
		return errCopyUnverified
	}
	if !fresh.SurvivesLosingHolder(chunkIndex, shard.ID, source) {
		return errWouldWeakenChunk
	}

	// 4. DELETE, through the recall verb and nothing else. A revocation is
	//    already "this owner no longer wants this shard here": coordinator-signed,
	//    bound to one shard, one holder and one presenter, and audited. A second
	//    destructive primitive for moves would be a second one to review.
	tokens, err := n.requestRevocations(ctx, row.ObjectID, []revocationRequestShard{
		{ShardID: shard.ID, Recipient: source},
	})
	if err != nil {
		// The copy stands. A duplicate costs the sink some bytes until the next
		// pass; the alternative is deleting without an authority to.
		return err
	}
	var token Revocation
	for _, granted := range tokens {
		if granted.ShardID == shard.ID && granted.Recipient == source {
			token = granted
			break
		}
	}
	if token.Signature == "" {
		return errors.New("the coordinator issued no delete token for the source")
	}
	recallCtx, cancel := context.WithTimeout(ctx, rebalanceDialTO)
	defer cancel()
	state, detail := n.recallFromPeer(recallCtx, from, token)
	switch state {
	case store.RecallDeleted, store.RecallAbsent:
		// Both are terminal and both mean the same thing for the ledger: the
		// source is not holding these bytes. The holder has now set its own
		// six-hour refusal for this object's copy of this shard either way (see
		// DeleteRemoteShard), so remember it before anything tries to place
		// there again.
		if err := n.store.NoteShardMovedAway(row.ObjectID, shard.ID, source); err != nil {
			n.logger.Printf("shard move: could not record the move away from %s: %v", shortID(source), err)
		}
		return n.store.DropShardHolder(row.ObjectID, shard.ID, source)
	default:
		// The shard is now on both peers, which is the safe direction, and the
		// ledger says so. Nothing here retries: the next pass will see the source
		// still over target and decide again from measured usage.
		return errors.New("the source did not drop the shard: " + detail)
	}
}
