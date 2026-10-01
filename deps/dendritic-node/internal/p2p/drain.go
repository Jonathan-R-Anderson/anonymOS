package p2p

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/place"
	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// DRAINING A NODE: LEVELLING WITH A TARGET OF ZERO
// ===============================================
// An operator is retiring a machine. Everything it holds for other people has to
// leave first, and then it has to be possible to say, with something better than
// a guess, that the machine can be switched off.
//
// It is the same mover as rebalance.go -- copy, verify with a fresh `have`,
// prove the chunk survives losing the source, mint a revocation, recall -- with
// the source's target set to zero. Three things had to be added around it, and
// each of them is a decision rather than plumbing.
//
// 1. HOW A DRAIN IS REQUESTED
// ---------------------------
// On the node that is LEAVING, in its config file (config.Draining), published
// to owners in the capacity record it already advertises (place.Record.Draining).
//
// It has to work that way round because of the asymmetry step 3 resolved: the
// OWNER moves shards, never the holder. Only an owner has the placement ledger,
// so only an owner knows which peer holds a sibling of a chunk; only an owner
// can obtain a coordinator-signed revocation; and only an owner can confirm that
// a copy landed before authorising a delete. A volunteer holds shard ids and no
// chunk structure -- it could not shed one safely if it tried. So the node being
// retired cannot do the work, and the nodes that can do the work do not know it
// wants retiring: the intent has to travel from the one to the others.
//
// The alternatives were considered and are worse:
//
//   - AN OPERATOR ACTION ON THE OWNER. A volunteer retiring their own machine
//     would have to ask whoever owns the objects on it -- who they cannot
//     identify, since a holder knows shard ids and not who placed them -- and the
//     site would become the only party able to retire a machine.
//   - A NETWORK DIRECTIVE from the site. Same objection, plus it points the wrong
//     way: directives are how the site tells nodes something, and this is a node
//     telling owners something.
//   - A NEW VERB. A drain is a state, not an event; a message would have to be
//     re-sent to owners this node has never met, and be retried across the days a
//     drain can take. The capacity record is a state, republished on a timer,
//     already read by exactly the code that has to act on it.
//
// The config file is also the whole of the persistence this side needs. A drain
// runs for hours and the process will be restarted inside it -- restarting is
// what the operator is preparing to do -- so a runtime-only flag would silently
// un-drain the machine on the next start and owners would resume writing to a
// disk on its way out.
//
// 2. A DRAINING NODE MUST STOP BEING A DESTINATION
// ------------------------------------------------
// Two independent mechanisms, because they fail differently:
//
//   - Owners drop it from storageCandidates, so dispersal, repair AND levelling
//     stop offering it shards without spending a lease to be refused.
//   - It refuses "store" frames itself (see handleStream). That covers the record
//     ageing out, an owner running an older build that ignores the field, and the
//     window between the operator setting the flag and the next advertisement.
//
// 3. DURABILITY COMES FIRST, AND A DRAIN MAY STALL
// ------------------------------------------------
// Draining REMOVES a holder, so the order of operations matters even more than
// it does for levelling: the replacement is confirmed on another machine before
// the source is asked to delete, and never the reverse. moveShard is that order
// and this file does not reimplement it.
//
// Where draining deliberately differs from levelling is the MARGIN rule.
// Levelling refuses to touch a chunk sitting at exactly the durability
// threshold, because tidying is never worth spending an object's last margin. A
// drain must move exactly those chunks: the margin is not being spent, it is
// being LOST -- the machine is leaving with the shard on it -- and refusing to
// act would guarantee the loss the rule exists to prevent. What is kept is the
// hard part: the chunk must be durable NOW, the destination must be confirmed by
// a fresh probe, and SurvivesLosingHolder must hold against the re-read ledger
// before a revocation is minted. Copy-then-delete means an at-threshold chunk
// goes threshold -> threshold+1 -> threshold and never dips.
//
// And when the network cannot absorb a shard -- too few peers, or every
// candidate already holds a sibling, or the chunk is under-replicated so no move
// can be proved safe -- the shard STAYS WHERE IT IS and is reported, with the
// reason, as an unmovable remainder. A drain that completes by dropping data is
// worse than a drain that stalls and says so, and an operator reading "drained"
// over shards that were quietly abandoned is the failure this whole subsystem
// exists to make impossible.

const (
	// drainInterval is the drain cadence. Six times levelling's, because a person
	// is waiting on this one: levelling converges a fleet over days and nobody is
	// watching, a drain ends with a machine being switched off.
	drainInterval = 10 * time.Minute
	// drainObjectsPerPass and drainShardsPerPass bound one pass. Larger than
	// levelling's, and still bounded: the shared move budget is the real ceiling,
	// and a drain that tried to empty a node in one pass would take every slot
	// repair needs for the rest of the window.
	drainObjectsPerPass = 16
	drainShardsPerPass  = 16
	// drainCooldown is the minimum gap between drain passes over one object,
	// persisted in the ledger (ObjectPlacement.LastDrain). Short, because the
	// drain is the urgent mover; non-zero, because an object whose shards cannot
	// move must not consume the queue on every pass while the rest of the ledger
	// waits behind it.
	drainCooldown = 15 * time.Minute
	// drainReportInterval is how often a DRAINING node says where it has got to.
	// It reports on every tick whether or not anything changed: an operator
	// waiting to power a machine off is reading silence as either "finished" or
	// "broken", and it must never be ambiguous which.
	drainReportInterval = 5 * time.Minute
)

// Reasons a shard could not leave a draining node. Written out rather than
// formatted at the log line because they are also the report's own vocabulary,
// and an operator deciding whether to wait or to intervene is choosing between
// exactly these.
const (
	// drainReasonUnderReplicated: the chunk is below the durability threshold, so
	// no move off it can be proved not to weaken it. Dispersal and repair own the
	// object until it is durable again; the drain will move the shard on a later
	// pass once they have.
	drainReasonUnderReplicated = "the chunk is under-replicated, so moving a shard off it cannot be proved safe; repair owns it until it is durable again"
	// drainReasonNoDestination: every peer that could take it already holds a
	// sibling of the same chunk, or there is nowhere left to write at all. Sending
	// anyway would co-locate, which turns several tolerable losses into one.
	drainReasonNoDestination = "no peer can take it without holding a sibling of the same chunk; the network is too small to absorb this shard"
	// drainReasonWouldWeaken: the ledger changed under the move and dropping the
	// source would now take the chunk under the threshold. The copy stands, the
	// delete does not.
	drainReasonWouldWeaken = "dropping the source would take the chunk under the durability threshold"
	// drainReasonFailed: the move was attempted and did not complete. The shard is
	// still on the draining node, possibly also on the destination.
	drainReasonFailed = "the move did not complete"
)

// DrainStall is one shard that could not leave, and why.
type DrainStall struct {
	ObjectID string `json:"object_id"`
	ShardID  string `json:"shard_id"`
	Peer     string `json:"peer"`
	Reason   string `json:"reason"`
}

// maxReportedStalls bounds the detail carried in a report. The COUNT is exact
// (Unmovable); the list is a sample, because a drain of a large node with a
// small network behind it could otherwise accumulate one entry per shard in the
// ledger and put it all in a log line.
const maxReportedStalls = 16

// DrainReport is what one drain pass did and what it could not do.
//
// The refusals are the important half. A drain reports UNMOVABLE shards as
// loudly as moved ones because the operator's next action -- switching the
// machine off -- is safe only if that number is zero, and a report that only
// counts successes is one an operator can read as permission to unplug.
type DrainReport struct {
	// Peers are the nodes being drained, as this node currently understands it.
	Peers []string `json:"peers"`
	// Examined is how many objects the pass looked at.
	Examined int `json:"examined"`
	Moved    int `json:"moved"`
	Bytes    int64
	// Remaining is what the ledger still records on the draining peers AFTER this
	// pass, across the WHOLE ledger and not merely the objects examined. This is
	// the number that has to reach zero.
	Remaining store.DrainRemaining `json:"remaining"`
	// Unmovable is how many shards this pass could not move, and Stalls is a
	// bounded sample of them with reasons.
	Unmovable int          `json:"unmovable"`
	Stalls    []DrainStall `json:"stalls"`
	Failed    int          `json:"failed"`
	// BudgetExhausted records that the rate limit shared with repair, rather than
	// the absence of work, ended the pass. Not a fault: repair outranks a drain.
	BudgetExhausted bool `json:"budget_exhausted"`
	// NoCandidates means this node had nowhere at all to send a shard -- no
	// writable peer that is not itself draining. Distinguished from "nothing to
	// do" because they look identical in a bare move count and mean opposite
	// things.
	NoCandidates bool `json:"no_candidates"`
}

// note records an unmovable shard: the count is exact, the sample is bounded.
func (r *DrainReport) note(objectID, shardID, peerID, reason string) {
	r.Unmovable++
	if len(r.Stalls) >= maxReportedStalls {
		return
	}
	r.Stalls = append(r.Stalls, DrainStall{
		ObjectID: objectID, ShardID: shardID, Peer: peerID, Reason: reason,
	})
}

// markDraining remembers that a peer says it is retiring, for as long as its
// record would have been trusted.
//
// REMEMBERED WITH AN EXPIRY rather than recomputed from the current lookup,
// because the lookup fails routinely -- a DHT query times out, the record has not
// propagated, this node's tunnels are being rebuilt -- and treating "I did not
// hear it this minute" as "it stopped draining" would put a retiring machine
// straight back into every candidate set. The deadline is what lets a node that
// really has stopped draining come back without anybody intervening: one
// RecordTTL after its last draining record, it is an ordinary peer again.
func (n *Node) markDraining(peerID string) {
	if peerID == "" {
		return
	}
	n.drainingMu.Lock()
	if n.drainingUntil == nil {
		n.drainingUntil = make(map[string]time.Time)
	}
	_, known := n.drainingUntil[peerID]
	n.drainingUntil[peerID] = time.Now().Add(place.RecordTTL)
	n.drainingMu.Unlock()
	if !known {
		// Drop the cached candidate set at once, the way a peer crossing the
		// refusal threshold does. The cache exists to reuse one lookup across a
		// pass; holding a peer this node has just decided to stop writing to means
		// it keeps consuming a slot for the rest of the TTL.
		n.candidateMu.Lock()
		n.candidateCache = nil
		n.candidateMu.Unlock()
	}
}

// isDraining reports whether a peer said it was retiring recently enough to
// still believe.
func (n *Node) isDraining(peerID string) bool {
	n.drainingMu.Lock()
	defer n.drainingMu.Unlock()
	deadline, known := n.drainingUntil[peerID]
	if !known {
		return false
	}
	if time.Now().After(deadline) {
		delete(n.drainingUntil, peerID)
		return false
	}
	return true
}

// drainingPeers is the set this node should be emptying, refreshed from the
// capacity records behind the last discovery.
//
// Read from occupancyRecords -- the UNFILTERED half -- rather than from the
// candidate list, for the same reason levelling reads occupancy there: the
// candidate list is an eligibility list and a draining peer has just been
// removed from it. Looking for draining peers among the peers we are willing to
// write to would find none, by construction.
func (n *Node) drainingPeers(ctx context.Context) []string {
	for _, record := range n.occupancyRecords(ctx) {
		if record.Draining {
			n.markDraining(record.NodeID)
		}
	}
	self := n.host.ID().String()
	n.drainingMu.Lock()
	defer n.drainingMu.Unlock()
	now := time.Now()
	var out []string
	for peerID, deadline := range n.drainingUntil {
		if now.After(deadline) {
			delete(n.drainingUntil, peerID)
			continue
		}
		if peerID == self {
			// This node's own disk is not moved by this loop; see
			// ReportDrainStatus for what a node draining ITSELF does.
			continue
		}
		out = append(out, peerID)
	}
	sort.Strings(out)
	return out
}

// DrainStored moves shards off retiring peers in the background.
func (n *Node) DrainStored(ctx context.Context) {
	for {
		timer := time.NewTimer(drainInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		n.drainOnce(ctx)
	}
}

func (n *Node) drainOnce(ctx context.Context) {
	if len(n.host.Network().Peers()) == 0 {
		return
	}
	draining := n.drainingPeers(ctx)
	if len(draining) == 0 {
		// The overwhelmingly common case, and silent on purpose: a line every ten
		// minutes saying nobody is leaving would bury the lines that matter.
		return
	}
	report := n.drainWith(ctx, draining)
	n.logReport(report)
}

// logReport says where a drain has got to, on every pass, in the terms an
// operator is deciding in.
func (n *Node) logReport(report DrainReport) {
	short := make([]string, 0, len(report.Peers))
	for _, peerID := range report.Peers {
		short = append(short, shortID(peerID))
	}
	n.logger.Printf(
		"drain: %v is retiring; moved %d shard(s) (%d bytes) over %d object(s); "+
			"%d shard(s) of %d object(s) (%d bytes) still recorded there "+
			"[%d unmovable, %d failed, budget-exhausted=%t, nowhere-to-send=%t]",
		short, report.Moved, report.Bytes, report.Examined,
		report.Remaining.Shards, report.Remaining.Objects, report.Remaining.Bytes,
		report.Unmovable, report.Failed, report.BudgetExhausted, report.NoCandidates)
	for _, stall := range report.Stalls {
		n.logger.Printf("drain: shard %s of %s cannot leave %s: %s",
			shortID(stall.ShardID), shortID(stall.ObjectID), shortID(stall.Peer), stall.Reason)
	}
	if report.Remaining.Shards == 0 && report.Unmovable == 0 {
		n.logger.Printf(
			"drain: this node's ledger no longer records any shard on %v; nothing here is keeping those machines up",
			short)
	}
}

// drainWith runs one pass against a given set of retiring peers.
//
// The peers are a parameter rather than discovered inside, exactly as pools are
// for rebalanceWith: the invariants under a drain are testable without standing
// up a DHT that publishes capacity records.
// The result is NAMED so the deferred remaining-count below writes to the value
// that is actually returned: an unnamed result is copied at the `return`, and
// this report's most consequential field would silently always read zero --
// "nothing left on the retiring node", to an operator holding a power switch.
func (n *Node) drainWith(ctx context.Context, draining []string) (report DrainReport) {
	report = DrainReport{Peers: append([]string(nil), draining...)}
	self := n.host.ID().String()
	leaving := map[string]bool{}
	for _, peerID := range draining {
		if peerID == "" || peerID == self {
			continue
		}
		leaving[peerID] = true
	}
	if len(leaving) == 0 {
		return report
	}
	defer func() {
		// Measured at the END of the pass, and over the whole ledger: this is the
		// number the operator acts on, so it must describe the world after this
		// pass rather than the world it planned against.
		if remaining, err := n.store.ShardsRecordedOn(leaving); err == nil {
			report.Remaining = remaining
		}
	}()

	// Destinations are every peer this node would write to at all, minus the ones
	// that are leaving -- storageCandidates already drops those, and the filter is
	// re-applied here because a candidate list can be up to its cache TTL old and
	// moving a shard from one retiring machine to another is the one destination
	// that is strictly worse than not moving it.
	var destinations []placement.Candidate
	for _, candidate := range n.storageCandidates(ctx) {
		if leaving[candidate.PeerID] || candidate.PeerID == self {
			continue
		}
		destinations = append(destinations, candidate)
	}
	if len(destinations) == 0 {
		// Reported, not silent. "No moves" because there is nothing to move and
		// "no moves" because there is nowhere to put anything are the same log line
		// and opposite situations, and only one of them means the machine can be
		// switched off.
		report.NoCandidates = true
		return report
	}

	rows, err := n.store.DrainCandidates(leaving, drainObjectsPerPass, drainCooldown)
	if err != nil {
		n.logger.Printf("drain: cannot read the placement ledger: %v", err)
		return report
	}
	budget := drainShardsPerPass
	for _, row := range rows {
		if ctx.Err() != nil || budget <= 0 || report.BudgetExhausted {
			break
		}
		report.Examined++
		n.drainObject(ctx, row.ObjectID, leaving, destinations, &budget, &report)
	}
	return report
}

// drainObject moves what it may off the retiring holders of ONE object.
func (n *Node) drainObject(
	ctx context.Context,
	objectID string,
	leaving map[string]bool,
	destinations []placement.Candidate,
	budget *int,
	report *DrainReport,
) {
	// The object's placement gate, held for the WHOLE move and taken before the
	// ledger is read -- the same discipline rebalanceObject follows and for the
	// same reason. A drain recalling a shard while a dispersal or repair round is
	// placing its sibling would co-locate a chunk neither round would have
	// co-located on its own.
	defer n.lockPlacement(objectID)()

	_ = n.store.MarkDrainAttempt(objectID)
	row, err := n.store.LoadObjectPlacement(objectID)
	if err != nil {
		return
	}
	for _, chunkIndex := range row.ChunkIndexes() {
		if ctx.Err() != nil || *budget <= 0 || report.BudgetExhausted {
			return
		}
		// Re-read per chunk: the previous chunk's move changed the holder lists
		// this one has to plan against.
		fresh, err := n.store.LoadObjectPlacement(objectID)
		if err != nil {
			return
		}
		moved := n.drainChunk(ctx, *fresh, chunkIndex, leaving, destinations, report)
		if moved {
			*budget--
		}
	}
}

// drainChunk moves at most ONE shard of one chunk off a retiring peer.
//
// One at a time, for the reason rebalanceChunk gives: every move changes the
// arrangement the next decision depends on. The next pass sees the new one.
func (n *Node) drainChunk(
	ctx context.Context,
	row store.ObjectPlacement,
	chunkIndex int,
	leaving map[string]bool,
	destinations []placement.Candidate,
	report *DrainReport,
) bool {
	source, shard, ok := pickRetiringShard(row, chunkIndex, leaving)
	if !ok {
		return false
	}

	// DURABILITY FIRST, and this is the gate that makes a drain able to stall.
	//
	// The chunk must be durable AS IT STANDS. If it is, swapping one holder for
	// another leaves the distinct-holder count where it was, and copy-then-delete
	// means it is momentarily one higher and never one lower. If it is not, no
	// move off it can be proved not to weaken it -- so the shard stays where it
	// is and is reported. It is repair's object until it is durable again, and a
	// later drain pass will move the shard once it is.
	//
	// Note what this is NOT: ChunkHasDurabilityMargin, which levelling uses. A
	// chunk sitting at exactly the threshold is refused by levelling because
	// tidying is not worth the last margin, and must be moved by a drain because
	// the margin is not being spent, it is walking out of the building.
	if !row.ChunkIsDurable(chunkIndex) {
		report.note(row.ObjectID, shard.ID, source, drainReasonUnderReplicated)
		return false
	}

	// THE DESTINATION COMES FROM THE PLANNER. Plan is the one place that knows a
	// peer holding a sibling of this chunk may not take another shard of it, and
	// a second implementation of that rule is a second chance to get it wrong.
	// The shard being moved is presented as unplaced -- its retiring holder
	// removed -- while every sibling keeps its holders, so Plan's exclusion set is
	// exactly "every peer holding any part of this chunk".
	view := placement.WithoutHolder(row.PlacementSnapshot(chunkIndex), shard.ID, source)
	destination := ""
	for _, assignment := range placement.Plan(view, destinations, 1) {
		if assignment.ShardID == shard.ID {
			destination = assignment.Peer
			break
		}
	}
	if destination == "" || destination == source || leaving[destination] {
		// LEFT ALONE, NOT DROPPED. The network cannot absorb this shard right now;
		// recalling it anyway would trade a machine that is about to be switched
		// off for a chunk that is one holder weaker immediately.
		report.note(row.ObjectID, shard.ID, source, drainReasonNoDestination)
		return false
	}
	if !n.shardMoves.allow() {
		// The window shared with repair is spent. Repair records against it and is
		// never refused; a drain is, because restoring durability outranks emptying
		// a machine, however much somebody wants to unplug it. Nothing is reported
		// as unmovable here -- the shard is not stuck, the pass merely ran out of
		// allowance and the next one continues.
		report.BudgetExhausted = true
		return false
	}

	if err := n.moveShard(ctx, row, shard, source, destination); err != nil {
		report.Failed++
		reason := drainReasonFailed
		if errors.Is(err, errWouldWeakenChunk) {
			reason = drainReasonWouldWeaken
		}
		report.note(row.ObjectID, shard.ID, source, reason)
		n.logger.Printf("drain: shard %s of %s did not move off %s to %s: %v",
			shortID(shard.ID), shortID(row.ObjectID), shortID(source), shortID(destination), err)
		return false
	}
	report.Moved++
	report.Bytes += shard.Size
	n.logger.Printf("drain: moved shard %s of %s off retiring %s onto %s (%d bytes)",
		shortID(shard.ID), shortID(row.ObjectID), shortID(source), shortID(destination), shard.Size)
	return true
}

// pickRetiringShard chooses which shard leaves, from the retiring peer holding
// one. Deterministic on ties, so two passes over the same ledger reach the same
// decision.
func pickRetiringShard(
	row store.ObjectPlacement, chunkIndex int, leaving map[string]bool,
) (string, placement.Shard, bool) {
	best := ""
	for peerID := range leaving {
		if best != "" && peerID >= best {
			continue
		}
		if len(row.ChunkShardsHeldBy(chunkIndex, peerID)) == 0 {
			continue
		}
		best = peerID
	}
	if best == "" {
		return "", placement.Shard{}, false
	}
	held := row.ChunkShardsHeldBy(chunkIndex, best)
	chosen := held[0]
	for _, shard := range held[1:] {
		if shard.Size > chosen.Size || (shard.Size == chosen.Size && shard.ID < chosen.ID) {
			chosen = shard
		}
	}
	return best, chosen, true
}

// ReportDrainStatus is the loop on the machine that is LEAVING.
//
// Everything above runs on owners. This runs where the operator is standing, and
// answers the only question they have: can I switch it off yet.
//
// IT REPORTS ON EVERY TICK, changed or not. "No log output" must never be
// readable as "finished" -- that ambiguity is how a drain gets declared complete
// over shards that are still on the disk. A drain that is stuck says so once
// every interval, in the same words as one that is progressing, with a different
// number.
func (n *Node) ReportDrainStatus(ctx context.Context) {
	for {
		n.reportDrainStatus()
		timer := time.NewTimer(drainReportInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (n *Node) reportDrainStatus() {
	if !n.draining.Load() || n.store == nil {
		return
	}
	held, err := n.store.HeldForOthers()
	if err != nil {
		// An unreadable count is UNKNOWN and must be said so. Reporting zero here
		// -- the shape of fault F6 -- would tell an operator to power down a
		// machine over a database error.
		n.logger.Printf("drain: DRAINING, but this node cannot count what it holds for other peers: %v; do NOT switch it off on the strength of this", err)
		return
	}
	summary, summaryErr := n.store.PlacementStatus()
	switch {
	case held.Shards > 0:
		n.logger.Printf(
			"drain: DRAINING -- still holding %d shard(s) (%d bytes) for other peers; their owners move them off, so leave this node RUNNING and connected",
			held.Shards, held.Bytes)
	default:
		n.logger.Printf("drain: DRAINING -- this node now holds no shards for other peers")
	}
	// The other half of "safe to switch off", and the half nothing else reports:
	// this node's OWN objects. They are not moved by a drain -- they are not on
	// somebody else's disk to be recalled, and the durability that matters for
	// them is already defined as "recoverable WITHOUT this node". So the question
	// is not whether they can be moved but whether they have been dispersed, and
	// the honest answer is a count.
	switch {
	case summaryErr != nil:
		n.logger.Printf("drain: cannot read this node's own placement ledger: %v; whether its own objects survive being switched off is UNKNOWN", summaryErr)
	case summary.UnderReplicated > 0:
		n.logger.Printf(
			"drain: %d of this node's own %d object(s) are NOT yet recoverable without it; switching it off now loses them",
			summary.UnderReplicated, summary.Objects)
	case held.Shards == 0:
		n.logger.Printf(
			"drain: DRAINED -- no shards held for other peers and all %d of this node's own objects are recoverable without it; it is safe to switch off",
			summary.Objects)
	}
}
