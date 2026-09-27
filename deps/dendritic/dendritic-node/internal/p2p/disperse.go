package p2p

import (
	"bufio"
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/place"
	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// DISPERSAL
// =========
// This replaces `target := peers[shardNumber%len(peers)]`.
//
// That line spread an object's shards across whatever libp2p happened to have a
// connection to -- gateway-only peers that never register the storage handler,
// cache-only peers that hard-refuse a store frame, probe nodes, the coordinator
// -- and with fewer than dataShards+parityShards of them it silently stacked
// several shards of one chunk on one host. Nothing recorded where anything
// went, nothing checked whether it arrived, and the caller marked the object
// done either way.
//
// Now: candidates are storage peers ranked by advertised free space, the
// assignment is computed by internal/placement (which cannot put two shards of
// a chunk on one node), every confirmed push is written to the ledger, and the
// result says how far it actually got.

const (
	// disperseConcurrency bounds simultaneous shard pushes. Each one is a lease
	// round trip over the I2P outproxy plus a stream, so this is about not
	// burying the lease service, not about local CPU.
	disperseConcurrency = 4
	// candidateLimit caps the DHT capacity lookup. More than this and the
	// lookup itself costs more than the placement it informs.
	candidateLimit = 32
	// candidateCacheTTL reuses a candidate set across the shards of one pass.
	// Rediscovering peers per chunk would issue a DHT query per megabyte.
	candidateCacheTTL = 2 * time.Minute
)

// DispersalResult reports what a dispersal pass achieved, per object.
//
// It exists because the old path returned nothing at all: DistributeManifest
// logged its failures and the caller then recorded the object as replicated
// regardless. That single fact explains the production symptom -- the backfill
// counter draining while every volunteer's shard directory stayed empty. The
// counter was measuring attempts.
type DispersalResult struct {
	// Placed is the number of shards a peer confirmed storing in THIS pass.
	Placed int
	// Failed is the number of attempted pushes that did not confirm.
	Failed int
	// Unassignable is the number of shards that had nowhere distinct to go,
	// because the network offered fewer usable peers than the chunk has shards.
	Unassignable int
	// WeakestChunk is the smallest number of DISTINCT HOLDERS across the
	// object's chunks, after this pass. This is the object's real durability:
	// how many separate machines would have to fail to take it away.
	WeakestChunk int
	// Durable is true when every chunk has at least
	// store.DurableRemoteHolders(DataShards, ParityShards) distinct holders AND
	// still decodes without this node after any one of them drops out.
	Durable bool
	// Complete is true when every shard of every chunk sits on some peer and no
	// peer holds enough of one chunk to matter, which is what buys tolerance of
	// ParityShards simultaneous node losses.
	Complete bool
}

// placementGate is one object's placement lock, refcounted so the map does not
// accumulate an entry per object ever written.
type placementGate struct {
	mu      sync.Mutex
	waiters int
}

// candidateSource returns peers that can actually take a shard.
//
// Preference order is deliberate:
//  1. Peers advertising storage capacity at the DHT rendezvous. Those records
//     are published by nodes that run the storage role and have measured free
//     space, so a candidate from here is both willing and able.
//  2. Connected peers, with unknown free space. A young network has no capacity
//     records yet; refusing to disperse until the directory fills would mean
//     never dispersing on a fresh install.
//
// Peers that refuse are simply not confirmed and the ledger keeps the deficit,
// so a wrong guess in tier 2 costs one wasted attempt, never a false durability.
func (n *Node) storageCandidates(ctx context.Context) []placement.Candidate {
	n.candidateMu.Lock()
	if time.Since(n.candidateAt) < candidateCacheTTL && len(n.candidateCache) > 0 {
		cached := append([]placement.Candidate(nil), n.candidateCache...)
		n.candidateMu.Unlock()
		return cached
	}
	n.candidateMu.Unlock()

	byID := make(map[string]placement.Candidate)
	lookupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	records, err := n.FindStoragePeers(lookupCtx, candidateLimit)
	cancel()
	var fresh []place.Record
	if err == nil {
		now := time.Now()
		for _, record := range records {
			if !record.Fresh(now) || record.NodeID == n.host.ID().String() {
				continue
			}
			// Kept BEFORE the dial and refusal filters below, and cached
			// separately, because occupancy and eligibility are different
			// questions. A peer refusing shards with "capacity exceeded" is
			// exactly the node levelling has to notice is fat -- dropping it
			// here would make the fullest machines on the network the only ones
			// the mover cannot see.
			fresh = append(fresh, record)
			if record.Draining {
				// Remembered before the filters below, so it survives the record
				// ageing out of the DHT while the drain is still running.
				n.markDraining(record.NodeID)
			}
			// Teach the host how to reach it, so the push does not fail on
			// "no addresses" for a peer we are not currently connected to.
			if _, dialErr := n.DialStoragePeer(ctx, record); dialErr != nil {
				continue
			}
			if n.refusingPeer(record.NodeID) {
				continue
			}
			if n.isDraining(record.NodeID) {
				continue
			}
			cand := placement.Candidate{
				PeerID: record.NodeID, FreeBytes: record.FreeBytes,
				// Carried for levelling, which needs occupancy rather than room:
				// Capacity-FreeBytes is what the peer measured on its own disk.
				Capacity: record.Capacity,
			}
			// Failure domains (T12.2). Taken from the LIVE CONNECTION the dial
			// above just established, never from record.Destination -- that is
			// an I2P b32, a public key deliberately unrelated to where the
			// machine is, and §1.4's whole finding.
			if pid, perr := peer.Decode(record.NodeID); perr == nil {
				cand.Domains = n.domainKeysFor(pid)
			}
			byID[record.NodeID] = cand
		}
	}
	for _, connected := range n.host.Network().Peers() {
		if connected == n.host.ID() {
			continue
		}
		id := connected.String()
		if _, known := byID[id]; known {
			continue
		}
		// The refusal filter belongs on BOTH tiers. It was applied only to the
		// DHT-record branch above, and the peers that refuse are exactly the
		// ones we stay connected to -- so every refusing peer walked straight
		// back in through this fallback and kept consuming a slot. Measured:
		// four peers still drew ~170 attempts each in twenty minutes with the
		// filter "on".
		if n.refusingPeer(id) {
			continue
		}
		// The draining filter belongs on BOTH tiers, exactly as the refusal
		// filter had to learn to. A peer that is retiring is one this node is
		// almost certainly still CONNECTED to -- it stays up for the whole drain
		// -- so filtering only the DHT-record branch above would let every
		// draining node walk straight back in through this fallback and keep
		// being offered shards it is about to hand back.
		if n.isDraining(id) {
			continue
		}
		byID[id] = placement.Candidate{PeerID: id, Domains: n.domainKeysFor(connected)}
	}

	out := make([]placement.Candidate, 0, len(byID))
	for _, candidate := range byID {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FreeBytes != out[j].FreeBytes {
			return out[i].FreeBytes > out[j].FreeBytes
		}
		return out[i].PeerID < out[j].PeerID
	})

	n.candidateMu.Lock()
	n.candidateCache, n.candidateAt = append([]placement.Candidate(nil), out...), time.Now()
	n.capacityRecords = fresh
	n.candidateMu.Unlock()
	return out
}

// occupancyRecords returns the fresh capacity records behind the last candidate
// discovery: every peer that published one, INCLUDING the ones this node will
// not currently write to.
//
// Levelling needs the whole picture. storageCandidates is an eligibility list --
// it drops peers that cannot be dialled and peers that have been refusing -- and
// a peer refusing because its disk is full is precisely a source. Computing the
// fleet mean over the eligible peers only would leave the fullest machines out
// of the average, understate the target, and make the healthy nodes look fat.
func (n *Node) occupancyRecords(ctx context.Context) []place.Record {
	n.storageCandidates(ctx)
	n.candidateMu.Lock()
	defer n.candidateMu.Unlock()
	return append([]place.Record(nil), n.capacityRecords...)
}

// DistributeManifest keeps its name and signature so the store's distributor
// hook and every existing caller stay wired, but it now disperses.
func (n *Node) DistributeManifest(ctx context.Context, manifest store.Manifest) {
	n.DisperseObject(ctx, manifest)
}

// DisperseObject places the shards of one object on distinct peers and returns
// how far it got.
func (n *Node) DisperseObject(ctx context.Context, manifest store.Manifest) DispersalResult {
	// Publish the chunk->shard map first, so a node holding none of the shards
	// can still locate them by bucket+key. Best-effort: a young network may have
	// nowhere to put it yet.
	if err := n.PublishManifest(ctx, manifest); err != nil {
		n.logger.Printf("could not publish manifest for %s: %v", shortID(manifest.ObjectID), err)
	}
	// The ledger row is normally written by putObject; an object stored before
	// this code existed has none, so create it here rather than skipping the
	// object forever.
	if _, err := n.store.LoadObjectPlacement(manifest.ObjectID); err != nil {
		if recordErr := n.store.RecordObjectPlacement(manifest); recordErr != nil {
			n.logger.Printf("could not open placement ledger for %s: %v",
				shortID(manifest.ObjectID), recordErr)
			return DispersalResult{}
		}
	}
	_ = n.store.MarkPlacementAttempt(manifest.ObjectID)

	candidates := n.storageCandidates(ctx)
	if len(candidates) == 0 {
		// NOT an error, and not a silent no-op either. A node with no peers must
		// still hold what it was given; it just must not pretend the object is
		// redundant. The ledger row stays under-replicated and the next pass
		// picks it up.
		row, err := n.store.LoadObjectPlacement(manifest.ObjectID)
		result := DispersalResult{}
		if err == nil {
			result.WeakestChunk = row.WeakestChunk()
			result.Durable = !row.UnderReplicated()
			result.Complete = row.FullyDispersed()
		}
		n.logger.Printf("object %s held locally and marked under-replicated; no storage peers available",
			shortID(manifest.ObjectID))
		return result
	}

	result := n.placeShards(ctx, manifest.ObjectID, candidates,
		func(shardID string) ([]byte, error) { return n.store.ReadShard(shardID) })

	row, err := n.store.LoadObjectPlacement(manifest.ObjectID)
	if err == nil {
		result.WeakestChunk = row.WeakestChunk()
		result.Durable = !row.UnderReplicated()
		result.Complete = row.FullyDispersed()
	}
	if !result.Durable {
		n.logger.Printf(
			"object %s is UNDER-REPLICATED: its weakest chunk sits on %d of the %d distinct peers it needs (placed %d, failed %d, unassignable %d)",
			shortID(manifest.ObjectID), result.WeakestChunk,
			store.DurableRemoteHolders(manifest.DataShards, manifest.ParityShards),
			result.Placed, result.Failed, result.Unassignable)
	}
	return result
}

// lockPlacement serialises placement rounds for ONE object and returns the
// release function.
//
// WHY THIS EXISTS
// ---------------
// placement.Plan cannot put two shards of a chunk on one peer, but that
// guarantee covers one call and nothing else, and three separate goroutines
// place shards for the same object: the PUT-time distributor hook, the
// replicate pass, and the repair pass. Two of them overlapping each read the
// ledger before the other's confirmations were written, so both planned from
// "this chunk has no holders". Identical inputs give identical plans and no
// harm -- but the candidate list is ranked by advertised free space, and any
// difference between the two rounds (a refreshed capacity record, a peer that
// connected in between, an expired candidate cache) permutes the ranking. Round
// one then sends shard 0 to the peer round two is sending shard 4 to, and the
// chunk is co-located on a node neither round ever planned to double up on.
//
// Per object rather than global: dispersal of unrelated objects should still
// run in parallel, and there is exactly one node -- the owner -- that ever
// places an object's shards, so an in-process gate is the whole of the race.
func (n *Node) lockPlacement(objectID string) func() {
	n.placingMu.Lock()
	if n.placing == nil {
		n.placing = make(map[string]*placementGate)
	}
	gate := n.placing[objectID]
	if gate == nil {
		gate = &placementGate{}
		n.placing[objectID] = gate
	}
	gate.waiters++
	n.placingMu.Unlock()

	gate.mu.Lock()
	return func() {
		gate.mu.Unlock()
		n.placingMu.Lock()
		gate.waiters--
		if gate.waiters == 0 {
			delete(n.placing, objectID)
		}
		n.placingMu.Unlock()
	}
}

// placeShards runs one placement round over every chunk of an object.
//
// read supplies the shard bytes. Dispersal reads them from local disk; repair
// hands in bytes it just regenerated, which is why this is a parameter and not
// a direct store call.
func (n *Node) placeShards(
	ctx context.Context,
	objectID string,
	candidates []placement.Candidate,
	read func(shardID string) ([]byte, error),
) DispersalResult {
	// Taken BEFORE the ledger is read: the plan and the confirmations it
	// produces have to be one atomic round, or a concurrent round plans against
	// holders that are about to change.
	defer n.lockPlacement(objectID)()

	var result DispersalResult
	row, err := n.store.LoadObjectPlacement(objectID)
	if err != nil {
		return result
	}
	limit := make(chan struct{}, disperseConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, chunkIndex := range row.ChunkIndexes() {
		if ctx.Err() != nil {
			break
		}
		shards := row.PlacementSnapshot(chunkIndex)
		// One holder per shard: the redundancy comes from the erasure code, not
		// from copying each shard. dataShards+parityShards shards on that many
		// distinct nodes already tolerates parityShards losses; a second copy of
		// each would double the traffic to raise it no further.
		//
		// The exception is a chunk that is fully placed and STILL co-located --
		// a row written before this node enforced the property, or an index that
		// two objects share. Every shard has a holder, so a plain plan has
		// nothing to do and the object would sit in the queue forever being
		// counted as under-replicated and never getting better. Treating the
		// surplus placements as unplaced gives those indexes a second holder on
		// a machine that holds nothing of the chunk, which is the only thing
		// that raises the number of node losses it survives.
		assignments := placement.Plan(placement.WithoutCrowdedHolders(shards), candidates, 1)
		// Unassignable counts shards that have NO holder at all and got no peer
		// this round. Measured against the real holder lists rather than against
		// the count of assignments, because some of those assignments are second
		// holders for crowded indexes and would otherwise hide a shard that
		// still has nowhere to go.
		holderless := make(map[int]bool, len(shards))
		for _, shard := range shards {
			if len(shard.Holders) == 0 {
				holderless[shard.Index] = true
			}
		}
		for _, assignment := range assignments {
			delete(holderless, assignment.ShardIndex)
		}
		mu.Lock()
		result.Unassignable += len(holderless)
		mu.Unlock()

		for _, assignment := range assignments {
			target, decodeErr := peer.Decode(assignment.Peer)
			if decodeErr != nil || target == n.host.ID() {
				mu.Lock()
				result.Failed++
				mu.Unlock()
				continue
			}
			wg.Add(1)
			go func(assignment placement.Assignment, target peer.ID) {
				defer wg.Done()
				select {
				case limit <- struct{}{}:
					defer func() { <-limit }()
				case <-ctx.Done():
					return
				}
				if err := n.placeOne(ctx, objectID, assignment.ShardID, target, read); err != nil {
					n.logger.Printf("shard %s not placed on %s: %v",
						shortID(assignment.ShardID), target, err)
					// An ANSWERED no counts against the peer; a dial that never
					// completed does not. Absence is already handled by the peer
					// dropping out of the candidate set, and counting it here
					// would punish a healthy volunteer for one bad tunnel.
					if reason := refusalReason(err); reason != "" {
						n.noteRefusal(target.String(), reason)
					}
					mu.Lock()
					result.Failed++
					mu.Unlock()
					return
				}
				n.noteAccepted(target.String())
				mu.Lock()
				result.Placed++
				mu.Unlock()
			}(assignment, target)
		}
	}
	wg.Wait()
	return result
}

// placeOne pushes a single shard and records the holder only once the peer has
// confirmed it.
func (n *Node) placeOne(
	ctx context.Context, objectID, shardID string, target peer.ID,
	read func(string) ([]byte, error),
) error {
	// Asked again here, against the ledger as it stands at this instant, rather
	// than trusted from the plan. Everything between planning and sending is a
	// window in which another round can have confirmed a sibling on this peer,
	// and a shard that would double up must not be sent at all: the bytes cannot
	// be recalled, and once they are there the ledger has to record them.
	if n.store.HoldsSiblingShard(objectID, shardID, target.String()) {
		return errWouldCoLocate
	}
	// A peer levelling has just taken this shard OFF is refusing it for the next
	// six hours (DeleteRemoteShard writes that refusal, and it must: it is what
	// stops the replicate loop undoing an operator's delete). Asking anyway would
	// spend a lease and an I2P round trip to be told "recalled recently" -- which
	// answeredNo counts as a refusal, so three of them would drop a healthy
	// volunteer out of every candidate set over a refusal this node caused.
	// Declining here is the mover skipping its own; see NoteShardMovedAway.
	if n.store.ShardMovedAwayFrom(objectID, shardID, target.String()) {
		return errRecentlyMovedAway
	}
	value, err := read(shardID)
	if err != nil {
		return err
	}
	// Ask before sending. A peer that already has the shard (a retry, or a
	// content-addressed shard shared with another object) costs one small frame
	// instead of a full transfer plus a lease.
	if has, probeErr := n.PeerHasShard(ctx, target, shardID); probeErr == nil && has {
		return n.store.ConfirmShardHolder(objectID, shardID, target.String())
	}
	lease, err := n.requestLease(ctx, target, objectID, shardID, int64(len(value)))
	if err != nil {
		return err
	}
	if err := n.storeOnPeer(ctx, target, objectID, shardID, value, lease); err != nil {
		return err
	}
	return n.store.ConfirmShardHolder(objectID, shardID, target.String())
}

// PeerHasShard asks a peer whether it holds a shard.
//
// The "have" verb has been implemented server-side since the protocol was
// written and had no client anywhere. It is the cheap probe an audit needs: a
// repair loop that had to fetch a shard to find out whether it still existed
// would move the whole object to answer a yes/no question.
func (n *Node) PeerHasShard(ctx context.Context, target peer.ID, shardID string) (bool, error) {
	askCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stream, err := n.host.NewStream(askCtx, target, ProtocolID)
	if err != nil {
		return false, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{Operation: "have", ShardID: shardID}); err != nil {
		return false, err
	}
	var reply responseHeader
	if err := readJSONFrame(bufio.NewReader(stream), &reply); err != nil {
		return false, err
	}
	if !reply.OK {
		return false, errShardProbeRefused
	}
	return reply.Present, nil
}

// PlacementReport is what the operator sees. A node must never state a
// durability it does not have, so this reports the deficit as loudly as the
// success.
func (n *Node) PlacementReport() (store.PlacementSummary, error) {
	return n.store.PlacementStatus()
}

// shortID trims a content address for a log line.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// errShardProbeRefused means the peer answered the "have" frame with an error
// rather than a yes/no -- it is not a "no", and an audit must not treat it as
// one or a peer having a bad minute would look like a node that dropped out.
var errShardProbeRefused = errors.New("peer refused the shard probe")

// errWouldCoLocate means the target already holds another shard of this chunk,
// so sending is refused. Counted as a failure rather than swallowed: an
// unplaced shard is a deficit the next pass can fix, and a silent skip would
// look like success.
var errWouldCoLocate = errors.New("peer already holds a shard of this chunk")

// errRecentlyMovedAway means levelling took this shard off this peer recently
// enough that the peer would refuse it. Not a fault of the peer's and not
// counted against it: this node created the condition and this node remembers.
var errRecentlyMovedAway = errors.New("this shard was levelled off that peer recently")

// A peer that keeps saying no is worse than a peer that is absent: candidates
// are ranked by ADVERTISED free space, and the peers refusing here advertise
// plenty of it -- a cache-only node, a node past its capacity, a node whose
// lease verification is broken. So they win slots on every round, consume one of
// the nine a chunk has, and the object stalls one holder short of the durability
// threshold forever. *Measured:* three such peers held the ceiling at
// "placed 6, failed 3" while seven healthy nodes were available.
//
// Deliberately NOT permanent and NOT persisted. A refusal is often temporary --
// capacity is freed, a config is fixed, a node is upgraded (RKLs was refusing
// every lease until its binary was replaced) -- and a permanent blacklist would
// quietly shrink the network every time a volunteer had a bad hour. Losing the
// counts on restart is a feature: the node re-learns from current behaviour
// rather than trusting a stale grudge.
const (
	refusalsBeforeSkipping = 3
	refusalCooldown        = 30 * time.Minute
)

type peerRefusal struct {
	count int
	last  time.Time
	// reason is the peer's own answer, classified. Kept because a count on its
	// own is undiagnosable: "3 failures" sends an operator to SSH and grep,
	// which is exactly how three peers spent a week refusing every round (one
	// cache-only, one out of capacity, one rejecting the coordinator's lease
	// signature) while the numbers on the admin page looked identical for all
	// three. See roadmap/dht-storage-roadmap.md phase 4.3.
	reason string
}

// noteRefusal records that a peer explicitly declined a shard, and WHY. Only for
// answers -- an unreachable peer is not refusing, it is absent, and the
// difference matters because absence is already handled by the dial failing.
func (n *Node) noteRefusal(peerID, reason string) {
	n.refusalMu.Lock()
	defer n.refusalMu.Unlock()
	if n.refusals == nil {
		n.refusals = make(map[string]*peerRefusal)
	}
	entry := n.refusals[peerID]
	if entry == nil {
		entry = &peerRefusal{}
		n.refusals[peerID] = entry
	}
	if reason != "" {
		// Latest wins. A peer that was full and is now cache-only should read as
		// cache-only; the previous answer is no longer why it is refusing.
		entry.reason = reason
	}
	// A refusal after the cooldown starts the count again rather than adding to
	// an old grudge: three refusals spread over a week is a peer having bad
	// luck, three in half an hour is a peer that will refuse the next one too.
	if !entry.last.IsZero() && time.Since(entry.last) > refusalCooldown {
		entry.count = 0
	}
	entry.count++
	entry.last = time.Now()
	crossed := entry.count == refusalsBeforeSkipping
	n.refusalMu.Unlock()
	if crossed {
		// Drop the cached candidate set immediately. The cache exists to reuse
		// one lookup across the shards of a pass, but holding a peer we have
		// just decided to stop asking means it keeps consuming a slot for the
		// rest of the TTL -- and with nine shards a pass, that is most of them.
		n.candidateMu.Lock()
		n.candidateCache = nil
		n.candidateMu.Unlock()
	}
	n.refusalMu.Lock()
}

// noteAccepted clears a peer's refusal history. Any success means the reason it
// was refusing is gone.
func (n *Node) noteAccepted(peerID string) {
	n.refusalMu.Lock()
	defer n.refusalMu.Unlock()
	delete(n.refusals, peerID)
}

// refusingPeer reports whether a peer should be skipped as a candidate.
func (n *Node) refusingPeer(peerID string) bool {
	n.refusalMu.Lock()
	defer n.refusalMu.Unlock()
	entry := n.refusals[peerID]
	if entry == nil || entry.count < refusalsBeforeSkipping {
		return false
	}
	// The cooldown expiring is what lets a fixed peer back in without anyone
	// intervening.
	return time.Since(entry.last) <= refusalCooldown
}

// refusalReasons maps the substring a peer's answer contains onto the phrase an
// operator reads. Ordered, because the first match wins and the list is scanned
// in order.
//
// A CLOSED vocabulary rather than the raw error text. The reason is reported to
// the coordinator in the heartbeat and rendered on the admin panel, so it must be
// bounded in length, stable enough to group by across the fleet, and incapable of
// carrying whatever a remote peer chose to put in an error string onto an
// operator's page.
var refusalReasons = [][2]string{
	{"cache-only", "node is cache-only"},
	{"capacity exceeded", "storage capacity exceeded"},
	// A retiring node refuses every store frame. Counting it lets an owner that
	// has not yet seen the draining record reach the same conclusion from
	// behaviour, which is the belt to the advertisement's braces.
	{"is draining", "node is draining"},
	{"invalid coordinator lease signature", "invalid coordinator lease signature"},
	{"recalled recently", "shard was recalled recently"},
	{"unsupported operation", "unsupported operation"},
	// Last: the most general phrasing, so a peer that says both "rejected by this
	// node: capacity exceeded" and nothing else is still classified by the
	// specific half.
	{"rejected by this node", "rejected by this node"},
}

// refusalReason classifies a peer that DECLINED, and returns "" for one that
// could not be reached. Only the former says anything about whether the next
// attempt will also fail; a dial failure says the network was busy, which is not
// the peer's fault and not predictive.
func refusalReason(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	for _, refusal := range refusalReasons {
		if strings.Contains(text, refusal[0]) {
			return refusal[1]
		}
	}
	return ""
}

// answeredNo is refusalReason's yes/no form, kept because most callers only need
// to know whether the count should move.
func answeredNo(err error) bool { return refusalReason(err) != "" }
