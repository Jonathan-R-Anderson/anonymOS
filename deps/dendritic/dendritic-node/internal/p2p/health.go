package p2p

import (
	"sort"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/heartbeat"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// Whether dispersal is WORKING, as opposed to what this node HOLDS.
//
// WHY THIS EXISTS
// ---------------
// Every fault fixed this week was diagnosed by SSHing to a node and grepping its
// journal, because the only place these numbers appeared was a log line. Five
// separate faults survived for days behind that blindness, and each one of them
// is a figure the node already had:
//
//   - replicateOnce marking objects replicated unconditionally: the backlog fell
//     on schedule while every peer's shard directory stayed empty. Placed/Failed
//     would have said so on day one.
//   - three peers refusing every round (cache-only, capacity exceeded, invalid
//     lease signature) and holding every object one holder short of durable.
//     Refusals carries the peer AND the reason.
//   - lease requests dying before leaving the box: "placed 0, failed 9".
//   - the i2pd router core-dumping: Peers drops to zero, and a pass with no peers
//     is recorded rather than skipped so that reads as isolation, not silence.
//
// See roadmap/dht-storage-roadmap.md phase 4.3.
//
// ABSENT IS NOT ZERO
// ------------------
// A Node publishes nothing here until a replicate pass has completed and read the
// ledger. PlacementHealth returns nil until then, the heartbeat omits the block
// entirely, and the coordinator renders "not reporting". A node that has never
// managed a pass, a node whose ledger will not open, and a node running a build
// that predates this field must never be drawn as a node with zero failures --
// which is precisely the mistake that let a draining backlog counter pass for
// replication for the life of the project.
type PlacementHealth struct {
	// The ledger, as of the pass that recorded this.
	Objects         int
	UnderReplicated int
	LocalOnly       int
	FullyDispersed  int

	// What the pass itself achieved. Shard-level, summed over every object it
	// attempted, which is the same arithmetic as the per-object "placed N,
	// failed N" line an operator currently greps for.
	Placed       int
	Failed       int
	Unassignable int
	// Objects the pass actually attempted. Distinguishes "nothing failed" from
	// "nothing was tried" -- an idle node with a fully dispersed corpus reports
	// zero failures and zero attempts, and those are not the same health.
	Attempted int
	// Connected peers at the moment of the pass. Zero placements with zero peers
	// is an isolated node; zero placements with nine peers is a node being
	// refused, and the two need entirely different repairs.
	Peers int

	// Recalls is nil when the recall ledger could not be read. Not zeroed: an
	// unreadable ledger reported as "nothing outstanding" is the same class of
	// lie this whole type exists to stop.
	Recalls *store.RecallSummary

	// Refusals is who is saying no, and what they are saying. Empty is a real
	// answer here (nobody is refusing) because the pass ran and looked.
	Refusals []PeerRefusal

	// ObservedAt is when the pass that produced this finished. The coordinator
	// turns it into an age, so a node that stopped passing is visibly stale
	// rather than quietly authoritative.
	ObservedAt time.Time
}

// PeerRefusal is one peer's refusal history, with the answer it gave.
type PeerRefusal struct {
	Peer   string
	Count  int
	Reason string
}

const (
	// How many refusing peers ride along on the heartbeat. The heartbeat is
	// signed and sent by every node on the network every five minutes, so this
	// is a summary, not a log: the worst few name the problem, and the gateway's
	// SigV4 ?placement surface is where per-object detail belongs.
	maxReportedRefusals = 5
	// Peer ids are ~52 characters and the operator only needs enough to tell one
	// dot from another -- the admin panel already truncates node ids to 12.
	refusalPeerIDLength = 16
)

// recordPlacementHealth publishes what a completed replicate pass observed.
//
// Called from replicateOnce and nowhere else, on the five-minute background
// loop. Deliberately not computed on demand: the coordinator reads this out of a
// database row, and anything that made the admin page's request path walk a bolt
// ledger -- let alone dial a peer -- would put slow work back on a request
// handler, which this site has 504'd over before.
func (n *Node) recordPlacementHealth(health PlacementHealth) {
	health.ObservedAt = time.Now()
	health.Refusals = n.refusalReport(maxReportedRefusals)
	n.healthMu.Lock()
	n.placementHealth = &health
	n.healthMu.Unlock()
}

// PlacementHealth returns the last completed pass, or nil if there has not been
// one. Nil is the honest answer and callers must render it as such.
func (n *Node) PlacementHealth() *PlacementHealth {
	n.healthMu.RLock()
	defer n.healthMu.RUnlock()
	if n.placementHealth == nil {
		return nil
	}
	snapshot := *n.placementHealth
	snapshot.Refusals = append([]PeerRefusal(nil), n.placementHealth.Refusals...)
	return &snapshot
}

// refusalReport snapshots the peers currently being skipped, worst first.
//
// Only peers inside the cooldown window, i.e. exactly the set refusingPeer is
// acting on. A peer whose grudge has expired is back in the candidate set and
// reporting it would send an operator after a problem that has already resolved
// itself.
func (n *Node) refusalReport(limit int) []PeerRefusal {
	n.refusalMu.Lock()
	report := make([]PeerRefusal, 0, len(n.refusals))
	for peerID, entry := range n.refusals {
		if entry == nil || entry.count == 0 {
			continue
		}
		if time.Since(entry.last) > refusalCooldown {
			continue
		}
		reason := entry.reason
		if reason == "" {
			// Should not happen -- noteRefusal is only called with a classified
			// reason -- but "unknown" is still the truthful rendering, and a
			// blank cell would read as "no reason, therefore no problem".
			reason = "refused, reason not reported"
		}
		report = append(report, PeerRefusal{
			Peer: shortenPeer(peerID), Count: entry.count, Reason: reason,
		})
	}
	n.refusalMu.Unlock()

	// Worst first, then by peer, so the truncation below keeps the peers doing
	// the most damage and the list does not reshuffle between heartbeats over
	// nothing (map iteration order would otherwise make every send look like a
	// change).
	sort.Slice(report, func(i, j int) bool {
		if report[i].Count != report[j].Count {
			return report[i].Count > report[j].Count
		}
		return report[i].Peer < report[j].Peer
	})
	if limit > 0 && len(report) > limit {
		report = report[:limit]
	}
	return report
}

// placementBeacon converts an observed pass into the heartbeat's wire form, and
// returns nil for nil so an unobserved node sends no block at all.
func placementBeacon(health *PlacementHealth, now time.Time) *heartbeat.Placement {
	if health == nil {
		return nil
	}
	beacon := &heartbeat.Placement{
		Objects: health.Objects, UnderReplicated: health.UnderReplicated,
		LocalOnly: health.LocalOnly, FullyDispersed: health.FullyDispersed,
		Placed: health.Placed, Failed: health.Failed,
		Unassignable: health.Unassignable, Attempted: health.Attempted,
		Peers: health.Peers,
	}
	if !health.ObservedAt.IsZero() {
		// Clamped at zero: a clock stepping backwards between the pass and the
		// beacon must not report a pass from the future.
		if age := now.Sub(health.ObservedAt); age > 0 {
			beacon.AgeSeconds = int(age / time.Second)
		}
	}
	if health.Recalls != nil {
		outstanding, deferred, unreadable :=
			health.Recalls.Outstanding, health.Recalls.Deferred, health.Recalls.Unreadable
		beacon.RecallsOutstanding = &outstanding
		beacon.RecallsDeferred = &deferred
		beacon.RecallsUnreadable = &unreadable
	}
	for _, refusal := range health.Refusals {
		beacon.Refusals = append(beacon.Refusals, heartbeat.Refusal{
			Peer: refusal.Peer, Count: refusal.Count, Reason: refusal.Reason,
		})
	}
	return beacon
}

// recallSummaryOrNil reads the recall ledger, and returns nil if it will not
// read. Nil travels all the way to the wire as an omitted field, so an
// unreadable ledger is reported as unknown rather than as zero outstanding.
func recallSummaryOrNil(s *store.Store) *store.RecallSummary {
	if s == nil {
		return nil
	}
	summary, err := s.RecallSummary()
	if err != nil {
		return nil
	}
	return &summary
}

func shortenPeer(id string) string {
	if len(id) <= refusalPeerIDLength {
		return id
	}
	return id[:refusalPeerIDLength]
}
