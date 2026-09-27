package path

import (
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
	"sync"
)

// The candidate pool (P12, R3, item 4.10c).
//
// Selector.Candidates is a func() []Relay, and until this file NOTHING SUPPLIED
// IT. That was found by E16.4's incident drill rather than by reading: the
// procedure's containment step could say how to eject a relay from the routing
// table and the peerbook, and for the selector it could only say "filter
// whatever supplies Candidates" -- which named no code, because there was none.
//
// WHY THE POOL IS A SEPARATE THING FROM THE PEERBOOK. The peerbook records
// observations and does not score them (P3 says so, and the separation is what
// keeps a later reputation decision auditable). Deciding WHICH of those
// observations may carry anonymous traffic is a different judgement with
// different inputs, and putting it in the peerbook would have made the raw
// observation unavailable to disagree with. So this is a projection, computed
// on demand, and the peerbook stays the record.
//
// COMPUTED ON DEMAND, NEVER CACHED, for the reason Selector already states
// about its own pool: "A cached pool would freeze a view, and a frozen view is
// a partition this node performed on itself."

// Denier answers whether a peer is contained. Satisfied by *contain.List.
type Denier interface {
	Denied(id string) bool
}

// PoolPolicy is what may enter the candidate pool.
type PoolPolicy struct {
	// Contained is the operator's containment list, or nil.
	//
	// Applied HERE as well as in the peerbook, and that redundancy is
	// deliberate. Peerbook.Observe refuses a contained peer and SweepContained
	// drops one already recorded, but the sweep is a call somebody has to make:
	// a node that loaded a list and forgot to sweep would otherwise hand
	// contained relays to the path selector. Containment is the one rule worth
	// checking twice, because the failure is silent and the cost is a map
	// lookup.
	Contained Denier

	// AllowUnreachable admits peers whose reachability is unknown or still
	// being probed.
	//
	// Default false, which is R3: a relay that cannot accept inbound
	// connections must not be advertised as a relay, because a path through it
	// silently fails. Available because a very small network may have no
	// probed peers at all, and a caller that would rather build a fragile path
	// than none should have to say so ON THE RECORD rather than by leaving a
	// field unset.
	AllowUnreachable bool
}

// PoolReport says what the pool left out, and why.
//
// Returned rather than logged because the counts are the difference between "no
// path exists on this network" and "no path exists because this node has
// contained or failed to probe everybody", and a caller that cannot tell those
// apart will report the first when it is looking at the second. The incident
// drill hit exactly that shape from the other direction -- see NoPath in
// CompromiseModel.
type PoolReport struct {
	// Considered is how many peerbook entries were examined.
	Considered int
	// Admitted is how many entered the pool.
	Admitted int
	// Contained were refused by operator decision.
	Contained int
	// Unreachable were refused for reachability (R3).
	Unreachable int
	// Unannotated had no address to derive a failure domain from, so no
	// diversity constraint could be applied to them at all.
	Unannotated int
}

// Empty reports whether the pool came back with nothing.
func (r PoolReport) Empty() bool { return r.Admitted == 0 }

// PeerSource is the peerbook, as this file needs it.
type PeerSource interface {
	Entries() []peer.PeerEntry
}

// Pool projects a peer source into selector candidates.
func Pool(src PeerSource, pol PoolPolicy) ([]Relay, PoolReport) {
	var rep PoolReport
	if src == nil {
		return nil, rep
	}
	entries := src.Entries()
	rep.Considered = len(entries)
	out := make([]Relay, 0, len(entries))

	for _, e := range entries {
		// Containment first: an operator's decision outranks every measurement,
		// and reporting a contained peer as "unreachable" would send whoever
		// reads the counts to look at probe coverage instead of at their own
		// list.
		if pol.Contained != nil && pol.Contained.Denied(e.NodeID) {
			rep.Contained++
			continue
		}
		if !pol.AllowUnreachable && e.ReachState != peer.ReachReachable {
			rep.Unreachable++
			continue
		}
		ann, ok := e.Primary()
		if !ok {
			rep.Unannotated++
			continue
		}
		// Weight is left at zero. The pool decides MEMBERSHIP; weighting is
		// WeightPolicy's job and takes different inputs (first-hand profile
		// observations, or bond-capped claims). Filling it in here would give
		// the selector a second, unaudited weight source.
		out = append(out, Relay{NodeID: e.NodeID, Ann: ann})
	}
	rep.Admitted = len(out)
	sortRelays(out)
	return out, rep
}

// Source is a reusable candidate supplier for Selector.Candidates.
//
//	sel := &path.Selector{Candidates: path.Source{Peers: book, Policy: pol}.Candidates}
//
// The report from the most recent call is available through LastReport, so a
// caller that gets ErrNoPath can say WHY the pool was thin rather than only
// that it was.
type Source struct {
	Peers  PeerSource
	Policy PoolPolicy

	// mu guards last. A Selector may draw paths concurrently -- a node builds
	// more than one circuit at once -- and SelectPath is otherwise stateless,
	// so this sidecar report is the only shared mutable state a draw touches.
	// Unguarded it is a data race, found by TestSourceRaceUnderConcurrentSelect.
	mu   sync.Mutex
	last PoolReport
}

// Candidates satisfies Selector.Candidates.
func (s *Source) Candidates() []Relay {
	relays, rep := Pool(s.Peers, s.Policy)
	s.mu.Lock()
	s.last = rep
	s.mu.Unlock()
	return relays
}

// LastReport is the report from the most recent Candidates call.
//
// Under concurrent draws it is whichever call last completed, which is the
// documented "most recent" semantics -- the guard makes it a consistent report
// rather than a torn one, not a per-caller one.
func (s *Source) LastReport() PoolReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}
