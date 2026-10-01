package bootstrap

// What a node knows about where compute lives.
//
// WHY A NODE KEEPS THIS AT ALL
// ----------------------------
// A node that only reported its own capabilities upward would make the site the
// network. Every dispatch would originate there, every failure would be its
// failure, and a volunteer wanting to hand work to a peer would have nowhere to
// look. Keeping the listing locally is what lets a node ask "who else can do
// this" without asking the site first.
//
// WHY IT IS REFRESHED AND NOT ACCUMULATED
// ---------------------------------------
// Each bootstrap document is a snapshot of who was alive when it was signed.
// Merging documents would build a list that only grows, so a node that left
// months ago stays a candidate forever and every dispatch to it is a wasted
// round trip over I2P. So a refresh REPLACES rather than merges, and a peer
// that stops being published stops being a candidate.
//
// The cost of that is a peer briefly absent from one document disappears for a
// cycle. That is the right trade: a stale candidate wastes real time on every
// selection, while a missing one is picked up on the next refresh.

import (
	"sort"
	"sync"
	"time"
)

// ComputeRegistry holds the compute peers from the newest bootstrap document.
type ComputeRegistry struct {
	mu        sync.RWMutex
	peers     []ComputePeer
	refreshed time.Time
	// expires is the document's own expiry. Kept because acting on an expired
	// listing is worse than having none: it produces confident dispatch to
	// nodes that may be long gone.
	expires time.Time
}

func NewComputeRegistry() *ComputeRegistry { return &ComputeRegistry{} }

// Update replaces the registry from a verified document.
//
// Takes the whole Document rather than just its peers, so the expiry travels
// with the data it governs — a caller that had to remember to pass both would
// eventually pass only one.
func (r *ComputeRegistry) Update(doc Document, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers = make([]ComputePeer, 0, len(doc.Compute))
	for _, p := range doc.Compute {
		if p.Reachable() {
			r.peers = append(r.peers, p)
		}
	}
	// Sorted by id so selection over this list is reproducible: two nodes
	// holding the same document must derive the same candidate order, or a
	// disputed placement cannot be re-derived.
	sort.Slice(r.peers, func(i, j int) bool { return r.peers[i].NodeID < r.peers[j].NodeID })
	r.refreshed = now
	r.expires = doc.ExpiresAt
}

// Candidates returns peers that can take a given kind of work.
//
// Returns NOTHING once the document has expired. A node acting on a stale
// listing dispatches confidently to peers that may be long gone, and the
// failure surfaces as "compute is broken" rather than "my directory is old".
func (r *ComputeRegistry) Candidates(device string, arbitrary bool, now time.Time) []ComputePeer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.expires.IsZero() || !now.Before(r.expires) {
		return nil
	}
	out := make([]ComputePeer, 0, len(r.peers))
	for _, p := range r.peers {
		if p.Offers(device, arbitrary) {
			out = append(out, p)
		}
	}
	return out
}

// Stale reports whether this node should refresh before trusting the listing.
func (r *ComputeRegistry) Stale(now time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.expires.IsZero() || !now.Before(r.expires)
}

// Summary is what an operator sees: counts, never a peer list.
//
// A node's UI showing every peer it knows about would publish the network's
// membership to anyone who opened it, which is a directory the network did not
// agree to hand out at that granularity.
type Summary struct {
	Total     int       `json:"total"`
	CPU       int       `json:"cpu"`
	GPU       int       `json:"gpu"`
	MicroVM   int       `json:"microvm"`
	Refreshed time.Time `json:"refreshed"`
	Expired   bool      `json:"expired"`
}

// Summarise counts what this node currently knows.
func (r *ComputeRegistry) Summarise(now time.Time) Summary {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := Summary{Total: len(r.peers), Refreshed: r.refreshed,
		Expired: r.expires.IsZero() || !now.Before(r.expires)}
	for _, p := range r.peers {
		if p.CPU {
			s.CPU++
		}
		if p.GPU {
			s.GPU++
		}
		if p.MicroVM {
			s.MicroVM++
		}
	}
	return s
}
