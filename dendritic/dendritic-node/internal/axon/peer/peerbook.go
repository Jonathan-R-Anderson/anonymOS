package peer

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// ReachState is what this node believes about a peer's reachability, or about
// itself.
//
// R3 gates the relay role on reachability: a node that cannot accept inbound
// connections must not advertise `relay`, because a relay nobody can reach is
// a path that silently fails.
type ReachState uint8

const (
	ReachUnknown     ReachState = iota // never probed
	ReachProbing                       // probes issued, quorum not yet met
	ReachReachable                     // quorum of diverse probers succeeded
	ReachUnreachable                   // probed and failed, or self-classified blocked
)

func (r ReachState) String() string {
	switch r {
	case ReachProbing:
		return "probing"
	case ReachReachable:
		return "reachable"
	case ReachUnreachable:
		return "unreachable"
	default:
		return "unknown"
	}
}

// MinProbeQuorum is the floor for admitting a reachability observation.
//
// E3.3 makes this an invariant rather than a default: no peerbook entry may
// exist with a quorum below it. One prober asserting a peer is reachable is one
// prober's word, and a single hostile prober would otherwise be able to mark
// arbitrary peers reachable or not.
const MinProbeQuorum = 2

// MinProbeNetworks is how many DISTINCT prober networks a quorum must span.
//
// T3.4 is why the count alone is insufficient: three probers behind one network
// are one vantage point wearing three hats, and a coalition that controls one
// network could otherwise manufacture a false positive.
const MinProbeNetworks = 2

// Evidence is what a caller offers in support of an observation.
type Evidence struct {
	// Probers that independently confirmed the observation.
	Probers []ProberID
	// Networks those probers sit in. Length is what MinProbeNetworks tests.
	Networks []string
	// At is when the observation was made.
	At time.Time
	// Reachable is what the probers concluded.
	Reachable bool
}

// ProberID identifies a prober. Opaque here; the gateway probe protocol owns
// its format and its signature verification.
type ProberID string

// Quorum reports the distinct prober and network counts in the evidence.
func (e Evidence) Quorum() (probers, networks int) {
	ps := map[ProberID]struct{}{}
	for _, p := range e.Probers {
		if p != "" {
			ps[p] = struct{}{}
		}
	}
	ns := map[string]struct{}{}
	for _, n := range e.Networks {
		if n != "" {
			ns[n] = struct{}{}
		}
	}
	return len(ps), len(ns)
}

// PeerEntry is what the peerbook knows about one peer.
type PeerEntry struct {
	NodeID      string
	Addrs       []netip.Addr
	Annotations []Annotation
	ReachState  ReachState
	LastProbe   time.Time
	ProbeQuorum int
	// ProbeNetworks is the diversity behind the quorum, kept so a later audit
	// can tell a 3-prober/3-network quorum from a 3-prober/1-network one.
	ProbeNetworks int
}

// Primary returns the annotation used for diversity decisions: the first
// address, which is the one the peer advertises first.
func (e PeerEntry) Primary() (Annotation, bool) {
	if len(e.Annotations) == 0 {
		return Annotation{}, false
	}
	return e.Annotations[0], true
}

var (
	ErrQuorumTooSmall = errors.New("axon/peer: observation lacks the minimum prober quorum")
	ErrNetworksTooFew = errors.New("axon/peer: observation lacks prober network diversity")
	ErrNoAddresses    = errors.New("axon/peer: observation carries no addresses")
	ErrUnknownNodeID  = errors.New("axon/peer: empty node id")
	// ErrContained is an observation refused because the operator contained this
	// peer. Distinct from a quorum refusal on purpose: a quorum error says the
	// EVIDENCE was too thin, this one says a person decided.
	ErrContained = errors.New("axon/peer: peer is contained by operator decision")
)

// Peerbook records peers and samples them under diversity constraints.
//
// It records observations; it does NOT score them. P3 says so explicitly, and
// the separation matters: a peerbook that also weighted peers would make every
// later reputation decision unauditable, because the raw observation would no
// longer exist to disagree with.
type Peerbook struct {
	annotator *Annotator
	rng       *rand.Rand

	mu      sync.RWMutex
	entries map[string]*PeerEntry
	// contained is the operator's containment list, or nil.
	//
	// The SAME list dht.Table consults. Two copies of a denial rule is one copy
	// too many: a peer contained in the routing table and admitted to the
	// peerbook is contained nowhere, because the peerbook is what SAMPLES.
	contained Denier
}

// Denier answers whether a peer is contained. Satisfied by *contain.List.
type Denier interface {
	Denied(id string) bool
}

// NewPeerbook builds an empty peerbook. A nil annotator uses the default.
func NewPeerbook(a *Annotator, seed int64) *Peerbook {
	if a == nil {
		a = &Annotator{}
	}
	return &Peerbook{
		annotator: a,
		rng:       rand.New(rand.NewSource(seed)),
		entries:   make(map[string]*PeerEntry),
	}
}

// SetContainment wires the operator's containment list in.
//
// Existing entries are NOT swept here; SweepContained does that, and the two
// are separate for the same reason they are in dht.Table -- wiring a list in
// should not silently reshape a structure according to a list nobody has read.
func (p *Peerbook) SetContainment(d Denier) {
	p.mu.Lock()
	p.contained = d
	p.mu.Unlock()
}

// Forget removes a peer's entry. Reports whether there was one.
//
// FORGETTING WITHOUT DENYING IS THEATRE: the next probe that meets the quorum
// re-creates the entry, so a responder who called only this would watch the
// peer come back. Deny it in the containment list, then sweep.
//
// Named Forget to match profile.Forget, and it has the same limit that one has:
// it drops what is RECORDED, not what is REACHABLE.
func (p *Peerbook) Forget(nodeID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.entries[nodeID]
	delete(p.entries, nodeID)
	return ok
}

// SweepContained drops every entry the containment list currently denies.
//
// This is what makes a denial retroactive across a restart: a list loaded from
// disk names peers ejected in an earlier incident, and without a sweep the
// peerbook keeps sampling them.
func (p *Peerbook) SweepContained() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.contained == nil {
		return 0
	}
	removed := 0
	for id := range p.entries {
		if p.contained.Denied(id) {
			delete(p.entries, id)
			removed++
		}
	}
	return removed
}

// Observe records a reachability observation about a peer.
//
// The quorum is enforced here rather than by the caller so that E3.3 holds by
// construction: there is no code path that creates an entry without one.
func (p *Peerbook) Observe(nodeID string, addrs []netip.Addr, ev Evidence) error {
	if nodeID == "" {
		return ErrUnknownNodeID
	}
	// Before the quorum checks: a contained peer is refused whatever evidence
	// arrives about it. The quorum decides whether an observation is BELIEVABLE;
	// containment decides whether this node is willing to act on it at all, and
	// those are different questions in that order.
	if p.denied(nodeID) {
		return fmt.Errorf("%w: %s", ErrContained, nodeID)
	}
	if len(addrs) == 0 {
		return ErrNoAddresses
	}
	probers, networks := ev.Quorum()
	if probers < MinProbeQuorum {
		return fmt.Errorf("%w: %d < %d", ErrQuorumTooSmall, probers, MinProbeQuorum)
	}
	if networks < MinProbeNetworks {
		return fmt.Errorf("%w: %d < %d", ErrNetworksTooFew, networks, MinProbeNetworks)
	}

	anns := make([]Annotation, 0, len(addrs))
	for _, a := range addrs {
		ann, err := p.annotator.Annotate(a)
		if err != nil {
			return err
		}
		anns = append(anns, ann)
	}

	state := ReachUnreachable
	if ev.Reachable {
		state = ReachReachable
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// REPLACE the entry, never mutate one in place. Sample() builds a slice of
	// *PeerEntry pointers under the read lock and dereferences them AFTER
	// releasing it, which is safe only because an entry, once inserted, is
	// immutable: a fresh struct is assigned here and the old one is never
	// touched again. Updating a field on an existing entry in place instead
	// would silently make Sample race -- TestPeerbookConcurrentAccess guards it.
	p.entries[nodeID] = &PeerEntry{
		NodeID:        nodeID,
		Addrs:         append([]netip.Addr(nil), addrs...),
		Annotations:   anns,
		ReachState:    state,
		LastProbe:     ev.At,
		ProbeQuorum:   probers,
		ProbeNetworks: networks,
	}
	return nil
}

func (p *Peerbook) denied(nodeID string) bool {
	p.mu.RLock()
	d := p.contained
	p.mu.RUnlock()
	return d != nil && d.Denied(nodeID)
}

// Get returns a copy of one entry.
func (p *Peerbook) Get(nodeID string) (PeerEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.entries[nodeID]
	if !ok {
		return PeerEntry{}, false
	}
	return *e, true
}

// Len is the number of known peers.
func (p *Peerbook) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

// DiversityConstraint says how distinct a sample must be.
type DiversityConstraint struct {
	// Domains every pair in the sample must differ in.
	Domains []Domain
	// ReachableOnly restricts the draw to peers confirmed reachable.
	ReachableOnly bool
}

// Sample draws up to k peers satisfying the constraint.
//
// It is best-effort by construction and returns fewer than k rather than
// relaxing the constraint. Section 46.1 is explicit about why: a sampler that
// quietly drops diversity to fill a quota returns a set with the throughput of
// k peers and the failure domain of one, and the caller cannot tell. Returning
// a short set is information; returning a full but correlated one is a lie.
func (p *Peerbook) Sample(k int, c DiversityConstraint) []PeerEntry {
	if k <= 0 {
		return nil
	}
	p.mu.RLock()
	candidates := make([]*PeerEntry, 0, len(p.entries))
	for _, e := range p.entries {
		if c.ReachableOnly && e.ReachState != ReachReachable {
			continue
		}
		if len(e.Annotations) == 0 {
			continue
		}
		candidates = append(candidates, e)
	}
	p.mu.RUnlock()

	// Deterministic order before shuffling, so a fixed seed gives a
	// reproducible draw: an unreproducible sampler cannot be tested against
	// E3.1's 10^4 draws in any meaningful way.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].NodeID < candidates[j].NodeID
	})
	p.mu.Lock()
	p.rng.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	p.mu.Unlock()

	out := make([]PeerEntry, 0, k)
	chosen := make([]Annotation, 0, k)
	for _, cand := range candidates {
		if len(out) == k {
			break
		}
		ann, ok := cand.Primary()
		if !ok {
			continue
		}
		if conflicts(ann, chosen, c.Domains) {
			continue
		}
		out = append(out, *cand)
		chosen = append(chosen, ann)
	}
	return out
}

func conflicts(ann Annotation, chosen []Annotation, domains []Domain) bool {
	for _, prev := range chosen {
		for _, d := range domains {
			if SameDomain(ann, prev, d) {
				return true
			}
		}
	}
	return false
}

// ConstraintReport describes how well a sample could actually be constrained.
//
// It exists so a caller learns when the ASN constraint was unenforceable rather
// than assuming it held. Section 56.2's failure mode is a diversity mechanism
// that reports success while measuring nothing; this is the report that makes
// that visible.
type ConstraintReport struct {
	Requested int
	Returned  int
	// ASNUnavailable counts returned peers whose ASN could not be determined,
	// so a DomainASN constraint could not be applied to them.
	ASNUnavailable int
}

// SampleWithReport is Sample plus the honesty about what it could enforce.
func (p *Peerbook) SampleWithReport(k int, c DiversityConstraint) ([]PeerEntry, ConstraintReport) {
	out := p.Sample(k, c)
	rep := ConstraintReport{Requested: k, Returned: len(out)}
	wantsASN := false
	for _, d := range c.Domains {
		if d == DomainASN {
			wantsASN = true
		}
	}
	if wantsASN {
		for _, e := range out {
			if ann, ok := e.Primary(); ok && ann.ASN == ASNUnknown {
				rep.ASNUnavailable++
			}
		}
	}
	return out, rep
}

// Entries returns a copy of every entry.
//
// Added because nothing could enumerate the peerbook: Sample applies a
// diversity constraint and Get needs a node id you already have, so a caller
// wanting the whole membership -- which is what a path selector's candidate
// pool is -- had no way to ask. Sampling with a large k is not the same thing:
// it would return a diversity-filtered subset and call it the population.
//
// A copy, and deliberately not a cursor: the peerbook is small (bounded by what
// probing establishes) and a caller iterating a live map under a read lock is
// how a slow consumer becomes a stalled writer.
func (p *Peerbook) Entries() []PeerEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]PeerEntry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}
