// Package profile is P12a: capacity measurement without a measurement
// authority.
//
// R14 forbids a consensus document and forbids anyone measuring the network on
// everyone else's behalf. That leaves a real problem — a client that cannot
// tell a 10 Gb/s relay from a Raspberry Pi either selects uniformly and gets
// the Raspberry Pi's throughput, or trusts a self-report and gets whatever the
// adversary claims. Tor solves it with bandwidth authorities, which R14 rules
// out. I2P has run for two decades without one, and its answer is imported here
// wholesale:
//
//	every node profiles ONLY the peers it actually uses,
//	ONLY from its own first-hand observations, and the profile
//	NEVER leaves the node — so there is no global metric to game.
//
// The consequence, stated rather than hidden: a peer that behaves well toward
// its measurers and badly toward everyone else is invisible to this. Local
// profiling measures the peer's behaviour TOWARD YOU, which is the only thing
// you can observe without an authority, and it is strictly less than what a
// bandwidth authority sees. What it buys is that there is nothing to corrupt.
//
// RelayDescriptor.claimed_bw is NOT an input, anywhere, by construction — it is
// the self-report this package exists to stop trusting (T12a.4).
//
// Nothing here is serialisable onto the wire and nothing here reads from it
// (T12a.1, T12a.3). A capacity tier derived from your own traffic is a
// fingerprint of your own traffic the moment it escapes the node.
package profile

import (
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// ObservationKind is a first-hand observation. Every kind is something this
// node did and watched the result of; there is no kind that means "somebody
// told me".
type ObservationKind uint8

const (
	// ObsExtendRTT is the round-trip time of a circuit extension through this
	// peer, in seconds. LOWER IS BETTER, which is why speed is stored as its
	// reciprocal and not as the raw value.
	ObsExtendRTT ObservationKind = iota

	// ObsBuildAccepted is 1 when the peer accepted a build request and 0 when
	// it refused. Its decayed mean is the accepted-build ratio, which is the
	// capacity signal: a relay at its limit refuses.
	ObsBuildAccepted

	// ObsDeliveryRatio is cells delivered divided by cells sent, in [0,1].
	ObsDeliveryRatio

	// ObsReachable is P3's reachability verdict, 1 or 0. It is the one input
	// that arrives from another package, and it is an observation about
	// whether THIS node could reach the peer, not a score somebody computed.
	ObsReachable
)

func (k ObservationKind) String() string {
	switch k {
	case ObsExtendRTT:
		return "extend-rtt"
	case ObsBuildAccepted:
		return "build-accepted"
	case ObsDeliveryRatio:
		return "delivery-ratio"
	case ObsReachable:
		return "reachable"
	default:
		return "unknown"
	}
}

// Tier is a peer's standing relative to the other peers this node has observed.
//
// Tiers are RELATIVE, never absolute: "top 10 %" and not "faster than X". See
// params.TierFastFraction for why.
type Tier uint8

const (
	// TierUntiered means not enough observations to say anything. Selection
	// falls back to uniform, which is E12a.3's requirement and also the honest
	// answer: an empty profile is an absence of evidence, not evidence of
	// mediocrity.
	TierUntiered Tier = iota
	TierFailing
	TierStandard
	TierHighCapacity
	TierFast
)

func (t Tier) String() string {
	switch t {
	case TierFailing:
		return "failing"
	case TierStandard:
		return "standard"
	case TierHighCapacity:
		return "high-capacity"
	case TierFast:
		return "fast"
	default:
		return "untiered"
	}
}

var (
	ErrNoNodeID     = errors.New("axon/profile: empty node id")
	ErrBadValue     = errors.New("axon/profile: observation value out of range")
	ErrUnknownKind  = errors.New("axon/profile: unknown observation kind")
	ErrTimeGoesBack = errors.New("axon/profile: observation predates the last one")
)

// decayed is an exponentially-decayed accumulator: a running sum and the weight
// behind it, both multiplied by the same factor as time passes.
//
// Decaying BOTH is what makes the mean stable — sum/weight is unchanged by
// decay alone, so a peer that stops being observed keeps its last known mean
// while its WEIGHT (its sample count) falls toward zero and it drops back to
// untiered. Decaying only the sum would make an unobserved peer look steadily
// worse, which is a different claim than "we no longer know".
type decayed struct {
	sum    float64
	weight float64
	at     time.Time
}

// decayTo advances the accumulator to now. It is applied on READ as well as on
// write (T12a.5): a node that stops observing must not freeze a stale tier, and
// a decay applied only on write does exactly that.
func (d decayed) decayTo(now time.Time) decayed {
	if d.at.IsZero() || !now.After(d.at) {
		return d
	}
	f := math.Exp2(-now.Sub(d.at).Seconds() / params.ProfileHalfLife.Seconds())
	return decayed{sum: d.sum * f, weight: d.weight * f, at: now}
}

func (d decayed) add(v float64, now time.Time) decayed {
	n := d.decayTo(now)
	n.sum += v
	n.weight++
	n.at = now
	return n
}

// mean returns the decayed mean and whether there is any weight behind it.
func (d decayed) mean(now time.Time) (float64, bool) {
	n := d.decayTo(now)
	if n.weight <= 0 {
		return 0, false
	}
	return n.sum / n.weight, true
}

// Profile is what this node has observed about one peer. It is returned by
// value and never stored anywhere but here.
type Profile struct {
	NodeID string
	// Speed is 1/RTT in extensions per second: higher is better, so every
	// tiering comparison in this package points the same way.
	Speed float64
	// Capacity is the decayed accepted-build ratio in [0,1].
	Capacity float64
	// Reliability is the decayed delivery-and-reachability ratio in [0,1].
	Reliability float64
	// Samples is the DECAYED observation count, not a lifetime total. It is
	// what ProfileMinSamples is compared against, so a peer that has not been
	// observed in many half-lives falls back to untiered on its own.
	Samples  float64
	LastSeen time.Time
	Tier     Tier
	// FailureStreak is consecutive failures since the last success.
	FailureStreak int
	// FailingSince is when the streak reached ProfileFailingStreak. Zero when
	// the peer is not excluded.
	FailingSince time.Time
}

type entry struct {
	nodeID        string
	speed         decayed
	capacity      decayed
	reliability   decayed
	samples       decayed
	lastSeen      time.Time
	failureStreak int
	failingSince  time.Time
}

// Profiles is this node's private view of the peers it has used.
//
// There is no constructor taking a wire message, no Unmarshal, no Merge, and no
// method that accepts another node's opinion. That is the design, not an
// omission (T12a.1).
type Profiles struct {
	// now is injectable so decay is testable; nil means time.Now.
	now func() time.Time

	mu sync.RWMutex
	m  map[string]*entry
}

// New builds an empty profile store. A nil clock uses time.Now.
func New(now func() time.Time) *Profiles {
	if now == nil {
		now = time.Now
	}
	return &Profiles{now: now, m: make(map[string]*entry)}
}

// Observe records one first-hand observation.
//
// `at` is the caller's timestamp so that a batch of observations recorded after
// the fact decays from when it happened rather than from when it was written.
// An observation older than the peer's last one is refused rather than folded
// in: out-of-order decay would apply the wrong factor and there is no honest
// way to correct it after the fact.
func (p *Profiles) Observe(nodeID string, kind ObservationKind, value float64, at time.Time) error {
	if nodeID == "" {
		return ErrNoNodeID
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return ErrBadValue
	}
	switch kind {
	case ObsExtendRTT:
		if value <= 0 {
			return ErrBadValue
		}
	case ObsBuildAccepted, ObsDeliveryRatio, ObsReachable:
		if value < 0 || value > 1 {
			return ErrBadValue
		}
	default:
		return ErrUnknownKind
	}
	if at.IsZero() {
		at = p.now()
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[nodeID]
	if !ok {
		e = &entry{nodeID: nodeID}
		p.m[nodeID] = e
	}
	if !e.lastSeen.IsZero() && at.Before(e.lastSeen) {
		return ErrTimeGoesBack
	}

	switch kind {
	case ObsExtendRTT:
		// Stored as a rate. Averaging RTTs and then inverting is not the same
		// number as averaging rates, and the rate is the one that composes with
		// a weighted mean the way a throughput estimate should.
		e.speed = e.speed.add(1/value, at)
	case ObsBuildAccepted:
		e.capacity = e.capacity.add(value, at)
	case ObsDeliveryRatio, ObsReachable:
		e.reliability = e.reliability.add(value, at)
	}
	e.samples = e.samples.add(1, at)
	e.lastSeen = at

	// The failure streak counts CONSECUTIVE failures, so any success clears it.
	// An RTT observation is by definition a success: the extension completed.
	failed := kind != ObsExtendRTT && value == 0
	if failed {
		e.failureStreak++
		if e.failureStreak >= params.ProfileFailingStreak && e.failingSince.IsZero() {
			e.failingSince = at
		}
	} else {
		e.failureStreak = 0
		e.failingSince = time.Time{}
	}
	return nil
}

// Forget drops a peer entirely. Used when a RoutingIdentity rotates: carrying a
// profile across a rotation would link the two identities, which is a worse
// outcome than losing the observations.
func (p *Profiles) Forget(nodeID string) {
	p.mu.Lock()
	delete(p.m, nodeID)
	p.mu.Unlock()
}

// Len is the number of peers with any observation.
func (p *Profiles) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.m)
}

// Get returns the decayed profile for one peer, including its tier.
func (p *Profiles) Get(nodeID string) (Profile, bool) {
	now := p.now()
	snap := p.snapshot(now)
	pr, ok := snap.byID[nodeID]
	return pr, ok
}

// All returns every peer's decayed profile, ordered by node id.
func (p *Profiles) All() []Profile {
	snap := p.snapshot(p.now())
	out := make([]Profile, 0, len(snap.byID))
	for _, pr := range snap.byID {
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// Tier is the peer's current tier, with decay applied on read.
func (p *Profiles) Tier(nodeID string) Tier {
	pr, ok := p.Get(nodeID)
	if !ok {
		return TierUntiered
	}
	return pr.Tier
}

// Weight is the selection weight for one peer.
//
// It is a MULTIPLIER on an otherwise-uniform draw, never a filter and never an
// ordering. P12's selector applies diversity constraints FIRST and weights
// second, so a weight can shift which of several admissible peers is drawn and
// can never admit a peer the constraints excluded (E12a.2).
//
// An unknown peer weighs exactly the same as an ordinary one. Treating "never
// observed" as "bad" would make a fresh node's first choices sticky, and a
// fresh node's profile is empty exactly when it is most vulnerable.
func (p *Profiles) Weight(nodeID string) float64 { return weightForTier(p.Tier(nodeID)) }

func weightForTier(t Tier) float64 {
	switch t {
	case TierFailing:
		return params.WeightFailing
	case TierHighCapacity:
		return params.WeightHighCapacity
	case TierFast:
		return params.WeightFast
	case TierStandard:
		return params.WeightStandard
	default:
		return params.WeightUntiered
	}
}
