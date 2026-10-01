// Package tunnel is AXON's L4.5: guard-constrained tunnel pools (R1).
//
// Every tunnel in a pool begins at one of that isolation context's pinned
// guards; hops 2..n churn freely. That is the whole point of a guard: an
// adversary who is not your guard has to wait to become one, and waiting is
// what guards make expensive.
//
// WHAT THIS PACKAGE MUST NEVER DO, and the reason it exists in this shape: it
// must not pick a new guard because the old ones failed. §8.4 states the rule
// plainly -- "an adversary who can make a client's guards fail can walk it onto
// a guard of the adversary's choosing" -- so guard failure produces a HARD
// FAILURE and no tunnel, not a quiet replacement (E7.4).
package tunnel

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// RelayID identifies a relay. Opaque here; the peerbook owns its meaning.
type RelayID [32]byte

var (
	ErrNoGuards       = errors.New("axon/tunnel: no primary guard is usable")
	ErrGuardHardFail  = errors.New("axon/tunnel: every primary guard has failed; refusing to build through an unpinned first hop")
	ErrOutsideSample  = errors.New("axon/tunnel: relay is outside this context's sampled guard set")
	ErrSampleFull     = errors.New("axon/tunnel: sampled guard set is full")
	ErrPoolExhausted  = errors.New("axon/tunnel: no tunnel available and none can be built")
	ErrUnknownContext = errors.New("axon/tunnel: unknown isolation context")
)

// GuardState is a guard's standing within a context.
type GuardState uint8

const (
	// GuardSampled is in the persisted sample and has never been used.
	GuardSampled GuardState = iota
	// GuardFiltered meets the current constraints (reachable, diverse).
	GuardFiltered
	// GuardConfirmed has carried a successful build.
	GuardConfirmed
	// GuardPrimary is one of the small set tried in order.
	GuardPrimary
)

// Down-ness is ORTHOGONAL to standing and is tracked separately (Guard.Down).
//
// The first version folded it into this ladder as a GuardDown state, which
// overwrote a guard's standing with its liveness -- and then "all my primaries
// are down" became indistinguishable from "I have no primaries", so the pool
// reported the wrong failure. A guard that is down is still a primary; that is
// the entire point of pinning it.

func (g GuardState) String() string {
	switch g {
	case GuardFiltered:
		return "filtered"
	case GuardConfirmed:
		return "confirmed"
	case GuardPrimary:
		return "primary"
	default:
		return "sampled"
	}
}

// Guard is one relay's standing.
type Guard struct {
	ID    RelayID
	State GuardState
	// Down is liveness, not standing. A down primary remains a primary.
	Down bool
	// Added is when the guard entered the SAMPLE, not when it became primary.
	// Rotation is measured from here so it is deterministic from stored state
	// and survives a restart (T7.3).
	Added time.Time
	// LastFailure drives backoff; it never removes the guard.
	LastFailure time.Time
	Failures    int
}

// GuardSet is one isolation context's guards: the PAR-05 sampled/filtered/
// confirmed/primary structure.
//
// The sampled set is the load-bearing part. Without it a client that keeps
// failing over eventually touches an unbounded fraction of the relay
// population, and an adversary who can induce failures enumerates the client by
// attrition. With it, the client's exposure is bounded at SampledGuardSize for
// the life of the sample.
type GuardSet struct {
	mu      sync.Mutex
	context string
	sampled []*Guard
	now     func() time.Time
}

// NewGuardSet builds an empty set for a context.
func NewGuardSet(context string, now func() time.Time) *GuardSet {
	if now == nil {
		now = time.Now
	}
	return &GuardSet{context: context, now: now}
}

// Context is the isolation context this set belongs to.
func (g *GuardSet) Context() string { return g.context }

// Sample adds a relay to the persisted sample.
//
// This is the ONLY way a relay becomes usable as a guard. Everything downstream
// draws from the sample, so the bound holds by construction rather than by
// remembering to check it.
func (g *GuardSet) Sample(id RelayID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.sampled {
		if x.ID == id {
			return nil
		}
	}
	if len(g.sampled) >= params.SampledGuardSize {
		return fmt.Errorf("%w: %d relays", ErrSampleFull, len(g.sampled))
	}
	g.sampled = append(g.sampled, &Guard{ID: id, State: GuardSampled, Added: g.now()})
	return nil
}

// Len is the size of the sample.
func (g *GuardSet) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sampled)
}

// InSample reports whether a relay is in the persisted sample.
func (g *GuardSet) InSample(id RelayID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.sampled {
		if x.ID == id {
			return true
		}
	}
	return false
}

// Promote moves a sampled relay toward primary. It refuses anything outside the
// sample, which is the invariant PAR-05 exists for.
func (g *GuardSet) Promote(id RelayID, to GuardState) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.sampled {
		if x.ID == id {
			x.State = to
			return nil
		}
	}
	return fmt.Errorf("%w: %x", ErrOutsideSample, id[:4])
}

// Primaries returns the current primary guards, in a stable order.
//
// Stable because the order is the order tried, and an order that reshuffled
// between calls would spread a client's builds across its primaries instead of
// concentrating them on one -- which is the opposite of what a guard is for.
func (g *GuardSet) Primaries() []Guard {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Guard
	for _, x := range g.sampled {
		if x.State == GuardPrimary {
			out = append(out, *x)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Added.Equal(out[j].Added) {
			return out[i].Added.Before(out[j].Added)
		}
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
	return out
}

// Usable returns the first primary that is not down, which is the guard a build
// must start at.
//
// It returns ErrGuardHardFail rather than falling back to a non-primary. That
// refusal IS the guard property: replacing a failed guard automatically would
// let an adversary who can make guards fail choose the next one.
func (g *GuardSet) Usable() (RelayID, error) {
	prim := g.Primaries()
	if len(prim) == 0 {
		return RelayID{}, ErrNoGuards
	}
	for _, p := range prim {
		if !p.Down {
			return p.ID, nil
		}
	}
	return RelayID{}, ErrGuardHardFail
}

// MarkDown records a guard failure with backoff. It never removes the guard and
// never selects a replacement.
func (g *GuardSet) MarkDown(id RelayID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.sampled {
		if x.ID == id {
			// Standing is untouched: it stays a primary, and stays ours.
			x.Down = true
			x.Failures++
			x.LastFailure = g.now()
			return nil
		}
	}
	return fmt.Errorf("%w: %x", ErrOutsideSample, id[:4])
}

// MarkUp restores a guard that answered again. It clears liveness only; the
// guard's standing was never changed by the failure.
func (g *GuardSet) MarkUp(id RelayID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.sampled {
		if x.ID == id {
			x.Down, x.Failures = false, 0
			return nil
		}
	}
	return fmt.Errorf("%w: %x", ErrOutsideSample, id[:4])
}

// DueForRotation reports the primaries whose GuardRotation has elapsed.
//
// Deterministic from stored state: it is a function of Added and the clock, so
// it survives a restart and two nodes with the same state agree (T7.3).
func (g *GuardSet) DueForRotation() []Guard {
	now := g.now()
	var out []Guard
	for _, p := range g.Primaries() {
		if now.Sub(p.Added) >= params.GuardRotation {
			out = append(out, p)
		}
	}
	return out
}

// Expired reports sampled entries past GuardListLifetime.
func (g *GuardSet) Expired() []Guard {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Guard
	for _, x := range g.sampled {
		if now.Sub(x.Added) >= params.GuardListLifetime {
			out = append(out, *x)
		}
	}
	return out
}

// Snapshot is the persisted form. Rotation and expiry are computed from it, so
// a restart resumes rather than restarting the clock.
type Snapshot struct {
	Context string
	Guards  []Guard
}

// Save returns the persistable state.
func (g *GuardSet) Save() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := Snapshot{Context: g.context, Guards: make([]Guard, 0, len(g.sampled))}
	for _, x := range g.sampled {
		out.Guards = append(out.Guards, *x)
	}
	return out
}

// Load restores a set from its snapshot.
func Load(s Snapshot, now func() time.Time) *GuardSet {
	g := NewGuardSet(s.Context, now)
	for i := range s.Guards {
		c := s.Guards[i]
		g.sampled = append(g.sampled, &c)
	}
	return g
}
