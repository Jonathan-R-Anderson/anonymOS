package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// The §9.2 pool state machine.
//
//	PLANNED -> BUILDING -> READY -> ACTIVE -> EXPIRING -> DEAD
//	                   \-> FAILED (backoff, <=5 tries)
//	                              ACTIVE <-> SUSPECT -> DEAD (immediate rebuild)

// TunnelState is a tunnel's position in that machine.
type TunnelState uint8

const (
	Planned TunnelState = iota
	Building
	Ready
	Active
	Suspect
	Expiring
	Failed
	Dead
)

var stateNames = map[TunnelState]string{
	Planned: "PLANNED", Building: "BUILDING", Ready: "READY", Active: "ACTIVE",
	Suspect: "SUSPECT", Expiring: "EXPIRING", Failed: "FAILED", Dead: "DEAD",
}

func (s TunnelState) String() string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return "?"
}

// Counts toward min_ready. A SUSPECT tunnel does not: it may be dead, and
// counting a maybe-dead tunnel toward the floor is how a pool convinces itself
// it is healthy while carrying traffic onto a black hole.
func (s TunnelState) counts() bool { return s == Ready || s == Active }

// tunnelSeq issues globally unique tunnel ids.
//
// Per-pool counters would restart at 1 in every isolation context, so two
// contexts would both hold "tunnel 1" -- a collision that means nothing to the
// code and everything to whoever is reading a log or a shared table.
var tunnelSeq atomic.Uint64

func nextTunnelID() uint64 { return tunnelSeq.Add(1) }

// Direction separates the two halves of a pool.
type Direction uint8

const (
	Inbound Direction = iota
	Outbound
)

func (d Direction) String() string {
	if d == Inbound {
		return "inbound"
	}
	return "outbound"
}

// Tunnel is one built path.
type Tunnel struct {
	ID    uint64
	Dir   Direction
	Guard RelayID
	// Hops are hops 2..n. Hop 1 is Guard and is NOT in here, so there is no way
	// to express a tunnel whose first hop is something else.
	Hops    []RelayID
	State   TunnelState
	Built   time.Time
	Misses  int
	Tries   int
	streams int
	// rebuildAt is this tunnel's OWN rebuild trigger as a fraction of the
	// lifetime: params.TunnelRebuildAt minus U(0, RotationJitter) of it (M5).
	//
	// It is drawn ONCE, at construction, and stored. Two mistakes it forecloses:
	// drawing it on every Tick would make the trigger a per-tick coin flip
	// rather than a jittered deadline, and sharing one draw across the pool
	// would leave the whole pool phase-locked to itself, which is most of the
	// signal M5 exists to remove.
	rebuildAt float64
}

// Age is how long the tunnel has been built.
func (t *Tunnel) Age(now time.Time) time.Duration { return now.Sub(t.Built) }

// RebuildFraction is the jittered trigger point, exposed for tests and metrics.
func (t *Tunnel) RebuildFraction() float64 { return t.rebuildAt }

// Pool is one isolation context's inbound and outbound tunnels.
type Pool struct {
	mu sync.Mutex

	guards *GuardSet
	now    func() time.Time

	in, out []*Tunnel

	// degraded is raised when either half falls below PoolMinReady.
	degraded bool

	// jitter returns a uniform float in [0,1) for M5's rebuild jitter. Nil
	// means crypto/rand. Injectable only so a test can pin a schedule.
	jitter func() float64
}

// drawRebuildAt is M5: params.TunnelRebuildAt jittered DOWNWARD by up to
// RotationJitter of itself.
//
// Downward, not symmetric. Jittering upward would push some tunnels past the
// point at which a replacement can still be built and probed before expiry --
// the 180 s that TunnelRebuildAt leaves is sized for the FAILURE case, five
// attempts under 1-2-4-8-16 s backoff, and eating into it converts a phase-lock
// fix into a rebuild-failure regression.
func (p *Pool) drawRebuildAt() float64 {
	u := p.jitter
	if u == nil {
		u = cryptoUniform
	}
	return params.TunnelRebuildAt * (1 - params.RotationJitter*u())
}

// cryptoUniform draws from crypto/rand. A predictable rotation schedule is a
// per-client identifier at the guard, which is the defect M5 repairs; a
// seedable PRNG here would repair it only against an observer who cannot guess
// the seed.
func cryptoUniform() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("axon/tunnel: crypto/rand unavailable: " + err.Error())
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(1<<53)
}

// Builder builds a tunnel starting at a given guard. Supplied by the caller so
// this package never learns how a circuit is constructed.
//
// The guard is an ARGUMENT, not a return value: a builder cannot choose its own
// first hop, which is R1 enforced by the signature.
type Builder func(dir Direction, guard RelayID) ([]RelayID, error)

// NewPool builds an empty pool for a context.
func NewPool(g *GuardSet, now func() time.Time) *Pool {
	if now == nil {
		now = time.Now
	}
	return &Pool{guards: g, now: now}
}

// Context is the isolation context.
func (p *Pool) Context() string { return p.guards.Context() }

// Degraded reports whether either half is below the ready floor.
func (p *Pool) Degraded() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.degraded
}

func (p *Pool) half(d Direction) []*Tunnel {
	if d == Inbound {
		return p.in
	}
	return p.out
}

func (p *Pool) setHalf(d Direction, ts []*Tunnel) {
	if d == Inbound {
		p.in = ts
	} else {
		p.out = ts
	}
}

// Target is how many tunnels a half wants: the working set plus its spares.
//
// The spares are PAR-10: built ahead so a first request never pays a cold
// build. A pool that builds on demand makes the user's first action the slowest
// one they will ever take.
func Target() int { return params.OutboundPoolSize + params.PoolSpares }

// Fill builds toward the target for one half.
//
// Every build starts at a pinned guard, obtained from the guard set. If no
// primary is usable the fill FAILS -- it does not select a substitute (E7.4).
func (p *Pool) Fill(d Direction, b Builder) error {
	for {
		p.mu.Lock()
		live := 0
		for _, t := range p.half(d) {
			if t.State != Dead && t.State != Failed {
				live++
			}
		}
		p.mu.Unlock()
		if live >= Target() {
			return nil
		}

		guard, err := p.guards.Usable()
		if err != nil {
			// Hard failure. NOT a signal to pick a different first hop.
			return err
		}
		hops, err := b(d, guard)
		if err != nil {
			p.noteBuildFailure(d)
			return err
		}

		p.mu.Lock()
		p.setHalf(d, append(p.half(d), &Tunnel{
			ID: nextTunnelID(), Dir: d, Guard: guard, Hops: hops,
			State: Ready, Built: p.now(), rebuildAt: p.drawRebuildAt(),
		}))
		p.recomputeLocked()
		p.mu.Unlock()
	}
}

func (p *Pool) noteBuildFailure(d Direction) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recomputeLocked()
}

// Get returns a tunnel to carry the next message.
//
// T7.6: exhaustion is a STATED FAILURE, not a hang. There is no blocking wait
// here and no retry loop -- a caller that cannot get a tunnel is told so and
// decides, because a pool that blocks turns a routing problem into an
// application hang with no diagnosis.
func (p *Pool) Get(d Direction) (*Tunnel, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var best *Tunnel
	for _, t := range p.half(d) {
		if !t.State.counts() {
			continue
		}
		// Prefer the least-loaded, then the youngest: spreading streams keeps
		// any one tunnel's death from taking everything with it.
		if best == nil || t.streams < best.streams ||
			(t.streams == best.streams && t.Built.After(best.Built)) {
			best = t
		}
	}
	if best == nil {
		return nil, fmt.Errorf("%w: %s half of %q has no ready tunnel",
			ErrPoolExhausted, d, p.guards.Context())
	}
	best.State = Active
	best.streams++
	return best, nil
}

// Release decrements a tunnel's stream count.
func (p *Pool) Release(id uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, half := range [][]*Tunnel{p.in, p.out} {
		for _, t := range half {
			if t.ID == id && t.streams > 0 {
				t.streams--
			}
		}
	}
}

// Tick advances the state machine: expiry, build-ahead and probe accounting.
func (p *Pool) Tick() (toBuild []Direction) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()

	for _, d := range []Direction{Inbound, Outbound} {
		planned := 0
		for _, t := range p.half(d) {
			age := t.Age(now)
			switch t.State {
			case Ready, Active:
				if age >= params.TunnelLifetime {
					t.State = Expiring
				} else if float64(age) >= t.rebuildAt*float64(params.TunnelLifetime) {
					// Build-ahead: plan a replacement, but the tunnel keeps
					// carrying what it already has.
					planned++
				}
			case Expiring:
				// An EXPIRING tunnel is NEVER extended past its lifetime, even
				// mid-stream. §9.8 moves the stream; the tunnel dies on time.
				if age >= params.TunnelLifetime {
					t.State = Dead
				}
			case Suspect:
				if t.Misses >= params.TunnelProbeMisses {
					// SUSPECT -> DEAD triggers an IMMEDIATE replacement, not
					// one deferred to the 70 % trigger.
					t.State = Dead
					planned++
				}
			}
		}
		if planned > 0 {
			toBuild = append(toBuild, d)
		}
	}
	p.reapLocked()
	p.recomputeLocked()
	return toBuild
}

// MissProbe records an unanswered liveness probe (PAR-25).
func (p *Pool) MissProbe(id uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, half := range [][]*Tunnel{p.in, p.out} {
		for _, t := range half {
			if t.ID != id {
				continue
			}
			t.Misses++
			if t.Misses >= params.TunnelProbeMisses && t.State.counts() {
				t.State = Suspect
			}
		}
	}
	p.recomputeLocked()
}

// AnswerProbe restores a suspect tunnel.
func (p *Pool) AnswerProbe(id uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, half := range [][]*Tunnel{p.in, p.out} {
		for _, t := range half {
			if t.ID == id {
				t.Misses = 0
				if t.State == Suspect {
					t.State = Active
				}
			}
		}
	}
	p.recomputeLocked()
}

// Kill forces a tunnel dead, for tests and for a received DESTROY.
func (p *Pool) Kill(id uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, half := range [][]*Tunnel{p.in, p.out} {
		for _, t := range half {
			if t.ID == id {
				t.State = Dead
			}
		}
	}
	p.reapLocked()
	p.recomputeLocked()
}

func (p *Pool) reapLocked() {
	for _, d := range []Direction{Inbound, Outbound} {
		kept := p.half(d)[:0]
		for _, t := range p.half(d) {
			if t.State != Dead {
				kept = append(kept, t)
			}
		}
		p.setHalf(d, kept)
	}
}

// recomputeLocked updates the DEGRADED signal.
//
// DEGRADED means the session layer STOPS OPENING NEW STREAMS rather than
// opening them all onto the single survivor. Concentrating a destination's
// whole traffic on one tunnel is worse than refusing to grow, because it turns
// one relay into the whole conversation.
func (p *Pool) recomputeLocked() {
	for _, d := range []Direction{Inbound, Outbound} {
		n := 0
		for _, t := range p.half(d) {
			if t.State.counts() {
				n++
			}
		}
		if n < params.PoolMinReady {
			p.degraded = true
			return
		}
	}
	p.degraded = false
}

// Tunnels returns a copy of one half, for tests and diagnostics.
func (p *Pool) Tunnels(d Direction) []Tunnel {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Tunnel, 0, len(p.half(d)))
	for _, t := range p.half(d) {
		out = append(out, *t)
	}
	return out
}
