package intro

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// IntroPoint is the verifying side. §23.6's `(*IntroPoint).Verify`.
type IntroPoint struct {
	scheme  Scheme
	kBlind  []byte
	seed    [32]byte
	prev    [32]byte
	hasPrev bool
	ctrl    *Controller
	queue   *Queue
}

// Config is what an intro point needs to exist.
type Config struct {
	// Scheme is the proof of work. Required.
	Scheme Scheme
	// KBlind binds challenges to this service.
	KBlind []byte
	// QueueCap bounds pending introductions.
	QueueCap int
	// AllowNonMemoryHardScheme permits a Scheme whose MemoryHard() is false.
	//
	// IT EXISTS TO BE GREPPABLE. §9.6's requirement (2) is that solving be
	// memory-hard, because a CPU-only puzzle hands a GPU or ASIC adversary a
	// two-to-three order-of-magnitude advantage over a phone and becomes
	// "targeted exclusion of exactly the users who most need the service". A
	// non-memory-hard scheme is therefore a TEST FIXTURE, and reaching for one
	// has to be a deliberate, searchable act rather than a default nobody
	// revisits.
	AllowNonMemoryHardScheme bool
}

// New builds an intro point, refusing configurations that cannot be safe.
func New(cfg Config) (*IntroPoint, error) {
	if cfg.Scheme == nil {
		return nil, ErrNoScheme
	}
	if !cfg.Scheme.MemoryHard() && !cfg.AllowNonMemoryHardScheme {
		return nil, fmt.Errorf("%w: %q", ErrNotMemoryHard, cfg.Scheme.Name())
	}
	ip := &IntroPoint{
		scheme: cfg.Scheme,
		kBlind: append([]byte(nil), cfg.KBlind...),
		ctrl:   NewController(),
		queue:  NewQueue(cfg.QueueCap),
	}
	if err := ip.RotateSeed(); err != nil {
		return nil, err
	}
	return ip, nil
}

// Puzzle is what to publish, and what a client solves against.
func (ip *IntroPoint) Puzzle() Puzzle {
	return Puzzle{
		Seed:       ip.seed,
		Difficulty: ip.ctrl.Difficulty(),
		SchemeName: ip.scheme.Name(),
	}
}

// RotateSeed draws a new seed. §23.6: every IntroPointRecord republish, 10 min,
// "so a solution bank has a 10-minute shelf life".
//
// THE PREVIOUS SEED IS NOT ACCEPTED AFTERWARDS. Keeping a grace window would be
// the natural kindness -- a client that solved just before rotation has wasted
// its work -- and it would double the shelf life of a precomputed bank, which is
// the entire quantity the rotation controls. The client re-solves; T6a.2 asserts
// the refusal.
func (ip *IntroPoint) RotateSeed() error {
	if _, err := rand.Read(ip.seed[:]); err != nil {
		return err
	}
	ip.hasPrev = true
	return nil
}

// Verify checks a solution and returns the verified effort.
//
// NO ASYMMETRIC CRYPTOGRAPHY HAPPENS HERE OR BELOW IT (T6a.4). The intro point
// must be able to reject a flood using only hashes, because an intro point that
// did a key exchange before checking the puzzle would be performing the
// attacker's chosen work at the attacker's chosen rate -- which is the attack,
// not the defence.
func (ip *IntroPoint) Verify(sol Solution) (uint64, error) {
	return Verify(ip.scheme, ip.Puzzle(), ip.kBlind, sol)
}

// Admit verifies a solution and queues it by effort.
func (ip *IntroPoint) Admit(sol Solution, payload []byte) error {
	effort, err := ip.Verify(sol)
	if err != nil {
		return err
	}
	if !ip.queue.Push(Admission{Effort: effort, Payload: payload}) {
		return errors.New("axon/intro: queue is full and the offered effort did not beat the lowest waiting")
	}
	return nil
}

// Next takes the highest-effort pending introduction.
func (ip *IntroPoint) Next() (Admission, bool) { return ip.queue.Pop() }

// Depth is the load figure the intro point REPORTS to the service (§9.6). It
// does not act on it: see conflict (1) in the package comment.
func (ip *IntroPoint) Depth() int { return ip.queue.Len() }

// Tick applies the service's controller decision.
func (ip *IntroPoint) Tick(serviceQueueDepth int) { ip.ctrl.Tick(serviceQueueDepth) }

// Solve is the client side. §23.6's `(*Client).Solve`.
//
// It searches nonces until one satisfies both the scheme and the effort dial.
// The cost is the client's; that is the point.
func Solve(s Scheme, p Puzzle, kBlind []byte, maxNonce uint32) (Solution, error) {
	if s == nil {
		return Solution{}, ErrNoScheme
	}
	effort := EffortOf(p.Difficulty)
	for nonce := uint32(0); nonce < maxNonce; nonce++ {
		ch := Challenge(p.Seed, kBlind, effort, nonce)
		proof, err := s.Solve(ch)
		if err != nil {
			continue
		}
		if !meetsEffort(ch, proof, effort) {
			continue
		}
		return Solution{Nonce: nonce, Proof: proof, Effort: effort}, nil
	}
	return Solution{}, errors.New("axon/intro: no solution within the nonce budget")
}
