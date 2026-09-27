package rendez

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// The two relays in the middle: the intro point and the rendezvous point.
//
// Both are deliberately ignorant. The IP knows an auth key and a circuit; the RP
// knows a cookie and two circuits. Neither struct has anywhere to put an address,
// which is how T6.1 and T6.2 are met by construction rather than by discipline.

// CircuitRef identifies a circuit at the relay holding it.
//
// It is an OPAQUE HANDLE, not an address. The type exists so that neither point
// can accidentally be given a `netip.Addr` -- there is no field of that type
// anywhere in this package, and E6.4 is checked against that.
type CircuitRef uint64

// -----------------------------------------------------------------------------
// Intro point
// -----------------------------------------------------------------------------

// PuzzleVerifier checks an INTRODUCE1 admission proof (R10).
//
// The puzzle itself is P6a / PAR-16 and is NOT built here. This interface is the
// seam: the IP must be able to reject before doing any work, and that decision
// has to be somebody's, so it is named rather than inlined.
type PuzzleVerifier interface {
	// Verify reports whether the proof admits this introduction. It must be
	// cheap: it runs before anything else, on every INTRODUCE1, including the
	// flood.
	Verify(authKey [32]byte, proof []byte) error
	// Required reports whether a proof is currently demanded. A puzzle that is
	// always on taxes every honest client to defend against an attack that may
	// not be happening.
	Required() bool
}

// UnsafeNoPuzzle is the declared mode when no verifier is configured.
//
// R10 REQUIRES INTRODUCE1 to be rate-limited by a puzzle or token. Running
// without one is permitted while P6a is unbuilt, and it is a known-unsafe mode
// rather than a default: the IP still rate-limits, but a flood costs the
// attacker nothing but bandwidth.
const UnsafeNoPuzzle = "no-intro-puzzle: INTRODUCE1 admission is rate-limited only (R10 unmet until P6a)"

// IntroPoint is a relay hosting introductions for services.
type IntroPoint struct {
	Puzzle PuzzleVerifier
	// Limit is the per-auth-key admission budget. A nil Limiter admits
	// everything, which is only sane in tests.
	Limit *RateLimiter

	mu sync.Mutex
	// circuits maps an auth key to the service's intro circuit. That is the
	// ENTIRE contents: an IP that held anything else could answer questions it
	// should not be able to answer.
	circuits map[[authKeySize]byte]CircuitRef
}

// NewIntroPoint builds an empty intro point.
func NewIntroPoint() *IntroPoint {
	return &IntroPoint{circuits: map[[authKeySize]byte]CircuitRef{}}
}

// UnsafeModes lists the known-unsafe modes this point is running in.
func (ip *IntroPoint) UnsafeModes() []string {
	if ip.Puzzle == nil || !ip.Puzzle.Required() {
		return []string{UnsafeNoPuzzle}
	}
	return nil
}

// Establish registers a service's intro circuit under its auth key.
func (ip *IntroPoint) Establish(authKey [authKeySize]byte, c CircuitRef) {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	ip.circuits[authKey] = c
}

// Teardown removes a registration.
func (ip *IntroPoint) Teardown(authKey [authKeySize]byte) {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	delete(ip.circuits, authKey)
}

// Admit decides whether to forward an INTRODUCE1, and returns the circuit to
// forward it on.
//
// ORDER IS THE WHOLE POINT (T6.3). The puzzle is checked FIRST, before the map
// lookup, before the rate accounting, and before anything touches a circuit. An
// implementation that looked up the circuit first would do work proportional to
// the flood, which is the attack the puzzle exists to price.
func (ip *IntroPoint) Admit(msg *Introduce1) (CircuitRef, AckStatus, error) {
	if ip.Puzzle != nil && ip.Puzzle.Required() {
		if len(msg.PuzzleProof) == 0 {
			return 0, AckPuzzleRequired, ErrPuzzleRequired
		}
		if err := ip.Puzzle.Verify(msg.AuthKeyID, msg.PuzzleProof); err != nil {
			return 0, AckPuzzleRequired, fmt.Errorf("%w: %v", ErrPuzzleInvalid, err)
		}
	}
	if ip.Limit != nil && !ip.Limit.Allow(msg.AuthKeyID) {
		return 0, AckRateLimited, ErrRateLimited
	}

	ip.mu.Lock()
	c, ok := ip.circuits[msg.AuthKeyID]
	ip.mu.Unlock()
	if !ok {
		return 0, AckUnknownAuthKey, ErrUnknownAuthKey
	}
	return c, AckOK, nil
}

// Forward produces the INTRODUCE2 body: the INTRODUCE1 verbatim plus the IP's
// verdict.
//
// VERBATIM is load-bearing. An IP that re-encoded the message could alter the
// header the encryption binds as AAD; forwarding the bytes it received means any
// tampering shows up as a decryption failure at the service rather than as a
// redirected introduction.
func (ip *IntroPoint) Forward(msg *Introduce1, verdict AckStatus) *Introduce2 {
	return &Introduce2{Intro: msg, Verdict: verdict}
}

// Introduce2 is what the IP sends the service.
type Introduce2 struct {
	Intro   *Introduce1
	Verdict AckStatus
}

// RateLimiter is a per-auth-key token bucket.
type RateLimiter struct {
	Rate  float64 // tokens per second
	Burst float64
	Now   func() time.Time

	mu      sync.Mutex
	buckets map[[authKeySize]byte]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter builds a limiter.
func NewRateLimiter(rate, burst float64, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{Rate: rate, Burst: burst, Now: now,
		buckets: map[[authKeySize]byte]*bucket{}}
}

// Allow consumes one token for an auth key.
func (l *RateLimiter) Allow(k [authKeySize]byte) bool {
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[k]
	if !ok {
		b = &bucket{tokens: l.Burst, last: now}
		l.buckets[k] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.Rate
	if b.tokens > l.Burst {
		b.tokens = l.Burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// -----------------------------------------------------------------------------
// Rendezvous point
// -----------------------------------------------------------------------------

var ErrCookieInUse = errors.New("axon/rendez: cookie is already established")

// Pending is the RP's entire per-rendezvous state.
//
// T6.2: two circuit ids and a cookie, NOTHING MORE. There is no address field,
// no service identity, no key material, and no timestamped log of who asked --
// the struct is the audit. E6.4 serialises it and checks.
type Pending struct {
	Cookie  Cookie
	Client  CircuitRef
	Service CircuitRef
	Spliced bool
}

// RendezvousPoint joins two circuits that present the same cookie.
type RendezvousPoint struct {
	mu sync.Mutex
	// byCookie holds established client circuits awaiting a service.
	byCookie map[Cookie]*Pending
	// used is the replay guard. A cookie is single-use: once spliced or torn
	// down it may never establish again, or a second service leg could be
	// joined to a client that has moved on (T6.4).
	used map[Cookie]struct{}
}

// NewRendezvousPoint builds an empty RP.
func NewRendezvousPoint() *RendezvousPoint {
	return &RendezvousPoint{byCookie: map[Cookie]*Pending{}, used: map[Cookie]struct{}{}}
}

// Establish records a client circuit under its cookie.
func (rp *RendezvousPoint) Establish(c Cookie, client CircuitRef) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if _, spent := rp.used[c]; spent {
		return ErrReplay
	}
	if _, exists := rp.byCookie[c]; exists {
		return ErrCookieInUse
	}
	rp.byCookie[c] = &Pending{Cookie: c, Client: client}
	return nil
}

// Splice joins a service circuit to the client circuit holding the same cookie.
//
// The cookie is DROPPED at the join: once the two circuits are connected the
// cookie has no further use, and keeping it would leave the RP holding a token
// that links this pair for as long as the session lasts.
func (rp *RendezvousPoint) Splice(c Cookie, service CircuitRef) (CircuitRef, error) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if _, spent := rp.used[c]; spent {
		return 0, ErrReplay
	}
	p, ok := rp.byCookie[c]
	if !ok {
		return 0, ErrCookieUnknown
	}
	if p.Spliced {
		return 0, ErrAlreadySpliced
	}
	p.Service, p.Spliced = service, true
	// Single-use, from this moment.
	rp.used[c] = struct{}{}
	delete(rp.byCookie, c)
	return p.Client, nil
}

// Pending returns a copy of an outstanding entry, for tests and diagnostics.
func (rp *RendezvousPoint) Pending(c Cookie) (Pending, bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	p, ok := rp.byCookie[c]
	if !ok {
		return Pending{}, false
	}
	return *p, true
}

// Len is the number of outstanding rendezvous.
func (rp *RendezvousPoint) Len() int {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return len(rp.byCookie)
}
