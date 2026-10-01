package rendez

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/session"
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
	// Grace is how long a service circuit is held after its client side drops
	// (§9.8 case A). Zero means params.SessionCarrierGrace.
	Grace time.Duration
	// Now is the clock; nil means time.Now. Tests set it.
	Now func() time.Time

	mu sync.Mutex
	// byCookie holds established client circuits awaiting a service.
	byCookie map[Cookie]*Pending
	// used is the replay guard. A cookie is single-use: once spliced or torn
	// down it may never establish again, or a second service leg could be
	// joined to a client that has moved on (T6.4).
	used map[Cookie]struct{}
	// joined holds spliced pairs by their client circuit, and held the pairs
	// whose client side has dropped, by the commitment that may reclaim them.
	joined map[CircuitRef]*Joined
	held   map[[32]byte]*Joined
	// bySvc indexes joined by the service circuit: Peer runs once per cell.
	bySvc map[CircuitRef]*Joined
}

// NewRendezvousPoint builds an empty RP.
func NewRendezvousPoint() *RendezvousPoint {
	return &RendezvousPoint{byCookie: map[Cookie]*Pending{}, used: map[Cookie]struct{}{},
		joined: map[CircuitRef]*Joined{}, held: map[[32]byte]*Joined{}, bySvc: map[CircuitRef]*Joined{}}
}

func (rp *RendezvousPoint) now() time.Time {
	if rp.Now != nil {
		return rp.Now()
	}
	return time.Now()
}

func (rp *RendezvousPoint) grace() time.Duration {
	if rp.Grace > 0 {
		return rp.Grace
	}
	return params.SessionCarrierGrace
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
	j := &Joined{Client: p.Client, Service: service}
	rp.joined[p.Client] = j
	rp.bySvc[service] = j
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

// -----------------------------------------------------------------------------
// Session resumption at the RP (§9.8 case A)
// -----------------------------------------------------------------------------
//
// The common migration: the client's circuit to the RP died (rotation kills
// one every ten minutes by design) while the RP and the service's circuit are
// fine. Instead of a new introduction and rendezvous, the client builds a fresh
// circuit to the SAME RP and reclaims the service's circuit with a preimage it
// committed to earlier. Cost 6L; no descriptor, no intro point, no puzzle.
//
// What the RP holds for this is one 32-byte commitment and a counter per
// spliced pair, freed with the pair. The commitment is SHA256 of a secret only
// the two session ends can derive, so holding it tells the RP nothing it can
// use until the client reveals the preimage -- at which moment the commitment
// is burned and the client registers the next one.

var (
	ErrNotJoined      = errors.New("axon/rendez: circuit is not a spliced client circuit")
	ErrResumeCounter  = errors.New("axon/rendez: resume counter is not newer than the registered one")
	ErrResumeRefused  = errors.New("axon/rendez: no held circuit answers that resume")
	ErrResumeNotFresh = errors.New("axon/rendez: resume must arrive on a circuit with no other role")
)

// Joined is the RP's state for a spliced pair: two circuit refs, the newest
// resume commitment and its counter, and when the client side dropped. Like
// Pending, it has nowhere to put an address or a key.
type Joined struct {
	Client    CircuitRef
	Service   CircuitRef
	Counter   uint32
	Commit    [32]byte
	HasCommit bool
	// ClientLostAt is zero while the client side is up.
	ClientLostAt time.Time
}

// RegisterResume records RESUME_REGISTER from a spliced client circuit. Only
// the newest commitment is kept, and its counter must exceed the last one, so
// a replayed registration cannot roll the pair back to a burned commitment.
func (rp *RendezvousPoint) RegisterResume(client CircuitRef, counter uint32, commit [32]byte) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	j, ok := rp.joined[client]
	if !ok {
		return ErrNotJoined
	}
	if j.HasCommit && counter <= j.Counter {
		return ErrResumeCounter
	}
	j.Counter, j.Commit, j.HasCommit = counter, commit, true
	return nil
}

// ClientLost reports that a spliced pair's client circuit died. If the client
// registered a commitment the service circuit is HELD for the grace window and
// keep is true -- the caller must not destroy it. Otherwise keep is false and
// the caller tears the service circuit down as before.
func (rp *RendezvousPoint) ClientLost(client CircuitRef) (service CircuitRef, keep bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	j, ok := rp.joined[client]
	if !ok {
		return 0, false
	}
	delete(rp.joined, client)
	if !j.HasCommit {
		delete(rp.bySvc, j.Service)
		return j.Service, false
	}
	j.ClientLostAt = rp.now()
	rp.held[j.Commit] = j
	return j.Service, true
}

// ServiceLost reports that a spliced pair's service circuit died; the client
// circuit is returned for teardown. A held pair whose service side dies is
// simply dropped. The client finds out when its RESUME_RENDEZVOUS is refused
// and falls back to case B -- the RP has nothing better to offer it.
func (rp *RendezvousPoint) ServiceLost(service CircuitRef) (client CircuitRef, ok bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	j, ok := rp.bySvc[service]
	if !ok {
		return 0, false
	}
	delete(rp.bySvc, service)
	if j.ClientLostAt.IsZero() {
		delete(rp.joined, j.Client)
		return j.Client, true
	}
	delete(rp.held, j.Commit)
	return 0, false
}

// Resume answers RESUME_RENDEZVOUS on a fresh client circuit: hash the
// preimage with the counter, find the held pair, splice, BURN the commitment.
//
// Every refusal is the same error, deliberately: a prober learns only that its
// guess was wrong, not whether a pair exists, has expired, or wanted another
// counter.
func (rp *RendezvousPoint) Resume(newClient CircuitRef, counter uint32, preimage [32]byte) (CircuitRef, error) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if _, busy := rp.joined[newClient]; busy {
		return 0, ErrResumeNotFresh
	}
	commit := session.ResumeCommit(preimage, counter)
	j, ok := rp.held[commit]
	if !ok || j.Counter != counter {
		return 0, ErrResumeRefused
	}
	delete(rp.held, commit) // burned: one use, whatever happens next
	if rp.now().Sub(j.ClientLostAt) > rp.grace() {
		delete(rp.bySvc, j.Service)
		return 0, ErrResumeRefused
	}
	j.Client = newClient
	j.ClientLostAt = time.Time{}
	j.HasCommit = false
	j.Commit = [32]byte{}
	rp.joined[newClient] = j
	return j.Service, nil
}

// Expire frees every held pair past its grace window and returns their service
// circuits for the caller to DESTROY.
func (rp *RendezvousPoint) Expire() []CircuitRef {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	var out []CircuitRef
	now := rp.now()
	for k, j := range rp.held {
		if now.Sub(j.ClientLostAt) > rp.grace() {
			out = append(out, j.Service)
			delete(rp.held, k)
			delete(rp.bySvc, j.Service)
		}
	}
	return out
}

// Held is how many service circuits the RP is holding for a resume.
func (rp *RendezvousPoint) Held() int {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return len(rp.held)
}

// Peer is the circuit spliced to the given one, in either direction: what the
// RP forwards a SESSION cell onto.
func (rp *RendezvousPoint) Peer(c CircuitRef) (CircuitRef, bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if j, ok := rp.joined[c]; ok {
		return j.Service, true
	}
	if j, ok := rp.bySvc[c]; ok && j.ClientLostAt.IsZero() {
		return j.Client, true
	}
	return 0, false
}
