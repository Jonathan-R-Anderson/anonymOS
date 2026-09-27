package dcs

import (
	"sync"
	"time"
)

// MemReplayGuard remembers nonces until they expire. Bounded by the envelope
// skew window (nonces past ExpiresAt cannot be replayed anyway), so the table
// stays small without a background sweeper: expired entries are dropped lazily
// on the next Accept that touches them.
type MemReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func NewMemReplayGuard() *MemReplayGuard {
	return &MemReplayGuard{seen: map[string]time.Time{}, now: time.Now}
}

// SetClock overrides the guard's clock. Used so the replay window uses the same
// notion of "now" as envelope verification -- a guard on a different clock
// would prune a valid nonce or keep an expired one.
func (g *MemReplayGuard) SetClock(now func() time.Time) { g.now = now }

// Accept returns false if the nonce was already seen within its validity
// window. A fresh nonce is recorded and returns true.
func (g *MemReplayGuard) Accept(nonce string, expires time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()

	// Opportunistic prune: cheap, and keeps the map from growing without an
	// extra goroutine to reason about.
	if len(g.seen) > 0 {
		for key, exp := range g.seen {
			if !exp.After(now) {
				delete(g.seen, key)
			}
		}
	}

	if exp, ok := g.seen[nonce]; ok && exp.After(now) {
		return false
	}
	g.seen[nonce] = expires
	return true
}
