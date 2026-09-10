package gateway

import (
	"strings"
	"sync"
	"time"
)

// OriginHealth decides when this gateway should stop asking the origin and
// start serving its snapshot — and, harder, when to go back.
//
// WHY NOT JUST "THE LAST REQUEST FAILED"
// --------------------------------------
// Because one timeout is not an outage. A single dropped connection, a TLS
// renegotiation, one slow upstream — flipping the whole site to a read-only
// hour-old copy over any of those would turn a blip into an incident, and the
// reader would see posting disabled for no reason they could observe.
//
// So entering emergency mode needs a THRESHOLD of failures inside a WINDOW,
// and — from the specification — more than one KIND of failure. Requiring two
// distinct kinds is the cheap discriminator between "the origin is down" and
// "one thing is flaky": a genuine outage produces refused connections and
// timeouts and gateway errors, while a flaky link produces the same failure
// over and over.
//
// COMING BACK IS THE DANGEROUS DIRECTION
// --------------------------------------
// Leaving emergency mode too eagerly is worse than entering it too slowly. The
// origin that just came up is the weakest it will ever be, and every gateway
// returning at once is a thundering herd that puts it straight back down. So
// recovery needs consecutive successes over a minimum time, and then a random
// delay before this gateway actually returns — so a fleet does not return in
// unison.
type OriginHealth struct {
	// FailureThreshold distinct failures before emergency mode.
	FailureThreshold int
	// FailureWindow is how long failures are remembered.
	FailureWindow time.Duration
	// DistinctKinds required — the "is it really down" discriminator.
	DistinctKinds int
	// RecoverySuccesses consecutive successes before returning.
	RecoverySuccesses int
	// RecoveryWindow is the minimum time those successes must span.
	RecoveryWindow time.Duration
	// RecoveryJitter bounds the random delay before returning, so a fleet does
	// not stampede a just-recovered origin.
	RecoveryJitter time.Duration

	Now    func() time.Time
	Random func(int64) int64

	mu            sync.Mutex
	failures      []failure
	successes     int
	firstSuccess  time.Time
	emergency     bool
	returnAllowed time.Time
	forcedUntil   time.Time
}

type failure struct {
	at   time.Time
	kind string
}

// Failure kinds. Coarse on purpose: the point is to tell "several different
// things are wrong" from "the same thing keeps happening", not to catalogue
// every way a request can fail.
const (
	FailureDial    = "dial"
	FailureTimeout = "timeout"
	FailureTLS     = "tls"
	FailureStatus  = "status"
	FailureSlow    = "slow"
)

func NewOriginHealth() *OriginHealth {
	return &OriginHealth{
		FailureThreshold: 3, FailureWindow: 15 * time.Second, DistinctKinds: 2,
		RecoverySuccesses: 5, RecoveryWindow: 60 * time.Second,
		RecoveryJitter: 120 * time.Second,
		Now:            time.Now,
	}
}

// ClassifyError maps a transport error to a failure kind.
func ClassifyError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "tls") || strings.Contains(text, "certificate"):
		return FailureTLS
	case strings.Contains(text, "timeout") || strings.Contains(text, "deadline"):
		return FailureTimeout
	default:
		return FailureDial
	}
}

// ClassifyStatus maps an origin status code to a failure kind, or "" if fine.
func ClassifyStatus(code int) string {
	if code == 502 || code == 503 || code == 504 {
		return FailureStatus
	}
	return ""
}

// RecordFailure notes one failed origin request.
func (h *OriginHealth) RecordFailure(kind string) {
	if kind == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.failures = append(h.failures, failure{at: now, kind: kind})
	h.prune(now)
	// A failure interrupts a recovery run: five successes and a failure is not
	// a recovered origin, and counting it as one is how a gateway flaps.
	h.successes = 0
	h.firstSuccess = time.Time{}

	if h.emergency {
		return
	}
	kinds := map[string]bool{}
	for _, entry := range h.failures {
		kinds[entry.kind] = true
	}
	if len(h.failures) >= h.FailureThreshold && len(kinds) >= h.DistinctKinds {
		h.emergency = true
		h.returnAllowed = time.Time{}
	}
}

// RecordSuccess notes one good origin request.
func (h *OriginHealth) RecordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.prune(now)
	if !h.emergency {
		h.successes = 0
		return
	}
	if h.successes == 0 {
		h.firstSuccess = now
	}
	h.successes++
	if h.successes < h.RecoverySuccesses {
		return
	}
	if now.Sub(h.firstSuccess) < h.RecoveryWindow {
		// Five successes in two seconds is not a minute of stability. Waiting
		// for the window is what stops a gateway returning during the brief
		// calm before an origin falls over again.
		return
	}
	if h.returnAllowed.IsZero() {
		h.returnAllowed = now.Add(h.jitter())
		return
	}
	if now.After(h.returnAllowed) {
		h.emergency = false
		h.successes = 0
		h.failures = nil
		h.returnAllowed = time.Time{}
	}
}

// Emergency reports whether the snapshot should be served.
func (h *OriginHealth) Emergency() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.forcedUntil.IsZero() && h.now().Before(h.forcedUntil) {
		return true
	}
	return h.emergency
}

// Force puts this gateway into emergency mode until a deadline, for a signed
// defensive-mode announcement.
//
// Bounded on purpose: a mode with no expiry is one that a lost control key
// leaves switched on forever, and "the site is permanently read-only because
// nobody can find the key" is a worse outage than the one it prevented.
func (h *OriginHealth) Force(until time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.forcedUntil = until
}

// State reports the current posture, for logs and the status endpoint.
func (h *OriginHealth) State() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case !h.forcedUntil.IsZero() && h.now().Before(h.forcedUntil):
		return "DEFENSIVE_MODE"
	case h.emergency:
		return "EMERGENCY"
	case len(h.failures) > 0:
		return "DEGRADED"
	default:
		return "HEALTHY"
	}
}

func (h *OriginHealth) prune(now time.Time) {
	cutoff := now.Add(-h.FailureWindow)
	kept := h.failures[:0]
	for _, entry := range h.failures {
		if entry.at.After(cutoff) {
			kept = append(kept, entry)
		}
	}
	h.failures = kept
}

func (h *OriginHealth) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *OriginHealth) jitter() time.Duration {
	if h.RecoveryJitter <= 0 {
		return 0
	}
	if h.Random != nil {
		return time.Duration(h.Random(int64(h.RecoveryJitter)))
	}
	// Derived from the clock rather than math/rand so this stays usable in a
	// test that controls Now, and so no global generator is seeded here.
	return time.Duration(h.now().UnixNano() % int64(h.RecoveryJitter))
}
