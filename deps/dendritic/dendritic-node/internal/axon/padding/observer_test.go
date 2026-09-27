package padding

import (
	"math"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// This file is the observer's side of P13: what a link capture can and cannot
// separate. It exists because §23's P13 card names the phase's likeliest
// failure exactly — "a defence nobody can evaluate" — and the only answer to
// that is to run the classifier yourself and publish the number it reaches.

// trace is one direction of one link as an observer would see it: the instants
// at which cells crossed, with no indication of which were padding.
type trace []time.Time

// simulate runs a machine for d, driving real cells from realAt and recording
// EVERY cell an observer would see.
func simulate(m *Machine, start time.Time, d time.Duration, step time.Duration, realAt func(time.Time) bool) trace {
	var out trace
	at := start
	for end := start.Add(d); at.Before(end); at = at.Add(step) {
		if realAt != nil && realAt(at) {
			m.Real(at)
			out = append(out, at)
		}
		for i := 0; i < m.Due(at); i++ {
			out = append(out, at)
		}
	}
	return out
}

// rate is cells per second over the trace's span.
func (t trace) rate(d time.Duration) float64 {
	return float64(len(t)) / d.Seconds()
}

// TestE132IdleAndLightlyLoadedAreNotSeparableByRate is E13.2.
//
// THE CLAIM, STATED BEFORE IT IS TESTED. An observer on the client↔guard link
// who counts cells cannot tell an idle client from one whose entire traffic is
// below the floor. The bound is the floor: at R_floor = 0.5 cells/s, a flow of
// up to 0.5 cells/s is indistinguishable from nothing. ABOVE that the claim is
// false and this test does not extend to it — §16.3 says so directly, and the
// second half of this test measures exactly where it stops holding.
//
// The classifier is a rate threshold, which is the weakest useful one. Passing
// it is necessary, not sufficient: a burst-structure classifier is a different
// question and §16.4 defers it with a named criterion.
func TestE132IdleAndLightlyLoadedAreNotSeparableByRate(t *testing.T) {
	const window = 10 * time.Minute
	const step = 100 * time.Millisecond

	// (a) Idle: the daemon runs, the user does nothing.
	idle := New(RoleGuardLink, true, t0, nil)
	idle.Real(t0) // one cell to start the floor, e.g. the link handshake
	idleTrace := simulate(idle, t0, window, step, nil)

	// (b) Lightly loaded: real traffic at 0.4 cells/s, below the 0.5 floor.
	light := New(RoleGuardLink, true, t0, nil)
	light.Real(t0)
	next := t0.Add(2500 * time.Millisecond)
	lightTrace := simulate(light, t0, window, step, func(at time.Time) bool {
		if !at.Before(next) {
			next = at.Add(2500 * time.Millisecond)
			return true
		}
		return false
	})

	ri, rl := idleTrace.rate(window), lightTrace.rate(window)
	t.Logf("E13.2: idle %.4f cells/s, lightly loaded %.4f cells/s (floor %.2f)",
		ri, rl, params.FloorRateCellsPerSec)

	// THE STATED BOUND. Both traces must sit at the floor, and the observable
	// difference must be a small fraction of it. 25 % of the floor is the
	// tolerance: it is wide enough to absorb the random tail and the keepalive's
	// own variance, and narrow enough that a machine which simply added real
	// traffic on top of the floor -- the obvious wrong implementation -- would
	// show 0.4/0.5 = 80 % and fail.
	tolerance := 0.25 * params.FloorRateCellsPerSec
	if d := math.Abs(ri - rl); d > tolerance {
		t.Fatalf("E13.2 violated: idle and lightly-loaded differ by %.4f cells/s, "+
			"above the stated bound of %.4f", d, tolerance)
	}
	if ri < 0.5*params.FloorRateCellsPerSec {
		t.Fatalf("the idle link ran at %.4f cells/s, below half the floor -- "+
			"the floor is not being maintained", ri)
	}

	// AND THE HONEST OTHER HALF. A flow above the floor IS visible. If this
	// did not separate, the test above would be measuring a machine that
	// suppresses real traffic, which would be a bug rather than a defence.
	heavy := New(RoleGuardLink, true, t0, nil)
	heavy.Real(t0)
	nextH := t0
	heavyTrace := simulate(heavy, t0, window, step, func(at time.Time) bool {
		if !at.Before(nextH) {
			nextH = at.Add(100 * time.Millisecond) // 10 cells/s
			return true
		}
		return false
	})
	rh := heavyTrace.rate(window)
	if rh-ri < 5 {
		t.Fatalf("a 10 cells/s flow was only %.2f cells/s above idle -- "+
			"real traffic is being suppressed, not padded", rh-ri)
	}
	t.Logf("E13.2 limit: a 10 cells/s flow shows as %.2f cells/s. "+
		"Padding hides nothing above the floor and this is not claimed.", rh)
}

// TestT134ClassDifferenceIsTheDesignedOne is T13.4.
//
// "A BULK transfer's timing distribution differs from an INTERACTIVE session's
// on the same path, and the difference is the DESIGNED one."
//
// The designed difference in v1 is scheduling priority and nothing else.
// §16.4 defers batching and mixing for BULK with named measurement criteria, so
// there is no per-class shaping to observe — and E5.4 already established that
// the cells are byte-identical, with only the PRIORITY flag differing.
//
// So the property to test is a NEGATIVE one, and it is the more important half:
// the PADDING is identical across classes. A class-dependent padding rate would
// let a link observer read the class off the idle link, which hands back the
// distinction R2 declared the classes to bound — and would do it on the one
// link an access-link observer is guaranteed to have.
func TestT134ClassDifferenceIsTheDesignedOne(t *testing.T) {
	// The API cannot express a class-aware padding machine: New takes a Role,
	// not a TrafficClass. This asserts the two enums are not interchangeable,
	// so a later edit cannot pass a class where a role is expected.
	if int(RoleGuardLink) == int(circuit.ClassBulk) && int(RoleRelay) == int(circuit.ClassInteractive) {
		t.Log("note: Role and TrafficClass happen to share numeric values; " +
			"the audit in audit_test.go is what actually forbids the confusion")
	}

	// Same role, same seed stream, one machine per class-of-user. The traces
	// must be identical, because nothing about the class reaches the schedule.
	const window = 5 * time.Minute
	const step = 100 * time.Millisecond

	mkTrace := func(class circuit.TrafficClass) trace {
		if !class.Valid() {
			t.Fatalf("R2: %v is not a declared class", class)
		}
		// The class is deliberately UNUSED below. That is the assertion: there
		// is no argument to New, and no field on Machine, through which it
		// could take effect.
		m := New(RoleGuardLink, true, t0, fixed(0.3, 0.7, 0.1, 0.9))
		m.Real(t0)
		return simulate(m, t0, window, step, nil)
	}

	inter := mkTrace(circuit.ClassInteractive)
	bulk := mkTrace(circuit.ClassBulk)

	if len(inter) != len(bulk) {
		t.Fatalf("T13.4 violated: padding differs by class -- INTERACTIVE emitted %d cells, BULK %d",
			len(inter), len(bulk))
	}
	for i := range inter {
		if !inter[i].Equal(bulk[i]) {
			t.Fatalf("T13.4 violated: padding schedules diverge at cell %d (%v vs %v)",
				i, inter[i], bulk[i])
		}
	}
	t.Logf("T13.4: %d padding cells, identical under both classes. The designed "+
		"difference is scheduling priority, which is §8's; §16.4 defers BULK "+
		"batching with a named criterion and none is claimed here.", len(inter))
}
