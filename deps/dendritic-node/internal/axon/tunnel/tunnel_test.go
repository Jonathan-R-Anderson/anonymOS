package tunnel

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

func rid(n byte) RelayID { var r RelayID; r[0] = n; return r }

// ctx builds a guard set with two promoted primaries drawn from a sample.
func ctx(t *testing.T, name string, now func() time.Time, ids ...byte) *GuardSet {
	t.Helper()
	g := NewGuardSet(name, now)
	for i, b := range ids {
		if err := g.Sample(rid(b)); err != nil {
			t.Fatal(err)
		}
		if i < params.PrimaryGuards {
			if err := g.Promote(rid(b), GuardPrimary); err != nil {
				t.Fatal(err)
			}
		}
	}
	return g
}

// builder records every guard it was asked to start from.
func builder(seen *[]RelayID) Builder {
	return func(d Direction, guard RelayID) ([]RelayID, error) {
		*seen = append(*seen, guard)
		return []RelayID{rid(200), rid(201)}, nil
	}
}

// TestT71EveryTunnelBeginsAtAPinnedGuard is T7.1 and E7.2.
func TestT71EveryTunnelBeginsAtAPinnedGuard(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	g := ctx(t, "alice", clock, 1, 2, 3, 4, 5)
	p := NewPool(g, clock)

	var seen []RelayID
	b := builder(&seen)

	// E7.2 is 10^3 builds; the pool caps at Target(), so cycle tunnels through.
	builds := 0
	for builds < 1000 {
		if err := p.Fill(Outbound, b); err != nil {
			t.Fatal(err)
		}
		for _, tn := range p.Tunnels(Outbound) {
			p.Kill(tn.ID)
			builds++
		}
	}

	primaries := map[RelayID]bool{}
	for _, pr := range g.Primaries() {
		primaries[pr.ID] = true
	}
	if len(primaries) != params.PrimaryGuards {
		t.Fatalf("%d primaries, want %d", len(primaries), params.PrimaryGuards)
	}
	for i, guard := range seen {
		if !primaries[guard] {
			t.Fatalf("T7.1/E7.2 violated: build %d started at %x, not a pinned guard", i, guard[:4])
		}
	}
	t.Logf("E7.2: %d builds, all at one of %d pinned guards", len(seen), len(primaries))

	// And the type system helps: a Tunnel's Hops are hops 2..n, so there is no
	// way to express a tunnel whose first hop is not the guard.
	for _, tn := range p.Tunnels(Outbound) {
		for _, h := range tn.Hops {
			if h == tn.Guard {
				t.Fatal("the guard appears again in hops 2..n")
			}
		}
	}
}

// TestE74BothGuardsDownIsAHardFailure is E7.4.
//
// This is the rule that makes guards worth having: an adversary who can make a
// client's guards fail must NOT thereby choose the next one.
func TestE74BothGuardsDownIsAHardFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	g := ctx(t, "alice", clock, 1, 2, 3, 4, 5)
	p := NewPool(g, clock)

	var seen []RelayID
	if err := p.Fill(Outbound, builder(&seen)); err != nil {
		t.Fatal(err)
	}
	before := len(seen)

	for _, pr := range g.Primaries() {
		if err := g.MarkDown(pr.ID); err != nil {
			t.Fatal(err)
		}
	}
	for _, tn := range p.Tunnels(Outbound) {
		p.Kill(tn.ID)
	}

	err := p.Fill(Outbound, builder(&seen))
	if !errors.Is(err, ErrGuardHardFail) {
		t.Fatalf("err = %v, want ErrGuardHardFail", err)
	}
	if len(seen) != before {
		t.Fatal("E7.4 violated: a tunnel was built after both guards failed")
	}
	if n := len(p.Tunnels(Outbound)); n != 0 {
		t.Fatalf("E7.4 violated: %d tunnels exist with no usable guard", n)
	}
	// The down guards are still OURS -- forgetting them is how an adversary
	// rotates us away.
	if g.Len() != 5 {
		t.Fatalf("sample shrank to %d; a failed guard must not be dropped", g.Len())
	}
}

// TestPAR05SampledSetBoundsExposure: a client never connects to a guard outside
// its persisted sample, so a long-running adversary cannot enumerate it by
// attrition.
func TestPAR05SampledSetBoundsExposure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := NewGuardSet("alice", func() time.Time { return now })
	for i := 0; i < params.SampledGuardSize; i++ {
		if err := g.Sample(rid(byte(i + 1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Sample(rid(99)); !errors.Is(err, ErrSampleFull) {
		t.Fatalf("err = %v, want ErrSampleFull at %d", err, params.SampledGuardSize)
	}
	// A relay outside the sample cannot be promoted, which is the invariant.
	if err := g.Promote(rid(99), GuardPrimary); !errors.Is(err, ErrOutsideSample) {
		t.Fatalf("err = %v, want ErrOutsideSample", err)
	}
	if g.InSample(rid(99)) {
		t.Fatal("a refused relay entered the sample")
	}
}

// TestT73RotationIsDeterministicAndSurvivesRestart is T7.3.
func TestT73RotationIsDeterministicAndSurvivesRestart(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	g := ctx(t, "alice", clock, 1, 2, 3)

	if due := g.DueForRotation(); len(due) != 0 {
		t.Fatalf("%d guards due immediately", len(due))
	}
	// Persist, restart, and advance past the rotation period.
	snap := g.Save()
	now = now.Add(params.GuardRotation + time.Hour)
	restored := Load(snap, clock)

	a, b := g.DueForRotation(), restored.DueForRotation()
	if len(a) != params.PrimaryGuards || len(b) != len(a) {
		t.Fatalf("due before restart = %d, after = %d, want %d", len(a), len(b), params.PrimaryGuards)
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatal("T7.3 violated: rotation is not deterministic across a restart")
		}
	}
	// Rotation is measured from Added, so it did not restart with the process.
	for _, x := range restored.Save().Guards {
		if !x.Added.Equal(snap.Guards[0].Added) && x.Added.After(now) {
			t.Fatal("a restored guard's Added moved")
		}
	}
}

// TestT74ContextsShareNoGuardAndNoTunnel is T7.4.
func TestT74ContextsShareNoGuardAndNoTunnel(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	alice := ctx(t, "alice", clock, 1, 2, 3)
	bob := ctx(t, "bob", clock, 10, 11, 12)

	pa, pb := NewPool(alice, clock), NewPool(bob, clock)
	var sa, sb []RelayID
	if err := pa.Fill(Outbound, builder(&sa)); err != nil {
		t.Fatal(err)
	}
	if err := pb.Fill(Outbound, builder(&sb)); err != nil {
		t.Fatal(err)
	}

	inA := map[RelayID]bool{}
	for _, x := range alice.Save().Guards {
		inA[x.ID] = true
	}
	for _, x := range bob.Save().Guards {
		if inA[x.ID] {
			t.Fatalf("T7.4 violated: %x is a guard in both contexts", x.ID[:4])
		}
	}
	ids := map[uint64]string{}
	for _, tn := range pa.Tunnels(Outbound) {
		ids[tn.ID] = "alice"
	}
	for _, tn := range pb.Tunnels(Outbound) {
		if who, dup := ids[tn.ID]; dup {
			t.Fatalf("T7.4 violated: tunnel %d shared with %s", tn.ID, who)
		}
	}
}

// TestT76ExhaustionIsAStatedFailureNotAHang is T7.6.
func TestT76ExhaustionIsAStatedFailureNotAHang(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	p := NewPool(ctx(t, "alice", clock, 1, 2), clock)

	done := make(chan error, 1)
	go func() {
		_, err := p.Get(Outbound)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPoolExhausted) {
			t.Fatalf("err = %v, want ErrPoolExhausted", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("T7.6 violated: Get blocked instead of failing")
	}
}

// TestPAR10SparesAreBuiltAhead: a first request must never pay a cold build.
func TestPAR10SparesAreBuiltAhead(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	p := NewPool(ctx(t, "alice", clock, 1, 2, 3), clock)

	var seen []RelayID
	if err := p.Fill(Outbound, builder(&seen)); err != nil {
		t.Fatal(err)
	}
	if got := len(p.Tunnels(Outbound)); got != Target() {
		t.Fatalf("pool filled to %d, want %d (working set %d + %d spare)",
			got, Target(), params.OutboundPoolSize, params.PoolSpares)
	}
	// The request that follows costs no build.
	before := len(seen)
	if _, err := p.Get(Outbound); err != nil {
		t.Fatal(err)
	}
	if len(seen) != before {
		t.Fatal("PAR-10 violated: Get triggered a build")
	}
}

// TestBuildAheadFiresInTheJitteredWindow.
//
// This test used to assert a build-ahead at exactly 70 % of the lifetime, and
// that assertion was the M5 defect written down as a requirement: a fixed
// trigger means every client in the network emits CREATE cells on a
// phase-locked 420 s cadence, and the phase offset is a stable per-client
// identifier at the guard. §16.3 says an unjittered M5 ADDS a fingerprint while
// claiming to reduce one.
//
// The trigger is now params.TunnelRebuildAt jittered DOWNWARD by up to
// RotationJitter, so the assertion is a window: nothing fires before the
// earliest possible trigger, everything has fired by the latest.
func TestBuildAheadFiresInTheJitteredWindow(t *testing.T) {
	life := float64(params.TunnelLifetime)
	earliest := params.TunnelRebuildAt * (1 - params.RotationJitter)
	latest := params.TunnelRebuildAt

	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	p := NewPool(ctx(t, "alice", clock, 1, 2, 3), clock)
	var seen []RelayID
	if err := p.Fill(Outbound, builder(&seen)); err != nil {
		t.Fatal(err)
	}

	// A hair before the earliest possible trigger: nothing may fire.
	now = now.Add(time.Duration(life * (earliest - 0.005)))
	if todo := p.Tick(); len(todo) != 0 {
		t.Fatalf("build-ahead fired below the jitter floor %.3f: %v", earliest, todo)
	}
	// A hair past the unjittered trigger: everything must have fired.
	now = now.Add(time.Duration(life * (latest - earliest + 0.01)))
	if todo := p.Tick(); len(todo) == 0 {
		t.Fatalf("build-ahead did not fire by %.3f of lifetime", latest)
	}
}

// TestRotationIsNotPhaseLocked is M5 itself.
//
// The property is that two tunnels built at the same instant do not rotate at
// the same instant. A fixed trigger passes every other tunnel test in this file
// and fails only this one, which is why it exists.
func TestRotationIsNotPhaseLocked(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	seenFractions := map[float64]int{}
	for i := 0; i < 200; i++ {
		p := NewPool(ctx(t, fmt.Sprintf("c%d", i), clock, 1, 2, 3), clock)
		var seen []RelayID
		if err := p.Fill(Outbound, builder(&seen)); err != nil {
			t.Fatal(err)
		}
		tn, err := p.Get(Outbound)
		if err != nil {
			t.Fatal(err)
		}
		f := tn.RebuildFraction()
		if f > params.TunnelRebuildAt || f < params.TunnelRebuildAt*(1-params.RotationJitter) {
			t.Fatalf("rebuild fraction %.4f outside [%.4f, %.4f]", f,
				params.TunnelRebuildAt*(1-params.RotationJitter), params.TunnelRebuildAt)
		}
		seenFractions[f]++
	}
	if len(seenFractions) < 150 {
		t.Fatalf("M5 violated: 200 tunnels produced only %d distinct rebuild triggers -- "+
			"the pool is phase-locked", len(seenFractions))
	}
	// The jitter must be DOWNWARD only: a tunnel that rotates late eats the
	// 180 s the schedule reserves for rebuild failures.
	for f := range seenFractions {
		if f > params.TunnelRebuildAt {
			t.Fatalf("rebuild fraction %.4f is later than the unjittered trigger", f)
		}
	}
}

// TestExpiringTunnelIsNeverExtended: even mid-stream, a tunnel dies on time.
func TestExpiringTunnelIsNeverExtended(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	p := NewPool(ctx(t, "alice", clock, 1, 2, 3), clock)
	var seen []RelayID
	if err := p.Fill(Outbound, builder(&seen)); err != nil {
		t.Fatal(err)
	}
	tn, err := p.Get(Outbound) // gives it a live stream
	if err != nil {
		t.Fatal(err)
	}
	id := tn.ID

	now = now.Add(params.TunnelLifetime + time.Second)
	p.Tick()
	p.Tick()
	for _, x := range p.Tunnels(Outbound) {
		if x.ID == id {
			t.Fatal("a tunnel carrying a stream survived past its lifetime")
		}
	}
}

// TestSuspectTunnelDoesNotCountTowardReady: a maybe-dead tunnel counted toward
// the floor is how a pool convinces itself it is healthy while carrying traffic
// onto a black hole.
func TestSuspectTunnelDoesNotCountTowardReady(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	p := NewPool(ctx(t, "alice", clock, 1, 2, 3), clock)
	var seen []RelayID
	// BOTH halves: a pool with an empty inbound half is degraded, correctly.
	for _, d := range []Direction{Inbound, Outbound} {
		if err := p.Fill(d, builder(&seen)); err != nil {
			t.Fatal(err)
		}
	}
	if p.Degraded() {
		t.Fatal("a full pool reports degraded")
	}
	// Push all but one into SUSPECT.
	ts := p.Tunnels(Outbound)
	for i := 0; i < len(ts)-1; i++ {
		for m := 0; m < params.TunnelProbeMisses; m++ {
			p.MissProbe(ts[i].ID)
		}
	}
	if !p.Degraded() {
		t.Fatal("pool did not raise DEGRADED with only one countable tunnel")
	}
	// A probe answered restores it.
	p.AnswerProbe(ts[0].ID)
	if p.Degraded() {
		t.Fatal("DEGRADED persisted after the pool recovered")
	}
}

// TestSuspectToDeadTriggersImmediateRebuild: not deferred to the 70 % trigger.
func TestSuspectToDeadTriggersImmediateRebuild(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	p := NewPool(ctx(t, "alice", clock, 1, 2, 3), clock)
	var seen []RelayID
	if err := p.Fill(Outbound, builder(&seen)); err != nil {
		t.Fatal(err)
	}
	ts := p.Tunnels(Outbound)
	for m := 0; m < params.TunnelProbeMisses; m++ {
		p.MissProbe(ts[0].ID)
	}
	// Far from the 70 % mark.
	if todo := p.Tick(); len(todo) == 0 {
		t.Fatal("a SUSPECT tunnel dying did not plan a replacement")
	}
}

// TestGuardIsAnArgumentNotAChoice: the Builder signature takes the guard, so a
// builder cannot select its own first hop. R1 enforced by the type.
func TestGuardIsAnArgumentNotAChoice(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	g := ctx(t, "alice", clock, 1, 2, 3)
	p := NewPool(g, clock)

	// A builder that tries to return its own first hop cannot: what it returns
	// is hops 2..n, and Guard is set by the pool from the guard set.
	var used RelayID
	err := p.Fill(Outbound, func(d Direction, guard RelayID) ([]RelayID, error) {
		used = guard
		return []RelayID{rid(250)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range p.Tunnels(Outbound) {
		if tn.Guard != used {
			t.Fatal("the pool used a guard the guard set did not give it")
		}
	}
}
