package profile

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// base is a fixed instant. Every test drives its own clock: a profiling package
// whose behaviour depends on wall-clock time cannot be tested for decay at all.
var base = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

// clock is a manually advanced clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

// observeN records n identical observations one second apart.
func observeN(t *testing.T, p *Profiles, id string, kind ObservationKind, v float64, at time.Time, n int) time.Time {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := p.Observe(id, kind, v, at); err != nil {
			t.Fatalf("Observe(%s, %v): %v", id, kind, err)
		}
		at = at.Add(time.Second)
	}
	return at
}

// TestObserveRejectsWhatItCannotMeasure covers the input contract.
//
// It matters more than a validation test usually would: every value here feeds
// a mean, and a single NaN or negative RTT poisons the mean permanently -- decay
// shrinks a NaN to a NaN.
func TestObserveRejectsWhatItCannotMeasure(t *testing.T) {
	c := &clock{base}
	p := New(c.now)

	cases := []struct {
		name string
		id   string
		kind ObservationKind
		v    float64
		want error
	}{
		{"empty id", "", ObsBuildAccepted, 1, ErrNoNodeID},
		{"NaN", "a", ObsBuildAccepted, math.NaN(), ErrBadValue},
		{"+Inf", "a", ObsExtendRTT, math.Inf(1), ErrBadValue},
		{"zero RTT", "a", ObsExtendRTT, 0, ErrBadValue},
		{"negative RTT", "a", ObsExtendRTT, -1, ErrBadValue},
		{"ratio above one", "a", ObsDeliveryRatio, 1.5, ErrBadValue},
		{"ratio below zero", "a", ObsReachable, -0.1, ErrBadValue},
		{"unknown kind", "a", ObservationKind(99), 1, ErrUnknownKind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.Observe(tc.id, tc.kind, tc.v, base); err != tc.want {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if p.Len() != 0 {
		t.Fatalf("a rejected observation created an entry: %d peers", p.Len())
	}

	// Out-of-order observations are refused rather than folded in.
	if err := p.Observe("a", ObsBuildAccepted, 1, base); err != nil {
		t.Fatal(err)
	}
	if err := p.Observe("a", ObsBuildAccepted, 1, base.Add(-time.Minute)); err != ErrTimeGoesBack {
		t.Fatalf("backdated observation accepted: %v", err)
	}
}

// TestT12a2FreshNodeIsUniform is T12a.2 and E12a.3.
//
// A fresh node must fall back to uniform selection rather than to whatever it
// heard first. The failure this prevents is the sticky one: a node that trusts
// its first handful of observations keeps choosing the peers it already chose,
// which is how a first-contact adversary keeps a client.
func TestT12a2FreshNodeIsUniform(t *testing.T) {
	c := &clock{base}
	p := New(c.now)

	// Never observed at all.
	if got := p.Tier("nobody"); got != TierUntiered {
		t.Fatalf("unknown peer tier = %v, want untiered", got)
	}
	if got := p.Weight("nobody"); got != params.WeightUntiered {
		t.Fatalf("unknown peer weight = %v, want %v", got, params.WeightUntiered)
	}

	// Observed, but below the store-wide floor: one peer, excellent, 9 samples.
	at := observeN(t, p, "great", ObsBuildAccepted, 1, base, params.ProfileMinSamples-1)
	c.t = at
	if got := p.Tier("great"); got != TierUntiered {
		t.Fatalf("E12a.3 violated: %d samples produced tier %v, want untiered",
			params.ProfileMinSamples-1, got)
	}
	if got := p.Weight("great"); got != params.WeightUntiered {
		t.Fatalf("E12a.3 violated: weight %v differs from uniform %v", got, params.WeightUntiered)
	}

	// Crossing the floor is what produces a tier. It takes slightly MORE than
	// ProfileMinSamples raw observations, because the floor is on the decayed
	// count: ten observations a second apart weigh 9.99, not 10. That is the
	// intended reading of the floor and not an off-by-one -- see the constant.
	at = observeN(t, p, "great", ObsBuildAccepted, 1, at, 3)
	c.t = at
	if got := p.Tier("great"); got == TierUntiered {
		t.Fatalf("above the sample floor the peer is still untiered")
	}
	if pr, _ := p.Get("great"); pr.Samples < params.ProfileMinSamples {
		t.Fatalf("tiered on %v decayed samples, below the floor %d",
			pr.Samples, params.ProfileMinSamples)
	}
}

// TestT12a5DecayAppliedOnRead is T12a.5.
//
// The bug it catches: decay applied only in Observe. A node that stops
// observing then holds its last tier forever, and the staler that tier gets the
// more confidently it is asserted.
func TestT12a5DecayAppliedOnRead(t *testing.T) {
	c := &clock{base}
	p := New(c.now)

	at := observeN(t, p, "a", ObsBuildAccepted, 1, base, 40)
	at = observeN(t, p, "b", ObsBuildAccepted, 0.5, at, 40)
	c.t = at

	pa, ok := p.Get("a")
	if !ok {
		t.Fatal("missing peer")
	}
	if pa.Tier != TierFast {
		t.Fatalf("setup: best peer tier = %v, want fast", pa.Tier)
	}
	before := pa.Samples

	// No further observations. Only time passes -- and NOTHING calls Observe,
	// so a write-only decay would leave every number exactly where it was.
	c.add(10 * params.ProfileHalfLife)

	pa, _ = p.Get("a")
	if pa.Samples >= before {
		t.Fatalf("T12a.5 violated: samples did not decay on read (%v -> %v)", before, pa.Samples)
	}
	if pa.Samples > 1 {
		t.Fatalf("after 10 half-lives 40 samples should be ~0.04, got %v", pa.Samples)
	}
	if pa.Tier != TierUntiered {
		t.Fatalf("T12a.5 violated: stale tier %v survived 10 half-lives", pa.Tier)
	}
	if w := p.Weight("a"); w != params.WeightUntiered {
		t.Fatalf("a decayed peer keeps a non-uniform weight %v", w)
	}

	// The MEAN is preserved while the confidence in it decays. That is the
	// deliberate difference between "this peer got worse" and "we no longer
	// know" -- decaying only the sum would assert the former.
	if math.Abs(pa.Capacity-1.0) > 1e-9 {
		t.Fatalf("decay changed the mean: capacity = %v, want 1.0", pa.Capacity)
	}
}

// TestTiersAreRelativeAndNested checks the tier ladder over a real population.
func TestTiersAreRelativeAndNested(t *testing.T) {
	c := &clock{base}
	p := New(c.now)
	at := base

	// 20 peers. Capacity descends with the index, so peer 00 is the best
	// builder; speed ASCENDS with the index, so the fastest peers are the ones
	// with the WORST capacity. If "fast" were computed over the whole
	// population instead of within high-capacity, peer 19 would be fast.
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("p%02d", i)
		cap := 1.0 - float64(i)*0.05
		rtt := 1.0 / (1.0 + float64(i)) // falling RTT => rising speed
		for j := 0; j < 10; j++ {
			if err := p.Observe(id, ObsBuildAccepted, cap, at); err != nil {
				t.Fatal(err)
			}
			at = at.Add(time.Second)
			if err := p.Observe(id, ObsExtendRTT, rtt, at); err != nil {
				t.Fatal(err)
			}
			at = at.Add(time.Second)
		}
	}
	c.t = at

	counts := map[Tier]int{}
	for _, pr := range p.All() {
		counts[pr.Tier]++
	}
	// 25 % of 20 = 5 high capacity, of which 10 % = 1 (rounded up) is fast.
	if counts[TierHighCapacity] != 4 || counts[TierFast] != 1 {
		t.Fatalf("tier sizes wrong: fast=%d high=%d standard=%d (want 1, 4, 15)",
			counts[TierFast], counts[TierHighCapacity], counts[TierStandard])
	}
	if counts[TierStandard] != 15 {
		t.Fatalf("standard = %d, want 15", counts[TierStandard])
	}

	// The fast peer must come from the high-capacity set: p00..p04 by capacity,
	// and within them p04 is the quickest.
	if got := p.Tier("p04"); got != TierFast {
		t.Fatalf("fast peer is not the quickest of the high-capacity set: p04 = %v", got)
	}
	// p19 is the quickest peer overall and the worst builder. It must not be
	// fast -- speed alone would promote a relay that answers probes and refuses
	// every build.
	if got := p.Tier("p19"); got != TierStandard {
		t.Fatalf("p19 (quickest, worst capacity) = %v, want standard", got)
	}
}

// TestFailingIsTemporary covers the failure streak and re-admission.
func TestFailingIsTemporary(t *testing.T) {
	c := &clock{base}
	p := New(c.now)

	at := observeN(t, p, "x", ObsBuildAccepted, 1, base, 20)
	at = observeN(t, p, "y", ObsBuildAccepted, 1, at, 20)
	c.t = at
	if p.Tier("x") == TierFailing {
		t.Fatal("setup: peer already failing")
	}

	// Two failures is not enough; three is.
	at = observeN(t, p, "x", ObsBuildAccepted, 0, at, params.ProfileFailingStreak-1)
	c.t = at
	if got := p.Tier("x"); got == TierFailing {
		t.Fatalf("%d consecutive failures already excluded the peer", params.ProfileFailingStreak-1)
	}
	at = observeN(t, p, "x", ObsBuildAccepted, 0, at, 1)
	c.t = at
	if got := p.Tier("x"); got != TierFailing {
		t.Fatalf("%d consecutive failures did not exclude: %v", params.ProfileFailingStreak, got)
	}
	if w := p.Weight("x"); w != 0 {
		t.Fatalf("a failing peer has weight %v, want 0", w)
	}

	// It comes back on its own. Permanent exclusion would let anyone who can
	// cause three failures delete a peer from this node's view for good.
	c.add(params.ProfileRepromoteInterval + time.Second)
	if got := p.Tier("x"); got == TierFailing {
		t.Fatalf("peer still excluded after %v", params.ProfileRepromoteInterval)
	}

	// A single success clears the streak immediately -- the counter is
	// CONSECUTIVE failures, not a running total.
	at = c.t
	at = observeN(t, p, "y", ObsBuildAccepted, 0, at, params.ProfileFailingStreak-1)
	at = observeN(t, p, "y", ObsBuildAccepted, 1, at, 1)
	at = observeN(t, p, "y", ObsBuildAccepted, 0, at, params.ProfileFailingStreak-1)
	c.t = at
	if got := p.Tier("y"); got == TierFailing {
		t.Fatal("a success did not clear the consecutive-failure streak")
	}
}

// TestSuccessfulExtendNeverCountsAsFailure guards a specific mistake.
//
// ObsExtendRTT's value is a duration, so a "0 means failure" rule applied
// uniformly across kinds would read a very fast extension as a failure. The
// value is already rejected as out of range, but the streak logic must not
// depend on that having happened.
func TestSuccessfulExtendNeverCountsAsFailure(t *testing.T) {
	c := &clock{base}
	p := New(c.now)
	at := base
	for i := 0; i < 20; i++ {
		if err := p.Observe("a", ObsExtendRTT, 1e-9, at); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Second)
	}
	c.t = at
	if pr, _ := p.Get("a"); pr.FailureStreak != 0 {
		t.Fatalf("fast extensions counted as %d failures", pr.FailureStreak)
	}
}

// TestE12a1SelfReportsDoNotMove is E12a.1.
//
// 20 % of relays inflate their self-reported capacity by an arbitrary factor.
// The test is structural rather than statistical: the inflated figure is passed
// to the only entry point this package has, and the resulting profiles are
// compared against the honest population's. There is no channel through which
// claimed_bw could arrive, so the strongest statement available is that
// identical observations produce identical profiles regardless of what the peer
// claims -- and that is exactly the property E12a.1 asks for.
func TestE12a1SelfReportsDoNotMove(t *testing.T) {
	build := func(claimed func(i int) float64) []Profile {
		c := &clock{base}
		p := New(c.now)
		at := base
		for i := 0; i < 25; i++ {
			id := fmt.Sprintf("r%02d", i)
			// The peer's CLAIM. There is no Observe kind that accepts it, which
			// is the point; the loop below records only what was observed.
			_ = claimed(i)
			for j := 0; j < 12; j++ {
				if err := p.Observe(id, ObsBuildAccepted, 0.8, at); err != nil {
					t.Fatal(err)
				}
				at = at.Add(time.Second)
				if err := p.Observe(id, ObsExtendRTT, 0.05, at); err != nil {
					t.Fatal(err)
				}
				at = at.Add(time.Second)
			}
		}
		c.t = at
		return p.All()
	}

	honest := build(func(int) float64 { return 1e6 })
	inflated := build(func(i int) float64 {
		if i%5 == 0 { // 20 %
			return 1e12
		}
		return 1e6
	})

	if len(honest) != len(inflated) {
		t.Fatalf("population sizes differ: %d vs %d", len(honest), len(inflated))
	}
	for i := range honest {
		h, n := honest[i], inflated[i]
		if h.NodeID != n.NodeID || h.Tier != n.Tier ||
			h.Speed != n.Speed || h.Capacity != n.Capacity || h.Samples != n.Samples {
			t.Fatalf("E12a.1 violated: inflating claimed capacity moved %s\n honest=%+v\n inflated=%+v",
				h.NodeID, h, n)
		}
	}
}

// TestE12a2WeightsCannotAdmitOrExclude is the mechanical half of E12a.2.
//
// The statistical half belongs to P12's selector, where the draw happens. What
// is established here is the property the selector relies on: a weight is a
// bounded multiplier, never an ordering and never a filter, so no tier can
// reach past a diversity constraint. The bound is what stops tiering from
// concentrating selection onto a handful of relays and undoing P3's work.
func TestE12a2WeightsCannotAdmitOrExclude(t *testing.T) {
	c := &clock{base}
	p := New(c.now)
	at := base
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("n%02d", i)
		for j := 0; j < 14; j++ {
			if err := p.Observe(id, ObsBuildAccepted, float64(40-i)/40, at); err != nil {
				t.Fatal(err)
			}
			at = at.Add(time.Second)
		}
	}
	c.t = at

	min, max := math.Inf(1), 0.0
	for _, pr := range p.All() {
		w := p.Weight(pr.NodeID)
		if w < 0 {
			t.Fatalf("negative weight %v for %s", w, pr.NodeID)
		}
		if pr.Tier != TierFailing && w <= 0 {
			t.Fatalf("non-failing peer %s has weight 0 -- weights must not exclude", pr.NodeID)
		}
		if w < min {
			min = w
		}
		if w > max {
			max = w
		}
	}
	if max/min != params.WeightFast/params.WeightStandard {
		t.Fatalf("weight spread %v:%v is not the declared ratio %v",
			max, min, params.WeightFast/params.WeightStandard)
	}
	if max/min > 4 {
		t.Fatalf("weight ratio %v is wide enough to collapse selection onto one tier", max/min)
	}
}

// TestForgetLeavesNothing checks that a rotation drops the profile.
func TestForgetLeavesNothing(t *testing.T) {
	c := &clock{base}
	p := New(c.now)
	at := observeN(t, p, "a", ObsBuildAccepted, 1, base, 20)
	c.t = at
	p.Forget("a")
	if p.Len() != 0 {
		t.Fatalf("Forget left %d entries", p.Len())
	}
	if _, ok := p.Get("a"); ok {
		t.Fatal("Forget left the profile readable")
	}
}

// TestConcurrentObserveAndRead is run under -race.
func TestConcurrentObserveAndRead(t *testing.T) {
	c := &clock{base}
	p := New(c.now)
	done := make(chan struct{})
	go func() {
		at := base
		for i := 0; i < 2000; i++ {
			_ = p.Observe(fmt.Sprintf("p%d", i%17), ObsBuildAccepted, 1, at)
			at = at.Add(time.Millisecond)
		}
		close(done)
	}()
	for {
		select {
		case <-done:
			return
		default:
			_ = p.Weight("p3")
			_ = p.All()
		}
	}
}
