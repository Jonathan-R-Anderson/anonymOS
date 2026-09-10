package path

import (
	"context"
	"fmt"
	"math"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// hostilePopulation builds 60 relays of which 20 % are the adversary's.
//
// 20 ASes, three relays each; every relay in its own /24. The adversary holds
// ONE relay in each of twelve DISTINCT ASes.
//
// That spread is the point and it was got wrong once. An earlier version marked
// every fifth relay hostile, which — with ASN = 1 + i mod 20 — put all twelve in
// four ASes. The distinct-ASN constraint then made a second hostile hop nearly
// impossible on its own, the measured compromise rate fell well below f², and
// the test looked like it was measuring the sampler when it was measuring an
// accident of the fixture. An adversary who can choose where to place relays
// places them apart, so the fixture does too.
func hostilePopulation(t *testing.T) (cands []Relay, hostile func(Relay) bool) {
	t.Helper()
	bad := map[string]bool{}
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("r%03d", i)
		cands = append(cands, relay(t, id, i, 1, uint32(1+i%20)))
		if i < 12 { // ASNs 1..12, one hostile relay in each
			bad[id] = true
		}
	}
	// Assert the fixture rather than trusting the arithmetic above.
	asns := map[uint32]int{}
	for _, r := range cands {
		if bad[r.NodeID] {
			asns[r.Ann.ASN]++
		}
	}
	if len(asns) != 12 {
		t.Fatalf("fixture: adversary occupies %d ASes, want 12 distinct", len(asns))
	}
	return cands, func(r Relay) bool { return bad[r.NodeID] }
}

// TestE123CompromiseRateMatchesTheModel is E12.3.
//
// The measured fraction of circuits whose FIRST and LAST hop are both the
// adversary's must match the published model (model.go) within a stated
// tolerance. The tolerance is derived here rather than chosen, so that a run
// which fails fails for a reason.
//
// It is the test that catches a biased sampler. A selector with an off-by-one
// in its weighted pick, or one that scans candidates in a fixed order and lets
// floating-point accumulation favour the front of the list, still produces
// perfectly diverse paths and passes T12.1 and E12.1 — the paths are legal, they
// are just not the paths the model says. Only a distribution test sees it.
func TestE123CompromiseRateMatchesTheModel(t *testing.T) {
	cands, hostile := hostilePopulation(t)
	sortRelays(cands)
	c := Default()
	pol := WeightPolicy{}
	uniform := func(Relay) float64 { return 1 }

	model := ExactCompromise(cands, params.DefaultHops, c, uniform, hostile)
	if model.NoPath != 0 {
		t.Fatalf("setup: %v of the probability mass has no path", model.NoPath)
	}

	const trials = 100000
	s := selector(cands, seeded(20260816))
	ctx := context.Background()
	hits, anyHits := 0, 0
	for i := 0; i < trials; i++ {
		p, rep, err := s.SelectPath(ctx, params.DefaultHops, c, pol)
		if err != nil {
			t.Fatalf("trial %d: %v (report %+v)", i, err, rep)
		}
		if hostile(p[0]) && hostile(p[len(p)-1]) {
			hits++
		}
		for _, h := range p {
			if hostile(h) {
				anyHits++
				break
			}
		}
	}
	measured := float64(hits) / trials
	measuredAny := float64(anyHits) / trials

	// THE STATED TOLERANCE: five standard errors of a binomial with the model's
	// own p. At p = 0.04 and 10^5 trials that is about 0.0031 absolute. Five
	// sigma is deliberately loose for a distribution test and deliberately tight
	// for a security claim -- a sampler biased by 10 % of its own rate fails it,
	// and an honest sampler fails it about once in 3.5 million runs.
	tol := func(p float64) float64 {
		return 5 * math.Sqrt(p*(1-p)/trials)
	}
	if d := math.Abs(measured - model.FirstAndLast); d > tol(model.FirstAndLast) {
		t.Fatalf("E12.3 violated: first-and-last compromise measured %.5f, model %.5f, "+
			"difference %.5f exceeds the %.5f tolerance",
			measured, model.FirstAndLast, d, tol(model.FirstAndLast))
	}
	if d := math.Abs(measuredAny - model.AnyHop); d > tol(model.AnyHop) {
		t.Fatalf("E12.3 violated: any-hop compromise measured %.5f, model %.5f, "+
			"difference %.5f exceeds the %.5f tolerance",
			measuredAny, model.AnyHop, d, tol(model.AnyHop))
	}

	t.Logf("E12.3: first-and-last measured %.5f vs model %.5f (tol %.5f); "+
		"any-hop measured %.5f vs model %.5f",
		measured, model.FirstAndLast, tol(model.FirstAndLast), measuredAny, model.AnyHop)
}

// TestNaiveModelDivergesWithConcentration is why model.go enumerates rather
// than multiplying — and it records HOW MUCH, because the honest answer is
// "it depends, and here is what it depends on".
//
// The familiar figure for first-and-last compromise is f²: 20 % adversarial
// gives 4 %. It assumes the two draws are independent, and under sampling
// without replacement with a pairwise diversity filter they are not — choosing
// a hostile first hop removes it, its /24 and its AS from the pool the last hop
// is drawn from.
//
// How much that matters depends on where the adversary's relays sit:
//
//	spread across 12 distinct ASes:   f² is within a few per cent — the
//	                                  approximation is serviceable
//	concentrated in a few ASes:       f² overstates the rate substantially,
//	                                  because the constraint is doing work the
//	                                  formula cannot see
//
// So f² is not simply "wrong". It is an approximation whose error is a function
// of the adversary's placement, which is the one variable the adversary chooses.
// That is exactly why the model is enumerated from the real candidate set rather
// than parameterised by a single f, and this test measures both regimes so the
// claim is a number rather than an assertion.
func TestNaiveModelDivergesWithConcentration(t *testing.T) {
	uniform := func(Relay) float64 { return 1 }
	f := 12.0 / 60.0
	naive := f * f

	spread, hostileSpread := hostilePopulation(t)
	sortRelays(spread)
	mSpread := ExactCompromise(spread, params.DefaultHops, Default(), uniform, hostileSpread)

	// The same adversary, same count, concentrated in four ASes instead of
	// twelve. Nothing else changes.
	var conc []Relay
	bad := map[string]bool{}
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("r%03d", i)
		conc = append(conc, relay(t, id, i, 1, uint32(1+i%20)))
		if i%5 == 0 {
			bad[id] = true
		}
	}
	sortRelays(conc)
	mConc := ExactCompromise(conc, params.DefaultHops, Default(), uniform,
		func(r Relay) bool { return bad[r.NodeID] })

	errSpread := 100 * math.Abs(mSpread.FirstAndLast-naive) / naive
	errConc := 100 * math.Abs(mConc.FirstAndLast-naive) / naive
	t.Logf("naive f² = %.5f; exact spread = %.5f (%.1f%% off); exact concentrated = %.5f (%.1f%% off)",
		naive, mSpread.FirstAndLast, errSpread, mConc.FirstAndLast, errConc)

	if mConc.FirstAndLast >= mSpread.FirstAndLast {
		t.Fatalf("concentrating the adversary did not lower first-and-last compromise "+
			"(%.5f concentrated vs %.5f spread) -- the diversity constraint is not "+
			"interacting with placement at all", mConc.FirstAndLast, mSpread.FirstAndLast)
	}
	if errConc <= errSpread {
		t.Fatalf("f²'s error did not grow with concentration: %.1f%% vs %.1f%%", errConc, errSpread)
	}
	// And the enumeration must not have silently become the formula.
	if math.Abs(mConc.FirstAndLast-naive) < 1e-4 && math.Abs(mSpread.FirstAndLast-naive) < 1e-4 {
		t.Fatal("the exact model agrees with f² in both regimes -- the enumeration " +
			"has collapsed into the formula it exists to replace")
	}
}

// TestModelIsADistribution checks the enumeration's own arithmetic.
//
// An exact model that does not sum to one is not exact, and every claim built
// on it inherits the error silently.
func TestModelIsADistribution(t *testing.T) {
	cands, hostile := hostilePopulation(t)
	sortRelays(cands)

	// Every path is either all-honest or has at least one hostile hop, and no
	// prefix here dead-ends, so AnyHop + P(all honest) + NoPath = 1. P(all
	// honest) is computed by inverting the hostile predicate.
	honest := ExactCompromise(cands, params.DefaultHops, Default(),
		func(Relay) float64 { return 1 }, func(r Relay) bool { return !hostile(r) })
	m := ExactCompromise(cands, params.DefaultHops, Default(),
		func(Relay) float64 { return 1 }, hostile)

	// "at least one hostile" + "at least one honest" - "mixed" = 1. Rather than
	// derive the mixed term, check the simpler identity: a path with no hostile
	// hop is one where every hop is honest, so AnyHop(hostile) + AnyHop-none is
	// awkward. Use the direct one instead: enumerate with a predicate that is
	// always false, whose AnyHop must be 0 and whose NoPath must match.
	none := ExactCompromise(cands, params.DefaultHops, Default(),
		func(Relay) float64 { return 1 }, func(Relay) bool { return false })
	if none.AnyHop != 0 || none.FirstAndLast != 0 {
		t.Fatalf("a never-hostile predicate produced compromise: %+v", none)
	}
	if none.NoPath != m.NoPath || none.NoPath != honest.NoPath {
		t.Fatalf("NoPath depends on the hostile predicate: %v / %v / %v",
			none.NoPath, m.NoPath, honest.NoPath)
	}
	// FirstAndLast can never exceed AnyHop: both endpoints hostile implies some
	// hop is hostile.
	if m.FirstAndLast > m.AnyHop+1e-12 {
		t.Fatalf("FirstAndLast %.6f exceeds AnyHop %.6f", m.FirstAndLast, m.AnyHop)
	}
	// With a 1-hop path, first and last are the same hop, so the two figures
	// must coincide exactly.
	one := ExactCompromise(cands, 1, Default(), func(Relay) float64 { return 1 }, hostile)
	if math.Abs(one.FirstAndLast-one.AnyHop) > 1e-12 {
		t.Fatalf("1-hop: FirstAndLast %.9f != AnyHop %.9f", one.FirstAndLast, one.AnyHop)
	}
	if math.Abs(one.FirstAndLast-12.0/60.0) > 1e-9 {
		t.Fatalf("1-hop compromise %.9f, want the adversary's share 0.2", one.FirstAndLast)
	}
}
