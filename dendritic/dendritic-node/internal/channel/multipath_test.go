package channel

import (
	"errors"
	"testing"
)

func routeOf(operators ...string) []Candidate {
	out := make([]Candidate, 0, len(operators))
	for i, op := range operators {
		out = append(out, cand(op+string(rune('0'+i)), op, "dom-"+op))
	}
	return out
}

func threeIndependentRoutes() [][]Candidate {
	return [][]Candidate{
		routeOf("a1", "a2", "a3"),
		routeOf("b1", "b2", "b3"),
		routeOf("c1", "c2", "c3"),
	}
}

// Fragments must sum exactly to the payment. Anything else means the recipient
// is short-paid or the payer over-charged, silently.
func TestFragmentsSumToTheTotal(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	total := Amount(100_000)

	plan, err := Split(c, Z, total, threeIndependentRoutes())
	if err != nil {
		t.Fatal(err)
	}
	var sum Amount
	for _, f := range plan.Fragments {
		sum += f.Amount
	}
	if sum != total {
		t.Fatalf("fragments sum to %d, want %d", sum, total)
	}
	if err := plan.Verify(); err != nil {
		t.Fatalf("plan failed its own verification: %v", err)
	}
}

// Equal thirds reassemble on sight. Across many splits the sizes must vary.
func TestFragmentsAreUneven(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	equalRuns := 0
	for i := 0; i < 30; i++ {
		plan, err := Split(c, Z, 100_000, threeIndependentRoutes())
		if err != nil {
			t.Fatal(err)
		}
		if plan.AllEqual() {
			equalRuns++
		}
	}
	if equalRuns > 1 {
		t.Errorf("%d/30 splits produced equal fragments — they reassemble on sight", equalRuns)
	}
}

// No fragment may fall below the floor: a tiny fragment is conspicuous
// precisely because it is unusual.
func TestNoFragmentFallsBelowTheFloor(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	for i := 0; i < 30; i++ {
		plan, err := Split(c, Z, 3*MinFragment+7, threeIndependentRoutes())
		if err != nil {
			continue // legitimately refused as too small
		}
		for j, f := range plan.Fragments {
			if f.Amount < MinFragment {
				t.Fatalf("run %d fragment %d is %d, below the floor %d",
					i, j, f.Amount, MinFragment)
			}
		}
	}
}

// THE test for this file. Splitting across routes one operator controls gives
// that operator two views and a partial sum — worse than not splitting.
func TestRoutesSharingAnOperatorAreNotIndependent(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	// Every route passes through "shared".
	routes := [][]Candidate{
		routeOf("a1", "shared", "a3"),
		routeOf("b1", "shared", "b3"),
		routeOf("c1", "shared", "c3"),
	}
	_, err := Split(c, Z, 100_000, routes)
	if !errors.Is(err, ErrNotEnoughRoutes) {
		t.Fatalf("split across routes sharing an operator: %v", err)
	}
}

// A route containing an unlabelled hop cannot be counted toward cross-route
// independence — the same rule SelectRoute applies within a route.
func TestUnlabelledHopsDisqualifyARoute(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	routes := [][]Candidate{
		routeOf("a1", "a2", "a3"),
		{cand("x", "", "d"), cand("y", "b2", "d")},
		{cand("z", "", "d"), cand("w", "c2", "d")},
	}
	if _, err := Split(c, Z, 100_000, routes); !errors.Is(err, ErrNotEnoughRoutes) {
		t.Fatalf("counted routes with unlabelled hops as independent: %v", err)
	}
}

// Small payments must not be split — three tiny fragments are louder than one
// ordinary payment.
func TestSmallPaymentsAreNotSplit(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	if _, err := Split(c, Z, MinFragment, threeIndependentRoutes()); !errors.Is(err, ErrTooSmallToSplit) {
		t.Fatal("split a payment too small to split")
	}
	if ok, why := ShouldSplit(MinFragment, 3); ok || why == "" {
		t.Error("ShouldSplit did not explain the refusal")
	}
}

func TestOneRouteIsNotASplit(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	if _, err := Split(c, Z, 100_000, threeIndependentRoutes()[:1]); err == nil {
		t.Fatal("split across a single route")
	}
	if ok, _ := ShouldSplit(100_000, 1); ok {
		t.Error("ShouldSplit approved a single route")
	}
}

// Each fragment carries its OWN locks. Identical locks across fragments would
// make them trivially linkable as parts of one payment.
func TestEachFragmentHasItsOwnLocks(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	plan, err := Split(c, Z, 100_000, threeIndependentRoutes())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, f := range plan.Fragments {
		if f.Locks == nil || len(f.Locks.Locks) == 0 {
			t.Fatalf("fragment %d has no locks", i)
		}
		for _, lock := range f.Locks.Locks {
			key := lock.X.String() + ":" + lock.Y.String()
			if seen[key] {
				t.Fatal("two fragments share a lock — they are linkable")
			}
			seen[key] = true
		}
	}
}

// Verify must catch a tampered plan, not just a freshly built one.
func TestVerifyCatchesATamperedPlan(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	plan, err := Split(c, Z, 100_000, threeIndependentRoutes())
	if err != nil {
		t.Fatal(err)
	}
	plan.Fragments[0].Amount += 1
	if err := plan.Verify(); !errors.Is(err, ErrFragmentSum) {
		t.Fatalf("a plan that no longer sums was accepted: %v", err)
	}
}

func TestFragmentCountIsBounded(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	var many [][]Candidate
	for i := 0; i < 10; i++ {
		p := string(rune('a' + i))
		many = append(many, routeOf(p+"1", p+"2", p+"3"))
	}
	plan, err := Split(c, Z, 1_000_000, many)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Fragments) > MaxFragments {
		t.Errorf("produced %d fragments, cap is %d", len(plan.Fragments), MaxFragments)
	}
}
