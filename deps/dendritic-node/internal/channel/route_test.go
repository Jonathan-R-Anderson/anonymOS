package channel

import (
	"errors"
	"testing"
)

var routeSeed = [32]byte{0x5a}

func cand(id, operator, domain string) Candidate {
	return Candidate{
		NodeID: NodeID(id), Operator: operator, FaultDomain: domain,
		CapacityBucket: 5, SuccessRate: 0.95, LatencyMS: 200, PrivacyVersion: 1,
	}
}

func req() RouteRequest {
	return RouteRequest{Hops: 3, MinCapacityBucket: 1, MinSuccessRate: 0.5, PrivacyVersion: 1}
}

// THE test for this file. Three hops through one operator is three processes on
// one desktop: encrypted, verifiable, and providing no anonymity at all. It
// must refuse rather than return a route.
func TestOneOperatorCannotMakeAPrivateRoute(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"), cand("b", "acme", "d2"),
		cand("c", "acme", "d3"), cand("d", "acme", "d4"),
	}
	_, err := SelectRoute(candidates, req(), routeSeed)
	if err == nil {
		t.Fatal("built a three-hop route through a single operator")
	}
	var refusal *RouteRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("got %T, want *RouteRefusal", err)
	}
	if refusal.OperatorsFound != 1 || refusal.OperatorsNeeded != 3 {
		t.Errorf("refusal does not report the gap: %+v", refusal)
	}
}

func TestTwoOperatorsIsStillNotEnough(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"), cand("b", "acme", "d2"),
		cand("c", "beta", "d3"), cand("d", "beta", "d4"),
	}
	if _, err := SelectRoute(candidates, req(), routeSeed); err == nil {
		t.Fatal("built a three-hop route from two operators")
	}
}

func TestThreeOperatorsSucceedsAndIsDiverse(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"), cand("b", "beta", "d2"), cand("c", "gamma", "d3"),
	}
	route, err := SelectRoute(candidates, req(), routeSeed)
	if err != nil {
		t.Fatalf("refused a genuinely diverse set: %v", err)
	}
	if len(route) != 3 {
		t.Fatalf("got %d hops", len(route))
	}
	seen := map[string]bool{}
	for _, c := range route {
		if seen[c.Operator] {
			t.Fatalf("route reuses operator %q", c.Operator)
		}
		seen[c.Operator] = true
	}
}

// An unlabelled router cannot be shown independent of anything, so it must not
// count toward diversity — otherwise a swarm gains diversity by omitting a field.
func TestUnlabelledRoutersDoNotCountTowardDiversity(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"),
		{NodeID: "b", Operator: "", CapacityBucket: 5, SuccessRate: 0.9, PrivacyVersion: 1},
		{NodeID: "c", Operator: "", CapacityBucket: 5, SuccessRate: 0.9, PrivacyVersion: 1},
	}
	if _, err := SelectRoute(candidates, req(), routeSeed); err == nil {
		t.Fatal("unlabelled routers were counted as independent operators")
	}
}

// Fault-domain diversity is a stricter, separate ask, and its refusal must be
// distinguishable — relaxing it is a decision with a real cost.
func TestFaultDomainConstraintIsReportedSeparately(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "same"), cand("b", "beta", "same"), cand("c", "gamma", "same"),
	}
	r := req()
	// Without the constraint, three operators is a route.
	if _, err := SelectRoute(candidates, r, routeSeed); err != nil {
		t.Fatalf("refused three operators sharing a domain: %v", err)
	}
	// With it, refused — and the refusal must not claim operators were missing.
	r.RequireDistinctFaultDomains = true
	_, err := SelectRoute(candidates, r, routeSeed)
	if err == nil {
		t.Fatal("built a route with three hops in one fault domain")
	}
	var refusal *RouteRefusal
	if errors.As(err, &refusal) && refusal.OperatorsFound < 3 {
		t.Errorf("misreported an operator shortage: %+v", refusal)
	}
}

// Reusing a stable triple clusters a viewer's payments, so recently-used
// routers are avoided by default.
func TestRecentlyUsedRoutersAreAvoided(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"), cand("b", "beta", "d2"),
		cand("c", "gamma", "d3"), cand("d", "delta", "d4"),
	}
	r := req()
	r.AvoidNodes = map[NodeID]bool{"a": true}
	route, err := SelectRoute(candidates, r, routeSeed)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range route {
		if c.NodeID == "a" {
			t.Fatal("selected a router marked as recently used")
		}
	}
}

// Deterministic: a disputed route must be re-derivable by whoever questions it.
func TestSelectionIsReproducible(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"), cand("b", "beta", "d2"),
		cand("c", "gamma", "d3"), cand("d", "delta", "d4"),
	}
	first, err := SelectRoute(candidates, req(), routeSeed)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := SelectRoute(candidates, req(), routeSeed)
		if err != nil {
			t.Fatal(err)
		}
		for h := range first {
			if again[h].NodeID != first[h].NodeID {
				t.Fatalf("run %d differed at hop %d", i, h)
			}
		}
	}
}

// Different seeds must spread across the available routers, or the best-scoring
// three become the whole network's route and diversity is concentrated away.
func TestDifferentSeedsSpreadTheLoad(t *testing.T) {
	var candidates []Candidate
	for i := 0; i < 9; i++ {
		id := string(rune('a' + i))
		candidates = append(candidates, cand(id, "op"+id, "dom"+id))
	}
	seen := map[NodeID]bool{}
	for i := 0; i < 40; i++ {
		seed := [32]byte{byte(i), byte(i >> 8)}
		route, err := SelectRoute(candidates, req(), seed)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range route {
			seen[c.NodeID] = true
		}
	}
	if len(seen) < 5 {
		t.Errorf("only %d of 9 routers were ever chosen — selection is concentrated", len(seen))
	}
}

// Filters must exclude before diversity is counted, or a route is promised
// through routers that cannot carry it.
func TestFiltersApplyBeforeDiversityIsCounted(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"),
		func() Candidate { c := cand("b", "beta", "d2"); c.SuccessRate = 0.1; return c }(),
		func() Candidate { c := cand("c", "gamma", "d3"); c.CapacityBucket = 0; return c }(),
		func() Candidate { c := cand("d", "delta", "d4"); c.PrivacyVersion = 99; return c }(),
	}
	_, err := SelectRoute(candidates, req(), routeSeed)
	if err == nil {
		t.Fatal("counted unusable routers toward diversity")
	}
	var refusal *RouteRefusal
	if errors.As(err, &refusal) {
		if refusal.CandidatesBefore != 4 || refusal.CandidatesAfter != 1 {
			t.Errorf("refusal does not show what was filtered: %+v", refusal)
		}
	}
}

func TestDiversityOfCountsOperatorsNotNodes(t *testing.T) {
	candidates := []Candidate{
		cand("a", "acme", "d1"), cand("b", "acme", "d2"), cand("c", "beta", "d3"),
	}
	if got := DiversityOf(candidates); got != 2 {
		t.Errorf("DiversityOf = %d, want 2 operators from 3 nodes", got)
	}
}

func TestEmptyCandidateSetRefuses(t *testing.T) {
	if _, err := SelectRoute(nil, req(), routeSeed); err == nil {
		t.Fatal("built a route from no candidates")
	}
}
