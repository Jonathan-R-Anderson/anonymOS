package channel

// Choosing three routers.
//
// THIS FILE IS WHERE "THREE HOPS" EITHER MEANS SOMETHING OR DOES NOT
// ------------------------------------------------------------------
// Onion encryption distributes trust across three OPERATORS. Three hops through
// machines one party runs is three processes on one desktop: the packets are
// encrypted, the proofs verify, the diagrams are right, and the operator sees
// every hop. That is worse than having no privacy layer, because a system that
// looks private invites people to behave as though it is.
//
// So this selector REFUSES rather than degrades. If it cannot draw three
// independent operators it returns an error naming what was missing, and the
// caller must either fall back to a non-private path — telling the user so — or
// not send. There is deliberately no "best effort" mode: best effort here means
// a route that provides no anonymity while reporting success.
//
// CLAIMS ARE HINTS, NOT FACTS
// ---------------------------
// Operator and fault-domain labels are self-declared. A Sybil swarm declares
// exactly what an honest diverse set declares, so these are weighted and used
// to EXCLUDE, never to prove independence. Excluding on a claim is safe: the
// worst case is refusing a route that would have been fine. Trusting a claim is
// not: the worst case is a route through one party that reports three.

import (
	"errors"
	"sort"
)

// Candidate is a router the DHT offered. Everything here except NodeID is a
// hint (see above).
type Candidate struct {
	NodeID NodeID
	// Operator is who runs it, self-declared.
	Operator string
	// FaultDomain groups machines that fail together — ASN, host, region.
	FaultDomain string
	// CapacityBucket is a coarse band, never an exact balance: publishing exact
	// channel balances would let anyone map the network's liquidity.
	CapacityBucket int
	// SuccessRate over recent attempts, 0..1.
	SuccessRate float64
	LatencyMS   int
	// PrivacyVersion the router speaks. A route may not mix versions that
	// cannot interpret each other's onion.
	PrivacyVersion uint16
	// Jurisdiction is self-declared and unverifiable. Carried because users ask
	// for it; never presented as enforced.
	Jurisdiction string
}

// RouteRequest is what the payer wants.
type RouteRequest struct {
	Hops int
	// MinCapacityBucket filters routers too small for the payment.
	MinCapacityBucket int
	MinSuccessRate    float64
	PrivacyVersion    uint16
	// AvoidNodes are routers used recently for this session. Reusing a stable
	// triple clusters a viewer's payments, so repetition is avoided by default
	// rather than as an option.
	AvoidNodes map[NodeID]bool
	// RequireDistinctFaultDomains additionally demands three failure domains,
	// not merely three operators. Stricter, and correct when the concern is
	// correlated observation rather than only collusion.
	RequireDistinctFaultDomains bool
}

// RouteRefusal explains why no route could be drawn. Typed, because "not enough
// operators" and "not enough liquidity" have completely different remedies and
// only one of them is the user's problem.
type RouteRefusal struct {
	Reason           string
	OperatorsFound   int
	OperatorsNeeded  int
	CandidatesBefore int
	CandidatesAfter  int
}

func (r *RouteRefusal) Error() string { return r.Reason }

var ErrNoRoute = errors.New("channel: no route")

// SelectRoute draws a route, or refuses.
//
// Deterministic given the same inputs and seed, so a route can be re-derived
// when disputed — the same reasoning as provider selection for compute work.
func SelectRoute(candidates []Candidate, req RouteRequest, seed [32]byte) ([]Candidate, error) {
	if req.Hops <= 0 {
		req.Hops = MaxHops
	}
	before := len(candidates)

	// Filter first, on properties that are this node's own business to check.
	var usable []Candidate
	for _, c := range candidates {
		if c.NodeID == "" || c.Operator == "" {
			// An unlabelled router cannot be shown to be independent of
			// anything, so it cannot count toward diversity. Excluded rather
			// than treated as its own operator, which would let a swarm gain
			// diversity by omitting the field.
			continue
		}
		if req.AvoidNodes[c.NodeID] {
			continue
		}
		if c.CapacityBucket < req.MinCapacityBucket {
			continue
		}
		if c.SuccessRate < req.MinSuccessRate {
			continue
		}
		if req.PrivacyVersion != 0 && c.PrivacyVersion != req.PrivacyVersion {
			continue
		}
		usable = append(usable, c)
	}

	distinctOperators := map[string]bool{}
	for _, c := range usable {
		distinctOperators[c.Operator] = true
	}
	if len(distinctOperators) < req.Hops {
		return nil, &RouteRefusal{
			Reason: "not enough independent operators to build a private route; " +
				"routing anyway would provide no anonymity",
			OperatorsFound:   len(distinctOperators),
			OperatorsNeeded:  req.Hops,
			CandidatesBefore: before,
			CandidatesAfter:  len(usable),
		}
	}

	// Rank deterministically. Sorted by a score, then by NodeID so ties break
	// the same way for every party deriving this route.
	sort.Slice(usable, func(i, j int) bool {
		si, sj := score(usable[i], seed), score(usable[j], seed)
		if si != sj {
			return si > sj
		}
		return usable[i].NodeID < usable[j].NodeID
	})

	// Greedy pick under the diversity constraint: take the best candidate whose
	// operator (and optionally fault domain) is unused.
	var chosen []Candidate
	usedOperator := map[string]bool{}
	usedDomain := map[string]bool{}
	for _, c := range usable {
		if usedOperator[c.Operator] {
			continue
		}
		if req.RequireDistinctFaultDomains && c.FaultDomain != "" && usedDomain[c.FaultDomain] {
			continue
		}
		chosen = append(chosen, c)
		usedOperator[c.Operator] = true
		if c.FaultDomain != "" {
			usedDomain[c.FaultDomain] = true
		}
		if len(chosen) == req.Hops {
			return chosen, nil
		}
	}

	// Enough operators existed but the fault-domain constraint could not be
	// met. Reported distinctly: relaxing it is a decision with a real cost, and
	// the caller should make it knowingly rather than have it made here.
	return nil, &RouteRefusal{
		Reason: "not enough independent fault domains to build a private route " +
			"under the requested constraints",
		OperatorsFound:   len(distinctOperators),
		OperatorsNeeded:  req.Hops,
		CandidatesBefore: before,
		CandidatesAfter:  len(usable),
	}
}

// score ranks a candidate. Success rate dominates, latency breaks near-ties.
//
// Capacity is deliberately NOT scored beyond the filter: it is self-reported
// and cheap to inflate, so rewarding a larger claim would pay routers to lie.
// It is used to exclude the obviously-too-small and nothing more.
func score(c Candidate, seed [32]byte) float64 {
	s := c.SuccessRate * 100
	if c.LatencyMS > 0 {
		// Diminishing penalty: the difference between 50ms and 100ms matters,
		// between 2s and 3s barely does once I2P dominates the total anyway.
		s -= float64(c.LatencyMS) / 100.0
	}
	// A small deterministic jitter from the seed, so the same handful of
	// routers do not win every draw across the whole network. Without it the
	// best-scoring three become the de facto route for everyone, which
	// concentrates exactly what diversity is meant to spread.
	j := derive("syndichan/route/jitter/v1", []byte(c.NodeID), seed[:])
	s += float64(j[0]) / 255.0
	return s
}

// DiversityOf reports how many distinct operators a set of candidates
// represents.
//
// Exported so the UI can say "2 operators available" rather than only failing
// at send time. A user deciding whether to send privately deserves to know the
// anonymity set before they commit, not after.
func DiversityOf(candidates []Candidate) int {
	seen := map[string]bool{}
	for _, c := range candidates {
		if c.Operator != "" {
			seen[c.Operator] = true
		}
	}
	return len(seen)
}
