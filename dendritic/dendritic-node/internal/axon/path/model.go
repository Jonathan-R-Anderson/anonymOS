package path

// model.go is E12.4: the published model behind E12.3's claim.
//
// E12.3 says the measured fraction of circuits with a compromised
// first-and-last pair must match "the published model within a stated
// tolerance". A model that exists only as a closed form in a document is not
// falsifiable by a third party — they would have to trust the derivation and
// the parameters both. So the model is CODE, it lives beside the selector, and
// E12.3 is the test that the selector's empirical distribution agrees with it.
//
// It is an exact enumeration rather than a formula. Sequential weighted draw
// without replacement under a pairwise diversity filter has no clean closed
// form: the admissible set and the normalising constant both change after every
// hop, and the standard f^2 approximation silently assumes neither does. On a
// small network with real address concentration that approximation is wrong in
// the flattering direction, which is the direction that matters.
//
// WHAT THIS MODEL DOES NOT ESTABLISH. It shares the diversity predicate
// (conflicts) with the selector, so it tests that the DRAW is unbiased, not
// that the predicate is correct. If conflicts were wrong, model and selector
// would agree on the same wrong answer. T12.1 and E12.1 test the predicate
// directly and independently, which is why both kinds of test exist.

// CompromiseModel is the exact distribution of first-and-last compromise for
// one candidate set under one policy.
type CompromiseModel struct {
	// FirstAndLast is P(hop 0 hostile AND hop n-1 hostile).
	FirstAndLast float64
	// AnyHop is P(at least one hop hostile), reported because a reader who sees
	// only FirstAndLast will read it as the whole exposure.
	AnyHop float64
	// NoPath is the probability mass on prefixes from which no complete path
	// exists. It is not zero on a small or concentrated network, and folding it
	// into the other two would understate them.
	NoPath float64
}

// ExactCompromise enumerates every path the selector could draw and sums the
// exact probability of each.
//
// weight must be the same function the selector would apply; hostile marks the
// adversary's relays. cands must already be the admissible pool, sorted.
func ExactCompromise(cands []Relay, n int, c DiversityConstraint, weight func(Relay) float64, hostile func(Relay) bool) CompromiseModel {
	var m CompromiseModel
	if n <= 0 || len(cands) == 0 {
		m.NoPath = 1
		return m
	}
	chosen := make([]Relay, 0, n)
	var walk func(depth int, prob float64)
	walk = func(depth int, prob float64) {
		if prob == 0 {
			return
		}
		if depth == n {
			if hostile(chosen[0]) && hostile(chosen[n-1]) {
				m.FirstAndLast += prob
			}
			for _, r := range chosen {
				if hostile(r) {
					m.AnyHop += prob
					break
				}
			}
			return
		}
		// Same two steps as the selector, in the same order: filter by the
		// constraint, then weight within what survives.
		total := 0.0
		idx := make([]int, 0, len(cands))
		ws := make([]float64, 0, len(cands))
		for i, cand := range cands {
			if used(chosen, cand.NodeID) || conflicts(cand, chosen, c) {
				continue
			}
			w := weight(cand)
			if w <= 0 {
				continue
			}
			idx = append(idx, i)
			ws = append(ws, w)
			total += w
		}
		if total == 0 {
			m.NoPath += prob
			return
		}
		for j, i := range idx {
			chosen = append(chosen, cands[i])
			walk(depth+1, prob*ws[j]/total)
			chosen = chosen[:len(chosen)-1]
		}
	}
	walk(0, 1)
	return m
}
