package channel

// Splitting one payment across several independent routes.
//
// WHAT SPLITTING DOES AND DOES NOT BUY
// ------------------------------------
// It divides an amount. It does not divide knowledge. If the same operator sits
// on two of the three routes, splitting hands that operator two views and a
// partial sum — it has multiplied the observable events without adding an
// observer to hide from, which is strictly worse than not splitting at all.
//
// So `Split` refuses when the fragments cannot take genuinely independent
// paths, for the same reason `SelectRoute` refuses a single-operator route. The
// failure mode being avoided is identical: a feature that looks like privacy
// while providing none.
//
// WHY FRAGMENTS ARE UNEQUAL
// -------------------------
// Three equal thirds arriving at once are a signature — they reassemble on
// sight. Fragment sizes are therefore drawn unevenly, and not from a fixed
// ladder either, since a predictable set of sizes is only marginally better
// than equal ones.
//
// There is a floor, and it matters in the other direction: a fragment far
// smaller than a normal payment stands out precisely BECAUSE it is unusual. A
// fragment should look like an ordinary payment, which is why very small totals
// are not split at all.

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sort"
)

var (
	ErrTooSmallToSplit = errors.New("channel: payment is too small to split usefully")
	ErrNotEnoughRoutes = errors.New("channel: not enough independent routes to split across")
	ErrFragmentSum     = errors.New("channel: fragments do not sum to the payment")
)

// MinFragment is the smallest fragment worth sending.
//
// Below this a fragment is conspicuous rather than concealing, and it still
// costs a full three-hop forward. Payments smaller than 2×MinFragment are sent
// whole.
const MinFragment Amount = 1000

// MaxFragments bounds the split. More fragments means more routes, more locks
// and more chances one stalls — and the anonymity gain flattens quickly once
// the operator set is the binding constraint, which it always is here.
const MaxFragments = 4

// Fragment is one part of a split payment.
type Fragment struct {
	Amount Amount
	Route  []Candidate
	// Locks are this fragment's own per-hop points. Every fragment gets its own
	// chain even though they share the recipient's secret — otherwise two
	// fragments would carry identical locks and be trivially linkable as parts
	// of one payment.
	Locks *LockChain
}

// SplitPlan is a whole payment, divided.
type SplitPlan struct {
	Total     Amount
	Fragments []Fragment
}

// ShouldSplit reports whether a payment is worth splitting, and why not.
//
// Returns a reason rather than a bare bool so a caller can tell a user "this is
// too small to split" instead of silently sending it whole — the difference
// between a considered decision and an apparent one.
func ShouldSplit(total Amount, routesAvailable int) (bool, string) {
	if total < 2*MinFragment {
		return false, "too small to split without producing conspicuous fragments"
	}
	if routesAvailable < 2 {
		return false, "not enough independent routes to split across"
	}
	return true, ""
}

// Split divides a payment into unequal fragments over independent routes.
//
// Each route must come from a DIFFERENT set of operators. That is checked here
// rather than assumed from SelectRoute having been called per fragment: three
// separately-valid routes can still share an operator between them, and the
// whole point of splitting is defeated exactly then.
func Split(c Curve, recipient Point, total Amount, routes [][]Candidate) (*SplitPlan, error) {
	if ok, _ := ShouldSplit(total, len(routes)); !ok {
		return nil, ErrTooSmallToSplit
	}
	if len(routes) < 2 {
		return nil, ErrNotEnoughRoutes
	}
	if len(routes) > MaxFragments {
		routes = routes[:MaxFragments]
	}

	// Cross-route independence. A route is only useful as a fragment carrier if
	// it shares no operator with any other fragment's route.
	usable := independentRoutes(routes)
	if len(usable) < 2 {
		return nil, ErrNotEnoughRoutes
	}

	// Cap the fragment count so no fragment falls below the floor.
	maxByFloor := int(total / MinFragment)
	n := len(usable)
	if maxByFloor < n {
		n = maxByFloor
	}
	if n < 2 {
		return nil, ErrTooSmallToSplit
	}
	usable = usable[:n]

	amounts, err := unevenSplit(total, n)
	if err != nil {
		return nil, err
	}

	plan := &SplitPlan{Total: total}
	for i, route := range usable {
		locks, err := BuildLocks(c, recipient, len(route))
		if err != nil {
			return nil, err
		}
		plan.Fragments = append(plan.Fragments, Fragment{
			Amount: amounts[i], Route: route, Locks: locks,
		})
	}
	if err := plan.Verify(); err != nil {
		return nil, err
	}
	return plan, nil
}

// independentRoutes keeps a maximal set of routes sharing no operator.
//
// Greedy: take routes in order, skipping any that reuses an operator already
// committed. Deterministic, so the same candidate set produces the same plan
// and a disputed split can be re-derived.
func independentRoutes(routes [][]Candidate) [][]Candidate {
	var kept [][]Candidate
	used := map[string]bool{}
	for _, route := range routes {
		clash := false
		for _, hop := range route {
			// An unlabelled hop cannot be shown independent of anything, so a
			// route containing one cannot be counted toward cross-route
			// independence — the same rule SelectRoute applies within a route.
			if hop.Operator == "" || used[hop.Operator] {
				clash = true
				break
			}
		}
		if clash {
			continue
		}
		for _, hop := range route {
			used[hop.Operator] = true
		}
		kept = append(kept, route)
	}
	return kept
}

// unevenSplit divides total into n fragments, none below MinFragment, summing
// exactly to total.
//
// Random weights rather than a fixed ladder: a predictable set of proportions
// is only marginally harder to reassemble than equal thirds. The remainder is
// added to the largest fragment, so rounding never produces a sub-floor piece.
func unevenSplit(total Amount, n int) ([]Amount, error) {
	if n < 2 {
		return nil, ErrTooSmallToSplit
	}
	// Reserve the floor for every fragment, then distribute what is left by
	// random weight. This guarantees the floor rather than hoping for it.
	reserved := MinFragment * Amount(n)
	if reserved > total {
		return nil, ErrTooSmallToSplit
	}
	spare := total - reserved

	weights := make([]int64, n)
	var sum int64
	for i := range weights {
		w, err := rand.Int(rand.Reader, big.NewInt(1000))
		if err != nil {
			return nil, err
		}
		weights[i] = w.Int64() + 1 // never zero, so no fragment is only the floor
		sum += weights[i]
	}

	out := make([]Amount, n)
	var assigned Amount
	for i := range out {
		share := Amount(int64(spare) * weights[i] / sum)
		out[i] = MinFragment + share
		assigned += out[i]
	}
	// Rounding remainder goes to the largest fragment: adding it to the
	// smallest could push a fragment to an oddly precise value, and the largest
	// absorbs it least conspicuously.
	if remainder := total - assigned; remainder != 0 {
		largest := 0
		for i := range out {
			if out[i] > out[largest] {
				largest = i
			}
		}
		out[largest] += remainder
	}
	return out, nil
}

// Verify checks a plan is internally consistent before anything is sent.
//
// The sum check is the one that must never be skipped: fragments that do not
// add up mean either the recipient is short-paid or the payer is over-charged,
// and both are silent until somebody reconciles.
func (p *SplitPlan) Verify() error {
	if p == nil || len(p.Fragments) < 2 {
		return ErrNotEnoughRoutes
	}
	var sum Amount
	seenOperators := map[string]bool{}
	for _, f := range p.Fragments {
		if f.Amount < MinFragment {
			return ErrTooSmallToSplit
		}
		sum += f.Amount
		for _, hop := range f.Route {
			if seenOperators[hop.Operator] {
				return ErrNotEnoughRoutes
			}
			seenOperators[hop.Operator] = true
		}
	}
	if sum != p.Total {
		return ErrFragmentSum
	}
	return nil
}

// AllEqual reports whether every fragment is the same size — the signature the
// uneven split exists to avoid. Exported so a test, or a caller auditing a
// plan, can assert against it directly.
func (p *SplitPlan) AllEqual() bool {
	if p == nil || len(p.Fragments) < 2 {
		return false
	}
	first := p.Fragments[0].Amount
	for _, f := range p.Fragments[1:] {
		if f.Amount != first {
			return false
		}
	}
	return true
}

// Sizes returns fragment amounts, sorted, for inspection.
func (p *SplitPlan) Sizes() []Amount {
	out := make([]Amount, 0, len(p.Fragments))
	for _, f := range p.Fragments {
		out = append(out, f.Amount)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
