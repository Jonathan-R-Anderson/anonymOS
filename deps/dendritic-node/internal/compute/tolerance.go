package compute

// M5, GPU half — verifying work whose correct answers are not equal.
//
// verify.go compares digests, which is total and cheap and works for anything
// bit-reproducible. GPUs are not. Different warp scheduling changes the order of
// a reduction, fused multiply-add contracts differently, a driver update selects
// a different kernel, and `atomicAdd` on floats is non-deterministic by
// construction. Two honest cards return two different answers and both are
// correct. Hashing them says "disagreed", which would mark honest work as fraud.
//
// So agreement has to be defined numerically. That sounds like a small change
// and is not, because of one property:
//
// TOLERANCE IS NOT TRANSITIVE
// ---------------------------
// a≈b and b≈c does not give a≈c. Which means the obvious implementation — walk
// the results, put each into the first group it is close to — produces groups
// that depend on the ORDER the results arrived in. Two verifiers holding the
// same replies would reach different verdicts, and a verdict that cannot be
// reproduced cannot be audited, disputed, or paid on.
//
// It is also exploitable directly: a chain of values each within tolerance of
// its neighbour spans an arbitrarily wide range, so a naive clustering can be
// walked from a correct answer to a wrong one in small steps, with every
// adjacent pair looking fine.
//
// The fix is to stop comparing pairwise. Agreement is measured against a single
// ANCHOR: the element-wise median of all replies. Every node is compared to the
// same value, so the relation is order-independent by construction, chaining is
// impossible, and the answer is identical no matter who computes it.
//
// The median rather than the mean, because the mean is what an attacker moves.
// One node returning 10^12 drags a mean anywhere it likes; the median of an
// odd number of replies is a value some node actually returned, and moving it
// requires controlling half of them — which is the same threshold the quorum
// already assumes.
//
// WHAT THIS COSTS, STATED PLAINLY
// -------------------------------
// A tolerance window is the size of the lie that cannot be detected. Bit-exact
// comparison catches a wrong answer in the last bit; tolerance comparison
// cannot, by design, because that is the thing it exists to permit. A
// dishonest node that returns a value just inside the window is indistinguishable
// from an honest one with different rounding.
//
// So this is a WEAKER guarantee than verify.go's, and it should be used only
// where bit-exactness is genuinely unavailable — never as a convenience for
// deterministic work. Where the stakes justify it, the answer is not a wider
// quorum but a spot-check recomputation on a node with a track record, which is
// what SpotCheckNeeded exists to trigger.

import (
	"math"
	"sort"
)

// Tolerance is how far apart two answers may be and still count as the same.
//
// Both terms are needed and neither works alone. Pure relative tolerance
// collapses near zero — the relative difference between 1e-18 and 2e-18 is
// 100%, though for most work both are indistinguishable from zero. Pure
// absolute tolerance is meaningless at scale: 1e-6 is a rounding artefact next
// to 1e9 and a catastrophe next to 1e-9.
type Tolerance struct {
	// Relative is the fraction of the anchor's magnitude allowed.
	Relative float64
	// Absolute is the floor, which is what makes values near zero comparable.
	Absolute float64
}

// DefaultTolerance suits float32 GPU work.
//
// 1e-5 relative because float32 carries ~7 decimal digits and a long reduction
// loses two or three of them to ordering alone. Tighter than this reports
// honest cards as disagreeing, which is the failure mode that matters: it
// destroys the reputation of nodes doing exactly what was asked.
func DefaultTolerance() Tolerance {
	return Tolerance{Relative: 1e-5, Absolute: 1e-8}
}

// StrictTolerance suits float64 work that is *nearly* reproducible.
func StrictTolerance() Tolerance {
	return Tolerance{Relative: 1e-12, Absolute: 1e-15}
}

// Close reports whether a is within tolerance of the anchor.
//
// Not symmetric, deliberately: the tolerance is scaled by the ANCHOR's
// magnitude, not by whichever of the two happens to be larger. Since every
// comparison in this file is against the median, that asymmetry is exactly
// what keeps the relation order-independent.
func (t Tolerance) Close(value, anchor float64) bool {
	// NaN is not close to anything, including itself — but two nodes both
	// returning NaN have agreed, and that is handled by the caller rather than
	// here, because "both failed the same way" is a different statement from
	// "both computed the same number".
	if math.IsNaN(value) || math.IsNaN(anchor) {
		return false
	}
	if math.IsInf(value, 0) || math.IsInf(anchor, 0) {
		// Infinities agree only with identical infinities. A tolerance window
		// around infinity is meaningless, and treating +Inf as close to a very
		// large finite number would let an overflow pass as a correct result.
		return value == anchor
	}
	diff := math.Abs(value - anchor)
	return diff <= t.Absolute+t.Relative*math.Abs(anchor)
}

// ApproxResult is one node's numeric answer.
//
// Separate from UnitResult because that carries a DIGEST of the output blob,
// which is precisely what cannot be compared here — the caller fetches the
// blob and parses it, and this type is what comes back.
type ApproxResult struct {
	Node   string
	Values []float64
	Failed bool
}

// VerifyApprox decides whether non-deterministic replicas agree.
//
// Returns the same Check type as verify.go so a caller does not have to branch
// on which verification method was used — the verdict means the same thing, it
// was just reached differently.
func VerifyApprox(u Unit, results []ApproxResult, quorum Quorum, tol Tolerance) Check {
	if quorum.Need <= 0 {
		quorum = DefaultQuorum()
	}

	var usable []ApproxResult
	var failed []string
	for _, r := range results {
		if r.Failed {
			failed = append(failed, r.Node)
			continue
		}
		if r.Values == nil {
			// A result with no parsed values is not a zero-length answer, it is
			// an answer nobody could read. Counting it as usable would let an
			// unparseable blob vote.
			continue
		}
		usable = append(usable, r)
	}

	if len(usable) == 0 {
		if len(failed) > 0 {
			return Check{
				Verdict:  VerdictFailed,
				Reason:   "every replica reported the unit could not be completed",
				Agreeing: append([]string(nil), failed...),
			}
		}
		return Check{Verdict: VerdictInsufficient, Reason: "no usable replies"}
	}
	if len(usable) < quorum.Need {
		return Check{
			Verdict: VerdictInsufficient,
			Reason:  "fewer usable replies than the quorum needs",
		}
	}

	// Differing lengths are a disagreement about the SHAPE of the answer, which
	// no tolerance can bridge. Checked before any arithmetic so a short vector
	// cannot be silently compared element-wise against a long one.
	width := len(usable[0].Values)
	for _, r := range usable[1:] {
		if len(r.Values) != width {
			return Check{
				Verdict:    VerdictDisagreed,
				Reason:     "replicas returned different numbers of values",
				Dissenting: approxNodes(usable),
			}
		}
	}

	anchor := elementwiseMedian(usable, width)

	var agreeing, dissenting []string
	for _, r := range usable {
		if withinAll(r.Values, anchor, tol) {
			agreeing = append(agreeing, r.Node)
		} else {
			dissenting = append(dissenting, r.Node)
		}
	}
	// Sorted so the Check is byte-identical between verifiers. Map iteration is
	// not involved here, but the input slice order is caller-controlled, and a
	// verdict that differs by input order is not reproducible.
	sort.Strings(agreeing)
	sort.Strings(dissenting)

	if len(agreeing) < quorum.Need {
		return Check{
			Verdict: VerdictDisagreed,
			Reason: "no group of replicas agrees to within tolerance; " +
				"the answers are too far apart for any to be believed",
			Agreeing:   agreeing,
			Dissenting: dissenting,
		}
	}

	return Check{
		Verdict: VerdictAgreed,
		Reason: "replicas agree to within tolerance of the element-wise median" +
			spotCheckNote(len(dissenting)),
		Agreeing:   agreeing,
		Dissenting: dissenting,
	}
}

func spotCheckNote(dissenting int) string {
	if dissenting == 0 {
		return ""
	}
	return " (some replicas dissent — a spot check is warranted)"
}

// withinAll reports whether every element is close to its anchor.
//
// ALL, not most. A single wrong element is a wrong answer: partial credit on a
// vector would let a node return mostly-correct output and be paid for it,
// which is a strictly easier attack than computing the thing properly.
func withinAll(values, anchor []float64, tol Tolerance) bool {
	for i := range anchor {
		a, b := values[i], anchor[i]
		// Both NaN at the same index is agreement about a value that is
		// genuinely not a number — an overflow both nodes reached honestly.
		// Only one NaN is a disagreement.
		if math.IsNaN(a) && math.IsNaN(b) {
			continue
		}
		if !tol.Close(a, b) {
			return false
		}
	}
	return true
}

// elementwiseMedian builds the anchor.
//
// Per element rather than one median over everything: the values in a result
// vector are unrelated quantities, and a single median across all of them would
// anchor element 0 to a number that came from element 900.
func elementwiseMedian(results []ApproxResult, width int) []float64 {
	anchor := make([]float64, width)
	column := make([]float64, 0, len(results))
	for i := 0; i < width; i++ {
		column = column[:0]
		for _, r := range results {
			column = append(column, r.Values[i])
		}
		anchor[i] = median(column)
	}
	return anchor
}

// median of a slice it is allowed to reorder.
//
// NaNs are sorted to the end and excluded from the count, so a single node
// returning NaN cannot drag the anchor. If every value is NaN the median is
// NaN, which is correct: that is what the replicas actually agreed on.
func median(values []float64) float64 {
	sort.Float64s(values)
	n := len(values)
	for n > 0 && math.IsNaN(values[n-1]) {
		n--
	}
	if n == 0 {
		return math.NaN()
	}
	if n%2 == 1 {
		return values[n/2]
	}
	// Even count: the lower of the two middles rather than their mean.
	//
	// The mean would invent a value no node returned, and for infinities it
	// produces NaN — (+Inf + -Inf)/2 — turning a clean disagreement into an
	// anchor nothing can match.
	return values[n/2-1]
}

func approxNodes(results []ApproxResult) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.Node)
	}
	sort.Strings(out)
	return out
}

// SpotCheckNeeded reports whether a unit should be recomputed on a node with a
// track record, despite having reached a verdict.
//
// Tolerance agreement is weaker than bit-exact agreement (see the file
// comment), so for non-deterministic work the quorum is a filter rather than a
// proof. A spot check is the thing that makes returning a plausible-but-wrong
// answer unprofitable: it cannot be predicted, and being caught costs more than
// the work saved.
//
// Triggered when anyone dissented — the cheapest signal that the window is
// doing real work — and otherwise sampled at random by the caller, which is
// why this takes the sample decision rather than making it. A deterministic
// spot-check schedule is one a dishonest node can wait out.
func SpotCheckNeeded(check Check, sampled bool) bool {
	switch check.Verdict {
	case VerdictAgreed:
		return sampled || len(check.Dissenting) > 0
	case VerdictDisagreed:
		// Already known to be in trouble; a spot check is how it is resolved.
		return true
	default:
		return false
	}
}
