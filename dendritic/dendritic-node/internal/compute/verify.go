package compute

// M5 — proof of computation.
//
// The roadmap calls this the crux, and it is, but not uniformly: the CPU case
// is tractable and the GPU case is genuinely hard. This file builds the
// tractable one and refuses to pretend it also solves the other.
//
// WHY CPU IS EASY AND GPU IS NOT
// ------------------------------
// Two CPUs running the same IEEE-754 code over the same input produce
// byte-identical output. Two GPUs generally do not: warp scheduling changes
// reduction order, fused multiply-add fires at the compiler's discretion,
// driver versions select different kernels, and atomicAdd on floats is
// non-deterministic by construction. Those results are all CORRECT. They are
// not EQUAL.
//
// So for deterministic (CPU) work, verification is redundant execution and a
// digest comparison — cheap, total, and needing no novel cryptography. For
// non-deterministic (GPU) work it is not, and this file returns
// VerdictUndecidable rather than a false answer. An undecidable verdict is
// useful: it tells the caller to escalate to tolerance-windowed comparison or
// a spot-check recomputation, which are M5's harder half.
//
// WHY DISAGREEMENT IS NOT FRAUD
// -----------------------------
// Two replicas disagreeing proves that at least one is wrong. It does not say
// which, and treating the minority as the liar is how an honest node with a
// failing DIMM gets slashed while a coordinated pair of cheats agrees with each
// other. So this file reports what happened and leaves punishment to the
// dispute process, which can bond, escalate and be appealed. Verification finds
// disagreement; adjudication assigns blame.

import (
	"fmt"
	"sort"
)

// Verdict is the outcome of checking a result.
type Verdict string

const (
	// VerdictAgreed — enough replicas returned the same output.
	VerdictAgreed Verdict = "agreed"
	// VerdictDisagreed — replicas returned different outputs. Somebody is
	// wrong; this does not say who.
	VerdictDisagreed Verdict = "disagreed"
	// VerdictInsufficient — not enough usable replies to decide yet. A
	// scheduling state, not a judgement.
	VerdictInsufficient Verdict = "insufficient"
	// VerdictUndecidable — the work is not deterministic, so equality is the
	// wrong question and this method cannot answer it.
	VerdictUndecidable Verdict = "undecidable"
	// VerdictFailed — every replica reported the unit could not be completed.
	// Agreement about failure IS agreement, and worth distinguishing: it means
	// stop reissuing.
	VerdictFailed Verdict = "failed"
)

// Check is the result of verifying one unit.
type Check struct {
	Verdict Verdict `json:"verdict"`
	// Output is the agreed digest, empty unless VerdictAgreed.
	Output string `json:"output,omitempty"`
	// Agreeing and Dissenting name nodes. Both are recorded even on agreement:
	// who was right is what M8 reputation is built from, and it cannot be
	// reconstructed later.
	Agreeing   []string `json:"agreeing,omitempty"`
	Dissenting []string `json:"dissenting,omitempty"`
	Reason     string   `json:"reason"`
}

// Quorum is how many agreeing replicas a result needs.
//
// Two is the minimum that means anything, and it is what this defaults to for
// ordinary work: one replica proves nothing, since a node that returns
// plausible garbage is exactly the case being defended against.
//
// It is a parameter rather than a constant because the right number is an
// economic decision, not a technical one — high-value work buys more replicas,
// and the marketplace (M7) is where that is priced.
type Quorum struct {
	Need int
}

// DefaultQuorum requires two independent agreeing results.
func DefaultQuorum() Quorum { return Quorum{Need: 2} }

// Verify checks a set of replica results for one unit.
//
// Takes the Unit, not just the results, because whether equality is even the
// right question is a property of the work — u.Deterministic — and asking the
// results would mean trusting the thing being checked to describe itself.
func Verify(u Unit, results []UnitResult, quorum Quorum) Check {
	if quorum.Need <= 0 {
		quorum = DefaultQuorum()
	}

	digest := u.Digest()
	var usable []UnitResult
	var mismatched []string
	failures := 0

	for _, r := range results {
		// A result naming a different unit is not evidence about this one.
		// Content addressing makes this checkable rather than trusted: a result
		// cannot be re-attributed by relabelling it.
		if r.Unit != digest {
			mismatched = append(mismatched, r.Node)
			continue
		}
		if r.Failed {
			failures++
			continue
		}
		// A partial result is a checkpoint, not an answer. Counting one toward
		// quorum would let a node bank credit for stopping early.
		if r.Progress < 100 || r.Output == "" {
			continue
		}
		usable = append(usable, r)
	}

	if failures > 0 && len(usable) == 0 && failures >= quorum.Need {
		return Check{
			Verdict: VerdictFailed,
			Reason: fmt.Sprintf("%d node(s) independently could not complete this unit; "+
				"reissuing it will not help", failures),
			Agreeing: nodesOf(results),
		}
	}

	if len(usable) < quorum.Need {
		return Check{
			Verdict: VerdictInsufficient,
			Reason: fmt.Sprintf("%d usable result(s), %d needed",
				len(usable), quorum.Need),
			Dissenting: mismatched,
		}
	}

	// Group by output digest. For deterministic work every honest node lands in
	// one group; more than one group means at least one node is wrong.
	groups := map[string][]string{}
	for _, r := range usable {
		groups[r.Output] = append(groups[r.Output], r.Node)
	}

	if !u.Deterministic {
		// Equality is the wrong question here and answering it anyway would be
		// worse than not answering. Two honest GPUs differ in the last bits;
		// calling that disagreement would mark correct work as fraud, and
		// calling a coincidental match agreement would pass garbage.
		return Check{
			Verdict: VerdictUndecidable,
			Reason: "this unit is not deterministic, so identical output is not " +
				"expected and its absence is not evidence — needs tolerance " +
				"comparison or a spot-check recomputation",
			Agreeing: nodesOf(usable),
		}
	}

	best, bestNodes := "", []string(nil)
	for output, nodes := range groups {
		if len(nodes) > len(bestNodes) {
			best, bestNodes = output, nodes
		}
	}

	if len(bestNodes) < quorum.Need {
		// Every group is below quorum: the replicas disagree and none has
		// enough support to be believed.
		return Check{
			Verdict:    VerdictDisagreed,
			Dissenting: nodesOf(usable),
			Reason: fmt.Sprintf("%d node(s) returned %d different outputs for deterministic "+
				"work; at least one is wrong, and which is a question for the dispute "+
				"process rather than for this check", len(usable), len(groups)),
		}
	}

	var dissenting []string
	for output, nodes := range groups {
		if output != best {
			dissenting = append(dissenting, nodes...)
		}
	}
	dissenting = append(dissenting, mismatched...)
	sort.Strings(dissenting)
	sort.Strings(bestNodes)

	if len(dissenting) > 0 {
		// Quorum reached AND somebody disagreed. Both facts matter: the result
		// stands, and the dissent is recorded rather than discarded — it is
		// either a failing machine or an attempt, and reputation needs to see
		// it either way.
		return Check{
			Verdict:    VerdictAgreed,
			Output:     best,
			Agreeing:   bestNodes,
			Dissenting: dissenting,
			Reason: fmt.Sprintf("%d of %d nodes agreed; %d dissented and are recorded",
				len(bestNodes), len(usable), len(dissenting)),
		}
	}

	return Check{
		Verdict:  VerdictAgreed,
		Output:   best,
		Agreeing: bestNodes,
		Reason:   fmt.Sprintf("%d nodes independently produced the same output", len(bestNodes)),
	}
}

// Replicas is how many workers a unit should be sent to.
//
// Quorum + 1 for deterministic work: one spare, so a single node going offline
// does not force a second scheduling round. Non-deterministic work gets the
// same count, but the extra replica buys a tolerance comparison rather than a
// digest match — it is the same redundancy serving a harder check.
func Replicas(u Unit, quorum Quorum) int {
	if quorum.Need <= 0 {
		quorum = DefaultQuorum()
	}
	return quorum.Need + 1
}

func nodesOf(results []UnitResult) []string {
	var out []string
	for _, r := range results {
		if r.Node != "" {
			out = append(out, r.Node)
		}
	}
	sort.Strings(out)
	return out
}
