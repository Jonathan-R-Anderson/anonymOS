package compute

import (
	"math"
	"math/rand"
	"reflect"
	"testing"
)

func approxUnit() Unit {
	return Unit{Deterministic: false}
}

func res(node string, values ...float64) ApproxResult {
	return ApproxResult{Node: node, Values: values}
}

// Honest GPUs differing in the last bits must agree. This is the whole reason
// the file exists: hashing would call this fraud.
func TestHonestFloatDriftAgrees(t *testing.T) {
	results := []ApproxResult{
		res("a", 1.0000001, 2.0000002, 3.0),
		res("b", 1.0000002, 2.0000001, 3.0000001),
		res("c", 1.0, 2.0, 3.0),
	}
	got := VerifyApprox(approxUnit(), results, Quorum{Need: 2}, DefaultTolerance())
	if got.Verdict != VerdictAgreed {
		t.Fatalf("got %s (%s)", got.Verdict, got.Reason)
	}
	if len(got.Agreeing) != 3 {
		t.Errorf("agreeing = %v, want all three", got.Agreeing)
	}
}

// THE headline property. Tolerance is not transitive, so a verdict must not
// depend on the order replies arrived in — two verifiers must agree, or the
// verdict cannot be audited or paid on.
func TestVerdictIsIndependentOfResultOrder(t *testing.T) {
	base := []ApproxResult{
		res("a", 1.0),
		res("b", 1.000004),
		res("c", 1.000008),
		res("d", 5.0),
	}
	want := VerifyApprox(approxUnit(), base, Quorum{Need: 2}, DefaultTolerance())

	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		shuffled := append([]ApproxResult(nil), base...)
		rng.Shuffle(len(shuffled), func(x, y int) {
			shuffled[x], shuffled[y] = shuffled[y], shuffled[x]
		})
		got := VerifyApprox(approxUnit(), shuffled, Quorum{Need: 2}, DefaultTolerance())
		if got.Verdict != want.Verdict {
			t.Fatalf("order changed the verdict: %s vs %s", got.Verdict, want.Verdict)
		}
		if !reflect.DeepEqual(got.Agreeing, want.Agreeing) {
			t.Fatalf("order changed who agreed: %v vs %v", got.Agreeing, want.Agreeing)
		}
		if !reflect.DeepEqual(got.Dissenting, want.Dissenting) {
			t.Fatalf("order changed who dissented: %v vs %v", got.Dissenting, want.Dissenting)
		}
	}
}

// Chaining: values each within tolerance of their neighbour span a range far
// wider than the tolerance. Anchoring on the median makes this impossible;
// pairwise grouping would have swept the whole chain into one group.
func TestChainedValuesDoNotAllAgree(t *testing.T) {
	tol := Tolerance{Relative: 0, Absolute: 1.0}
	// Each is within 1.0 of the next, but the ends are 6 apart.
	results := []ApproxResult{
		res("a", 0), res("b", 1), res("c", 2),
		res("d", 3), res("e", 4), res("f", 5), res("g", 6),
	}
	got := VerifyApprox(approxUnit(), results, Quorum{Need: 2}, tol)
	for _, node := range got.Agreeing {
		if node == "a" || node == "g" {
			t.Fatalf("both ends of a chain agreed: %v", got.Agreeing)
		}
	}
}

// An outlier must not drag the anchor. The mean would follow it anywhere; the
// median of an odd count is a value some node actually returned.
func TestExtremeOutlierCannotMoveTheAnchor(t *testing.T) {
	results := []ApproxResult{
		res("a", 1.0), res("b", 1.0), res("c", 1.0), res("liar", 1e12),
	}
	got := VerifyApprox(approxUnit(), results, Quorum{Need: 3}, DefaultTolerance())
	if got.Verdict != VerdictAgreed {
		t.Fatalf("got %s (%s)", got.Verdict, got.Reason)
	}
	if len(got.Dissenting) != 1 || got.Dissenting[0] != "liar" {
		t.Errorf("dissenting = %v, want just the outlier", got.Dissenting)
	}
}

// Vectors of different length are a disagreement about the shape of the
// answer, which no tolerance can bridge — and must be caught before any
// element-wise arithmetic reads past the end of a short slice.
func TestDifferentLengthsDisagreeWithoutPanicking(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on mismatched lengths: %v", r)
		}
	}()
	results := []ApproxResult{res("a", 1, 2, 3), res("b", 1, 2)}
	if got := VerifyApprox(approxUnit(), results, Quorum{Need: 2}, DefaultTolerance()); got.Verdict != VerdictDisagreed {
		t.Fatalf("got %s, want disagreed", got.Verdict)
	}
}

// Relative tolerance alone collapses near zero; absolute alone is meaningless
// at scale. Both terms must be doing work.
func TestBothToleranceTermsMatter(t *testing.T) {
	tol := DefaultTolerance()
	// Near zero: relative would say 100% different, absolute rescues it.
	if !tol.Close(1e-18, 2e-18) {
		t.Error("two values indistinguishable from zero were called different")
	}
	// At scale: absolute alone would reject a rounding artefact.
	if !tol.Close(1.000000001e9, 1.0e9) {
		t.Error("a rounding artefact at 1e9 was called different")
	}
	// And a genuinely wrong answer is still wrong.
	if tol.Close(1.1e9, 1.0e9) {
		t.Error("a 10% error was accepted")
	}
}

// NaN is not close to anything, including itself — but two nodes that both
// overflowed to NaN have agreed about what happened.
func TestNaNAgreesWithNaNButNotWithANumber(t *testing.T) {
	nan := math.NaN()
	both := []ApproxResult{res("a", nan), res("b", nan), res("c", nan)}
	if got := VerifyApprox(approxUnit(), both, Quorum{Need: 2}, DefaultTolerance()); got.Verdict != VerdictAgreed {
		t.Errorf("all-NaN got %s (%s), want agreed", got.Verdict, got.Reason)
	}

	mixed := []ApproxResult{res("a", nan), res("b", 1.0), res("c", 1.0)}
	got := VerifyApprox(approxUnit(), mixed, Quorum{Need: 2}, DefaultTolerance())
	if got.Verdict != VerdictAgreed {
		t.Fatalf("got %s, want the two real answers to carry it", got.Verdict)
	}
	if len(got.Dissenting) != 1 || got.Dissenting[0] != "a" {
		t.Errorf("dissenting = %v, want the NaN node", got.Dissenting)
	}
}

// A tolerance window around infinity is meaningless. Treating +Inf as close to
// a very large finite number would let an overflow pass as a correct result.
func TestInfinityOnlyAgreesWithTheSameInfinity(t *testing.T) {
	tol := DefaultTolerance()
	if !tol.Close(math.Inf(1), math.Inf(1)) {
		t.Error("+Inf did not agree with +Inf")
	}
	if tol.Close(math.Inf(1), math.Inf(-1)) {
		t.Error("+Inf agreed with -Inf")
	}
	if tol.Close(math.Inf(1), 1e308) {
		t.Error("an overflow was accepted as a large finite number")
	}
}

// Partial credit on a vector would let a node return mostly-correct output and
// be paid for it, which is easier than computing the thing properly.
func TestOneWrongElementIsAWrongAnswer(t *testing.T) {
	results := []ApproxResult{
		res("a", 1, 2, 3, 4),
		res("b", 1, 2, 3, 4),
		res("c", 1, 2, 3, 999), // only the last element is wrong
	}
	got := VerifyApprox(approxUnit(), results, Quorum{Need: 2}, DefaultTolerance())
	if len(got.Dissenting) != 1 || got.Dissenting[0] != "c" {
		t.Fatalf("dissenting = %v, want the node with one bad element", got.Dissenting)
	}
}

func TestUnparseableResultDoesNotVote(t *testing.T) {
	results := []ApproxResult{
		{Node: "a", Values: nil}, // could not be read
		res("b", 1.0),
		res("c", 1.0),
	}
	got := VerifyApprox(approxUnit(), results, Quorum{Need: 3}, DefaultTolerance())
	if got.Verdict != VerdictInsufficient {
		t.Fatalf("got %s — an unreadable blob was counted as a reply", got.Verdict)
	}
}

func TestAllFailedIsFailedNotDisagreement(t *testing.T) {
	results := []ApproxResult{
		{Node: "a", Failed: true}, {Node: "b", Failed: true},
	}
	if got := VerifyApprox(approxUnit(), results, Quorum{Need: 2}, DefaultTolerance()); got.Verdict != VerdictFailed {
		t.Fatalf("got %s, want failed", got.Verdict)
	}
}

func TestTooFewRepliesIsInsufficient(t *testing.T) {
	results := []ApproxResult{res("a", 1.0)}
	if got := VerifyApprox(approxUnit(), results, Quorum{Need: 3}, DefaultTolerance()); got.Verdict != VerdictInsufficient {
		t.Fatalf("got %s, want insufficient", got.Verdict)
	}
}

// Wildly different answers must not be rescued by a median that sits between
// them — with no group reaching quorum, nobody is believed.
func TestScatteredAnswersDisagree(t *testing.T) {
	results := []ApproxResult{res("a", 1), res("b", 100), res("c", 10000)}
	got := VerifyApprox(approxUnit(), results, Quorum{Need: 2}, DefaultTolerance())
	if got.Verdict != VerdictDisagreed {
		t.Fatalf("got %s (%s), want disagreed", got.Verdict, got.Reason)
	}
}

func TestSpotCheckTriggers(t *testing.T) {
	clean := Check{Verdict: VerdictAgreed}
	if SpotCheckNeeded(clean, false) {
		t.Error("a unanimous result demanded a spot check without being sampled")
	}
	if !SpotCheckNeeded(clean, true) {
		t.Error("random sampling did not trigger a spot check")
	}
	// Any dissent is the cheapest signal that the window is doing real work.
	withDissent := Check{Verdict: VerdictAgreed, Dissenting: []string{"x"}}
	if !SpotCheckNeeded(withDissent, false) {
		t.Error("dissent did not trigger a spot check")
	}
	if !SpotCheckNeeded(Check{Verdict: VerdictDisagreed}, false) {
		t.Error("a disagreement did not trigger a spot check")
	}
	if SpotCheckNeeded(Check{Verdict: VerdictInsufficient}, true) {
		t.Error("an undecided unit was spot checked")
	}
}

// The even-count median must not invent a value. Averaging +Inf and -Inf
// yields NaN, which would anchor on something nothing can match.
func TestEvenCountMedianDoesNotInventAValue(t *testing.T) {
	got := median([]float64{math.Inf(-1), math.Inf(1)})
	if math.IsNaN(got) {
		t.Fatal("median of two infinities produced NaN")
	}
	if !math.IsInf(got, 0) {
		t.Errorf("median = %v, want one of the actual values", got)
	}
}

func TestMedianIgnoresNaNUnlessEverythingIsNaN(t *testing.T) {
	if got := median([]float64{1, 2, 3, math.NaN()}); math.IsNaN(got) {
		t.Error("one NaN dragged the median to NaN")
	}
	if got := median([]float64{math.NaN(), math.NaN()}); !math.IsNaN(got) {
		t.Errorf("all-NaN median = %v, want NaN", got)
	}
}
