package content

import (
	"fmt"
	"math"
	"net/netip"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// perfect is the strongest reporter the system can describe: maximum
// reputation, a flawless history, and a proven bond.
func perfect() ReporterStats {
	return ReporterStats{Reputation: 1.0, Upheld: 10000, Overturned: 0, Bonded: true}
}

func at(id byte, prefix string, asn uint32, op byte) Reporter {
	var cid ClaimantID
	cid[0] = id
	var oid peer.OperatorID
	ann := peer.Annotation{ASN: asn}
	if prefix != "" {
		ann.Prefix = netip.MustParsePrefix(prefix)
	}
	if op != 0 {
		oid[0] = op
		ann.Operator = oid
		ann.OperatorSource = peer.OperatorSourceChain
	}
	return Reporter{ID: cid, Stats: perfect(), Ann: ann}
}

// TestEG5OneReporterCannotReachThePruneThreshold is E-G5 and R-90.1.
//
// "One reporter at maximum reputation cannot reach the prune threshold alone —
// falsified by any parameter set where they can."
//
// The assertion is on the RELATIONSHIP, not the numbers. Asserting
// weight < 1.0 would pass by coincidence after a recalibration that raised the
// cap and the threshold together; asserting cap < threshold cannot.
func TestEG5OneReporterCannotReachThePruneThreshold(t *testing.T) {
	if MaxSingleReporterWeight >= PruneThreshold {
		t.Fatalf("R-90.1 violated at the parameter level: one reporter caps at %v and "+
			"the threshold is %v, so a single trusted denouncer is a veto over anybody's "+
			"content", MaxSingleReporterWeight, PruneThreshold)
	}

	res := Weigh([]Reporter{at(1, "198.51.100.0/24", 64500, 0xa1)})
	if res.ReachesThreshold {
		t.Fatalf("a single maximum-reputation reporter reached the prune threshold "+
			"(weight %v)", res.Weight)
	}

	// And they cannot get there by filing repeatedly. A reporter who says one
	// thing ten times has said one thing.
	r := at(1, "198.51.100.0/24", 64500, 0xa1)
	many := make([]Reporter, 50)
	for i := range many {
		many[i] = r
	}
	res = Weigh(many)
	if res.ReachesThreshold {
		t.Fatalf("one reporter filing 50 times reached the threshold (weight %v)", res.Weight)
	}
	if res.Reporters != 1 {
		t.Fatalf("50 filings from one identity counted as %d reporters", res.Reporters)
	}
}

// TestSybilsInOneFailureDomainAreOneVoice is P12b's ladder doing the work.
//
// The cheapest attack on a reporting system is k identities. If they sit behind
// one prefix, one ASN or one on-chain operator they are ONE voice, because they
// can be compelled at once -- which is the only sense of "independent" that
// means anything here.
func TestSybilsInOneFailureDomainAreOneVoice(t *testing.T) {
	// Twenty identities, one operator.
	var sybils []Reporter
	for i := 0; i < 20; i++ {
		sybils = append(sybils, at(byte(i+1), fmt.Sprintf("198.51.%d.0/24", i), uint32(64500+i), 0xa1))
	}
	res := Weigh(sybils)
	if res.IndependentGroups != 1 {
		t.Fatalf("20 identities under one on-chain operator counted as %d independent "+
			"groups; ten reports from one operator must be one report", res.IndependentGroups)
	}
	if res.ReachesThreshold {
		t.Fatalf("20 sybils under one operator reached the prune threshold (weight %v)", res.Weight)
	}

	// Transitivity: A shares a prefix with B, B shares an operator with C.
	// If B can be compelled alongside both, all three fall together.
	chain := []Reporter{
		at(1, "198.51.100.0/24", 0, 0),
		at(2, "198.51.100.0/24", 0, 0xb2),
		at(3, "203.0.113.0/24", 0, 0xb2),
	}
	if res := Weigh(chain); res.IndependentGroups != 1 {
		t.Fatalf("a transitively-linked trio counted as %d groups", res.IndependentGroups)
	}
}

// TestCorroborationIsSublinearInIdentityCount is the property that makes the
// weighting worth having.
//
// If k independent-looking reporters buy k times the influence, §17's Sybil
// analysis applies unchanged and none of this bought anything.
func TestCorroborationIsSublinearInIdentityCount(t *testing.T) {
	for _, n := range []int{2, 4, 8, 16, 64, 1000} {
		got, linear := CorroborationFactor(n), CorroborationFactor(1)*float64(n)
		if got >= linear {
			t.Fatalf("corroboration at n=%d is %v, at least linear (%v): buying k "+
				"identities buys k times the influence", n, got, linear)
		}
		// Sublinear specifically means the MARGINAL value falls.
		if n > 2 {
			marginal := CorroborationFactor(n) - CorroborationFactor(n-1)
			prev := CorroborationFactor(2) - CorroborationFactor(1)
			if marginal >= prev {
				t.Fatalf("the %dth reporter is worth %v, no less than the 2nd (%v)",
					n, marginal, prev)
			}
		}
	}
	// Doubling influence costs quadratically more identities.
	if math.Abs(CorroborationFactor(4)/CorroborationFactor(1)-2) > 1e-9 {
		t.Fatal("four identities did not cost exactly a doubling")
	}
}

// TestWorthlessReportersCannotOutweighAGoodOne guards the mean-vs-sum choice.
//
// Summing weights and then multiplying by sqrt(n) would let a crowd of
// zero-reputation identities beat one credible reporter -- which is the attack
// the corroboration factor was supposed to price.
func TestWorthlessReportersCannotOutweighAGoodOne(t *testing.T) {
	one := Weigh([]Reporter{at(1, "198.51.100.0/24", 64500, 0xa1)})

	crowd := []Reporter{at(1, "198.51.100.0/24", 64500, 0xa1)}
	for i := 0; i < 200; i++ {
		r := at(byte(i+2), fmt.Sprintf("203.0.%d.0/24", i), uint32(65000+i), byte(i+2))
		r.Stats = ReporterStats{} // no reputation, no history, no bond
		crowd = append(crowd, r)
	}
	got := Weigh(crowd)
	if got.Weight > one.Weight {
		t.Fatalf("200 zero-reputation identities raised the weight from %v to %v; "+
			"a crowd of worthless reporters outweighs a credible one",
			one.Weight, got.Weight)
	}
}

// TestGenuineIndependentReportersCanReachTheThreshold is the other direction.
//
// A mechanism that no honest coalition can ever trigger is not a safe
// mechanism, it is an absent one -- and §93's states would be unreachable.
func TestGenuineIndependentReportersCanReachTheThreshold(t *testing.T) {
	var honest []Reporter
	for i := 0; i < 10; i++ {
		honest = append(honest, at(byte(i+1),
			fmt.Sprintf("198.%d.100.0/24", i+1), uint32(64500+i), byte(i+1)))
	}
	res := Weigh(honest)
	if res.IndependentGroups != 10 {
		t.Fatalf("10 fully-distinct reporters counted as %d groups", res.IndependentGroups)
	}
	if !res.ReachesThreshold {
		t.Fatalf("10 independent maximum-reputation reporters could not reach the "+
			"threshold (weight %v < %v); reporting accomplishes nothing",
			res.Weight, PruneThreshold)
	}
}

// TestUndeterminedReportersAreCountedAndReported keeps the flattering case
// honest.
func TestUndeterminedReportersAreCountedAndReported(t *testing.T) {
	var anon []Reporter
	for i := 0; i < 5; i++ {
		r := at(byte(i+1), "", peer.ASNUnknown, 0)
		anon = append(anon, r)
	}
	res := Weigh(anon)
	if res.Undetermined != 5 {
		t.Fatalf("5 unplaceable reporters were reported as %d undetermined", res.Undetermined)
	}
	if res.IndependentGroups != 5 {
		t.Fatalf("unplaceable reporters collapsed into %d groups; two unknowns are "+
			"never the same domain", res.IndependentGroups)
	}
}

// TestAccuracyIsSmoothed stops a single outcome being a verdict.
func TestAccuracyIsSmoothed(t *testing.T) {
	fresh := ReporterStats{}
	if fresh.Accuracy() != 0.5 {
		t.Fatalf("a reporter with no history scores %v, not the 0.5 prior", fresh.Accuracy())
	}
	if a := (ReporterStats{Upheld: 1}).Accuracy(); a >= 1 {
		t.Fatalf("one upheld report scored %v; a single outcome is not a history", a)
	}
	if a := (ReporterStats{Overturned: 1}).Accuracy(); a <= 0 {
		t.Fatalf("one overturned report scored %v; a single outcome is not a history", a)
	}
	// It does move with evidence.
	good := ReporterStats{Upheld: 100, Overturned: 1}
	bad := ReporterStats{Upheld: 1, Overturned: 100}
	if good.Accuracy() <= bad.Accuracy() {
		t.Fatal("accuracy does not respond to history at all")
	}
}

// TestUnbondedReportsStillCountForSomething is the young-network case.
func TestUnbondedReportsStillCountForSomething(t *testing.T) {
	unbonded := ReporterStats{Reputation: 1, Upheld: 100, Bonded: false}
	if ReporterWeight(unbonded) <= 0 {
		t.Fatal("an unbonded reporter is worth nothing, so on a network with no bonds " +
			"deployed no report ever counts")
	}
	bonded := unbonded
	bonded.Bonded = true
	if ReporterWeight(bonded) <= ReporterWeight(unbonded) {
		t.Fatal("a proven bond bought nothing, so identities are free")
	}
}

// TestCapIsUnconditional checks no input combination escapes R-90.1.
func TestCapIsUnconditional(t *testing.T) {
	for _, rep := range []float64{-5, 0, 0.5, 1, 1e9, math.Inf(1)} {
		for _, bonded := range []bool{false, true} {
			w := ReporterWeight(ReporterStats{
				Reputation: rep, Upheld: 1 << 20, Bonded: bonded,
			})
			if w > MaxSingleReporterWeight {
				t.Fatalf("reputation %v bonded=%v produced weight %v, above the cap %v",
					rep, bonded, w, MaxSingleReporterWeight)
			}
			if math.IsNaN(w) {
				t.Fatalf("reputation %v produced NaN, which compares false against every "+
					"threshold and silently disables the mechanism", rep)
			}
		}
	}
}
