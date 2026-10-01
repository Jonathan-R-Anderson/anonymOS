package content

import (
	"math"
	"sort"

	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// G5 — reporter reputation and report weight (§90).
//
// §90's formula, made precise:
//
//	weight(report) = clamp(reporter_rep[category], 0, 1)
//	               x accuracy[category]
//	               x sybil_factor(reporter)
//	               x corroboration_factor(reports)
//
// TWO PROPERTIES CARRY THE WHOLE THING AND BOTH ARE TESTED.
//
// R-90.1 — NO REPORTER CAN CARRY A PRUNE ALONE, AT ANY REPUTATION. The cap is
// not a tuning parameter. It is what stops the system converging on a small
// number of trusted denouncers, which is the failure mode every
// reputation-weighted moderation system has actually exhibited. A perfect
// history must not be a veto over anybody's content.
//
// CORROBORATION MUST BE SUBLINEAR IN IDENTITY COUNT. §90's draft did not draw
// this and it is the difference between "several people saw this" and "someone
// bought several identities": if k independent-looking reporters buy k times the
// influence, §17's Sybil analysis applies unchanged and the weighting has bought
// nothing. sqrt is used, and the choice is argued at CorroborationFactor.
//
// INDEPENDENCE IS P12b's, NOT A NEW NOTION. Two reporters are independent when
// they differ at prefix, ASN and ON-CHAIN OPERATOR. Ten reports from one
// operator are one report, and an operator who cannot be determined is counted
// conservatively -- see independentGroups.
//
// EVERY NUMBER HERE IS PROVISIONAL and inherits P14's [UNSOLVED] calibration in
// full: there is no bond amount known to make governance capture infeasible,
// because that depends on a token price and a population that do not exist.
// What is NOT provisional is the SHAPE -- the cap and the sublinearity are
// structural, and a parameter set cannot switch them off.

const (
	// MaxSingleReporterWeight is R-90.1's cap: the most one reporter can
	// contribute, however perfect their record.
	//
	// PROVISIONAL as a figure. Structural as a rule: PruneThreshold below is
	// strictly greater than it, and a test asserts the relationship rather than
	// the numbers, so a recalibration cannot quietly make one reporter enough.
	MaxSingleReporterWeight = 0.40

	// PruneThreshold is the weight at which §93's machine moves a subject from
	// REPORTED to UNDER_REVIEW.
	//
	// PROVISIONAL. Derivation: it must exceed MaxSingleReporterWeight, and it
	// must be reachable by a small number of independent reporters or reporting
	// accomplishes nothing. Everything else about it is unknown.
	PruneThreshold = 1.0

	// UnbondedSybilFactor is what a reporter with no verified bond is worth.
	//
	// PROVISIONAL. Not zero, deliberately: an unbonded reporter is the ordinary
	// case on a network with nothing deployed, and zeroing them would mean no
	// report ever counts. Not one either, or identities are free.
	UnbondedSybilFactor = 0.25
)

// ReporterStats is what this node has observed about one reporter, per category.
//
// PER CATEGORY, per §90 and §88: someone can be an excellent malware reporter
// and a poor governance participant, and a single score forces the network to
// choose which of those to be wrong about.
type ReporterStats struct {
	// Reputation in [0,1] for this category.
	Reputation float64
	// Upheld and Overturned are the reporter's history in this category:
	// reports that survived challenge, and reports a successful appeal
	// reversed (§93).
	Upheld     int
	Overturned int
	// Bonded reports whether a bond was PROVEN (P14's VerifyBond), not claimed.
	Bonded bool
}

// Accuracy is the Laplace-smoothed rate of reports that survived challenge.
//
// Smoothed because an unsmoothed rate makes a reporter's FIRST report either
// worthless (0/0 read as 0) or perfect (1/1), and both are wrong: one outcome
// is not a history. The +1/+2 prior starts everyone at 0.5 and moves with
// evidence.
func (s ReporterStats) Accuracy() float64 {
	return float64(s.Upheld+1) / float64(s.Upheld+s.Overturned+2)
}

// SybilFactor is what P14's bond buys a reporter.
func (s ReporterStats) SybilFactor() float64 {
	if s.Bonded {
		return 1
	}
	return UnbondedSybilFactor
}

// ReporterWeight is one reporter's contribution, before corroboration.
//
// CAPPED AT MaxSingleReporterWeight. The cap is applied last and unconditionally
// so that no combination of reputation, accuracy and bond can exceed it.
func ReporterWeight(s ReporterStats) float64 {
	rep := math.Max(0, math.Min(1, s.Reputation))
	w := rep * s.Accuracy() * s.SybilFactor()
	return math.Min(w, MaxSingleReporterWeight)
}

// CorroborationFactor scales weight by how many INDEPENDENT groups reported.
//
// sqrt(n), and the choice is the point rather than the formula:
//
//	linear (n)      k identities buy k times the influence. §17's Sybil analysis
//	                applies unchanged and the whole weighting is decorative.
//	sqrt(n)         doubling your influence costs FOUR identities, and the cost
//	                grows quadratically from there.
//	log(n)          also sublinear, and so flat that fifty genuine independent
//	                reporters barely outweigh five -- which punishes the case
//	                the system exists to reward.
//
// sqrt is the standard sublinear choice and sits between those failures. THE
// EXPONENT IS PROVISIONAL; the sublinearity is not.
func CorroborationFactor(independentGroups int) float64 {
	if independentGroups <= 0 {
		return 0
	}
	return math.Sqrt(float64(independentGroups))
}

// Reporter is one filed report, with what is known about who filed it.
type Reporter struct {
	ID    ClaimantID
	Stats ReporterStats
	// Where the reporter was observed, for the independence test. A zero
	// Annotation means nothing could be determined.
	Ann peer.Annotation
}

// independentGroups counts distinct reporters under P12b's ladder.
//
// IT DOES NOT REIMPLEMENT THE LADDER. peer.DomainKeys is the one place that
// decides what a failure domain is, and it already carries the rule that
// matters here: an UNKNOWN domain produces NO KEY AT ALL rather than a
// placeholder, so two unknowns never collide -- they have nothing to collide
// on. A second copy of that logic in this package would be a second place to
// get it wrong, and the two would drift the first time the ladder gained a rung.
//
// Reporters sharing ANY key collapse into one group, transitively: A shares a
// prefix with B, B shares an operator with C, so all three are one voice.
// Transitive because §7.2's point is about who can be compelled at once, and if
// B can be compelled alongside both A and C then all three fall together. Union-
// find, since the relation is not an equivalence on any single key.
//
// A reporter whose domains cannot be determined at all counts as its OWN group.
// That is the flattering direction, so it is REPORTED rather than buried: on a
// network where most reporters are unannotated, the corroboration figure is an
// upper bound, and Result.Undetermined says by how much.
func independentGroups(reporters []Reporter) (groups int, undetermined int) {
	parent := make([]int, len(reporters))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	owner := map[string]int{} // domain key -> first reporter seen with it
	for i, r := range reporters {
		keys := peer.DomainKeys(r.Ann)
		if len(keys) == 0 {
			undetermined++
			continue // stays its own group
		}
		for _, k := range keys {
			if j, ok := owner[k]; ok {
				union(i, j)
			} else {
				owner[k] = i
			}
		}
	}

	roots := map[int]bool{}
	for i := range reporters {
		roots[find(i)] = true
	}
	return len(roots), undetermined
}

// Result is a weighed set of reports about one subject.
type Result struct {
	// Weight is the total.
	Weight float64
	// Reporters is how many filed.
	Reporters int
	// IndependentGroups is how many of them are independent under P12b.
	IndependentGroups int
	// Undetermined is how many reporters could not be placed in a domain at
	// all, and were therefore counted as independent. On a young network this
	// is most of them, and it means the corroboration figure is an upper bound.
	Undetermined int
	// ReachesThreshold reports whether §93's machine should advance.
	ReachesThreshold bool
}

// Weigh computes the weight of a set of reports about one subject.
//
// Reports from the SAME reporter contribute once. §90's corroboration is about
// independent voices, and a reporter who files ten times has said one thing ten
// times -- which G4's key derivation already makes a rewrite rather than a
// repeat, and this enforces again at the weighing layer because the two are
// separately reachable.
func Weigh(reporters []Reporter) Result {
	byID := map[ClaimantID]Reporter{}
	for _, r := range reporters {
		if existing, ok := byID[r.ID]; ok {
			// Keep the better-evidenced record, not the newest: a reporter
			// should not improve their weight by refiling.
			if ReporterWeight(r.Stats) <= ReporterWeight(existing.Stats) {
				continue
			}
		}
		byID[r.ID] = r
	}

	unique := make([]Reporter, 0, len(byID))
	for _, r := range byID {
		unique = append(unique, r)
	}
	sort.Slice(unique, func(i, j int) bool {
		return string(unique[i].ID[:]) < string(unique[j].ID[:])
	})

	groups, undetermined := independentGroups(unique)

	base := 0.0
	for _, r := range unique {
		base += ReporterWeight(r.Stats)
	}
	// Corroboration scales the MEAN rather than the sum, so that adding a
	// zero-weight reporter cannot raise the total. Summing and then multiplying
	// by sqrt(n) would make a crowd of worthless reporters worth more than one
	// good one.
	weight := 0.0
	if len(unique) > 0 {
		weight = (base / float64(len(unique))) * CorroborationFactor(groups)
	}

	return Result{
		Weight:            weight,
		Reporters:         len(unique),
		IndependentGroups: groups,
		Undetermined:      undetermined,
		ReachesThreshold:  weight >= PruneThreshold,
	}
}
