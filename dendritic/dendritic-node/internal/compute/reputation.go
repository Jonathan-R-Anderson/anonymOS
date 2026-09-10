package compute

// M8 — reputation: what a node has earned the right to be trusted with.
//
// PER DEVICE, NOT PER NODE
// -----------------------
// A machine with two cards has two capabilities, and they can be good and bad
// independently: a working CUDA card and a flaky one in the same chassis are
// one node with two very different track records. Scoring the node averages
// them, which both overstates the bad device and understates the good one, and
// the scheduler then places work on whichever it happens to pick.
//
// So the key is (node, device) and the node's overall score is only ever a
// summary for a human to read.
//
// WHY IT DECAYS
// -------------
// Reputation earned two years ago on hardware since replaced should not price
// today's scheduling. Without decay a node that was excellent in 2024 and has
// been quietly failing since coasts on a number nothing can move: the good
// history is too large a denominator for recent failures to dent.
//
// Decay is by HALF-LIFE rather than a window. A window has an edge — a result
// counts fully on day 29 and not at all on day 31 — and edges are what get
// gamed. A half-life makes the old evidence fade smoothly and never quite
// vanish, so a long good record still counts for something, just less than last
// week's.
//
// WHY IT CANNOT REACH ZERO
// ------------------------
// The floor lives in price.go (MinReputationFactor) and the reason is the same
// one: a multiplicative factor of zero means a new or unlucky node can never
// earn its way back, and a scoring system nobody can recover from is one nobody
// joins. This file produces a 0..1 score; what that is worth in money is the
// marketplace's decision, not reputation's.

import (
	"math"
	"sort"
	"time"
)

// HalfLife is how long it takes a result to count for half as much. Thirty days
// is roughly "last month matters most, last quarter still matters, last year is
// context" — which is the shape of how fast this hardware actually changes.
const HalfLife = 30 * 24 * time.Hour

// PriorWeight is how much benefit of the doubt a node starts with, expressed as
// pseudo-observations of average behaviour.
//
// Without it, one lucky success reads as a flawless record and one unlucky
// failure as a hopeless one — and the scheduler acts on both. Five is enough
// that a node has to actually demonstrate something before its score moves far,
// and small enough that a genuinely bad node is not protected for long.
const PriorWeight = 5.0

// PriorScore is what an unproven node is assumed to be worth: middling.
// Not 1.0 (which would hand every newcomer the best work before it has done
// any) and not 0 (which is a closed shop — see the file comment).
const PriorScore = 0.6

// Outcome is one thing a device did.
type Outcome struct {
	// Agreed: its result matched the verified answer. Disagreed: it did not —
	// which is evidence of being wrong, not proof of dishonesty (see verify.go).
	Agreed bool
	// Failed is a unit the node could not complete. Weighted less than
	// disagreeing: giving up honestly is better than returning a wrong answer
	// confidently, and pricing them the same encourages the wrong one.
	Failed bool
	// Late means it missed the deadline it accepted. Counted, because a result
	// that arrives after it was needed is a result nobody could use.
	Late bool
	At   time.Time
}

// Device identifies what is being scored.
type Device struct {
	Node string `json:"node"`
	// "cpu", or "gpu:<vendor>/<model>" — the same shape the scheduler matches
	// on, so a score can be looked up for exactly the thing being placed.
	Device string `json:"device"`
}

// Score is a device's standing.
type Score struct {
	Device Device  `json:"device"`
	Value  float64 `json:"value"` // 0..1
	// Observations is the DECAYED count, so it says how much recent evidence
	// this rests on rather than how many results were ever recorded. A score
	// from one result last week and one from four hundred last year are
	// different claims and should not print the same number.
	Observations float64   `json:"observations"`
	Newest       time.Time `json:"newest,omitempty"`
}

// weightAt is how much an outcome from `when` counts as of `now`.
func weightAt(when, now time.Time) float64 {
	age := now.Sub(when)
	if age <= 0 {
		return 1
	}
	return math.Pow(0.5, age.Hours()/HalfLife.Hours())
}

// value scores a single outcome.
//
// Not a boolean: agreeing, failing and disagreeing are three different things
// and collapsing them loses the distinction the network most needs. A node that
// declines work it cannot do is behaving WELL; one that returns a wrong answer
// is the case verification exists for.
func value(o Outcome) float64 {
	switch {
	case o.Agreed && !o.Late:
		return 1.0
	case o.Agreed && o.Late:
		// Right but late. Still useful — somebody may have consumed it — and
		// still a broken promise about a deadline the node accepted.
		return 0.5
	case o.Failed:
		// Honest inability. Better than a confident wrong answer, worse than
		// not taking the work at all.
		return 0.25
	default:
		// Disagreed with the verified result.
		return 0.0
	}
}

// Rate scores one device from its outcomes.
//
// A Bayesian mean rather than a plain average: the prior is what stops a single
// result reading as a complete track record, and it is the difference between
// "unproven" and "perfect" for a node that has done one unit.
func Rate(device Device, outcomes []Outcome, now time.Time) Score {
	if now.IsZero() {
		now = time.Now()
	}
	weighted, total := PriorScore*PriorWeight, PriorWeight
	var newest time.Time
	for _, o := range outcomes {
		w := weightAt(o.At, now)
		if w <= 0.0001 {
			// So old it cannot move the number. Skipped rather than summed, so
			// a decade of ancient history does not accumulate into weight
			// through sheer count.
			continue
		}
		weighted += value(o) * w
		total += w
		if o.At.After(newest) {
			newest = o.At
		}
	}
	return Score{
		Device:       device,
		Value:        clamp01(weighted / total),
		Observations: total - PriorWeight,
		Newest:       newest,
	}
}

func clamp01(v float64) float64 {
	if !(v == v) { // NaN
		return PriorScore
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Tier is what a score entitles a device to. The spec's escalating privileges,
// made concrete enough to act on.
type Tier string

const (
	// TierProbation — new, or recently wrong. Gets work, because that is the
	// only way to earn anything, but not work anybody is relying on.
	TierProbation Tier = "probation"
	// TierStandard — the ordinary case.
	TierStandard Tier = "standard"
	// TierTrusted — long, recent, consistent agreement.
	TierTrusted Tier = "trusted"
)

// TierOf maps a score to a tier.
//
// Requires OBSERVATIONS as well as a high score for the top tier. Otherwise a
// device with two successes and no history outranks one with two hundred, and
// "trusted" comes to mean "lucky twice".
func TierOf(s Score) Tier {
	switch {
	case s.Value >= 0.9 && s.Observations >= 20:
		return TierTrusted
	case s.Value >= 0.55:
		return TierStandard
	default:
		return TierProbation
	}
}

// MaxUnitsFor is how many units a tier may hold at once — the "more work"
// privilege, bounded so an unproven device cannot take on a queue it will drop.
func MaxUnitsFor(t Tier) int {
	switch t {
	case TierTrusted:
		return 8
	case TierStandard:
		return 3
	default:
		return 1
	}
}

// MayTake reports whether a tier is allowed a given unit, and why not.
//
// The gate that matters: a unit nobody else can verify (non-deterministic, or
// the only replica) should not go to a device on probation, because there is
// nothing to catch it being wrong.
func MayTake(t Tier, u Unit, replicas int) (bool, string) {
	if t == TierProbation {
		if !u.Deterministic {
			return false, "unverifiable work needs a device with a track record"
		}
		if replicas < 2 {
			return false, "unreplicated work needs a device with a track record"
		}
	}
	return true, ""
}

// Summarise reduces a node's devices to one number for a human.
//
// The MINIMUM, not the mean. A node is only as trustworthy as its worst device
// for the work that device would be given, and averaging lets a good card hide
// a failing one — which is exactly the confusion per-device scoring exists to
// remove, reintroduced at the display layer.
func Summarise(scores []Score) float64 {
	if len(scores) == 0 {
		return PriorScore
	}
	worst := scores[0].Value
	for _, s := range scores[1:] {
		if s.Value < worst {
			worst = s.Value
		}
	}
	return worst
}

// Ranked orders devices best-first, deterministically.
func Ranked(scores []Score) []Score {
	out := append([]Score(nil), scores...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		if out[i].Observations != out[j].Observations {
			return out[i].Observations > out[j].Observations
		}
		return out[i].Device.Node < out[j].Device.Node
	})
	return out
}
