// Package path is P12: locally computed path selection with diversity
// constraints and no consensus document.
//
// R14 forbids a consensus and forbids a measurement authority. Everything here
// is therefore computed from what this node can see for itself: the address
// annotations P3 produces, the first-hand profiles P12a keeps, and — only if
// the operator turns it on — a self-report that bonded stake puts a ceiling on.
//
// TWO RULES ORDER THE WHOLE PACKAGE:
//
//  1. Diversity constraints are applied FIRST and weights SECOND. A weight can
//     change which of several admissible relays is drawn. It can never admit a
//     relay the constraints excluded. That is what keeps P12a's tiering from
//     undoing P3's diversity work (E12a.2).
//  2. A constraint that could not be met is REPORTED, never silently dropped.
//     §46.1's failure mode is a sampler that quietly relaxes to fill a quota and
//     returns a set with the throughput of n relays and the failure domain of
//     one, with the caller unable to tell.
//
// R14's residual is here in full and this phase does not fix it: without a
// consensus, two clients can be shown different networks. T12.5 catches a crude
// partition. It does not catch a careful one.
package path

import (
	"math"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/profile"
)

// Weight is the bonded-self-report weighting from §23's P12 card.
//
// It exists for the peer this node has never used and therefore cannot profile.
// Local profiling is strictly better evidence — it is first-hand and cannot be
// asserted — but it only covers peers you have already used, and a client with
// an empty profile store either selects uniformly or believes somebody.
type Weight struct {
	// Claimed is the relay's self-reported capacity in bytes per second,
	// exactly as it claimed it. It is stored unmodified so that an audit can
	// see what was claimed alongside what it was worth.
	Claimed float64
	// BondCap is the most that relay's bonded stake justifies, in the same
	// units. See params.BondBytesPerSecondPerToken.
	BondCap float64
	// ReceiptObserved is the fraction of promised delivery that receipts
	// actually evidence, in [0,1]. It is a REDUCTION factor and nothing else.
	ReceiptObserved float64
}

// Value is the effective capacity a claim is worth.
//
// T12.3: a relay claiming 10 Gb/s on a minimal bond is worth the bond's cap,
// not the claim. T12.4: receipts can only lower the result, never raise it
// above the claim — which is why the receipt term is a multiplier in [0,1] and
// not an addend. An addend, however small, would make a relay that produced
// receipts worth more than it ever claimed, and the claim is the only figure
// the bond is holding it to.
func (w Weight) Value() float64 {
	v := w.Claimed
	if w.BondCap < v {
		v = w.BondCap
	}
	if v < 0 || math.IsNaN(v) {
		return 0
	}
	r := w.ReceiptObserved
	switch {
	case math.IsNaN(r), r < 0:
		r = 0
	case r > 1:
		// A receipt fraction above 1 means more was delivered than promised,
		// which is not evidence of extra capacity — it is evidence of a bug or
		// a forged receipt. Clamping is the conservative reading.
		r = 1
	}
	return v * r
}

// BondCapFor converts bonded stake, in whole tokens, into a capacity ceiling.
func BondCapFor(bondedTokens float64) float64 {
	if bondedTokens <= 0 || math.IsNaN(bondedTokens) {
		return 0
	}
	return bondedTokens * params.BondBytesPerSecondPerToken
}

// WeightSource records which evidence actually decided a relay's weight, so a
// report can distinguish "profiled" from "believed" from "no opinion".
type WeightSource uint8

const (
	// SourceUniform means no evidence was used: every admissible relay was
	// equally likely. It is the default and it is not a failure.
	SourceUniform WeightSource = iota
	// SourceProfile means P12a's first-hand tiering decided it.
	SourceProfile
	// SourceClaim means a bond-capped self-report decided it, because there was
	// no first-hand evidence and the policy permits claims.
	SourceClaim
)

func (s WeightSource) String() string {
	switch s {
	case SourceProfile:
		return "profile"
	case SourceClaim:
		return "claim"
	default:
		return "uniform"
	}
}

// WeightPolicy says what evidence selection is allowed to use.
//
// THE RULING THIS STRUCT ENCODES.
//
// P12 was written before P12a and specifies bond-capped self-reports as the
// weighting mechanism. P12a then arrives from the parity audit and says
// claimed_bw must not be an input, because it is the self-report the phase
// exists to stop trusting. Both are in the roadmap and they disagree.
//
// They are resolved rather than averaged:
//
//   - Where first-hand evidence exists, it WINS OUTRIGHT. The claim is not
//     blended in, not used as a prior, not used to break ties. Blending leaves
//     the adversary a term it controls in every product.
//   - Where there is no first-hand evidence, the choice is between uniform
//     selection and a bounded amount of belief. Both are defensible and they
//     trade different things, so it is a POLICY and its default is off.
//
// With UseClaims false — the default — a fresh node selects uniformly and
// E12a.3 holds end to end, at the cost of a fresh node getting the slowest
// relay's throughput as often as the fastest one's. With it true, a fresh node
// gets usable throughput sooner and is steerable by whoever supplied its
// descriptors, bounded by WeightClaimSpread. P12a's own failure-mode note is
// the reason for the default: a fresh node's profile is empty exactly when it
// is most vulnerable.
type WeightPolicy struct {
	// UseProfile enables P12a's local tiering. Default (false) is uniform.
	UseProfile bool
	// UseClaims enables bond-capped self-reports for peers with no first-hand
	// evidence. Default is off. See above.
	UseClaims bool
	// Profiles is the local profile store. Required when UseProfile is set.
	Profiles *profile.Profiles
	// AllowRelaxation permits dropping a diversity constraint when no path
	// exists under the full set. Default is off: SelectPath returns ErrNoPath
	// rather than a shorter-lived guarantee the caller did not ask for.
	AllowRelaxation bool
}

// weightOf is the effective selection weight for one relay under a policy,
// together with the evidence that decided it.
//
// The clamp to [1/WeightClaimSpread, WeightClaimSpread] is applied to the CLAIM
// branch only. Tier weights carry their own bound (params.WeightFast /
// params.WeightStandard) and are already relative; capacity claims are absolute
// byte rates and would otherwise span whatever range the population spans.
//
// The view is passed in rather than read per call: tiering is a population
// operation, so asking Profiles.Tier once per candidate per hop recomputes the
// whole store O(hops x candidates) times and makes selection quadratic in the
// population. One view is taken per selection, which is also the correct
// semantics -- every hop of one path is then weighted against one instant's
// view rather than against a store that moved underneath it.
func weightOf(r Relay, pol WeightPolicy, view profile.View, claimScale float64) (float64, WeightSource) {
	if pol.UseProfile {
		if t := view.Tier(r.NodeID); t != profile.TierUntiered {
			return view.Weight(r.NodeID), SourceProfile
		}
	}
	if pol.UseClaims && claimScale > 0 {
		v := r.Weight.Value()
		if v <= 0 {
			return 1 / params.WeightClaimSpread, SourceClaim
		}
		w := v / claimScale
		if w > params.WeightClaimSpread {
			w = params.WeightClaimSpread
		}
		if w < 1/params.WeightClaimSpread {
			w = 1 / params.WeightClaimSpread
		}
		return w, SourceClaim
	}
	return 1, SourceUniform
}
