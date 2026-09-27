package aggregator

import (
	"math/big"
	"sort"
)

// Witness selection (roadmap §5). Attestation is only worth anything if the
// provider cannot choose who attests: otherwise a ring of colluding nodes signs
// each other's receipts and the whole ledger is self-reported. So the witness
// set for every (provider, service, challenge) is DERIVED from randomness the
// provider could not know when it did the work:
//
//	witnessSet = Select(previousEpochRandomness, providerNodeId, serviceType, challengeIndex)
//
// Every field of that seed is public after the fact, so any auditor re-runs this
// function over the same candidate set and gets the same witnesses — that is
// what makes a receipt checkable by someone who was not there.
//
// Everything here is integer arithmetic. This function has to agree bit-for-bit
// across every aggregator, auditor and disputing node; floating point weights
// would let two honest implementations disagree about who was eligible and turn
// a rounding difference into a slashable "invalid epoch root".

// Candidate is one node eligible to witness, as of the epoch being settled.
type Candidate struct {
	NodeID [32]byte
	// Stake in CREDIT wei, from StakeVault. Selection uses sqrt(stake): a whale
	// with 100x the stake gets ~10x the weight, not 100x, so buying the witness
	// set costs quadratically more than the reward it could steal.
	Stake *big.Int
	// ReputationBps is 0..10000. Zero reputation cannot be selected at all.
	ReputationBps uint32
	// Group buckets nodes that are plausibly the same operator — /24, ASN, I2P
	// router, funding wallet. It is the independenceFactor from the roadmap,
	// applied as a hard constraint rather than a multiplier: one seat per group
	// while independent candidates remain. An empty Group is treated as its own
	// unique group (unknown, not shared).
	Group string
}

// Threshold is the m-of-n rule for a service: Need valid attestations out of a
// selected set of Of.
type Threshold struct{ Need, Of int }

// ThresholdFor returns the roadmap §5 threshold table. Higher-value or
// harder-to-refute claims demand larger sets: a routine DHT ping is cheap to
// re-check, a large Docker job is not.
func ThresholdFor(svc ServiceType) Threshold {
	switch svc {
	case ServiceDHT:
		return Threshold{Need: 2, Of: 3}
	case ServiceGateway, ServiceStorage:
		return Threshold{Need: 3, Of: 5}
	case ServiceDockerWorker, ServiceDockerController:
		return Threshold{Need: 4, Of: 7}
	case ServiceLoadBalance:
		return Threshold{Need: 3, Of: 5}
	default:
		return Threshold{Need: 2, Of: 3}
	}
}

// DisputeThreshold is the set used for a high-value dispute, which is resolved
// by a much larger quorum than routine work.
func DisputeThreshold() Threshold { return Threshold{Need: 7, Of: 11} }

// witnessSeed binds the selection to the epoch randomness AND to exactly which
// claim is being witnessed, so one draw cannot be replayed onto another receipt.
func witnessSeed(randomness, provider [32]byte, svc ServiceType, challengeIndex uint32) [32]byte {
	return keccak(randomness[:], provider[:], []byte{byte(svc)}, be32(challengeIndex))
}

// BootstrapStakeFloorWei is the stake an unstaked but registered node counts as
// while the network is bootstrapping.
//
// The rule it relaxes is a good one: an unstaked node has no bond, so there is
// nothing to slash, so its attestation carries no cost and — the argument goes —
// no meaning. But applied from block zero it is a deadlock, not a policy. Stake
// is denominated in CREDIT; CREDIT is earned by having work witnessed; work
// cannot be witnessed until somebody has stake. A network that requires a bond
// to earn the asset the bond is made of never starts.
//
// So during bootstrap an unstaked registered node counts as holding this much.
// What still constrains it is registration: a node must be in NodeRegistry,
// bound to a wallet that paid gas to put it there, and every attestation it
// signs is public and attributable. That is weaker than a slashable bond and it
// is meant to be temporary — set the floor to zero once real stake exists and
// the original rule applies again with nothing else changed.
//
// Deliberately a plain constant rather than a config knob: node, aggregator and
// site all have to apply the same floor or they compute different witness sets,
// and a value three programs must agree on is safer as one they cannot
// individually change. Raising it is a protocol change, not a deployment
// setting.
var BootstrapStakeFloorWei = big.NewInt(1)

// effectiveStake applies the bootstrap floor to a registered candidate.
func effectiveStake(c Candidate) *big.Int {
	stake := c.Stake
	if stake == nil || stake.Sign() < 0 {
		stake = big.NewInt(0)
	}
	if stake.Sign() == 0 && BootstrapStakeFloorWei != nil &&
		BootstrapStakeFloorWei.Sign() > 0 {
		return new(big.Int).Set(BootstrapStakeFloorWei)
	}
	return stake
}

// selectionWeight is sqrt(stake) x reputation, as integers:
//
//	isqrt(stakeWei) * reputationBps
//
// The reputation factor is left in basis points rather than divided out; only
// the RATIO between candidates matters to weighted sampling, so scaling every
// weight by 10000 changes nothing and avoids an integer division that would
// flush small stakes to zero.
//
// A staked node still outweighs an unstaked one by sqrt of its stake, so the
// floor lets unstaked nodes participate without letting them dominate: once
// anyone posts a real bond, they are drawn far more often than the floor.
func selectionWeight(c Candidate) *big.Int {
	if c.ReputationBps == 0 {
		return big.NewInt(0)
	}
	root := new(big.Int).Sqrt(effectiveStake(c))
	if root.Sign() == 0 {
		return big.NewInt(0)
	}
	return root.Mul(root, big.NewInt(int64(c.ReputationBps)))
}

// SelectWitnesses draws t.Of witnesses for one claim: deterministic weighted
// sampling without replacement, seeded by the epoch randomness.
//
// The provider is never eligible for its own receipt, zero-weight candidates are
// excluded, and at most one witness comes from any Group while independent
// groups remain. If the pool is too small it returns FEWER than t.Of — the
// caller must treat a short set as "this claim cannot be settled this epoch"
// rather than lowering the threshold, which is why the shortfall is visible
// instead of silently padded.
func SelectWitnesses(randomness, provider [32]byte, svc ServiceType, challengeIndex uint32, t Threshold, candidates []Candidate) []Candidate {
	type entry struct {
		c Candidate
		w *big.Int
	}
	pool := make([]entry, 0, len(candidates))
	for _, c := range candidates {
		if c.NodeID == provider {
			continue
		}
		w := selectionWeight(c)
		if w.Sign() <= 0 {
			continue
		}
		pool = append(pool, entry{c: c, w: w})
	}
	// Canonical order first: map iteration or caller ordering must not be able
	// to change the outcome.
	sort.Slice(pool, func(i, j int) bool { return less(pool[i].c.NodeID, pool[j].c.NodeID) })

	seed := witnessSeed(randomness, provider, svc, challengeIndex)
	picked := make([]Candidate, 0, t.Of)
	usedGroup := make(map[string]bool)
	taken := make([]bool, len(pool))

	// Two passes: fill with one-per-group, then, only if still short, allow a
	// second seat per group rather than returning an unusable set.
	for pass := 0; pass < 2 && len(picked) < t.Of; pass++ {
		for len(picked) < t.Of {
			total := big.NewInt(0)
			for i, e := range pool {
				if taken[i] {
					continue
				}
				if pass == 0 && e.c.Group != "" && usedGroup[e.c.Group] {
					continue
				}
				total.Add(total, e.w)
			}
			if total.Sign() == 0 {
				break // nothing eligible left in this pass
			}
			// Draw deterministically from [0, total): a fresh keccak per round,
			// so successive picks are independent but reproducible.
			draw := new(big.Int).SetBytes(keccakRound(seed, len(picked)))
			draw.Mod(draw, total)

			acc := big.NewInt(0)
			for i, e := range pool {
				if taken[i] {
					continue
				}
				if pass == 0 && e.c.Group != "" && usedGroup[e.c.Group] {
					continue
				}
				acc.Add(acc, e.w)
				if acc.Cmp(draw) > 0 {
					taken[i] = true
					picked = append(picked, e.c)
					if e.c.Group != "" {
						usedGroup[e.c.Group] = true
					}
					break
				}
			}
		}
	}
	return picked
}

// keccakRound derives round r's draw from the selection seed.
func keccakRound(seed [32]byte, r int) []byte {
	h := keccak(seed[:], be32(uint32(r)))
	return h[:]
}

// SelectedIDs is the node-id set of a selection, for membership checks.
func SelectedIDs(sel []Candidate) map[[32]byte]bool {
	out := make(map[[32]byte]bool, len(sel))
	for _, c := range sel {
		out[c.NodeID] = true
	}
	return out
}
