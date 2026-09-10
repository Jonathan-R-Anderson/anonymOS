package facilitation

import (
	"math/big"
	"sort"
)

// Witness selection, computed here so a provider knows whom to ask.
//
// This is a DELIBERATE second implementation of
// proof-of-facilitation/aggregator/witness.go. The two are separate Go modules
// that cannot import each other, and both must draw the identical set: the
// provider uses it to decide whom to ask for attestations, and settlement uses
// it to decide whether the attestations it received were legitimate. If they
// diverge by one candidate, every honest receipt is rejected for carrying
// "attestations from witnesses the protocol did not select" — a verdict
// indistinguishable, from the outside, from fraud, and one the reputation
// system scores as cheating.
//
// witness_golden_test.go pins the outputs both sides must produce. Nothing in
// this file may be changed without changing the aggregator in the same commit
// and re-running both sets of vectors.

// BootstrapStakeFloorWei is the stake an unstaked but registered node counts as
// while the network is bootstrapping. See the aggregator's copy for why it
// exists; the value must be identical in both.
var BootstrapStakeFloorWei = big.NewInt(1)

// Candidate is one node eligible to witness.
type Candidate struct {
	NodeID        [32]byte
	Stake         *big.Int
	ReputationBps uint32
	// Group buckets nodes that are plausibly the same operator. Empty means
	// "unknown", which is treated as its own unique group rather than as a
	// shared one — guessing that two unknowns are the same operator would
	// exclude honest independent nodes.
	Group string
}

// Threshold is "Need of Of": how many attestations make a receipt settleable,
// out of how many witnesses are drawn.
type Threshold struct{ Need, Of int }

// ThresholdFor mirrors the aggregator's table exactly.
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

func witnessSeed(randomness, provider [32]byte, svc ServiceType, challengeIndex uint32) [32]byte {
	return keccak32(randomness[:], provider[:], []byte{byte(svc)}, be32(challengeIndex))
}

func effectiveStake(c Candidate) *big.Int {
	stake := c.Stake
	if stake == nil || stake.Sign() < 0 {
		stake = big.NewInt(0)
	}
	if stake.Sign() == 0 && BootstrapStakeFloorWei != nil && BootstrapStakeFloorWei.Sign() > 0 {
		return new(big.Int).Set(BootstrapStakeFloorWei)
	}
	return stake
}

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

func lessNodeID(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// SelectWitnesses draws t.Of witnesses for one claim: deterministic weighted
// sampling without replacement, seeded by the epoch randomness.
//
// A short set is returned as a short set. The caller must NOT lower the
// threshold to fit it: settlement will not, and a provider that quietly
// collected fewer attestations would spend a whole epoch producing receipts
// nothing can accept.
func SelectWitnesses(randomness, provider [32]byte, svc ServiceType, challengeIndex uint32,
	t Threshold, candidates []Candidate) []Candidate {
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
	sort.Slice(pool, func(i, j int) bool { return lessNodeID(pool[i].c.NodeID, pool[j].c.NodeID) })

	seed := witnessSeed(randomness, provider, svc, challengeIndex)
	picked := make([]Candidate, 0, t.Of)
	usedGroup := make(map[string]bool)
	taken := make([]bool, len(pool))

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
				break
			}
			round := keccak32(seed[:], be32(uint32(len(picked))))
			draw := new(big.Int).SetBytes(round[:])
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

// IsSelectedWitness reports whether a node was drawn for this claim. The
// witness side calls it before signing: an attestation from a node nobody drew
// is worse than useless, since it invalidates the receipt it was meant to help.
func IsSelectedWitness(randomness, provider [32]byte, svc ServiceType, challengeIndex uint32,
	t Threshold, candidates []Candidate, me [32]byte) bool {
	for _, c := range SelectWitnesses(randomness, provider, svc, challengeIndex, t, candidates) {
		if c.NodeID == me {
			return true
		}
	}
	return false
}
