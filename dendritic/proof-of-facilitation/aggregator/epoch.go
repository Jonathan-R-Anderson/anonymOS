package aggregator

import (
	"math/big"
	"sort"
)

// Epoch settlement (roadmap §7). This is the loop that turns a pile of
// off-chain receipts into the five values EpochManager.submitEpoch takes:
//
//	1. Collect accepted service receipts.
//	2. Canonically sort them.
//	3. Build a Merkle tree.          -> receiptRoot
//	4. Calculate scores and rewards.
//	5. Build a reward Merkle tree.   -> rewardRoot
//	6. Publish both roots to Ethereum.
//	7. Open a challenge window.
//	8. Finalize the epoch.
//	9. Nodes claim rewards using Merkle proofs.
//
// Steps 1-5 happen here. 6-8 are contract calls; 9 is a node with a proof from
// ProofForNode.
//
// The settlement runs under an adversarial assumption that shapes every choice
// below: the aggregator posts a bond, and anyone may re-run this computation
// during the challenge window and slash it for a mismatch. So this function is
// written to be reproducible by a stranger holding the same receipts — no wall
// clock, no map iteration order, no floating point, and every rejection
// recorded rather than silently dropped.

// RejectReason says why a receipt did not make it into the epoch. They are kept
// (not discarded) because "why was my work not paid" must be answerable, and
// because a spike in one reason is the earliest signal of an attack.
type RejectReason string

const (
	RejectWrongEpoch    RejectReason = "receipt belongs to a different epoch"
	RejectDuplicate     RejectReason = "duplicate receipt hash"
	RejectBadSignature  RejectReason = "provider signature invalid"
	RejectSelfWitness   RejectReason = "provider witnessed its own receipt"
	RejectThreshold     RejectReason = "not enough attestations from the selected witness set"
	RejectNotSelected   RejectReason = "attestations came from witnesses the protocol did not select"
	RejectNoWitnessPool RejectReason = "witness pool too small to draw a valid set"
	RejectUnregistered  RejectReason = "provider has no payout address in NodeRegistry"
)

// Rejection is one excluded receipt and the reason.
type Rejection struct {
	ReceiptHash [32]byte
	Provider    [32]byte
	Service     ServiceType
	Reason      RejectReason
}

// EpochInput is everything needed to settle one epoch. Randomness is the
// PREVIOUS epoch's on-chain randomness (EpochManager.randomnessOf), which is
// what witness selection was seeded with while the work was being done.
type EpochInput struct {
	Epoch      uint64
	Randomness [32]byte
	Receipts   []SignedReceipt
	Candidates []Candidate
	Policy     Policy
	Recipients map[[32]byte][20]byte
	// NodeStateRoot commits off-chain per-node state (reputation, capacity
	// history). Phase 1 has no reputation system yet, so callers pass zero and
	// the field exists to keep the on-chain shape stable.
	NodeStateRoot [32]byte
}

// EpochCommitment mirrors the on-chain struct, plus what a node needs to claim.
type EpochCommitment struct {
	Epoch         uint64
	ReceiptRoot   [32]byte
	RewardRoot    [32]byte
	NodeStateRoot [32]byte
	Randomness    [32]byte
	TotalRewards  *big.Int

	// Accepted is the canonically sorted set behind ReceiptRoot; Rows is the
	// sorted set behind RewardRoot (leaf i of the reward tree is Rows[i]).
	Accepted   []SignedReceipt
	Rows       []RewardRow
	Rejections []Rejection

	receiptTree *Tree
	rewardTree  *Tree
}

// SettleEpoch runs the whole pipeline. It never returns an error: a malformed
// receipt is a Rejection, not a failure to settle, because one bad receipt must
// not be able to stop an epoch from paying everyone else.
func SettleEpoch(in EpochInput) EpochCommitment {
	c := EpochCommitment{
		Epoch:         in.Epoch,
		Randomness:    in.Randomness,
		NodeStateRoot: in.NodeStateRoot,
		TotalRewards:  big.NewInt(0),
	}

	// 1 + 2. Collect and canonically sort. Sorting by receipt hash gives one
	// order for everyone regardless of arrival order — the receiptRoot must not
	// depend on which aggregator saw which receipt first.
	sorted := make([]SignedReceipt, len(in.Receipts))
	copy(sorted, in.Receipts)
	sort.Slice(sorted, func(i, j int) bool {
		return less(CanonicalReceiptHash(sorted[i].Receipt), CanonicalReceiptHash(sorted[j].Receipt))
	})

	seen := make(map[[32]byte]bool, len(sorted))
	for _, sr := range sorted {
		h := CanonicalReceiptHash(sr.Receipt)
		reject := func(reason RejectReason) {
			c.Rejections = append(c.Rejections, Rejection{
				ReceiptHash: h, Provider: sr.Receipt.ProviderNodeID,
				Service: sr.Receipt.ServiceType, Reason: reason,
			})
		}

		if sr.Receipt.Epoch != in.Epoch {
			reject(RejectWrongEpoch)
			continue
		}
		// Replay defense: the same receipt paid twice is the cheapest possible
		// attack, so dedup happens on the canonical hash before any signature
		// work.
		if seen[h] {
			reject(RejectDuplicate)
			continue
		}
		if _, ok := in.Recipients[sr.Receipt.ProviderNodeID]; !ok {
			reject(RejectUnregistered)
			continue
		}

		t := ThresholdFor(sr.Receipt.ServiceType)
		selected := SelectWitnesses(in.Randomness, sr.Receipt.ProviderNodeID,
			sr.Receipt.ServiceType, ChallengeIndexOf(sr.Receipt), t, in.Candidates)
		if len(selected) < t.Of {
			// Too few independent, staked candidates to draw a real set. This is
			// a network-health problem, not the provider's fault, so it is
			// called out separately from a threshold miss.
			reject(RejectNoWitnessPool)
			continue
		}

		switch err := ValidateAttested(sr, SelectedIDs(selected), t); err {
		case nil:
			seen[h] = true
			c.Accepted = append(c.Accepted, sr)
		case ErrWitnessNotSelected:
			reject(RejectNotSelected)
		case ErrWitnessThreshold:
			reject(RejectThreshold)
		case ErrWitnessSelf:
			reject(RejectSelfWitness)
		default:
			reject(RejectBadSignature)
		}
	}

	// 3. Receipt tree over the accepted set, in the same sorted order.
	leaves := make([][32]byte, len(c.Accepted))
	for i, sr := range c.Accepted {
		leaves[i] = CanonicalReceiptHash(sr.Receipt)
	}
	c.receiptTree = BuildTree(leaves)
	c.ReceiptRoot = c.receiptTree.Root

	// 4 + 5. Score the accepted receipts and commit the payouts.
	plain := make([]ServiceReceipt, len(c.Accepted))
	for i, sr := range c.Accepted {
		plain[i] = sr.Receipt
	}
	rows := Score(plain, in.Policy, in.Recipients)
	c.rewardTree, c.Rows = RewardTree(rows)
	c.RewardRoot = c.rewardTree.Root
	for _, r := range c.Rows {
		if r.Amount != nil {
			c.TotalRewards.Add(c.TotalRewards, r.Amount)
		}
	}
	return c
}

// ChallengeIndexOf derives the per-claim index that witness selection is seeded
// with. It is not a receipt field: adding one would change the canonical hash
// (and so every existing signature), and it would let a provider pick its own
// index and grind the draw for a friendly set. Deriving it from the job and
// nonce the provider already committed to keeps the seed bound to this specific
// claim while staying outside the provider's control.
func ChallengeIndexOf(r ServiceReceipt) uint32 {
	h := keccak(r.JobID[:], be64(r.Nonce))
	return uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
}

// ProofForNode returns the reward row and Merkle proof a node passes to
// RewardDistributor.claim. ok is false if the node earned nothing this epoch.
func (c *EpochCommitment) ProofForNode(nodeID [32]byte) (RewardRow, [][32]byte, bool) {
	for i, r := range c.Rows {
		if r.NodeID == nodeID {
			return r, c.rewardTree.Proof(i), true
		}
	}
	return RewardRow{}, nil, false
}

// ReceiptProof returns the inclusion proof for accepted receipt i — what a
// challenger cites when disputing a specific receipt inside a posted epoch.
func (c *EpochCommitment) ReceiptProof(i int) [][32]byte { return c.receiptTree.Proof(i) }

// WithinBudget reports whether the epoch pays out no more than the policy
// allows. The contract does not enforce this, so an aggregator that posts an
// over-budget root is inflating the currency; check before submitting, and a
// challenger checks the same thing to slash it.
func (c *EpochCommitment) WithinBudget(p Policy) bool {
	if p.EpochBudget == nil {
		return true
	}
	return c.TotalRewards.Cmp(p.EpochBudget) <= 0
}
