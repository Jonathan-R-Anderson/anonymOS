package facilitation

import (
	"context"
	"errors"
	"math/big"
	"sort"
)

// The challenge scheduler: who challenges whom, in which epoch.
//
// Two problems it exists to solve.
//
// First, stampeding. If every node challenged every peer's every shard, load
// would grow with the square of the network and the challenges themselves would
// become the dominant traffic. Each (epoch, assignment) therefore has a small
// fixed set of designated challengers.
//
// Second, and the reason the selection is derived rather than chosen: a
// provider must not be able to arrange who audits it. The challenger set comes
// out of the same epoch randomness as witness selection, so it is fixed before
// the epoch's work happens, unpredictable to the provider, and recomputable by
// anyone auditing the result afterwards. A scheduler that picked its own targets
// would let a colluding pair agree to only ever challenge each other.
//
// Transport is injected. The p2p layer, an HTTP probe, or an in-memory pipe in
// tests all satisfy it, and none of the fairness logic here depends on which.

// ChallengersPerAssignment is how many nodes are designated to test each shard
// each epoch. Three is enough that one lazy or offline challenger does not mean
// a provider goes untested, without making auditing the network's main workload.
const ChallengersPerAssignment = 3

// ChunksPerChallenge is how many chunks a single challenge demands. Small
// enough to stay cheap over I2P, large enough that guessing is hopeless: a node
// holding half the shard passes a 4-chunk challenge only 1 time in 16.
const ChunksPerChallenge = 4

var (
	ErrNoSeed      = errors.New("facilitation: epoch randomness is zero — genesis has not landed")
	ErrNoTransport = errors.New("facilitation: no transport configured")
)

// Assignment is one shard held by one node, as the network believes it.
type Assignment struct {
	NodeID       [32]byte // who should be holding it
	AssignmentID [32]byte // which shard
	ShardRoot    [32]byte // committed Merkle root
	NumChunks    int
	Bytes        uint64 // shard size, the Quantity a passing proof earns
}

// Transport carries a challenge to a peer and brings back its answer.
type Transport interface {
	Challenge(ctx context.Context, target [32]byte, c StorageChallenge) (StorageResponse, error)
}

// AttestFunc asks the designated witnesses to countersign. It is separate from
// Transport because attestation is a different conversation from challenging,
// and early deployments may run without it (receipts then simply fail to reach
// quorum at settlement rather than being silently counted).
type AttestFunc func(ctx context.Context, sr *SignedReceipt, c StorageChallenge, resp StorageResponse, provenBytes uint64) error

// Scheduler drives one node's challenge duties.
type Scheduler struct {
	Agent     *Agent
	Store     *ReceiptStore
	Transport Transport
	Attest    AttestFunc
}

// IsDesignatedChallenger reports whether `challenger` is drawn to test this
// assignment in this epoch.
//
// Deterministic from public inputs, so a provider can be told exactly who
// should have tested it, and an auditor can check that the nodes which did test
// it were entitled to. Candidates are every registered node except the provider.
func IsDesignatedChallenger(seed [32]byte, epoch uint64, a Assignment, challenger [32]byte, candidates [][32]byte) bool {
	for _, c := range DesignatedChallengers(seed, epoch, a, candidates) {
		if c == challenger {
			return true
		}
	}
	return false
}

// DesignatedChallengers draws the challenger set for one assignment.
func DesignatedChallengers(seed [32]byte, epoch uint64, a Assignment, candidates [][32]byte) [][32]byte {
	pool := make([][32]byte, 0, len(candidates))
	for _, c := range candidates {
		if c == a.NodeID {
			continue // a node cannot audit itself
		}
		pool = append(pool, c)
	}
	if len(pool) == 0 {
		return nil
	}
	// Canonical order first: the draw must not depend on how a caller happened
	// to enumerate the network.
	sort.Slice(pool, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if pool[i][k] != pool[j][k] {
				return pool[i][k] < pool[j][k]
			}
		}
		return false
	})

	want := ChallengersPerAssignment
	if want > len(pool) {
		want = len(pool)
	}
	out := make([][32]byte, 0, want)
	taken := make(map[int]bool, want)
	for round := 0; len(out) < want; round++ {
		h := keccak32(seed[:], be64(epoch), a.AssignmentID[:], a.NodeID[:], be64(uint64(round)))
		idx := int(new(big.Int).Mod(new(big.Int).SetBytes(h[:]), big.NewInt(int64(len(pool)))).Int64())
		// Linear probe on collision so the loop always terminates, rather than
		// re-hashing until it happens to miss.
		for taken[idx] {
			idx = (idx + 1) % len(pool)
		}
		taken[idx] = true
		out = append(out, pool[idx])
	}
	return out
}

// MyAssignments filters the network's assignments down to the ones this node is
// drawn to challenge this epoch.
func (s *Scheduler) MyAssignments(seed [32]byte, epoch uint64, all []Assignment, candidates [][32]byte) []Assignment {
	me := s.Agent.NodeID()
	out := make([]Assignment, 0, 8)
	for _, a := range all {
		if a.NodeID == me {
			continue
		}
		if IsDesignatedChallenger(seed, epoch, a, me, candidates) {
			out = append(out, a)
		}
	}
	return out
}

// ChallengeResult is one completed audit.
type ChallengeResult struct {
	Assignment Assignment
	Challenge  StorageChallenge
	Response   StorageResponse
	Passed     bool
	Err        error
}

// RunEpoch challenges every assignment this node is drawn for, verifies the
// answers, and spools a receipt for each pass.
//
// A failed proof is recorded as a result, not an error: a node that cannot
// prove possession is exactly what this is for, and the run must continue
// through it to test everyone else. Errors returned are the scheduler's own
// (no seed, no transport), never a peer's failure.
func (s *Scheduler) RunEpoch(ctx context.Context, seed [32]byte, epoch uint64,
	all []Assignment, candidates [][32]byte) ([]ChallengeResult, error) {
	var zero [32]byte
	if seed == zero {
		// A zero seed makes every draw predictable, so this is refused rather
		// than treated as "no randomness yet, carry on".
		return nil, ErrNoSeed
	}
	if s.Transport == nil {
		return nil, ErrNoTransport
	}

	mine := s.MyAssignments(seed, epoch, all, candidates)
	results := make([]ChallengeResult, 0, len(mine))
	for _, a := range mine {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		res := ChallengeResult{Assignment: a}
		res.Challenge = s.Agent.IssueStorageChallenge(
			a.NodeID, a.AssignmentID, a.ShardRoot, seed, epoch, a.NumChunks, ChunksPerChallenge)

		resp, err := s.Transport.Challenge(ctx, a.NodeID, res.Challenge)
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.Response = resp
		if err := s.Agent.VerifyStorageResponse(res.Challenge, resp); err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}
		res.Passed = true
		results = append(results, res)
	}
	return results, nil
}

// AnswerChallenge is the provider side: prove possession, build the receipt,
// collect attestations, and spool it.
//
// The receipt is spooled even with no attestations yet. Witnesses arrive
// asynchronously and re-putting updates the row in place; dropping the receipt
// until quorum would mean losing the proof if the node restarts mid-collection.
// Returns the response as well as the receipt, and callers must send back THAT
// response: answering twice produces a different AnsweredAt, hence a different
// ResultHash, and the challenger would then verify a proof whose receipt is not
// the one spooled here — the attestations would sign a different hash and
// silently never count.
func (s *Scheduler) AnswerChallenge(ctx context.Context, c StorageChallenge, data []byte,
	chunkSize int, provenBytes uint64) (SignedReceipt, StorageResponse, error) {
	resp, err := s.Agent.AnswerStorageChallenge(c, data, chunkSize)
	if err != nil {
		return SignedReceipt{}, StorageResponse{}, err
	}
	sr, err := s.Agent.BuildReceipt(c, resp, provenBytes)
	if err != nil {
		return SignedReceipt{}, resp, err
	}
	if s.Attest != nil {
		// Attestation failures are not fatal: an unattested receipt simply does
		// not reach quorum at settlement, which is the correct outcome — far
		// better than discarding proof of work that genuinely happened.
		_ = s.Attest(ctx, &sr, c, resp, provenBytes)
	}
	if s.Store != nil {
		if err := s.Store.Put(sr); err != nil {
			return sr, resp, err
		}
	}
	return sr, resp, nil
}
