package aggregator

import (
	"math/big"
	"sort"
)

// ServiceType mirrors NodeRegistry's capability bits.
type ServiceType uint8

const (
	ServiceDHT ServiceType = iota
	ServiceGateway
	ServiceStorage
	ServiceLoadBalance
	ServiceDockerWorker
	ServiceDockerController
	ServiceWitness
)

// ServiceReceipt is one rewarded, witness-attested action. It lives off-chain
// (in the DHT); only the aggregated reward Merkle root reaches Ethereum. Fields
// mirror the roadmap's ServiceReceipt struct.
type ServiceReceipt struct {
	ProviderNodeID [32]byte
	VerifierNodeID [32]byte
	ServiceType    ServiceType
	JobID          [32]byte
	ChallengeHash  [32]byte
	ResultHash     [32]byte
	Epoch          uint64
	StartedAt      uint64
	CompletedAt    uint64
	Quantity       uint64
	Quality        uint32
	Nonce          uint64
}

// RewardRow is one node's settled reward for an epoch — a single leaf in the
// reward tree. Service is the serviceBreakdownHash committed alongside the
// amount (e.g. a hash of the per-service point breakdown behind this payout).
type RewardRow struct {
	NodeID    [32]byte
	Recipient [20]byte
	Amount    *big.Int
	Service   [32]byte
}

// RewardTree builds the epoch's reward Merkle tree from the settled rows. Rows
// are sorted by nodeId first so the aggregator and any independent verifier
// derive the identical root from the same set. Returns the tree and the rows in
// the order their leaves occupy (so Proof(i) corresponds to rows[i]).
func RewardTree(rows []RewardRow) (*Tree, []RewardRow) {
	sorted := make([]RewardRow, len(rows))
	copy(sorted, rows)
	sort.Slice(sorted, func(i, j int) bool { return less(sorted[i].NodeID, sorted[j].NodeID) })
	leaves := make([][32]byte, len(sorted))
	for i, r := range sorted {
		amount := r.Amount
		if amount == nil {
			amount = big.NewInt(0)
		}
		leaves[i] = RewardLeaf(r.NodeID, r.Recipient, amount, r.Service)
	}
	return BuildTree(leaves), sorted
}
