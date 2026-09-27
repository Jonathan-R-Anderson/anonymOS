// Package sybil is P14: bonded admission, proof-of-work for cheap roles, and
// the composition of §15's caps into one policy.
//
// THE HONEST CENTRE OF THIS PHASE IS THAT ITS PARAMETERS ARE UNCALIBRATED.
// Nobody can say what bond makes 20 % of relays infeasible: it depends on a
// token price, on an adversary's budget, and on a deployed population, and
// §18.22 records that none of the three exists. So what P14 delivers is a
// MECHANISM whose parameters are marked provisional in params.go, each with the
// derivation it does or does not have. Shipping a number without that caveat
// would imply a claim the number does not support.
//
// The second thing it delivers is the property that makes the mechanism worth
// anything: a bond is read from the light client's VERIFIED STATE ROOT and
// never from a provider's word. See VerifyBond.
package sybil

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

// Address is a 20-byte Ethereum address.
type Address [20]byte

// BondRef identifies a bond claim in a relay's descriptor.
//
// It is a REFERENCE, not an amount. The descriptor says where to look; it never
// says how much, because a self-declared amount is exactly the self-report the
// bond exists to replace. The Amount and VerifiedAt fields are filled in by
// VerifyBond from proven data and are zero on a descriptor as received.
type BondRef struct {
	// Chain is the EIP-155 chain id the bond lives on.
	Chain uint64
	// Contract is the StakeVault address.
	Contract Address
	// Owner is the wallet whose bond backs this node, i.e. NodeRegistry's
	// Node.owner. StakeVault keys `bonded` by address, not by node id.
	Owner Address

	// Amount is the PROVEN active bond in wei-equivalent base units. Zero until
	// VerifyBond fills it.
	Amount *big.Int
	// PendingWithdraw is the proven amount already in the withdrawal window.
	PendingWithdraw *big.Int
	// VerifiedAt is the execution block the proof was taken against.
	VerifiedAt uint64
}

var (
	// ErrNoBond means the proof showed a zero active bond: the node either
	// never bonded or has fully withdrawn (T14.1).
	ErrNoBond = errors.New("axon/sybil: no active bond at the referenced address")
	// ErrBelowFloor means the bond exists but is under the role's floor.
	ErrBelowFloor = errors.New("axon/sybil: bond is below the floor for this role")
	// ErrWrongChain means the descriptor points at a chain this node does not
	// follow. It is refused rather than shrugged at: a bond on a chain nobody
	// verifies is a bond nobody can slash.
	ErrWrongChain = errors.New("axon/sybil: bond references a chain this node does not follow")
	// ErrUnverifiable means the proof did not check out against the
	// authenticated state root. It is NOT a soft failure and never degrades to
	// "assume the provider is honest".
	ErrUnverifiable = errors.New("axon/sybil: bond proof does not verify against the authenticated state root")
)

// StateSource yields an AUTHENTICATED execution state root.
//
// The only implementation that matters is `internal/ethproof`'s light client,
// which derives the root from a sync-committee-verified beacon header. The
// interface exists so this package does not depend on the client's construction,
// not so the root can come from somewhere cheaper.
type StateSource interface {
	// AuthenticatedStateRoot returns the verified execution state root and the
	// block it belongs to.
	AuthenticatedStateRoot(ctx context.Context) (root [32]byte, block uint64, err error)
	// ChainID is the chain the source follows.
	ChainID() uint64
}

// ProofSource fetches Merkle proofs. IT IS UNTRUSTED.
//
// T14.2 IS ENFORCED BY THIS TYPE'S SHAPE. It returns proof nodes and nothing
// else: no balance, no decoded slot, no "amount" field. There is therefore no
// value a caller could take from it and use, and no code path in which trusting
// the provider is expressible. An interface that returned a uint64 balance
// alongside the proof would make the wrong thing the easy thing, and the easy
// thing is what a later edit reaches for.
type ProofSource interface {
	// AccountAndSlots returns the account proof for `contract` and a storage
	// proof for each slot, all against `block`.
	AccountAndSlots(ctx context.Context, contract Address, slots [][32]byte, block uint64) (accountProof [][]byte, slotProofs [][][]byte, err error)
}

// StakeVault storage layout, CONFIRMED BY solc --storage-layout, not sketched:
//
//	slot 0  _owner (address) + withdrawDelay (uint64), packed
//	slot 1  bonded            mapping(address => uint256)
//	slot 2  pendingWithdraw   mapping(address => uint256)
//	slot 3  withdrawableAt    mapping(address => uint64)
//	slot 4  isSlasher         mapping(address => bool)
//
// The packing in slot 0 is the reason this is read from the compiler rather than
// counted by hand: `_owner` comes from Ownable, so the mappings do not start
// where a reading of StakeVault.sol alone would put them. §12.5 records the same
// lesson for AxonRegistry.
const (
	slotBonded          = 1
	slotPendingWithdraw = 2
)

// VerifyBond proves a node's bond against the light client's state root.
//
// THE ORDER OF OPERATIONS IS THE SECURITY PROPERTY. The root comes first and
// from the authenticated source; the proof comes second and from anywhere; the
// amount is DERIVED from the proof by verification. There is no branch in which
// an unverified value reaches the return.
func VerifyBond(ctx context.Context, ref BondRef, state StateSource, proofs ProofSource) (BondRef, error) {
	out := ref
	out.Amount, out.PendingWithdraw = big.NewInt(0), big.NewInt(0)

	if state == nil || proofs == nil {
		return out, ErrUnverifiable
	}
	if ref.Chain != state.ChainID() {
		return out, fmt.Errorf("%w: descriptor says %d, this node follows %d",
			ErrWrongChain, ref.Chain, state.ChainID())
	}

	root, block, err := state.AuthenticatedStateRoot(ctx)
	if err != nil {
		// A light client that cannot produce a root has not produced an
		// unverified one. Failing here is correct: the alternative is admitting
		// a node on no evidence during exactly the window an adversary would
		// choose to cause.
		return out, fmt.Errorf("%w: %v", ErrUnverifiable, err)
	}

	var ownerKey [32]byte
	copy(ownerKey[12:], ref.Owner[:])
	bondedSlot := ethproof.StorageSlotKey(ownerKey, slotBonded)
	pendingSlot := ethproof.StorageSlotKey(ownerKey, slotPendingWithdraw)

	accountProof, slotProofs, err := proofs.AccountAndSlots(ctx, ref.Contract,
		[][32]byte{bondedSlot, pendingSlot}, block)
	if err != nil {
		return out, fmt.Errorf("%w: fetching proof: %v", ErrUnverifiable, err)
	}
	if len(slotProofs) != 2 {
		return out, fmt.Errorf("%w: got %d slot proofs, want 2", ErrUnverifiable, len(slotProofs))
	}

	accountKey := ethproof.Keccak256(ref.Contract[:])
	accountRLP, err := ethproof.VerifyProof(root[:], accountKey, accountProof)
	if err != nil {
		return out, fmt.Errorf("%w: account: %v", ErrUnverifiable, err)
	}
	if len(accountRLP) == 0 {
		// The contract address holds no account. That is a real answer -- the
		// StakeVault is not deployed on this chain -- and it is not a bond.
		return out, ErrNoBond
	}
	storageRoot, err := ethproof.AccountStorageRoot(accountRLP)
	if err != nil {
		return out, fmt.Errorf("%w: storage root: %v", ErrUnverifiable, err)
	}

	read := func(slot [32]byte, proof [][]byte) (*big.Int, error) {
		key := ethproof.Keccak256(slot[:])
		raw, err := ethproof.VerifyProof(storageRoot, key, proof)
		if err != nil {
			return nil, err
		}
		if len(raw) == 0 {
			return big.NewInt(0), nil // an absent slot is zero, proven
		}
		v, err := ethproof.DecodeSlotValue(raw)
		if err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(v[:]), nil
	}

	bonded, err := read(bondedSlot, slotProofs[0])
	if err != nil {
		return out, fmt.Errorf("%w: bonded slot: %v", ErrUnverifiable, err)
	}
	pending, err := read(pendingSlot, slotProofs[1])
	if err != nil {
		return out, fmt.Errorf("%w: pendingWithdraw slot: %v", ErrUnverifiable, err)
	}

	out.Amount, out.PendingWithdraw, out.VerifiedAt = bonded, pending, block
	if bonded.Sign() == 0 {
		// T14.1. A withdrawn bond proves as zero in `bonded` even while
		// `pendingWithdraw` still holds the amount, because StakeVault moves it
		// between the two mappings. The active bond is the one that backs a
		// claim going forward, so the node is refused -- it has announced its
		// exit, and the withdrawal window is not a reason to keep routing
		// through it.
		return out, ErrNoBond
	}
	return out, nil
}

// Role is a bonded role. It mirrors NodeRegistry's capability bits; CLIENT and
// SERVICE are absent because neither is ever registered (§17.1).
type Role uint8

const (
	RoleRelay Role = iota
	RoleStorage
	RoleDHT
	RoleExit
)

func (r Role) String() string {
	switch r {
	case RoleStorage:
		return "storage"
	case RoleDHT:
		return "dht"
	case RoleExit:
		return "exit"
	default:
		return "relay"
	}
}

// BondFloor is the minimum bond for a role, in whole tokens. See params for why
// every one of these figures is provisional.
func BondFloor(r Role) int64 {
	switch r {
	case RoleStorage:
		return bondFloorStorage
	case RoleDHT:
		return bondFloorDHT
	case RoleExit:
		return bondFloorExit
	default:
		return bondFloorRelay
	}
}

// Admit is E14.1: a node without a sufficient proven bond cannot enter a
// consequential role.
//
// `Withdrawing` is reported rather than refused on its own. A node with a
// pending withdrawal still has an active bond and is still slashable, so it may
// still serve -- but a caller building a 45-day guard relationship should know
// the operator has announced an exit, and only a caller can weigh that.
func Admit(ref BondRef, r Role) (withdrawing bool, err error) {
	if ref.VerifiedAt == 0 || ref.Amount == nil {
		// An unverified reference has never been past VerifyBond. Treating it
		// as "not yet checked" rather than "no bond" would let a caller admit
		// on a struct it forgot to verify.
		return false, ErrUnverifiable
	}
	if ref.Amount.Sign() == 0 {
		return false, ErrNoBond
	}
	floor := big.NewInt(BondFloor(r))
	if ref.Amount.Cmp(floor) < 0 {
		return false, fmt.Errorf("%w: %s < %s for role %s",
			ErrBelowFloor, ref.Amount, floor, r)
	}
	return ref.PendingWithdraw != nil && ref.PendingWithdraw.Sign() > 0, nil
}

// Freshness is how old a proven bond may be before it must be re-proven.
//
// PROVISIONAL. Derivation: a bond can be withdrawn, and StakeVault's
// withdrawDelay is the window in which that is visible before the funds leave.
// Re-proving materially faster than that window buys nothing; materially slower
// admits a node whose bond is already gone. The correct value is therefore
// withdrawDelay read from the chain, and this constant is the fallback for a
// node that has not read it.
const Freshness = 1 * time.Hour

// Stale reports whether a verified bond is old enough to need re-proving.
func Stale(ref BondRef, currentBlock uint64, blockTime time.Duration) bool {
	if ref.VerifiedAt == 0 || currentBlock < ref.VerifiedAt {
		return true
	}
	age := time.Duration(currentBlock-ref.VerifiedAt) * blockTime
	return age > Freshness
}
