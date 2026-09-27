package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

// On-chain resolution against the deployed AxonRegistry (items 2.4, 2.5).
//
// This is the resolver's SLOW PATH: it answers "what is the state and the
// DomainIdentity of this name, proven against the light client's verified state
// root". It is the T14.2 property, reused -- the same shape as sybil.VerifyBond,
// and for the same reason: the root comes first from the authenticated source,
// the proof second from anywhere, and the value is DERIVED from the proof by
// verification. There is no branch in which an unverified value reaches the
// return.
//
// STORAGE LAYOUT, CONFIRMED BY solc --storage-layout, not sketched (§12.5's
// discipline; the same lesson bond.go records for StakeVault). AxonRegistry's
// _owner from Ownable takes slot 0, so the mappings do not start where a reading
// of AxonRegistry.sol alone would put them:
//
//	slot 1   _names    mapping(bytes32 => Name)          -> struct base per name
//	slot 8   stateOf   mapping(bytes32 => NameState)     -> ACTIVE/PRUNED/...
//
// and WITHIN the Name struct, again from solc:
//
//	struct slot 0   owner(0) expiresAt(20) version(28)   packed
//	struct slot 1   domainKey (bytes32)                  <- the DomainIdentity
//
// so domainKey's storage slot is SlotAt(keccak(nameHash‖1), 1).

// NameState is AxonRegistry's per-name lifecycle enum, in its on-chain order.
type NameState uint8

const (
	StateActive     NameState = iota // 0
	StatePruned                      // 1
	StateSeized                      // 2
	StateRecyclable                  // 3
)

func (s NameState) String() string {
	switch s {
	case StateActive:
		return "ACTIVE"
	case StatePruned:
		return "PRUNED"
	case StateSeized:
		return "SEIZED"
	case StateRecyclable:
		return "RECYCLABLE"
	default:
		return fmt.Sprintf("NameState(%d)", uint8(s))
	}
}

const (
	slotNames   = 1 // _names   mapping(bytes32 => Name)
	slotStateOf = 8 // stateOf  mapping(bytes32 => NameState)

	// domainKey is the SECOND word of the Name struct (slot 0 packs
	// owner/expiresAt/version; slot 1 is domainKey).
	structOffsetDomainKey = 1
)

var (
	// ErrUnverifiable means no verified state root, or a proof that did not
	// verify. It is NOT "the name does not exist" -- it is "this node cannot
	// currently prove anything", which must fail closed rather than resolve.
	ErrUnverifiable = errors.New("axon/registry: name state is unverifiable")
	// ErrNotActive means the name is PRUNED, SEIZED or RECYCLABLE. E-G9b: a
	// PRUNED name is refused at resolve. Carried as a typed error so a caller
	// can distinguish a governance refusal from a missing name.
	ErrNotActive = errors.New("axon/registry: name is not ACTIVE on chain")
	// ErrNoSuchName means the name resolves to the zero domain key -- never
	// registered, or SEIZED (seizure rotates the key to zero, R-93.4).
	ErrNoSuchName = errors.New("axon/registry: name has no domain key on chain")
	// ErrWrongChain means the reader follows a different chain than asked.
	ErrWrongChain = errors.New("axon/registry: descriptor chain does not match this node's")
)

// StateSource is the authenticated light client. Same shape as sybil's.
type StateSource interface {
	AuthenticatedStateRoot(ctx context.Context) (root [32]byte, block uint64, err error)
	ChainID() uint64
}

// ProofSource fetches Merkle proofs. IT IS UNTRUSTED -- it returns proof nodes
// and nothing a caller could take on faith. Same shape as sybil's.
type ProofSource interface {
	AccountAndSlots(ctx context.Context, contract [20]byte, slots [][32]byte, block uint64) (accountProof [][]byte, slotProofs [][][]byte, err error)
}

// ChainReader resolves names against the deployed AxonRegistry.
type ChainReader struct {
	// Registry is the AxonRegistry contract address (contracts.Mainnet.AxonRegistry).
	Registry [20]byte
	// ChainID this reader follows; a descriptor for another chain is refused.
	ChainID uint64
	State   StateSource
	Proofs  ProofSource
}

// Authenticated satisfies resolver.ChainSource: it reports whether a verified
// header chain is actually held. An RPC that answers is not a chain that
// verifies, and the resolver refuses the slow path (T10.2) when this is false.
func (c *ChainReader) Authenticated() bool {
	if c == nil || c.State == nil || c.Proofs == nil {
		return false
	}
	_, _, err := c.State.AuthenticatedStateRoot(context.Background())
	return err == nil
}

// Resolve reads stateOf + domainKey for nameHash and returns the verified
// DomainIdentity, or an error. It satisfies resolver.ChainSource.
//
// records is always nil: the chain holds the IDENTITY and the STATE, never the
// DomainRecord -- records are the DHT's job, keyed by the identity this returns.
// A chain answer establishes WHO the name is and WHETHER it may resolve; the
// service records are fetched separately.
func (c *ChainReader) Resolve(ctx context.Context, nameHash [32]byte) (identity [32]byte, records []byte, err error) {
	if c == nil || c.State == nil || c.Proofs == nil {
		return identity, nil, ErrUnverifiable
	}

	// Root FIRST, from the authenticated source. A light client that cannot
	// produce a root has not produced an unverified one; failing here is
	// correct, because the alternative is resolving on no evidence.
	root, block, err := c.State.AuthenticatedStateRoot(ctx)
	if err != nil {
		return identity, nil, fmt.Errorf("%w: %v", ErrUnverifiable, err)
	}

	stateSlot := ethproof.StorageSlotKey(nameHash, slotStateOf)
	nameBase := ethproof.StorageSlotKey(nameHash, slotNames)
	domainKeySlot := ethproof.SlotAt(nameBase, structOffsetDomainKey)

	accountProof, slotProofs, err := c.Proofs.AccountAndSlots(ctx, c.Registry,
		[][32]byte{stateSlot, domainKeySlot}, block)
	if err != nil {
		return identity, nil, fmt.Errorf("%w: fetching proof: %v", ErrUnverifiable, err)
	}
	if len(slotProofs) != 2 {
		return identity, nil, fmt.Errorf("%w: got %d slot proofs, want 2",
			ErrUnverifiable, len(slotProofs))
	}

	// Verify the account, then the two slots against its storage root.
	accountKey := ethproof.Keccak256(c.Registry[:])
	accountRLP, err := ethproof.VerifyProof(root[:], accountKey, accountProof)
	if err != nil {
		return identity, nil, fmt.Errorf("%w: account: %v", ErrUnverifiable, err)
	}
	if len(accountRLP) == 0 {
		// No account at the registry address on this chain. A real answer -- the
		// registry is not deployed here -- and not a resolution.
		return identity, nil, ErrUnverifiable
	}
	storageRoot, err := ethproof.AccountStorageRoot(accountRLP)
	if err != nil {
		return identity, nil, fmt.Errorf("%w: storage root: %v", ErrUnverifiable, err)
	}

	read := func(slot [32]byte, proof [][]byte) ([32]byte, error) {
		key := ethproof.Keccak256(slot[:])
		raw, verr := ethproof.VerifyProof(storageRoot, key, proof)
		if verr != nil {
			return [32]byte{}, verr
		}
		if len(raw) == 0 {
			return [32]byte{}, nil // an absent slot is zero, PROVEN
		}
		return ethproof.DecodeSlotValue(raw)
	}

	stateRaw, err := read(stateSlot, slotProofs[0])
	if err != nil {
		return identity, nil, fmt.Errorf("%w: stateOf slot: %v", ErrUnverifiable, err)
	}
	// The enum occupies the low byte of a 32-byte word.
	state := NameState(stateRaw[31])

	// E-G9b: a PRUNED (or SEIZED, or RECYCLABLE) name is refused at resolve. The
	// state is read and checked BEFORE the identity, so a non-ACTIVE name never
	// returns a usable key -- and this holds even though seizure ALSO rotates
	// the key to zero (R-93.4): two independent barriers, either sufficient.
	if state != StateActive {
		return identity, nil, fmt.Errorf("%w: %s", ErrNotActive, state)
	}

	domainKey, err := read(domainKeySlot, slotProofs[1])
	if err != nil {
		return identity, nil, fmt.Errorf("%w: domainKey slot: %v", ErrUnverifiable, err)
	}
	if domainKey == ([32]byte{}) {
		// Zero key: never registered, or seized (seizure zeroes the key). Either
		// way there is no identity to resolve to.
		return identity, nil, ErrNoSuchName
	}

	return domainKey, nil, nil
}
