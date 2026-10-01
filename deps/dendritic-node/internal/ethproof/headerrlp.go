package ethproof

// The execution block header, RLP-encoded — roadmap P14.5.
//
// WHY A WATCHTOWER NEEDS THIS AT ALL
// ----------------------------------
// The light-client API serves the CURRENT finality update and one update per
// sync-committee period. It cannot hand back the execution payload header for an
// arbitrary past block, so there is no way to ask "what was block N's
// receiptsRoot" and get an authenticated answer.
//
// A watchtower that was down therefore cannot authenticate the blocks it missed
// by asking for them. It has to walk BACKWARDS from a block it does trust,
// re-encoding each header and checking that it hashes to the parentHash the
// block after it declared:
//
//	authenticated block hash  (from the finalised execution payload)
//	         ▲
//	         │ parentHash
//	    block N-1  ── keccak(rlp(header)) must equal it
//	         ▲
//	         │ parentHash
//	    block N-2  ── and so on, back to the last authenticated checkpoint
//
// Each link binds by HASH, never by height, so the walk cannot wander onto a
// competing branch during a reorg. That property is why catch-up is allowed to
// exist at all.
//
// THE FORK TRAP
// -------------
// The header gained fields at London (baseFeePerGas), Shanghai
// (withdrawalsRoot), Cancun (blobGasUsed, excessBlobGas, parentBeaconBlockRoot)
// and Prague (requestsHash). A header encoded with the wrong field COUNT hashes
// to something that looks like a perfectly good block hash and matches nothing,
// so the layout is selected from the recorded fork and an unrecognised chain
// refuses rather than guessing — exactly as ExecutionPayloadHeader.HashTreeRoot
// does for the consensus side.
//
// There is no fallback to an older layout anywhere in this file. The hash check
// is the backstop: an encoding this file gets wrong cannot produce a matching
// hash, so the failure mode is a refusal rather than a false authentication.

import (
	"errors"
	"fmt"
	"math/big"
)

// ExecutionFork names a header layout, not a fork's full semantics. Two forks
// that do not change the header share a value here.
type ExecutionFork uint8

const (
	// ForkUnknown is the zero value and is never valid. A caller that forgot to
	// record the fork must fail, not silently get the oldest layout.
	ForkUnknown ExecutionFork = iota
	// ForkLondon added baseFeePerGas: 16 fields.
	ForkLondon
	// ForkShanghai added withdrawalsRoot: 17 fields.
	ForkShanghai
	// ForkCancun added blobGasUsed, excessBlobGas, parentBeaconBlockRoot: 20.
	ForkCancun
	// ForkPrague added requestsHash: 21 fields.
	//
	// Osaka (Fusaka) does not change the header layout and shares this value —
	// confirmed against live mainnet blocks, not assumed.
	ForkPrague
)

func (f ExecutionFork) String() string {
	switch f {
	case ForkLondon:
		return "london"
	case ForkShanghai:
		return "shanghai"
	case ForkCancun:
		return "cancun"
	case ForkPrague:
		return "prague/osaka"
	default:
		return "unknown"
	}
}

var (
	// ErrForkUnrecorded means the header layout for this chain or time is not
	// recorded here. Refused rather than guessed.
	ErrForkUnrecorded = errors.New("ethproof: execution header layout is not recorded for this fork")
	// ErrHeaderIncomplete means a field the recorded layout requires is absent.
	ErrHeaderIncomplete = errors.New("ethproof: execution header is missing a field its fork requires")
	// ErrHeaderHashMismatch means a header did not hash to the value that
	// authenticated it.
	ErrHeaderHashMismatch = errors.New("ethproof: execution header does not hash to its authenticated hash")
)

// Mainnet fork activation timestamps. Recorded constants, so that a header's own
// timestamp selects its layout without asking anybody.
const (
	mainnetLondonTime   uint64 = 1628166822 // block 12965000
	mainnetShanghaiTime uint64 = 1681338455
	mainnetCancunTime   uint64 = 1710338135
	mainnetPragueTime   uint64 = 1746612311
)

// ExecutionForkAt selects the header layout for a chain and block timestamp.
//
// Mainnet only. A testnet has different activation times and returning mainnet's
// would be a confident wrong answer, so an unrecognised chain is an error.
//
// The newest RECORDED layout applies from its activation onward. A future fork
// that changes the header will therefore be encoded with Prague's layout, fail
// the hash check, and stop the watchtower — which is the correct outcome and the
// reason this can be strict without needing to predict Ethereum's schedule.
func ExecutionForkAt(chainID uint64, timestamp uint64) (ExecutionFork, error) {
	if chainID != 1 {
		return ForkUnknown, fmt.Errorf("%w: chain %d has no recorded activation times",
			ErrForkUnrecorded, chainID)
	}
	switch {
	case timestamp >= mainnetPragueTime:
		return ForkPrague, nil
	case timestamp >= mainnetCancunTime:
		return ForkCancun, nil
	case timestamp >= mainnetShanghaiTime:
		return ForkShanghai, nil
	case timestamp >= mainnetLondonTime:
		return ForkLondon, nil
	default:
		// Pre-London headers exist but this system has never needed one, and a
		// layout nothing exercises is a layout nobody knows is right.
		return ForkUnknown, fmt.Errorf("%w: timestamp %d predates London",
			ErrForkUnrecorded, timestamp)
	}
}

// ExecutionHeader is an execution-layer block header.
//
// The post-fork fields are POINTERS so that "absent" and "zero" are different
// things. A Cancun header with excessBlobGas of zero is ordinary; a Cancun
// header with excessBlobGas missing is malformed, and a value type could not
// tell them apart.
type ExecutionHeader struct {
	ParentHash  [32]byte
	UncleHash   [32]byte
	Coinbase    [20]byte
	StateRoot   [32]byte
	TxRoot      [32]byte
	ReceiptRoot [32]byte
	Bloom       Bloom2048
	Difficulty  *big.Int
	Number      *big.Int
	GasLimit    uint64
	GasUsed     uint64
	Time        uint64
	Extra       []byte
	MixDigest   [32]byte
	Nonce       [8]byte

	BaseFee               *big.Int  // London
	WithdrawalsRoot       *[32]byte // Shanghai
	BlobGasUsed           *uint64   // Cancun
	ExcessBlobGas         *uint64   // Cancun
	ParentBeaconBlockRoot *[32]byte // Cancun
	RequestsHash          *[32]byte // Prague
}

// EncodeExecutionHeader produces the RLP whose keccak is the block hash.
func EncodeExecutionHeader(h ExecutionHeader, fork ExecutionFork) ([]byte, error) {
	if fork == ForkUnknown {
		return nil, fmt.Errorf("%w: no fork given", ErrForkUnrecorded)
	}

	items := [][]byte{
		EncodeRLPBytes(h.ParentHash[:]),
		EncodeRLPBytes(h.UncleHash[:]),
		EncodeRLPBytes(h.Coinbase[:]),
		EncodeRLPBytes(h.StateRoot[:]),
		EncodeRLPBytes(h.TxRoot[:]),
		EncodeRLPBytes(h.ReceiptRoot[:]),
		EncodeRLPBytes(h.Bloom[:]),
		EncodeRLPBig(h.Difficulty),
		EncodeRLPBig(h.Number),
		EncodeRLPUint(h.GasLimit),
		EncodeRLPUint(h.GasUsed),
		EncodeRLPUint(h.Time),
		EncodeRLPBytes(h.Extra),
		EncodeRLPBytes(h.MixDigest[:]),
		EncodeRLPBytes(h.Nonce[:]),
	}

	// From London on, every later layout is a strict extension of the one
	// before, so the field list is built by falling THROUGH the cases in order.
	// The switch is on the layout, and there is no default that quietly stops
	// early.
	need := func(name string, present bool) error {
		if !present {
			return fmt.Errorf("%w: %s is required at %s", ErrHeaderIncomplete, name, fork)
		}
		return nil
	}

	if fork >= ForkLondon {
		if err := need("baseFeePerGas", h.BaseFee != nil); err != nil {
			return nil, err
		}
		items = append(items, EncodeRLPBig(h.BaseFee))
	}
	if fork >= ForkShanghai {
		if err := need("withdrawalsRoot", h.WithdrawalsRoot != nil); err != nil {
			return nil, err
		}
		items = append(items, EncodeRLPBytes(h.WithdrawalsRoot[:]))
	}
	if fork >= ForkCancun {
		if err := need("blobGasUsed", h.BlobGasUsed != nil); err != nil {
			return nil, err
		}
		if err := need("excessBlobGas", h.ExcessBlobGas != nil); err != nil {
			return nil, err
		}
		if err := need("parentBeaconBlockRoot", h.ParentBeaconBlockRoot != nil); err != nil {
			return nil, err
		}
		items = append(items,
			EncodeRLPUint(*h.BlobGasUsed),
			EncodeRLPUint(*h.ExcessBlobGas),
			EncodeRLPBytes(h.ParentBeaconBlockRoot[:]),
		)
	}
	if fork >= ForkPrague {
		if err := need("requestsHash", h.RequestsHash != nil); err != nil {
			return nil, err
		}
		items = append(items, EncodeRLPBytes(h.RequestsHash[:]))
	}

	return EncodeRLPList(items...), nil
}

// AuthenticateHeader returns the header's own hash only if it equals the hash
// that authenticated it.
//
// The same shape as AuthenticateReceipts and for the same reason: there is no
// boolean for a caller to ignore, and the only way to get a usable header is to
// have supplied the hash it must match.
func AuthenticateHeader(h ExecutionHeader, fork ExecutionFork, authenticated [32]byte) ([32]byte, error) {
	encoded, err := EncodeExecutionHeader(h, fork)
	if err != nil {
		return [32]byte{}, err
	}
	var got [32]byte
	copy(got[:], Keccak256(encoded))
	if got != authenticated {
		return [32]byte{}, fmt.Errorf("%w: computed %x, authenticated %x",
			ErrHeaderHashMismatch, got[:8], authenticated[:8])
	}
	return got, nil
}
