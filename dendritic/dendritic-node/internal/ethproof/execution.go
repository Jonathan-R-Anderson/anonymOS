package ethproof

// The execution bridge — roadmap P12-5.7.
//
// WHERE THE TWO HALVES OF P12 MEET
// --------------------------------
//	finalised beacon header
//	      │ BodyRoot
//	      ▼
//	execution_branch          SSZ proof at EXECUTION_PAYLOAD_INDEX
//	      ▼
//	ExecutionPayloadHeader    authenticated
//	      │ StateRoot
//	      ▼
//	eth_getProof verifier     P12-2, unchanged
//	      ▼
//	channels(channelID)
//
// P12-2 could already prove a storage slot against a state root. What it could
// not do was say where a trustworthy state root comes from. This is that.
//
// THE DESIGN DECISION THAT MATTERS
// --------------------------------
// This does NOT take an RPC-supplied execution header and check it against the
// authenticated one. It takes the authenticated payload and RETURNS its state
// root, and that is the only root a caller gets.
//
// The difference is the whole security property. A comparison is a step that
// can be skipped, inverted, or made non-fatal by a well-meaning refactor —
// and if it is skipped, everything downstream still works perfectly, because a
// fabricated state root produces storage proofs that verify against it. There
// is no comparison here to skip: the fabricated root is simply never in scope.
//
// FORK-DEPENDENT, LIKE EVERYTHING ELSE IN THIS FILE'S NEIGHBOURHOOD
// -----------------------------------------------------------------
// ExecutionPayloadHeader gained fields at Capella (withdrawals_root) and Deneb
// (blob gas). A root computed with the wrong field count is a self-consistent
// wrong answer, so the field list is selected by the state's SpecVersion and an
// unrecorded fork refuses rather than guessing.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ExecutionPayloadIndex is the generalized index of the execution payload
// header within BeaconBlockBody.
//
// FORK-DEPENDENT, like the light client indices in rotation.go. This is the
// Bellatrix-through-Deneb value.
const ExecutionPayloadIndex uint64 = 25

var (
	// ErrNotFinalized means the bridge was asked to authenticate a payload
	// against a header that is not finalised.
	ErrNotFinalized = errors.New("lightclient: execution payload must hang from a FINALIZED beacon header")
	// ErrPayloadNotAuthenticated means the execution branch does not place this
	// payload in that beacon block.
	ErrPayloadNotAuthenticated = errors.New("lightclient: execution payload is not in the finalised beacon block")
)

// ExecutionPayloadHeader is the consensus layer's summary of an execution
// block. Only the fields needed to compute its root and to bridge to the
// execution layer are modelled.
type ExecutionPayloadHeader struct {
	ParentHash    Root
	FeeRecipient  [20]byte
	StateRoot     Root
	ReceiptsRoot  Root
	LogsBloom     [256]byte
	PrevRandao    Root
	BlockNumber   uint64
	GasLimit      uint64
	GasUsed       uint64
	Timestamp     uint64
	ExtraData     []byte
	BaseFeePerGas [32]byte // uint256, little-endian
	BlockHash     Root
	TxRoot        Root
	// Capella and later.
	WithdrawalsRoot Root
	// Deneb and later.
	BlobGasUsed   uint64
	ExcessBlobGas uint64
}

// HashTreeRoot computes the payload header's SSZ root for a fork.
//
// The field COUNT is what the fork changes, and a root computed over the wrong
// count is self-consistent and wrong — it will match nothing Ethereum published
// and the mismatch will look like a bad branch. Hence the explicit switch and
// the refusal to guess.
func (p ExecutionPayloadHeader) HashTreeRoot(spec SpecVersion) (Root, error) {
	extraData, err := byteListRoot(p.ExtraData, 32)
	if err != nil {
		return Root{}, err
	}
	logsBloom, err := BytesRoot(p.LogsBloom[:])
	if err != nil {
		return Root{}, err
	}
	var feeRecipient Root
	copy(feeRecipient[:], p.FeeRecipient[:])
	var baseFee Root
	copy(baseFee[:], p.BaseFeePerGas[:])

	fields := []Root{
		p.ParentHash, feeRecipient, p.StateRoot, p.ReceiptsRoot, logsBloom,
		p.PrevRandao, Uint64Root(p.BlockNumber), Uint64Root(p.GasLimit),
		Uint64Root(p.GasUsed), Uint64Root(p.Timestamp), extraData, baseFee,
		p.BlockHash, p.TxRoot,
	}

	switch spec {
	case SpecAltair, SpecElectra, SpecFulu:
		// The Deneb field set: Capella added withdrawals_root and Deneb added
		// the blob gas fields. Neither Electra nor Fulu redefines
		// ExecutionPayloadHeader — consensus-specs v1.6.1 has no class
		// definition for it under specs/electra or specs/fulu, only usages —
		// so all three share this layout.
		//
		// Confirmed against live mainnet Fulu data, which serialises exactly
		// these seventeen fields in this order.
		fields = append(fields, p.WithdrawalsRoot,
			Uint64Root(p.BlobGasUsed), Uint64Root(p.ExcessBlobGas))
	default:
		return Root{}, fmt.Errorf(
			"%w: execution payload field set for %q is not recorded", ErrSpecUnsupported, spec)
	}
	return ContainerRoot(fields)
}

// byteListRoot merkleises a variable-length byte list and mixes in its length.
//
// The length is what distinguishes a list from a vector, and omitting it would
// make two different extra_data values with the same prefix hash identically.
func byteListRoot(b []byte, limitBytes uint64) (Root, error) {
	if uint64(len(b)) > limitBytes {
		return Root{}, fmt.Errorf("ethproof: byte list is %d bytes, limit %d", len(b), limitBytes)
	}
	chunkLimit := int((limitBytes + BytesPerChunk - 1) / BytesPerChunk)
	if chunkLimit == 0 {
		chunkLimit = 1
	}
	chunks := make([]Root, 0, chunkLimit)
	for i := 0; i < len(b); i += BytesPerChunk {
		var chunk Root
		copy(chunk[:], b[i:])
		chunks = append(chunks, chunk)
	}
	root, err := Merkleize(chunks, nextPowerOfTwo(chunkLimit))
	if err != nil {
		return Root{}, err
	}
	return MixInLength(root, uint64(len(b))), nil
}

// AuthenticatedStateRoot is the bridge, and the only way to obtain a state root
// this system will act on.
//
// Returns the execution state root authenticated by the FINALISED beacon
// header, with the execution block number and hash it belongs to. Nothing
// RPC-supplied is consulted: the payload must be proven into the beacon block
// this state has already finalised, and what comes back is that payload's own
// state root.
//
// A caller cannot pass in an execution header and ask whether it is acceptable,
// because that question invites a comparison, and a comparison invites being
// skipped.
func (s *LightClientState) AuthenticatedStateRoot(
	payload ExecutionPayloadHeader, executionBranch []Root) (Root, uint64, Root, error) {

	// 1. The beacon header must be FINALIZED, not merely verified. A payload
	//    hanging from an attested-but-reorgeable header could name a block that
	//    never existed.
	if s.FinalizedHeader.Slot == 0 && s.FinalizedHeader.BodyRoot == (Root{}) {
		return Root{}, 0, Root{}, ErrNotFinalized
	}
	level, err := s.TrustLevelOf(s.FinalizedHeader)
	if err != nil {
		return Root{}, 0, Root{}, err
	}
	if level != HeaderFinalized {
		return Root{}, 0, Root{}, fmt.Errorf("%w: header is %s", ErrNotFinalized, level)
	}

	// 2. The payload must be IN that block. Its root, proven at the execution
	//    payload index against the finalised header's body root.
	payloadRoot, err := payload.HashTreeRoot(s.Spec)
	if err != nil {
		return Root{}, 0, Root{}, err
	}
	if err := VerifyBranch(payloadRoot, executionBranch,
		ExecutionPayloadIndex, s.FinalizedHeader.BodyRoot); err != nil {
		return Root{}, 0, Root{}, fmt.Errorf("%w: %v", ErrPayloadNotAuthenticated, err)
	}

	// 3. The state root comes from the authenticated payload. There is no other
	//    candidate anywhere in this function.
	return payload.StateRoot, payload.BlockNumber, payload.BlockHash, nil
}

// ExecutionBlockNumber reads a payload's height, for matching against an
// execution-layer header a caller may have fetched.
//
// Deliberately NOT a comparison helper. A caller that wants to know whether an
// RPC's header is the right one should ask what the authenticated block number
// and hash ARE, and then use the authenticated state root regardless.
func (p ExecutionPayloadHeader) ExecutionBlockNumber() uint64 { return p.BlockNumber }

// Uint256LE builds a little-endian uint256 field from a small value, for tests
// and for callers assembling a payload header from RPC data.
func Uint256LE(v uint64) [32]byte {
	var out [32]byte
	binary.LittleEndian.PutUint64(out[:8], v)
	return out
}
