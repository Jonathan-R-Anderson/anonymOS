package ethproof

// Authenticated blocks and the logs inside them — roadmap P14.5.
//
// This is where the two halves meet. An AuthenticatedBlock is a block whose
// identity and whose commitments are established, by one of exactly two routes
// and no others:
//
//	from the FINALISED execution payload   (the beacon chain, via P12's branch)
//	from a parentHash link                 (a header that hashes to what the
//	                                        block after it declared)
//
// There is no constructor taking an RPC response. That is deliberate: an
// AuthenticatedBlock assembled from JSON would be indistinguishable, at every
// later call site, from one the chain actually attests to.

import (
	"errors"
	"fmt"
)

// ErrBlockNotAuthenticated means a block was offered without either route
// having established it.
var ErrBlockNotAuthenticated = errors.New("ethproof: block is not authenticated")

// AuthenticatedBlock carries the commitments a watchtower reasons about.
//
// authentic is unexported and is the guard, the same device OnChainChannel uses
// for fromChain: no package outside this one can construct a value that claims
// to be authenticated.
type AuthenticatedBlock struct {
	Number       uint64
	Hash         [32]byte
	ParentHash   [32]byte
	ReceiptsRoot Root
	LogsBloom    Bloom2048
	Timestamp    uint64

	authentic bool
}

// Authenticated reports whether this value came from one of the two routes.
func (b AuthenticatedBlock) Authenticated() bool { return b.authentic }

// BlockFromFinalizedPayload builds an AuthenticatedBlock from an execution
// payload that a LightClientState has already proven into a finalised beacon
// header.
//
// The caller must have obtained the payload through AuthenticatedStateRoot,
// which verifies the SSZ execution branch. Passing a payload that has not been
// through it is a programming error this cannot detect — hence the name, which
// says what the argument has to be.
func BlockFromFinalizedPayload(p ExecutionPayloadHeader) AuthenticatedBlock {
	return AuthenticatedBlock{
		Number:       p.BlockNumber,
		Hash:         p.BlockHash,
		ParentHash:   p.ParentHash,
		ReceiptsRoot: p.ReceiptsRoot,
		LogsBloom:    p.LogsBloom,
		Timestamp:    p.Timestamp,
		authentic:    true,
	}
}

// BlockFromParentLink authenticates a header against the hash a block already
// authenticated declared as its parent.
//
// This is the only way to move backwards in time, and it binds by HASH. A caller
// cannot pass a height and get a block: heights are ambiguous across a reorg and
// hashes are not.
func BlockFromParentLink(h ExecutionHeader, fork ExecutionFork, childParentHash [32]byte) (AuthenticatedBlock, error) {
	hash, err := AuthenticateHeader(h, fork, childParentHash)
	if err != nil {
		return AuthenticatedBlock{}, err
	}
	if h.Number == nil {
		return AuthenticatedBlock{}, fmt.Errorf("%w: header has no number", ErrHeaderIncomplete)
	}
	var receipts Root
	copy(receipts[:], h.ReceiptRoot[:])
	return AuthenticatedBlock{
		Number:       h.Number.Uint64(),
		Hash:         hash,
		ParentHash:   h.ParentHash,
		ReceiptsRoot: receipts,
		LogsBloom:    h.Bloom,
		Timestamp:    h.Time,
		authentic:    true,
	}, nil
}

// MayContainAddress asks the AUTHENTICATED bloom whether this address could have
// emitted here.
//
// False is a proof of absence and the block may be skipped without any further
// request. True is permission to go and look, and nothing more — see bloom.go.
func (b AuthenticatedBlock) MayContainAddress(addr [20]byte) bool {
	return MayContain(b.LogsBloom, addr[:])
}

// AuthenticatedLogsFrom returns the logs `addr` emitted in this block.
//
// The receipts are untrusted input. They are rebuilt into a trie whose root must
// equal this block's authenticated receiptsRoot before a single log is looked
// at, so a provider that omitted, added or altered anything gets an error rather
// than a filtered view of its own fiction.
//
// Returns an empty slice, not an error, when the contract genuinely emitted
// nothing — that is an answer.
func (b AuthenticatedBlock) AuthenticatedLogsFrom(addr [20]byte, receipts []Receipt) ([]Log, error) {
	if !b.authentic {
		return nil, ErrBlockNotAuthenticated
	}
	verified, err := AuthenticateReceipts(b.ReceiptsRoot, receipts)
	if err != nil {
		return nil, fmt.Errorf("block %d: %w", b.Number, err)
	}

	// The bloom is checked AFTER authentication as a consistency cross-check,
	// not as a filter. The union of the receipt blooms is committed to by the
	// same payload root as the block bloom, so a disagreement means the two
	// authenticated fields contradict each other and nothing here should be
	// believed.
	if union := unionBloom(verified); union != b.LogsBloom {
		return nil, fmt.Errorf("%w: block %d receipt blooms do not union to the "+
			"authenticated logsBloom", ErrReceiptsRootMismatch, b.Number)
	}

	out := []Log{}
	for _, r := range verified {
		for _, l := range r.Logs {
			if l.Address == addr {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

func unionBloom(receipts []Receipt) Bloom2048 {
	var out Bloom2048
	for _, r := range receipts {
		for i := range out {
			out[i] |= r.Bloom[i]
		}
	}
	return out
}
