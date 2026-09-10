package ethproof

// The authenticated end of the P14.5 pipeline.
//
// BeaconFinalizedSource is the ONLY way a ChainFollower obtains a starting
// point, and it produces one exactly as P12 does: a finalised beacon header
// whose execution payload is proven into it at EXECUTION_PAYLOAD_INDEX.
//
// It does not compare an RPC header against the authenticated one. It returns
// the authenticated one, for the reason execution.go gives — a comparison is a
// step a refactor can drop, and if it is dropped everything downstream still
// works perfectly against a fabricated root.

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoFinalizedExecution means the consensus node served a finalised header
// with no execution payload attached.
var ErrNoFinalizedExecution = errors.New(
	"ethproof: the finalised light client header carries no execution payload")

// BeaconFinalizedSource turns a beacon finality update into an
// AuthenticatedBlock.
type BeaconFinalizedSource struct {
	Beacon *BeaconClient
	// State supplies the spec version used to merkleise the payload header. The
	// field COUNT is fork-dependent and a wrong one produces a self-consistent
	// root that matches nothing.
	Spec SpecVersion
}

// FinalizedBlock fetches the finality update and authenticates its payload.
//
// The SSZ branch is verified here. Without it the "authenticated" receiptsRoot
// would be one more piece of provider JSON, which is the whole failure this
// design exists to avoid.
func (s *BeaconFinalizedSource) FinalizedBlock(ctx context.Context) (AuthenticatedBlock, error) {
	update, err := s.Beacon.FinalityUpdate(ctx)
	if err != nil {
		return AuthenticatedBlock{}, err
	}
	if update.FinalizedExecution == nil {
		return AuthenticatedBlock{}, ErrNoFinalizedExecution
	}
	payload := *update.FinalizedExecution
	root, err := payload.HashTreeRoot(s.Spec)
	if err != nil {
		return AuthenticatedBlock{}, err
	}
	if err := VerifyBranch(root, update.FinalizedExecutionBranch,
		ExecutionPayloadIndex, update.FinalizedHeader.BodyRoot); err != nil {
		return AuthenticatedBlock{}, fmt.Errorf("%w: %v", ErrPayloadNotAuthenticated, err)
	}
	return BlockFromFinalizedPayload(payload), nil
}
