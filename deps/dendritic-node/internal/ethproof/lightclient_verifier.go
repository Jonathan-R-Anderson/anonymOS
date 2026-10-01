package ethproof

// The native verifier, wired in — roadmap P12-5.8.
//
// WHAT CHANGES AND WHAT DOES NOT
// ------------------------------
// This replaces HeaderVerifier's AnchorNone stub. Nothing above it changes:
// Index.Lookup, EvidenceChainReader and the Watchtower are untouched, and none
// of them can tell whether the chain behind ChainReader is an RPC reader or
// this. That indifference is the payoff of the whole phase.
//
// THE DIRECTION OF THE CHECK
// --------------------------
// 5.7 established that a state root is never accepted from outside and checked
// against something. That rule survives here, and it decides which way this
// comparison runs:
//
//	WRONG   evidence supplies a state root -> is it plausible?
//	RIGHT   the light client HOLDS authenticated roots -> does this evidence
//	        use one of them?
//
// The authenticated roots come from AuthenticatedStateRoot, which derives them
// from finalised beacon blocks and nothing else. Evidence is matched against
// that record; the record is never built from evidence. So a fabricated root
// does not fail a plausibility test — it simply is not in the set, and there is
// no operation that would put it there.
//
// NO BEST-EFFORT MODE
// -------------------
// Two outcomes: the header is authenticated, or it is refused. There is
// deliberately no degraded path that accepts an RPC's word when the light
// client is behind, unsynced, or unavailable — a watchtower that fell back
// would be a watchtower whose security depended on nothing having gone wrong.
// Being unable to act is an outage; acting on unauthenticated data is a loss.

import (
	"errors"
	"fmt"
	"sync"
)

// ErrNotAuthenticated means the light client holds no authenticated execution
// state for a block, or holds a different one.
var ErrNotAuthenticated = errors.New(
	"lightclient: no authenticated execution state for this block")

// authenticatedExecution is one finalised block's execution identity.
type authenticatedExecution struct {
	StateRoot Root
	BlockHash Root
}

// LightClient is the native verifier: a light client state plus the execution
// roots it has authenticated.
//
// Safe for concurrent use. The watchtower reads while the follower advances.
type LightClient struct {
	mu    sync.RWMutex
	state *LightClientState
	// execution maps execution block number to what was authenticated for it.
	// Written ONLY by AdoptExecutionPayload, which requires a finalised beacon
	// header and a verified branch.
	execution map[uint64]authenticatedExecution
}

// NewLightClient builds one around a state anchored at a sealed checkpoint.
func NewLightClient(state *LightClientState) *LightClient {
	return &LightClient{state: state, execution: map[uint64]authenticatedExecution{}}
}

// State exposes the underlying state for the follower that advances it.
func (c *LightClient) State() *LightClientState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// AdoptExecutionPayload authenticates a payload and records its execution root.
//
// The only writer of the execution map. Everything it records came through
// AuthenticatedStateRoot, which requires the beacon header to be FINALIZED and
// the payload to be proven into it.
//
// Idempotent, and refuses to change an entry: two different execution states
// for one block number is a reorg past finality, which does not happen, and
// silently preferring the newer one would be the wrong resolution if it did.
func (c *LightClient) AdoptExecutionPayload(
	payload ExecutionPayloadHeader, executionBranch []Root) error {

	c.mu.Lock()
	defer c.mu.Unlock()

	stateRoot, number, hash, err := c.state.AuthenticatedStateRoot(payload, executionBranch)
	if err != nil {
		return err
	}
	if existing, ok := c.execution[number]; ok {
		if existing.StateRoot != stateRoot || existing.BlockHash != hash {
			return fmt.Errorf(
				"lightclient: block %d already authenticated with a different execution state",
				number)
		}
		return nil
	}
	c.execution[number] = authenticatedExecution{StateRoot: stateRoot, BlockHash: hash}
	return nil
}

// AuthenticatedExecution returns what was authenticated for a block number.
func (c *LightClient) AuthenticatedExecution(number uint64) (Root, Root, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.execution[number]
	return e.StateRoot, e.BlockHash, ok
}

// VerifyExecutionHeader is the integration point.
//
// Answers whether an execution header is one the light client has
// authenticated, by looking up what IT holds for that block number and
// requiring the header to match. The stored value is the authority; the header
// is the claim.
func (c *LightClient) VerifyExecutionHeader(h BlockHeader) error {
	number := h.BlockNumber()
	stateRoot, blockHash, ok := c.AuthenticatedExecution(number)
	if !ok {
		return fmt.Errorf("%w: block %d", ErrNotAuthenticated, number)
	}

	claimedState, err := decodeHex32(h.StateRoot)
	if err != nil {
		return fmt.Errorf("%w: stateRoot: %v", ErrNotAuthenticated, err)
	}
	if claimedState != stateRoot {
		return fmt.Errorf(
			"%w: block %d was authenticated with stateRoot %x, this header claims %x",
			ErrNotAuthenticated, number, stateRoot[:8], claimedState[:8])
	}
	// The block hash too: a header matching on state root but not on identity
	// would be a different block that happens to share a state, which is not a
	// thing that should pass unremarked.
	if h.Hash != "" {
		claimedHash, err := decodeHex32(h.Hash)
		if err != nil {
			return fmt.Errorf("%w: hash: %v", ErrNotAuthenticated, err)
		}
		if claimedHash != blockHash {
			return fmt.Errorf("%w: block %d hash mismatch", ErrNotAuthenticated, number)
		}
	}
	return nil
}

// AttachLightClient makes a HeaderVerifier use the native light client.
//
// The anchor is taken from the light client's sealed checkpoint, so the two
// cannot disagree about what is being trusted. SetAnchor's independence check
// still applies: the checkpoint's Source must not share a provider with the RPC
// endpoint this verifier is checking.
func (v *HeaderVerifier) AttachLightClient(c *LightClient) error {
	if c == nil {
		return errors.New("ethproof: no light client")
	}
	checkpoint, sealed := c.State().Anchor.Checkpoint()
	if !sealed {
		return fmt.Errorf("%w: the light client's anchor is not sealed", ErrNoTrustAnchor)
	}
	if err := v.SetAnchor(Anchor{
		Kind:        AnchorSyncCommittee,
		Source:      checkpoint.Source,
		BlockNumber: checkpoint.Slot,
		BlockHash:   fmt.Sprintf("0x%x", checkpoint.BlockRoot),
		Note:        checkpoint.Note,
	}); err != nil {
		return err
	}
	v.client = c
	return nil
}
