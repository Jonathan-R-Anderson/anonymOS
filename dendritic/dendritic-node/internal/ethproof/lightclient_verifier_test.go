package ethproof

// Native verifier integration — roadmap P12-5.8.
//
// The gate that has been closed since P12-2 opens here, and only here. What
// these assert is that it opens for exactly one reason: a header the native
// light client authenticated from finalised beacon data.

import (
	"errors"
	"fmt"
	"testing"
)

// authenticatedClient is a light client that has finalised a block and adopted
// its execution payload — the state a real follower reaches after syncing.
func authenticatedClient(t *testing.T) (*LightClient, ExecutionPayloadHeader) {
	t.Helper()
	payload := samplePayload()
	state, branch := bridgedState(t, payload)
	if err := state.Anchor.Seal(goodCheckpoint()); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	c := NewLightClient(state)
	if err := c.AdoptExecutionPayload(payload, branch); err != nil {
		t.Fatalf("AdoptExecutionPayload: %v", err)
	}
	return c, payload
}

// headerFor renders an execution header as an RPC would.
func headerFor(p ExecutionPayloadHeader) BlockHeader {
	return BlockHeader{
		Number:    fmt.Sprintf("0x%x", p.BlockNumber),
		Hash:      fmt.Sprintf("0x%x", p.BlockHash),
		StateRoot: fmt.Sprintf("0x%x", p.StateRoot),
	}
}

// ---- the gate opens, for one reason -----------------------------------------

func TestAnAuthenticatedHeaderPassesTheGate(t *testing.T) {
	c, payload := authenticatedClient(t)
	v := &HeaderVerifier{ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key"}

	if err := v.AttachLightClient(c); err != nil {
		t.Fatalf("AttachLightClient: %v", err)
	}
	if err := v.VerifyHeader(headerFor(payload)); err != nil {
		t.Fatalf("an authenticated header was refused: %v", err)
	}
}

// ---- THE HEADLINE -----------------------------------------------------------

// Fabricated evidence dies at the light client, not at a plausibility check.
//
// The forged header is internally perfect and storage proofs beneath its state
// root would verify. It fails because that root is not in the set the light
// client authenticated, and there is no operation that would put it there.
func TestFabricatedEvidenceIsRejectedByTheLightClient(t *testing.T) {
	c, payload := authenticatedClient(t)
	v := &HeaderVerifier{ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key"}
	if err := v.AttachLightClient(c); err != nil {
		t.Fatalf("AttachLightClient: %v", err)
	}

	forged := payload
	forged.StateRoot[0] ^= 0xFF
	if err := v.VerifyHeader(headerFor(forged)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("a fabricated state root passed the gate: %v", err)
	}

	// A different block entirely — nothing authenticated for it at all.
	unknown := payload
	unknown.BlockNumber += 999
	if err := v.VerifyHeader(headerFor(unknown)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("an unauthenticated block passed the gate: %v", err)
	}

	// Right state root, wrong block identity.
	swapped := payload
	swapped.BlockHash[0] ^= 0xFF
	if err := v.VerifyHeader(headerFor(swapped)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("a header with a mismatched block hash passed: %v", err)
	}
}

// ---- no best-effort mode ----------------------------------------------------

// An anchor without a client is not permission to proceed.
func TestAnAnchorWithoutAClientStillRefuses(t *testing.T) {
	v := &HeaderVerifier{ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key"}
	if err := v.SetAnchor(Anchor{
		Kind: AnchorSyncCommittee, Source: "https://beaconstate.example",
	}); err != nil {
		t.Fatalf("SetAnchor: %v", err)
	}
	_, payload := authenticatedClient(t)

	if err := v.VerifyHeader(headerFor(payload)); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("a bare anchor authorised a header: %v", err)
	}
}

// A light client that has authenticated nothing refuses everything, rather than
// deferring to the RPC while it catches up.
func TestAnUnsyncedClientRefusesRatherThanDeferring(t *testing.T) {
	payload := samplePayload()
	state, _ := bridgedState(t, payload)
	if err := state.Anchor.Seal(goodCheckpoint()); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	empty := NewLightClient(state) // nothing adopted

	v := &HeaderVerifier{ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key"}
	if err := v.AttachLightClient(empty); err != nil {
		t.Fatalf("AttachLightClient: %v", err)
	}
	if err := v.VerifyHeader(headerFor(payload)); !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("an unsynced client deferred to the header: %v", err)
	}
}

// ---- the anchor rules survive integration -----------------------------------

// Attaching must not become a way around the independence check.
func TestAttachingRefusesACircularAnchor(t *testing.T) {
	c, _ := authenticatedClient(t)
	// The checkpoint's source is the SAME provider as the endpoint.
	state := c.State()
	state.Anchor = SealedAnchor{}
	cp := goodCheckpoint()
	cp.Source = "https://eth-mainnet.g.alchemy.com/v2/other"
	if err := state.Anchor.Seal(cp); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	v := &HeaderVerifier{ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key"}
	if err := v.AttachLightClient(c); !errors.Is(err, ErrAnchorNotIndependent) {
		t.Fatalf("got %v, want ErrAnchorNotIndependent", err)
	}
	// And the gate stays shut.
	if err := v.VerifyHeader(BlockHeader{Number: "0x1"}); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("the gate opened despite a refused attach: %v", err)
	}
}

// An unsealed anchor cannot be attached: the whole chain hangs from it.
func TestAttachingRequiresASealedAnchor(t *testing.T) {
	payload := samplePayload()
	state, _ := bridgedState(t, payload)
	c := NewLightClient(state) // anchor never sealed

	v := &HeaderVerifier{ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key"}
	if err := v.AttachLightClient(c); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("got %v, want ErrNoTrustAnchor", err)
	}
}

// ---- adoption discipline ----------------------------------------------------

// Only a finalised, proven payload enters the authenticated set.
func TestOnlyProvenPayloadsAreAdopted(t *testing.T) {
	c, payload := authenticatedClient(t)

	forged := payload
	forged.StateRoot[0] ^= 0xFF
	forgedRoot, err := forged.HashTreeRoot(SpecAltair)
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	forgedBranch, _ := branchFor(t, forgedRoot, ExecutionPayloadIndex)

	if err := c.AdoptExecutionPayload(forged, forgedBranch); err == nil {
		t.Fatal("a payload not in the finalised block was adopted")
	}
	// And the honest entry is untouched.
	root, _, ok := c.AuthenticatedExecution(payload.BlockNumber)
	if !ok || root != payload.StateRoot {
		t.Fatal("the authenticated entry was disturbed by a failed adoption")
	}
}

// Re-adopting the same payload is a no-op; a DIFFERENT one for the same block
// is a reorg past finality and must be refused rather than resolved.
func TestAdoptionIsIdempotentAndNeverOverwrites(t *testing.T) {
	c, payload := authenticatedClient(t)
	_, branch := bridgedState(t, payload)

	if err := c.AdoptExecutionPayload(payload, branch); err != nil {
		t.Fatalf("re-adopting the same payload: %v", err)
	}

	// Force a conflicting entry through the map's own guard.
	c.mu.Lock()
	c.execution[payload.BlockNumber] = authenticatedExecution{}
	c.mu.Unlock()
	if err := c.AdoptExecutionPayload(payload, branch); err == nil {
		t.Fatal("a conflicting execution state for one block was accepted")
	}
}

// ---- the consumers are unchanged --------------------------------------------

// The watchtower's ChainReader path must not know which verifier is behind it.
// This asserts the type still satisfies the interface with a client attached.
func TestTheVerifierStaysADropInForTheExistingConsumers(t *testing.T) {
	c, payload := authenticatedClient(t)
	v := &HeaderVerifier{ChainID: 1, Endpoint: "https://eth-mainnet.g.alchemy.com/v2/key"}
	if err := v.AttachLightClient(c); err != nil {
		t.Fatalf("AttachLightClient: %v", err)
	}

	// Index.Lookup calls exactly this, and now gets a real answer.
	if !v.Anchor().Trustworthy() {
		t.Fatal("the attached anchor does not read as trustworthy")
	}
	if err := v.VerifyHeader(headerFor(payload)); err != nil {
		t.Fatalf("the integrated path refused an authenticated header: %v", err)
	}
}
