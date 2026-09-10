package ethproof

// The external trust anchor — roadmap P12-5.1.
//
// WHAT AN ANCHOR IS
// -----------------
// One finalised beacon block, obtained from OUTSIDE the RPC being verified, and
// everything needed to start following the chain from it:
//
//	block root + slot            what is being anchored
//	sync committee               who is authorised to attest to what comes next
//	fork version + genesis root  what those signatures are computed over
//
// Everything after this is derived. The light client never trusts an RPC again;
// it trusts this, once, and then checks signatures.
//
// WHY IT MUST BE IMMUTABLE FOR A SESSION
// --------------------------------------
// A verifier whose anchor can change underneath it has no anchor. If a caller
// could re-point it mid-run — from configuration, from an RPC, from a retry
// path — then the whole chain of authenticated updates hangs from whatever was
// most recently supplied, which is exactly the property the anchor exists to
// avoid. So Checkpoint is a value, taken once, and Seal makes further changes
// an error rather than a silent replacement.
//
// WHY THE FORK VERSION IS PART OF IT
// ----------------------------------
// Sync committee signatures are over a DOMAIN that mixes in the fork version
// and the genesis validators root. A signature valid under one fork verifies
// under no other — which is the property that stops a signature captured from
// a testnet, or from an earlier fork, being replayed here. Anchoring without
// them would leave the domain to be supplied later, by whoever supplies the
// update, which is the same circularity in a different place.
//
// THE RESIDUAL, STATED PLAINLY
// ----------------------------
// The initial checkpoint is subjective. Somebody must obtain it from a source
// they trust — a client release, several independent explorers, a peer they
// know — and no amount of cryptography downstream removes that. This is weak
// subjectivity and it is inherent, not a defect. What the design CAN guarantee
// is that the subjectivity is confined to one value, recorded, auditable, and
// never silently refreshed.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Checkpoint is the anchoring beacon block and its context.
type Checkpoint struct {
	// Slot and BlockRoot identify the anchoring block.
	Slot      uint64
	BlockRoot Root
	// SyncCommitteeRoot is the hash tree root of the committee authorised at
	// this point. The committee ITSELF may be fetched from anywhere — it is
	// checked against this root, so a hostile RPC can only supply the real one
	// or fail.
	SyncCommitteeRoot Root
	// GenesisValidatorsRoot and ForkVersion define the signing domain. Without
	// them a signature from another chain or another fork could be replayed.
	GenesisValidatorsRoot Root
	ForkVersion           [4]byte
	// Source records where a human got this, for whoever audits it later. It
	// must not be the RPC being verified — HeaderVerifier.SetAnchor enforces
	// that separately.
	Source string
	// Note is free text: which explorers were compared, who checked, when.
	Note string
}

var (
	// ErrCheckpointIncomplete means the anchor does not say enough to anchor.
	ErrCheckpointIncomplete = errors.New("ethproof: checkpoint is incomplete")
	// ErrAnchorSealed means something tried to change an anchor mid-session.
	ErrAnchorSealed = errors.New("ethproof: the trust anchor is sealed and cannot be replaced")
)

// Validate reports whether a checkpoint can serve as an anchor.
//
// Every field is required. A checkpoint missing its committee root anchors
// nothing — the next update would supply both the committee and the signature
// over it, which is a chain that hangs from the RPC.
func (c Checkpoint) Validate() error {
	var zero Root
	switch {
	case c.BlockRoot == zero:
		return fmt.Errorf("%w: no block root", ErrCheckpointIncomplete)
	case c.SyncCommitteeRoot == zero:
		return fmt.Errorf("%w: no sync committee root; the first update would "+
			"then supply both the committee and its own authorisation", ErrCheckpointIncomplete)
	case c.GenesisValidatorsRoot == zero:
		return fmt.Errorf("%w: no genesis validators root, so the signing domain "+
			"is undefined and a signature from another chain would verify", ErrCheckpointIncomplete)
	case c.ForkVersion == [4]byte{}:
		return fmt.Errorf("%w: no fork version", ErrCheckpointIncomplete)
	case strings.TrimSpace(c.Source) == "":
		return fmt.Errorf("%w: no source; an anchor nobody can attribute is not one",
			ErrCheckpointIncomplete)
	}
	return nil
}

// String renders a checkpoint for an operator to compare against an explorer.
//
// The point of this format is that it is checkable BY HAND: somebody pasting
// the block root into two explorers is the actual security mechanism at this
// step, and a rendering they cannot read defeats it.
func (c Checkpoint) String() string {
	return fmt.Sprintf(
		"slot %d\n  block root  0x%s\n  committee   0x%s\n  genesis     0x%s\n"+
			"  fork        0x%s\n  source      %s\n  note        %s",
		c.Slot, hex.EncodeToString(c.BlockRoot[:]),
		hex.EncodeToString(c.SyncCommitteeRoot[:]),
		hex.EncodeToString(c.GenesisValidatorsRoot[:]),
		hex.EncodeToString(c.ForkVersion[:]), c.Source, c.Note)
}

// MainnetGenesisValidatorsRoot is Ethereum mainnet's, a published constant.
//
// Hardcoded deliberately: it is the one value that distinguishes mainnet's
// signing domain from every testnet's, it has never changed and cannot, and
// taking it from configuration would let a misconfiguration silently move the
// verifier to another chain.
var MainnetGenesisValidatorsRoot = mustRoot(
	"4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")

func mustRoot(s string) Root {
	var out Root
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		panic("ethproof: bad compiled-in root " + s)
	}
	copy(out[:], raw)
	return out
}

// SealedAnchor is a checkpoint that cannot be replaced.
type SealedAnchor struct {
	checkpoint Checkpoint
	sealed     bool
}

// Seal fixes a checkpoint for the session.
//
// Returns ErrAnchorSealed if one is already set. Replacing an anchor is never a
// legitimate runtime operation: a verifier that accepted a new one would let
// whoever supplied it rewrite the entire chain of trust behind every header
// already accepted. Changing anchors means restarting.
func (a *SealedAnchor) Seal(c Checkpoint) error {
	if a.sealed {
		return ErrAnchorSealed
	}
	if err := c.Validate(); err != nil {
		return err
	}
	a.checkpoint = c
	a.sealed = true
	return nil
}

// Checkpoint returns the sealed anchor and whether one exists.
func (a *SealedAnchor) Checkpoint() (Checkpoint, bool) {
	return a.checkpoint, a.sealed
}

// ComputeDomain builds the signing domain sync committee signatures are made
// over.
//
//	domain = domain_type ‖ hash_tree_root(fork_version, genesis_validators_root)[:28]
//
// DOMAIN_SYNC_COMMITTEE is 0x07000000. Mixing the fork and genesis roots in is
// what makes a signature chain-specific and fork-specific: the same committee
// signing the same header under a different fork produces a signature that
// verifies nowhere here.
func (c Checkpoint) ComputeDomain() (Root, error) {
	var forkChunk Root
	copy(forkChunk[:4], c.ForkVersion[:])

	forkData, err := ContainerRoot([]Root{forkChunk, c.GenesisValidatorsRoot})
	if err != nil {
		return Root{}, err
	}
	var domain Root
	domain[0] = 0x07 // DOMAIN_SYNC_COMMITTEE
	copy(domain[4:], forkData[:28])
	return domain, nil
}

// SigningRoot is what a sync committee actually signs: the header root bound to
// the domain.
//
// Signing the bare header root would let a signature be replayed on any chain
// using the same containers. The domain is what stops that.
func SigningRoot(headerRoot Root, domain Root) (Root, error) {
	return ContainerRoot([]Root{headerRoot, domain})
}
