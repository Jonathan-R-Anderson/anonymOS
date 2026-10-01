package ethproof

// Finality, and the three trust levels — roadmap P12-5.6.
//
// THE DISTINCTION, AND WHY IT IS NOT COSMETIC
// -------------------------------------------
//	Observed    a header arrived. No authority whatsoever.
//	Verified    the sync committee signed it. Authentic, and REORGEABLE.
//	Finalized   Ethereum finality is authenticated for it. Settled.
//
// Collapsing Verified into Finalized is the tempting mistake, because a
// committee-signed header feels authoritative — it is signed by 512 validators
// and it verifies. But an attested header is one slot of attestation and can
// still be reorged out, whereas a finalised one cannot without an amount of
// stake being burned. A watchtower deciding to challenge on a Verified header
// may act on a block that never existed.
//
// So they are separate FIELDS holding separate headers, not one header with a
// label. A label can be raised by assignment; a field can only be filled by the
// function that requires the proof.
//
// PROMOTION REQUIRES PROOF, NOT FIELDS
// ------------------------------------
// A provider can put anything in an update. Attaching a FinalizedHeader and a
// FinalityBranch is free; what is not free is a branch that verifies against an
// attested state root that a committee actually signed. So:
//
//	ApplyOptimisticUpdate  cannot reach the finalised field AT ALL. It does not
//	                       take a finality branch and has no code path to it.
//	ApplyFinalityUpdate    requires the branch AND the signature, and writes
//	                       nothing until both hold.
//
// The separation is structural rather than conditional. An implementation with
// one function and an `if update.FinalityBranch != nil` would be one refactor
// away from promoting on the presence of a field.

import (
	"errors"
	"fmt"
)

// TrustLevel is how much authority a header carries.
type TrustLevel int

const (
	// HeaderObserved: received, nothing established. Useful for knowing where
	// the chain probably is; useless for deciding anything.
	HeaderObserved TrustLevel = iota
	// HeaderVerified: the authenticated sync committee signed it. Authentic and
	// still reorgeable.
	HeaderVerified
	// HeaderFinalized: Ethereum finality authenticated. The level the
	// watchtower's canonicality requirement is satisfied by.
	HeaderFinalized
)

func (l TrustLevel) String() string {
	switch l {
	case HeaderFinalized:
		return "finalized"
	case HeaderVerified:
		return "verified"
	default:
		return "observed"
	}
}

var (
	// ErrFinalityRegression means the update would move the finalised point
	// backward. Finality does not un-happen.
	ErrFinalityRegression = errors.New("lightclient: finality cannot move backward")
	// ErrFinalityConflict means a different header is offered as final for a
	// slot already finalised.
	ErrFinalityConflict = errors.New("lightclient: conflicting finality for an already-finalised slot")
	// ErrNoFinalityProof means an update was offered as a finality update
	// without the branch that would make it one.
	ErrNoFinalityProof = errors.New("lightclient: finality update carries no finality branch")
)

// OptimisticHeader is the newest committee-signed header, at HeaderVerified.
//
// Separate from FinalizedHeader so the two cannot be confused by a caller
// reading one field and assuming the other's guarantees.
type optimisticState struct {
	header BeaconBlockHeader
	known  bool
}

// TrustLevelOf reports what this state can say about a header.
//
// Compares by ROOT, not by slot. Two different headers at one slot is exactly
// what a reorg produces, and a comparison by slot would report a header as
// finalised because something else at that height was.
func (s *LightClientState) TrustLevelOf(h BeaconBlockHeader) (TrustLevel, error) {
	want, err := h.HashTreeRoot()
	if err != nil {
		return HeaderObserved, err
	}
	if s.FinalizedHeader.Slot != 0 || s.FinalizedHeader.BodyRoot != (Root{}) {
		final, err := s.FinalizedHeader.HashTreeRoot()
		if err != nil {
			return HeaderObserved, err
		}
		if final == want {
			return HeaderFinalized, nil
		}
	}
	if s.optimistic.known {
		opt, err := s.optimistic.header.HashTreeRoot()
		if err != nil {
			return HeaderObserved, err
		}
		if opt == want {
			return HeaderVerified, nil
		}
	}
	return HeaderObserved, nil
}

// OptimisticHeader returns the newest verified-but-not-finalised header.
func (s *LightClientState) OptimisticHeader() (BeaconBlockHeader, bool) {
	return s.optimistic.header, s.optimistic.known
}

// ApplyOptimisticUpdate advances the verified head only.
//
// STRUCTURALLY UNABLE to touch finality: it takes no branch, and the finalised
// field is not written anywhere below. That is the guarantee — not a check that
// could be inverted, but an absence of any path.
func (s *LightClientState) ApplyOptimisticUpdate(
	attested BeaconBlockHeader, signatureSlot uint64,
	participation Participation, signature []byte, v SyncCommitteeVerifier) error {

	if v == nil {
		return errors.New("lightclient: no signature verifier; refusing to advance")
	}
	if signatureSlot <= attested.Slot {
		return fmt.Errorf("lightclient: signature slot %d does not follow the attested slot %d",
			signatureSlot, attested.Slot)
	}
	if got := participation.Count(); got < MinParticipation {
		return fmt.Errorf("%w: %d of %d, need %d",
			ErrInsufficientParticipation, got, SyncCommitteeSize, MinParticipation)
	}
	// Never backward: an older attested header is not news.
	if s.optimistic.known && attested.Slot <= s.optimistic.header.Slot {
		return fmt.Errorf("%w: attested slot %d is not beyond the known %d",
			ErrUpdateStale, attested.Slot, s.optimistic.header.Slot)
	}

	committee, err := s.committeeFor(SyncCommitteePeriod(signatureSlot))
	if err != nil {
		return err
	}
	attestedRoot, err := attested.HashTreeRoot()
	if err != nil {
		return err
	}
	domain, err := s.Checkpoint.ComputeDomain()
	if err != nil {
		return err
	}
	signingRoot, err := SigningRoot(attestedRoot, domain)
	if err != nil {
		return err
	}
	if err := v.VerifySyncCommitteeSignature(
		signingRoot, committee, participation, signature); err != nil {
		return fmt.Errorf("lightclient: sync committee signature: %w", err)
	}

	// The ONLY write. Note what is absent: FinalizedHeader.
	s.optimistic.header = attested
	s.optimistic.known = true
	return nil
}

// ApplyFinalityUpdate authenticates finality and advances the finalised head.
//
// Requires the branch AND the signature. Writes nothing until both hold, so a
// rejected update leaves the finalised point exactly where it was.
func (s *LightClientState) ApplyFinalityUpdate(u *Update, v SyncCommitteeVerifier) error {
	if v == nil {
		return errors.New("lightclient: no signature verifier; refusing to advance")
	}
	// A "finality update" with no finality proof is an optimistic update wearing
	// the wrong name, and must not reach the finalised field.
	if len(u.FinalityBranch) == 0 {
		return ErrNoFinalityProof
	}

	// Finality does not un-happen, and it does not change its mind. Both checks
	// before any work, because both are cheap and both are absolute.
	if u.FinalizedHeader.Slot < s.FinalizedHeader.Slot {
		return fmt.Errorf("%w: offered slot %d, already at %d",
			ErrFinalityRegression, u.FinalizedHeader.Slot, s.FinalizedHeader.Slot)
	}
	if u.FinalizedHeader.Slot == s.FinalizedHeader.Slot && s.FinalizedHeader.Slot != 0 {
		known, err := s.FinalizedHeader.HashTreeRoot()
		if err != nil {
			return err
		}
		offered, err := u.FinalizedHeader.HashTreeRoot()
		if err != nil {
			return err
		}
		if known != offered {
			return fmt.Errorf("%w: slot %d", ErrFinalityConflict, u.FinalizedHeader.Slot)
		}
		// Same header, same slot: idempotent. Re-authenticating it would be
		// correct and pointless; saying so is better than silently redoing it.
		return nil
	}

	// Everything else — branch at the right index, participation, ordering,
	// committee by signing period, signature — is the rotation path, which is
	// already the one place those rules live.
	return s.ApplyRotatingUpdate(u, v)
}
