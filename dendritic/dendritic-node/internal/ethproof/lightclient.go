package ethproof

// Beacon header progression — roadmap P12-5.3.
//
// WHERE THE DEPENDENCY BOUNDARY IS
// --------------------------------
// Everything in this file is Ethereum concepts. The only cryptography it
// performs is SHA-256 through the SSZ code next door. The pairing check sits
// behind ONE interface method:
//
//	SyncCommitteeVerifier.VerifySyncCommitteeSignature(...)
//
// Nothing above that line touches a curve point, and nothing below it knows
// what a light client update is. That boundary is deliberate: it is what stops
// a caller reaching a raw pairing operation and skipping a validation step by
// accident, and it is why a vetted library can be swapped in without any of
// this code changing.
//
// WHAT IS CHECKED WITHOUT ANY SIGNATURE AT ALL
// --------------------------------------------
// Most of an update's validity is structural, and all of it is checkable now:
//
//	slot ordering            an update must move forward, and the signature
//	                         slot must be strictly after the attested slot
//	participation            below the threshold, a valid signature by a
//	                         handful of validators proves nothing useful
//	finality branch          the finalised header must be AT the right
//	                         generalized index in the attested state
//	committee branch         likewise for the next committee
//	committee identity       the committee used must be the one the
//	                         authenticated state already knows
//
// The signature is the last check, not the first, because it is the expensive
// one and because an update that fails any of the above is not worth verifying.
//
// THE ORDER THAT MATTERS
// ----------------------
// The committee comes from the AUTHENTICATED STATE, never from the update. An
// implementation that took the committee out of the same message it is checking
// would verify that the message is self-consistent, which is a property every
// forgery has.

import (
	"errors"
	"fmt"
)

// SyncCommitteeSize is the number of validators in a sync committee.
const SyncCommitteeSize = 512

// MinParticipation is the supermajority a light client requires.
//
// The consensus spec's floor is far lower; light clients apply 2/3 because a
// header attested by a handful of validators is signed but not meaningfully
// attested to. Requiring it here rather than downstream means an update that
// cannot clear it is refused before anybody pays for a pairing.
const MinParticipation = SyncCommitteeSize * 2 / 3

// Generalized indices for the light client's Merkle branches.
//
// FORK-DEPENDENT. These are the Altair-through-Deneb values; Electra moved
// them. They are named rather than inlined so the fork schedule has one place
// to live, and they MUST be checked against the spec version being followed
// before any of this is relied on — a branch that verifies at the wrong index
// proves a true statement about the wrong field.
const (
	FinalizedRootIndex        uint64 = 105
	NextSyncCommitteeIndex    uint64 = 55
	CurrentSyncCommitteeIndex uint64 = 54
)

var (
	// ErrUpdateStale means the update does not move the client forward.
	ErrUpdateStale = errors.New("lightclient: update does not advance the finalised head")
	// ErrInsufficientParticipation means too few of the committee signed.
	ErrInsufficientParticipation = errors.New("lightclient: sync committee participation below threshold")
	// ErrBranchWrongField means a branch verified against the wrong position.
	ErrBranchWrongField = errors.New("lightclient: merkle branch is for the wrong field")
	// ErrCommitteeUnknown means an update was signed by a committee this client
	// has not authenticated.
	ErrCommitteeUnknown = errors.New("lightclient: update is signed by an unauthenticated committee")
)

// SyncCommittee is the validator set authorised to attest to headers.
type SyncCommittee struct {
	// Pubkeys are 48-byte BLS public keys, SyncCommitteeSize of them.
	Pubkeys [][]byte
	// AggregatePubkey is their sum, which the spec carries and this checks
	// rather than trusts.
	AggregatePubkey []byte
}

// HashTreeRoot is how a committee is referred to by an authenticated state.
//
// Pubkeys are a fixed vector, so no length is mixed in; each key is 48 bytes
// and therefore two chunks, which is why a committee root is not simply a hash
// of concatenated keys.
func (c SyncCommittee) HashTreeRoot() (Root, error) {
	if len(c.Pubkeys) != SyncCommitteeSize {
		return Root{}, fmt.Errorf("lightclient: committee has %d keys, want %d",
			len(c.Pubkeys), SyncCommitteeSize)
	}
	leaves := make([]Root, 0, SyncCommitteeSize)
	for i, key := range c.Pubkeys {
		leaf, err := BytesRoot(key)
		if err != nil {
			return Root{}, fmt.Errorf("lightclient: pubkey %d: %w", i, err)
		}
		leaves = append(leaves, leaf)
	}
	keysRoot, err := Merkleize(leaves, SyncCommitteeSize)
	if err != nil {
		return Root{}, err
	}
	aggregateRoot, err := BytesRoot(c.AggregatePubkey)
	if err != nil {
		return Root{}, err
	}
	return ContainerRoot([]Root{keysRoot, aggregateRoot})
}

// Participation is the bitfield saying which committee members signed.
type Participation []byte

// Count returns how many bits are set.
func (p Participation) Count() int {
	total := 0
	for _, b := range p {
		for i := 0; i < 8; i++ {
			if b&(1<<uint(i)) != 0 {
				total++
			}
		}
	}
	return total
}

// Members returns the indices that signed, in order.
func (p Participation) Members() []int {
	out := make([]int, 0, SyncCommitteeSize)
	for i := 0; i < len(p)*8 && i < SyncCommitteeSize; i++ {
		if p[i/8]&(1<<uint(i%8)) != 0 {
			out = append(out, i)
		}
	}
	return out
}

// SyncCommitteeVerifier is the ONE place pairing cryptography is reached.
//
// Implemented by a thin wrapper over a vetted BLS12-381 library — see the
// security constraint in the roadmap: pairing, hash-to-curve, subgroup checks
// and cofactor clearing are NEVER hand-written here.
//
// The implementation is required to perform subgroup checks on the public keys
// and the signature. A library API that skips them will verify signatures that
// no honest signer produced, and the call site cannot tell.
type SyncCommitteeVerifier interface {
	VerifySyncCommitteeSignature(
		signingRoot Root, committee *SyncCommittee,
		participation Participation, signature []byte) error
}

// LightClientState is everything this client has authenticated.
//
// The committees here are the AUTHORITY on who may sign the next update. They
// arrived either from the sealed checkpoint or from an update this state itself
// authenticated, and never from the message being checked.
type LightClientState struct {
	// FinalizedHeader is the newest header known to be finalised.
	FinalizedHeader BeaconBlockHeader
	// CurrentCommittee attests to headers in the present period.
	CurrentCommittee *SyncCommittee
	// NextCommittee is the following period's, learned in advance. Nil until an
	// update supplies and proves one.
	NextCommittee *SyncCommittee
	// Checkpoint is the sealed anchor everything descends from.
	Checkpoint Checkpoint
	// Anchor is that checkpoint, sealed against replacement. Held alongside
	// Checkpoint so the signing domain stays cheap to compute while the
	// immutability guarantee lives in one place.
	Anchor SealedAnchor
	// optimistic is the newest committee-signed but NOT finalised header.
	// Unexported so nothing outside this package can raise a header's trust
	// level by assignment — see finality.go.
	optimistic optimisticState
	// Spec is the fork whose container layout is in force. Carried on the state
	// rather than assumed, because the generalized indices are positions in
	// containers that changed shape across forks — a branch verified at a stale
	// index proves a TRUE statement about the WRONG FIELD. See rotation.go.
	Spec SpecVersion
}

// Update is one light client update, entirely untrusted.
type Update struct {
	// AttestedHeader is the header the committee signed over.
	AttestedHeader BeaconBlockHeader
	// FinalizedHeader is what the attested state says is finalised, with the
	// branch proving it sits at FinalizedRootIndex.
	FinalizedHeader BeaconBlockHeader
	FinalityBranch  []Root
	// NextCommittee, when present, is proven against the attested state at
	// NextSyncCommitteeIndex.
	NextCommittee       *SyncCommittee
	NextCommitteeBranch []Root
	// FinalizedExecution is the execution payload header carried by the
	// finalised LightClientHeader, with the branch proving it sits in that
	// beacon block. Present from Capella onward. This is the link from
	// consensus to the execution state root — see P12-5.7.
	FinalizedExecution       *ExecutionPayloadHeader
	FinalizedExecutionBranch []Root
	// Participation and Signature are the sync aggregate.
	Participation Participation
	Signature     []byte
	// SignatureSlot is the slot the aggregate was produced in. Strictly after
	// the attested slot, because a committee attests to the PREVIOUS block.
	SignatureSlot uint64
}

// ValidateStructure checks everything that does not need a signature.
//
// Separated from signature verification so the cheap checks run first, and so
// this half is testable with no BLS implementation at all — which is what lets
// P12-5.3 be finished and tested before P12-5.4 chooses a library.
func (s *LightClientState) ValidateStructure(u *Update) error {
	// 1. Ordering. An update that does not move forward is either stale or an
	//    attempt to walk this client backwards onto a state it has left.
	if u.FinalizedHeader.Slot <= s.FinalizedHeader.Slot {
		return fmt.Errorf("%w: finalised slot %d is not beyond the known %d",
			ErrUpdateStale, u.FinalizedHeader.Slot, s.FinalizedHeader.Slot)
	}
	if u.AttestedHeader.Slot < u.FinalizedHeader.Slot {
		return fmt.Errorf(
			"lightclient: attested slot %d precedes the finalised slot %d it claims",
			u.AttestedHeader.Slot, u.FinalizedHeader.Slot)
	}
	// A sync committee attests to the block BEFORE the slot it signs in.
	if u.SignatureSlot <= u.AttestedHeader.Slot {
		return fmt.Errorf(
			"lightclient: signature slot %d does not follow the attested slot %d",
			u.SignatureSlot, u.AttestedHeader.Slot)
	}

	// 2. Participation, before any pairing is paid for.
	if got := u.Participation.Count(); got < MinParticipation {
		return fmt.Errorf("%w: %d of %d, need %d",
			ErrInsufficientParticipation, got, SyncCommitteeSize, MinParticipation)
	}

	// 3. The finalised header must be AT FinalizedRootIndex in the attested
	//    state. Verifying at any other index would prove a true statement about
	//    a different field.
	finalizedRoot, err := u.FinalizedHeader.HashTreeRoot()
	if err != nil {
		return err
	}
	if err := VerifyBranch(finalizedRoot, u.FinalityBranch,
		FinalizedRootIndex, u.AttestedHeader.StateRoot); err != nil {
		return fmt.Errorf("%w: finality: %v", ErrBranchWrongField, err)
	}

	// 4. Likewise the next committee, when one is offered.
	if u.NextCommittee != nil {
		committeeRoot, err := u.NextCommittee.HashTreeRoot()
		if err != nil {
			return err
		}
		if err := VerifyBranch(committeeRoot, u.NextCommitteeBranch,
			NextSyncCommitteeIndex, u.AttestedHeader.StateRoot); err != nil {
			return fmt.Errorf("%w: next committee: %v", ErrBranchWrongField, err)
		}
	}
	return nil
}

// SigningRootFor is what the committee's signature is over.
//
// The domain uses the fork version IN FORCE AT THE SIGNATURE SLOT, not the
// checkpoint's. A signature made under Fulu does not verify under Electra's
// domain, so anchoring in one era and verifying signatures from another with
// the anchor's version rejects every real update. The genesis validators root
// stays fixed — it identifies the CHAIN, while the fork version identifies the
// ERA, and the domain needs both.
func (s *LightClientState) SigningRootFor(u *Update) (Root, error) {
	attestedRoot, err := u.AttestedHeader.HashTreeRoot()
	if err != nil {
		return Root{}, err
	}
	era := s.Checkpoint
	era.ForkVersion = ForkVersionAtSlot(u.SignatureSlot)
	domain, err := era.ComputeDomain()
	if err != nil {
		return Root{}, err
	}
	return SigningRoot(attestedRoot, domain)
}

// ApplyUpdate validates an update completely and advances the state.
//
// Structure first, then the signature — and the committee used is taken from
// THIS STATE, never from the update. An implementation that used the update's
// own committee would be checking that a message agrees with itself, which is a
// property every forgery has.
func (s *LightClientState) ApplyUpdate(u *Update, v SyncCommitteeVerifier) error {
	if err := s.ValidateStructure(u); err != nil {
		return err
	}
	if v == nil {
		return errors.New("lightclient: no signature verifier; refusing to advance")
	}
	if s.CurrentCommittee == nil {
		return ErrCommitteeUnknown
	}

	signingRoot, err := s.SigningRootFor(u)
	if err != nil {
		return err
	}
	if err := v.VerifySyncCommitteeSignature(
		signingRoot, s.CurrentCommittee, u.Participation, u.Signature); err != nil {
		return fmt.Errorf("lightclient: sync committee signature: %w", err)
	}

	s.FinalizedHeader = u.FinalizedHeader
	if u.NextCommittee != nil {
		s.NextCommittee = u.NextCommittee
	}
	return nil
}
