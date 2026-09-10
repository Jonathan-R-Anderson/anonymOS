package ethproof

// Sync committee rotation — roadmap P12-5.5.
//
// THE INVARIANT
// -------------
//	A committee becomes trusted ONLY by being authenticated with a committee
//	that was already trusted.
//
// The failure this prevents is circular and looks entirely reasonable in code:
//
//	RPC:  "here is the new committee, and here is its signature"
//	node: "the signature checks out against that committee — accepted"
//
// That verifies a message against itself, which every forgery satisfies. So the
// committee used to check an update is ALWAYS taken from the trusted state, and
// the committee an update carries is only ever a candidate — proven into the
// attested state by a Merkle branch, and adopted only after the update itself
// has been authenticated by a committee we already had.
//
//	sealed checkpoint
//	      │ committee N
//	      ▼
//	update signed by N  ──►  authenticated  ──►  adopt N+1 from its branch
//	                                                    │
//	                                                    ▼
//	                                       update signed by N+1  ──►  ...
//
// WHY PERIODS MATTER
// ------------------
// A committee serves one period of 8192 slots (~27 hours). An update signed in
// period P must be checked against the committee for period P, and an
// implementation that reached for whichever committee it happened to hold would
// accept a signature from the wrong set — valid, and about the wrong 27 hours.
//
// FORK-DEPENDENT LAYOUT TRAVELS WITH THE STATE
// --------------------------------------------
// The generalized indices are container positions, and containers changed shape
// across forks. A branch verified at a stale index proves a TRUE statement about
// the WRONG FIELD, which is the quietest failure available here. So the spec
// version is carried on the state and the indices are looked up from it rather
// than being package constants anybody can reach.
//
// Electra's values are deliberately absent rather than guessed: IndicesFor
// returns an error for it. Failing to start is recoverable; verifying against
// the wrong field is not.

import (
	"errors"
	"fmt"
)

// SlotsPerSyncCommitteePeriod is 32 slots per epoch × 256 epochs.
const SlotsPerSyncCommitteePeriod = 32 * 256

// SyncCommitteePeriod is the period a slot belongs to.
func SyncCommitteePeriod(slot uint64) uint64 {
	return slot / SlotsPerSyncCommitteePeriod
}

// SpecVersion names the fork whose container layout is in use.
type SpecVersion string

const (
	// SpecAltair covers Altair through Deneb, whose light client containers
	// share one layout.
	SpecAltair SpecVersion = "altair"
	// SpecElectra covers Electra and Fulu. Fulu did NOT change the light client
	// sync protocol — consensus-specs v1.6.1 has no specs/fulu/light-client
	// directory, so Fulu inherits Electra's containers and indices.
	SpecElectra SpecVersion = "electra"
	// SpecFulu is an alias for the same layout, so a caller reading "fulu" from
	// a beacon API's version field does not have to know that.
	SpecFulu SpecVersion = "fulu"
)

// Mainnet fork epochs, from configs/mainnet.yaml at consensus-specs v1.6.1.
//
// Compiled in rather than read from a beacon API, for the same reason
// MainnetGenesisValidatorsRoot is: a provider that could move a fork boundary
// could choose which container layout we verify against. A lie here fails
// closed — the branch depths would not match — but the value is a fact about
// mainnet, not a parameter, and facts belong in the binary.
const (
	MainnetAltairForkEpoch  = 74240
	MainnetElectraForkEpoch = 364032
	MainnetFuluForkEpoch    = 411392
)

// SlotsPerEpoch is the mainnet constant.
const SlotsPerEpoch = 32

// EpochAtSlot is compute_epoch_at_slot.
func EpochAtSlot(slot uint64) uint64 { return slot / SlotsPerEpoch }

// Generalized indices from consensus-specs v1.6.1,
// specs/electra/light-client/sync-protocol.md — the table under
// "Modified constants", lines 56-58:
//
//	FINALIZED_ROOT_GINDEX_ELECTRA          = 169
//	CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA  = 86
//	NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA     = 87
//
// TAKEN FROM THE SPEC, not inferred from observed branch depths. That the
// depths agree — floorlog2(169)=7, floorlog2(86)=floorlog2(87)=6, matching
// mainnet's 7/6/6 — is a CONFIRMATION, not the derivation. Deriving an index
// from a depth would pin only its magnitude and leave 64 candidates.
const (
	FinalizedRootIndexElectra        uint64 = 169
	CurrentSyncCommitteeIndexElectra uint64 = 86
	NextSyncCommitteeIndexElectra    uint64 = 87
)

// ForkIndices are the generalized indices for one fork's container layout.
type ForkIndices struct {
	FinalizedRoot        uint64
	NextSyncCommittee    uint64
	CurrentSyncCommittee uint64
}

// ErrSpecUnsupported means the layout for a fork has not been established here.
var ErrSpecUnsupported = errors.New("lightclient: generalized indices for this fork are not recorded")

// IndicesFor returns the container layout for a fork.
//
// Electra returns an error ON PURPOSE. Its indices differ from Altair's and the
// correct values must be taken from the specification, not inferred — a branch
// verified at a stale index proves a true statement about a different field,
// and nothing downstream would notice. Refusing to start is the recoverable
// failure; the other one is not.
func IndicesFor(v SpecVersion) (ForkIndices, error) {
	switch v {
	case SpecAltair:
		return ForkIndices{
			FinalizedRoot:        FinalizedRootIndex,
			NextSyncCommittee:    NextSyncCommitteeIndex,
			CurrentSyncCommittee: CurrentSyncCommitteeIndex,
		}, nil
	case SpecElectra, SpecFulu:
		return ForkIndices{
			FinalizedRoot:        FinalizedRootIndexElectra,
			NextSyncCommittee:    NextSyncCommitteeIndexElectra,
			CurrentSyncCommittee: CurrentSyncCommitteeIndexElectra,
		}, nil
	default:
		return ForkIndices{}, fmt.Errorf("%w: %q", ErrSpecUnsupported, v)
	}
}

// IndicesAtSlot selects the layout the way the spec does: BY SLOT.
//
// finalized_root_gindex_at_slot and its siblings switch on the slot's epoch,
// not on a configured fork. That matters at a boundary: a state following the
// chain across the Electra fork must verify a pre-fork update at Altair's
// indices and a post-fork one at Electra's, and a single configured version
// would get one of them wrong.
func IndicesAtSlot(slot uint64) ForkIndices {
	if EpochAtSlot(slot) >= MainnetElectraForkEpoch {
		return ForkIndices{
			FinalizedRoot:        FinalizedRootIndexElectra,
			NextSyncCommittee:    NextSyncCommitteeIndexElectra,
			CurrentSyncCommittee: CurrentSyncCommitteeIndexElectra,
		}
	}
	return ForkIndices{
		FinalizedRoot:        FinalizedRootIndex,
		NextSyncCommittee:    NextSyncCommitteeIndex,
		CurrentSyncCommittee: CurrentSyncCommitteeIndex,
	}
}

var (
	// ErrWrongPeriod means the update was signed in a period this state cannot
	// check — too old, or further ahead than the next committee covers.
	ErrWrongPeriod = errors.New("lightclient: update belongs to a sync committee period this state cannot authenticate")
	// ErrNextCommitteeUnknown means an update needs the next committee and this
	// state has not authenticated one.
	ErrNextCommitteeUnknown = errors.New("lightclient: update is for the next period and no next committee is known")
	// ErrCommitteeConflict means an update offers a different committee for a
	// period this state has already fixed.
	ErrCommitteeConflict = errors.New("lightclient: update contradicts an already-authenticated committee")
)

// Period is the period this state's finalised head sits in.
func (s *LightClientState) Period() uint64 {
	return SyncCommitteePeriod(s.FinalizedHeader.Slot)
}

// committeeFor returns the committee authorised to sign in a given period.
//
// From THIS STATE, never from the update. The whole rotation design is this one
// function refusing to look anywhere else.
func (s *LightClientState) committeeFor(period uint64) (*SyncCommittee, error) {
	switch period {
	case s.Period():
		if s.CurrentCommittee == nil {
			return nil, ErrCommitteeUnknown
		}
		return s.CurrentCommittee, nil
	case s.Period() + 1:
		if s.NextCommittee == nil {
			return nil, ErrNextCommitteeUnknown
		}
		return s.NextCommittee, nil
	default:
		return nil, fmt.Errorf("%w: update is in period %d, this state covers %d and %d",
			ErrWrongPeriod, period, s.Period(), s.Period()+1)
	}
}

// ApplyRotatingUpdate authenticates an update and rotates committees.
//
// ATOMIC. Nothing on the receiver is written until every check has passed, so a
// rejected update leaves the state exactly as it was — including the case where
// the signature fails after the structure verified.
func (s *LightClientState) ApplyRotatingUpdate(u *Update, v SyncCommitteeVerifier) error {
	if v == nil {
		return errors.New("lightclient: no signature verifier; refusing to advance")
	}
	// 1. Structure, against the layout in force AT THE ATTESTED SLOT.
	//
	// By slot, as finalized_root_gindex_at_slot does — not by a configured
	// version. At a fork boundary a client must verify a pre-fork update at the
	// old indices and a post-fork one at the new, and one configured value
	// would get one of them wrong. The branches are against the attested state,
	// so it is the attested slot that decides.
	indices := IndicesAtSlot(u.AttestedHeader.Slot)
	if err := s.validateStructureWith(u, indices); err != nil {
		return err
	}

	// 2. Which committee is authorised for the period this was SIGNED in — not
	//    the period it talks about. Taken from this state.
	signaturePeriod := SyncCommitteePeriod(u.SignatureSlot)
	committee, err := s.committeeFor(signaturePeriod)
	if err != nil {
		return err
	}

	// 3. An update must not contradict a committee already fixed for a period.
	//    Two different committees for one period is an ambiguity, and resolving
	//    it by preferring the newer message would let a later forgery win.
	if u.NextCommittee != nil && s.NextCommittee != nil &&
		signaturePeriod == s.Period() {
		known, err := s.NextCommittee.HashTreeRoot()
		if err != nil {
			return err
		}
		offered, err := u.NextCommittee.HashTreeRoot()
		if err != nil {
			return err
		}
		if known != offered {
			return fmt.Errorf("%w: period %d already has a different next committee",
				ErrCommitteeConflict, signaturePeriod+1)
		}
	}

	// 4. The signature, last and only now.
	signingRoot, err := s.SigningRootFor(u)
	if err != nil {
		return err
	}
	if err := v.VerifySyncCommitteeSignature(
		signingRoot, committee, u.Participation, u.Signature); err != nil {
		return fmt.Errorf("lightclient: sync committee signature: %w", err)
	}

	// 5. Everything passed. Only now is anything written.
	previousPeriod := s.Period()
	s.FinalizedHeader = u.FinalizedHeader
	// The attested header was signed by the committee, so it is Verified — a
	// weaker claim than the finalised one above, recorded separately because
	// the two levels must never be read off the same field.
	if !s.optimistic.known || u.AttestedHeader.Slot > s.optimistic.header.Slot {
		s.optimistic.header = u.AttestedHeader
		s.optimistic.known = true
	}

	if newPeriod := s.Period(); newPeriod > previousPeriod {
		// The head crossed a boundary: the committee that was "next" is now
		// current. Rotating rather than re-fetching is the point — the new
		// current committee was authenticated in the old period, by a committee
		// that was itself authenticated, all the way back to the checkpoint.
		if newPeriod == previousPeriod+1 && s.NextCommittee != nil {
			s.CurrentCommittee = s.NextCommittee
			s.NextCommittee = nil
		}
	}
	if u.NextCommittee != nil {
		s.NextCommittee = u.NextCommittee
	}
	return nil
}

// validateStructureWith is ValidateStructure against explicit fork indices.
//
// The exported ValidateStructure keeps the package constants for callers that
// have not adopted a spec version; this is the path rotation uses, and it takes
// the layout from the state so a branch cannot be checked against a fork the
// state is not following.
func (s *LightClientState) validateStructureWith(u *Update, indices ForkIndices) error {
	if u.FinalizedHeader.Slot <= s.FinalizedHeader.Slot {
		return fmt.Errorf("%w: finalised slot %d is not beyond the known %d",
			ErrUpdateStale, u.FinalizedHeader.Slot, s.FinalizedHeader.Slot)
	}
	if u.AttestedHeader.Slot < u.FinalizedHeader.Slot {
		return fmt.Errorf("lightclient: attested slot %d precedes the finalised slot %d",
			u.AttestedHeader.Slot, u.FinalizedHeader.Slot)
	}
	if u.SignatureSlot <= u.AttestedHeader.Slot {
		return fmt.Errorf("lightclient: signature slot %d does not follow the attested slot %d",
			u.SignatureSlot, u.AttestedHeader.Slot)
	}
	if got := u.Participation.Count(); got < MinParticipation {
		return fmt.Errorf("%w: %d of %d, need %d",
			ErrInsufficientParticipation, got, SyncCommitteeSize, MinParticipation)
	}

	finalizedRoot, err := u.FinalizedHeader.HashTreeRoot()
	if err != nil {
		return err
	}
	if err := VerifyBranch(finalizedRoot, u.FinalityBranch,
		indices.FinalizedRoot, u.AttestedHeader.StateRoot); err != nil {
		return fmt.Errorf("%w: finality: %v", ErrBranchWrongField, err)
	}

	if u.NextCommittee != nil {
		committeeRoot, err := u.NextCommittee.HashTreeRoot()
		if err != nil {
			return err
		}
		if err := VerifyBranch(committeeRoot, u.NextCommitteeBranch,
			indices.NextSyncCommittee, u.AttestedHeader.StateRoot); err != nil {
			return fmt.Errorf("%w: next committee: %v", ErrBranchWrongField, err)
		}
	}
	return nil
}

// ---- fork versions ----------------------------------------------------------
//
// The signing domain mixes in the fork version IN FORCE AT THE SIGNATURE SLOT.
// A signature made under Fulu does not verify under Electra's domain, so a
// verifier using one fixed version rejects every real signature from every
// other era — which is precisely what the first live mainnet run exposed.
//
// From configs/mainnet.yaml at consensus-specs v1.6.1, cross-checked against a
// live node's /eth/v1/config/fork_schedule. Compiled in for the same reason the
// fork epochs are: a provider that could move a fork boundary or rename a
// version could choose which domain we compute, and the domain is what makes a
// signature chain-specific.

type forkEra struct {
	epoch   uint64
	version [4]byte
}

// mainnetForks, newest first so the first match wins.
var mainnetForks = []forkEra{
	{411392, [4]byte{0x06, 0, 0, 0}}, // Fulu
	{364032, [4]byte{0x05, 0, 0, 0}}, // Electra
	{269568, [4]byte{0x04, 0, 0, 0}}, // Deneb
	{194048, [4]byte{0x03, 0, 0, 0}}, // Capella
	{144896, [4]byte{0x02, 0, 0, 0}}, // Bellatrix
	{74240, [4]byte{0x01, 0, 0, 0}},  // Altair
	{0, [4]byte{0x00, 0, 0, 0}},      // genesis
}

// ForkVersionAtSlot returns the mainnet fork version in force at a slot.
func ForkVersionAtSlot(slot uint64) [4]byte {
	epoch := EpochAtSlot(slot)
	for _, f := range mainnetForks {
		if epoch >= f.epoch {
			return f.version
		}
	}
	return mainnetForks[len(mainnetForks)-1].version
}
