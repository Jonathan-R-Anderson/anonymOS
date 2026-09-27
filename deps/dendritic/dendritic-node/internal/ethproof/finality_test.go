package ethproof

// Finality and the three trust levels — roadmap P12-5.6.
//
// The property under test throughout: a provider cannot raise a header's trust
// level by supplying more fields. Only proof does that, and the levels are
// separate fields so there is no assignment that could shortcut it.

import (
	"errors"
	"testing"
)

func finalityState(t *testing.T) *LightClientState {
	t.Helper()
	return &LightClientState{
		Spec:             SpecAltair,
		FinalizedHeader:  BeaconBlockHeader{Slot: periodSlots + 100},
		CurrentCommittee: committee(0xAA),
		NextCommittee:    committee(0xBB),
		Checkpoint:       goodCheckpoint(),
	}
}

// ---- 1. valid finality reaches HeaderFinalized ------------------------------

func TestValidFinalityFinalisesTheHeader(t *testing.T) {
	s := finalityState(t)
	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)

	if err := s.ApplyFinalityUpdate(u, &countingVerifier{}); err != nil {
		t.Fatalf("ApplyFinalityUpdate: %v", err)
	}
	level, err := s.TrustLevelOf(u.FinalizedHeader)
	if err != nil {
		t.Fatalf("TrustLevelOf: %v", err)
	}
	if level != HeaderFinalized {
		t.Fatalf("level %s, want finalized", level)
	}
}

// ---- 2, 3, 4, 8. the rejections leave nothing behind ------------------------

func TestFinalityRejectionsLeaveTheStateUntouched(t *testing.T) {
	cases := map[string]func(*Update){
		"bad signature": func(*Update) {}, // verifier errors instead
		"wrong finality branch": func(u *Update) {
			u.FinalityBranch = make([]Root, len(u.FinalityBranch))
		},
		"wrong finalised root": func(u *Update) {
			u.FinalizedHeader.BodyRoot[0] ^= 0xFF // branch no longer matches
		},
		"no finality proof": func(u *Update) { u.FinalityBranch = nil },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			s := finalityState(t)
			before := s.FinalizedHeader
			v := &countingVerifier{}
			if name == "bad signature" {
				v.err = errors.New("aggregate does not verify")
			}

			u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)
			break_(u)

			if err := s.ApplyFinalityUpdate(u, v); err == nil {
				t.Fatal("the update was accepted")
			}
			if s.FinalizedHeader != before {
				t.Fatal("a rejected finality update moved the finalised point")
			}
			if level, _ := s.TrustLevelOf(u.FinalizedHeader); level == HeaderFinalized {
				t.Fatal("the header finalised anyway")
			}
		})
	}
}

// An update presented as a finality update with no branch must not reach the
// finalised field at all.
func TestAFinalityUpdateWithoutAProofIsRefused(t *testing.T) {
	s := finalityState(t)
	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)
	u.FinalityBranch = nil

	if err := s.ApplyFinalityUpdate(u, &countingVerifier{}); !errors.Is(err, ErrNoFinalityProof) {
		t.Fatalf("got %v, want ErrNoFinalityProof", err)
	}
}

// ---- 5. wrong fork ----------------------------------------------------------

// A branch built for the WRONG fork's layout must be refused.
//
// Now that indices are chosen by slot, this is the real fork-mismatch: a branch
// of Altair depth offered for an Electra-era slot. It is what a client using a
// stale layout would produce, and it must fail rather than verify against a
// different field.
func TestABranchFromTheWrongForkLayoutIsRefused(t *testing.T) {
	// An Electra-era slot: the layout there wants a depth-7 finality branch.
	electraSlot := uint64(MainnetElectraForkEpoch)*SlotsPerEpoch + 100
	s := finalityState(t)
	s.FinalizedHeader = BeaconBlockHeader{Slot: electraSlot}
	s.CurrentCommittee = committee(0xAA)

	u := &Update{
		FinalizedHeader: BeaconBlockHeader{Slot: electraSlot + 10},
		AttestedHeader:  BeaconBlockHeader{Slot: electraSlot + 20},
		SignatureSlot:   electraSlot + 21,
		Participation:   fullParticipation(),
		Signature:       make([]byte, 96),
	}
	// A branch built at ALTAIR's index — the wrong depth for this slot.
	root, err := u.FinalizedHeader.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	branch, stateRoot := branchFor(t, root, FinalizedRootIndex)
	u.FinalityBranch, u.AttestedHeader.StateRoot = branch, stateRoot

	if err := s.ApplyFinalityUpdate(u, &countingVerifier{}); !errors.Is(err, ErrBranchWrongField) {
		t.Fatalf("an Altair-layout branch verified at an Electra-era slot: %v", err)
	}
}

// ---- 6. finality does not un-happen ----------------------------------------

func TestFinalityCannotMoveBackward(t *testing.T) {
	s := finalityState(t)
	v := &countingVerifier{}
	if err := s.ApplyFinalityUpdate(updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil), v); err != nil {
		t.Fatalf("first finality: %v", err)
	}
	after := s.FinalizedHeader

	older := updateAt(t, 2*periodSlots+5, 2*periodSlots+50, nil)
	if err := s.ApplyFinalityUpdate(older, v); !errors.Is(err, ErrFinalityRegression) {
		t.Fatalf("got %v, want ErrFinalityRegression", err)
	}
	if s.FinalizedHeader != after {
		t.Fatal("the finalised point moved backward")
	}
}

// ---- 11 & 12. idempotence and conflict --------------------------------------

func TestRepeatedFinalityIsIdempotent(t *testing.T) {
	s := finalityState(t)
	v := &countingVerifier{}
	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)

	if err := s.ApplyFinalityUpdate(u, v); err != nil {
		t.Fatalf("first: %v", err)
	}
	after, calls := s.FinalizedHeader, v.calls

	if err := s.ApplyFinalityUpdate(u, v); err != nil {
		t.Fatalf("repeat should be accepted as a no-op: %v", err)
	}
	if s.FinalizedHeader != after {
		t.Fatal("a repeat changed the finalised header")
	}
	if v.calls != calls {
		t.Error("a repeat re-verified the signature; it is already established")
	}
}

// Two different headers claiming the same finalised slot is the reorg case. The
// established one must win — preferring the newer message would let a later
// forgery replace an authenticated finality.
func TestConflictingFinalityCannotReplaceWhatIsFinalised(t *testing.T) {
	s := finalityState(t)
	v := &countingVerifier{}
	first := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)
	if err := s.ApplyFinalityUpdate(first, v); err != nil {
		t.Fatalf("first: %v", err)
	}
	established := s.FinalizedHeader

	rival := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)
	rival.FinalizedHeader.ProposerIndex = 99 // same slot, different header
	// Rebuild its branch so it is otherwise perfectly valid.
	root, err := rival.FinalizedHeader.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	branch, stateRoot := branchFor(t, root, FinalizedRootIndex)
	rival.FinalityBranch, rival.AttestedHeader.StateRoot = branch, stateRoot

	if err := s.ApplyFinalityUpdate(rival, v); !errors.Is(err, ErrFinalityConflict) {
		t.Fatalf("got %v, want ErrFinalityConflict", err)
	}
	if s.FinalizedHeader != established {
		t.Fatal("a rival header replaced an authenticated finality")
	}
}

// ---- 9 & 10. the levels stay distinct ---------------------------------------

// A header nobody authenticated is Observed, whatever it looks like.
func TestAnUnauthenticatedHeaderIsOnlyObserved(t *testing.T) {
	s := finalityState(t)
	stranger := BeaconBlockHeader{Slot: 3 * periodSlots, ProposerIndex: 7}

	level, err := s.TrustLevelOf(stranger)
	if err != nil {
		t.Fatalf("TrustLevelOf: %v", err)
	}
	if level != HeaderObserved {
		t.Fatalf("level %s, want observed", level)
	}
}

// THE HEADLINE. An optimistic update advances the VERIFIED head and cannot
// touch finality — there is no code path from it to the finalised field.
func TestAnOptimisticUpdateCannotFinaliseAnything(t *testing.T) {
	s := finalityState(t)
	before := s.FinalizedHeader
	v := &countingVerifier{}

	attested := BeaconBlockHeader{Slot: 2*periodSlots + 40, ProposerIndex: 3}
	if err := s.ApplyOptimisticUpdate(attested, 2*periodSlots+41,
		fullParticipation(), make([]byte, 96), v); err != nil {
		t.Fatalf("ApplyOptimisticUpdate: %v", err)
	}

	// It IS verified...
	level, err := s.TrustLevelOf(attested)
	if err != nil {
		t.Fatalf("TrustLevelOf: %v", err)
	}
	if level != HeaderVerified {
		t.Fatalf("level %s, want verified", level)
	}
	// ...and finality is exactly where it was.
	if s.FinalizedHeader != before {
		t.Fatal("an optimistic update moved the finalised point")
	}
	if lvl, _ := s.TrustLevelOf(before); lvl != HeaderFinalized {
		t.Error("the previously finalised header lost its level")
	}
}

// A verified header must not read as finalised however far ahead it is.
func TestAVerifiedHeaderNeverReadsAsFinalised(t *testing.T) {
	s := finalityState(t)
	attested := BeaconBlockHeader{Slot: 9 * periodSlots} // far beyond finality
	s.optimistic.header, s.optimistic.known = attested, true

	if level, _ := s.TrustLevelOf(attested); level != HeaderVerified {
		t.Fatalf("level %s, want verified — being newer is not being final", level)
	}
}

// Levels are compared by ROOT, not slot. Two headers at one slot is a reorg,
// and a slot comparison would report one as finalised because the other was.
func TestLevelsCompareByRootNotSlot(t *testing.T) {
	s := finalityState(t)
	impostor := s.FinalizedHeader
	impostor.ProposerIndex ^= 0xFF // same slot, different header

	if level, _ := s.TrustLevelOf(impostor); level != HeaderObserved {
		t.Fatalf("a different header at a finalised slot read as %s", level)
	}
}

// ---- 7. finality cannot skip the authenticated chain ------------------------

func TestFinalityCannotSkipTheCommitteeChain(t *testing.T) {
	s := finalityState(t)
	v := &countingVerifier{}

	// Signed three periods ahead: no authenticated committee covers it.
	u := updateAt(t, 4*periodSlots+10, 4*periodSlots+50, nil)
	if err := s.ApplyFinalityUpdate(u, v); !errors.Is(err, ErrWrongPeriod) {
		t.Fatalf("got %v, want ErrWrongPeriod", err)
	}
	if v.calls != 0 {
		t.Error("an unauthenticatable period reached the pairing check")
	}
}

func TestTrustLevelsAreOrdered(t *testing.T) {
	if !(HeaderObserved < HeaderVerified && HeaderVerified < HeaderFinalized) {
		t.Fatal("the levels are not ordered; a >= comparison would be wrong")
	}
	if HeaderObserved.String() != "observed" || HeaderVerified.String() != "verified" ||
		HeaderFinalized.String() != "finalized" {
		t.Error("a level renders as something an operator cannot read")
	}
}
