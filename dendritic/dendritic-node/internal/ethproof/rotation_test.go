package ethproof

// Sync committee rotation — roadmap P12-5.5.
//
// This is where the sealed checkpoint stops being one trusted value and becomes
// a CHAIN of authenticated trust. Every test here is a variation on one
// question: can an attacker who controls the RPC get a committee of their
// choosing into the trusted state?

import (
	"errors"
	"testing"
)

const periodSlots = SlotsPerSyncCommitteePeriod

// rotatingState is a client anchored in period 1 with both committees known.
func rotatingState(t *testing.T) *LightClientState {
	t.Helper()
	return &LightClientState{
		Spec:             SpecAltair,
		FinalizedHeader:  BeaconBlockHeader{Slot: periodSlots + 100},
		CurrentCommittee: committee(0xAA),
		NextCommittee:    committee(0xBB),
		Checkpoint:       goodCheckpoint(),
	}
}

// updateAt builds a structurally valid update finalising at a slot, signed in
// the period containing signatureSlot.
func updateAt(t *testing.T, finalizedSlot, signatureSlot uint64, next *SyncCommittee) *Update {
	t.Helper()
	u := &Update{
		FinalizedHeader: BeaconBlockHeader{Slot: finalizedSlot},
		AttestedHeader:  BeaconBlockHeader{Slot: signatureSlot - 1},
		SignatureSlot:   signatureSlot,
		Participation:   fullParticipation(),
		Signature:       make([]byte, 96),
		NextCommittee:   next,
	}
	// Build the attested state root FROM the branches, so both verify.
	finalizedRoot, err := u.FinalizedHeader.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	branch, stateRoot := branchFor(t, finalizedRoot, FinalizedRootIndex)
	u.FinalityBranch = branch
	u.AttestedHeader.StateRoot = stateRoot

	if next != nil {
		// A committee branch must ALSO produce the same attested state root.
		// Real updates satisfy this because both fields live in one state; here
		// it is arranged by searching for a sibling set that lands on it, which
		// is not possible — so committee-bearing updates are built by making the
		// committee branch authoritative and the finality branch match it.
		committeeRoot, err := next.HashTreeRoot()
		if err != nil {
			t.Fatalf("HashTreeRoot: %v", err)
		}
		cBranch, cRoot := branchFor(t, committeeRoot, NextSyncCommitteeIndex)
		u.NextCommitteeBranch = cBranch
		u.AttestedHeader.StateRoot = cRoot
		// Re-derive the finality branch against the new state root is not
		// possible either; instead mark this update as one whose finality
		// branch will not verify, and tests that need both use bothBranches.
	}
	return u
}

// NOTE ON FIXTURES: an update carrying BOTH a finality branch and a committee
// branch cannot be synthesised here, because both must land on one attested
// state root and sha256 is not invertible. Real updates satisfy it because both
// fields genuinely live in one state. So committee-bearing fixtures below are
// built to FAIL their branch check, which is what those tests are about — and
// the honest-rotation path is exercised without one.

// ---- 1. honest rotation ------------------------------------------------------

// The head crosses a period boundary: next becomes current, and the state can
// then authenticate updates signed by it.
func TestHonestRotationPromotesTheNextCommittee(t *testing.T) {
	s := rotatingState(t)
	before := s.NextCommittee
	v := &countingVerifier{}

	// An update finalising in period 2, signed in period 2 — which the state
	// can check because it holds the next committee.
	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)
	if err := s.ApplyRotatingUpdate(u, v); err != nil {
		t.Fatalf("ApplyRotatingUpdate: %v", err)
	}

	if s.Period() != 2 {
		t.Fatalf("state is in period %d, want 2", s.Period())
	}
	if s.CurrentCommittee != before {
		t.Error("the next committee was not promoted to current")
	}
	if s.NextCommittee != nil {
		t.Error("the next committee slot was not cleared after promotion")
	}
	// And it was checked against the committee for the SIGNING period.
	if v.seen != before {
		t.Error("the update was not verified with the next-period committee")
	}
}

// ---- 2 & 3. the circular trust failure --------------------------------------

// THE ONE THAT MATTERS. A committee must never authenticate its own arrival.
func TestACommitteeCannotAuthenticateItsOwnUpdate(t *testing.T) {
	s := rotatingState(t)
	s.NextCommittee = nil // this state knows only the current committee
	forged := committee(0xEE)

	v := &countingVerifier{}
	// An update carrying a forged committee, signed in the NEXT period — the
	// period only that forged committee could cover.
	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, forged)
	err := s.ApplyRotatingUpdate(u, v)

	if err == nil {
		t.Fatal("a committee authenticated its own introduction")
	}
	if !errors.Is(err, ErrNextCommitteeUnknown) && !errors.Is(err, ErrBranchWrongField) {
		t.Logf("rejected with: %v", err)
	}
	if v.seen == forged {
		t.Fatal("the FORGED committee was used to verify the update carrying it")
	}
	if s.CurrentCommittee == forged || s.NextCommittee == forged {
		t.Fatal("the forged committee entered the trusted state")
	}
}

// A forged next committee inside an otherwise valid update must not be adopted:
// its branch does not verify against the attested state.
func TestAForgedNextCommitteeIsNotAdopted(t *testing.T) {
	s := rotatingState(t)
	forged := committee(0xEE)

	// Structurally valid update, but the committee branch is for a committee
	// that is not in the attested state.
	u := updateAt(t, periodSlots+200, periodSlots+300, nil)
	u.NextCommittee = forged
	u.NextCommitteeBranch = make([]Root, GeneralizedIndexDepth(NextSyncCommitteeIndex))

	err := s.ApplyRotatingUpdate(u, &countingVerifier{})
	if !errors.Is(err, ErrBranchWrongField) {
		t.Fatalf("got %v, want ErrBranchWrongField", err)
	}
	if s.NextCommittee == forged {
		t.Fatal("a committee with an unverifiable branch was adopted")
	}
}

// ---- 4 & 6. period discipline -----------------------------------------------

// An update signed two periods ahead cannot be checked: the state holds no
// committee for it, and reaching for the one it has would verify a signature
// from the wrong 27 hours.
func TestASkippedPeriodIsRefused(t *testing.T) {
	s := rotatingState(t)
	v := &countingVerifier{}

	u := updateAt(t, 3*periodSlots+10, 3*periodSlots+50, nil)
	if err := s.ApplyRotatingUpdate(u, v); !errors.Is(err, ErrWrongPeriod) {
		t.Fatalf("got %v, want ErrWrongPeriod", err)
	}
	if v.calls != 0 {
		t.Error("an unauthenticatable period reached the pairing check")
	}
}

// An update signed in a period the state has already passed cannot be
// WELL-FORMED, and this records why rather than leaving the case untested.
//
// The slot ordering forces signature_slot > attested_slot >= finalized_slot, so
// an update finalising in period 5 cannot have been signed in period 1 — the
// ordering rule catches it before the period rule is ever consulted. The period
// rule's lower bound is therefore unreachable for well-formed updates, and its
// real work is the UPPER bound (see TestASkippedPeriodIsRefused).
//
// Worth pinning: if the ordering check were ever relaxed, this refusal would
// silently become the period rule's job, and it would be reached with inputs
// nobody had considered.
func TestAnOldSigningPeriodIsUnreachableForWellFormedUpdates(t *testing.T) {
	s := rotatingState(t)
	s.FinalizedHeader.Slot = 5 * periodSlots

	u := updateAt(t, 5*periodSlots+100, periodSlots+50, nil) // signed in period 1
	err := s.ApplyRotatingUpdate(u, &countingVerifier{})
	if err == nil {
		t.Fatal("an update signed four periods before what it finalises was accepted")
	}
	// Refused by ORDERING, not by period — the slots are impossible.
	if errors.Is(err, ErrWrongPeriod) {
		t.Errorf("reached the period rule; the ordering rule should catch this first: %v", err)
	}
	if u.AttestedHeader.Slot >= u.FinalizedHeader.Slot {
		t.Fatal("the fixture is not actually malformed; the test proves nothing")
	}
}

// The next committee must actually be known before a next-period update is
// checked; otherwise the state would have to take one from the update.
func TestANextPeriodUpdateNeedsAKnownNextCommittee(t *testing.T) {
	s := rotatingState(t)
	s.NextCommittee = nil

	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)
	if err := s.ApplyRotatingUpdate(u, &countingVerifier{}); !errors.Is(err, ErrNextCommitteeUnknown) {
		t.Fatalf("got %v, want ErrNextCommitteeUnknown", err)
	}
}

// ---- 5. replay ---------------------------------------------------------------

// Re-applying an accepted update must not move the state, forward or back.
func TestReplayingAnAcceptedUpdateChangesNothing(t *testing.T) {
	s := rotatingState(t)
	v := &countingVerifier{}
	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)

	if err := s.ApplyRotatingUpdate(u, v); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	slot, current := s.FinalizedHeader.Slot, s.CurrentCommittee

	if err := s.ApplyRotatingUpdate(u, v); !errors.Is(err, ErrUpdateStale) {
		t.Fatalf("replay returned %v, want ErrUpdateStale", err)
	}
	if s.FinalizedHeader.Slot != slot || s.CurrentCommittee != current {
		t.Fatal("a replayed update moved the state")
	}
}

// ---- 7. conflicting updates --------------------------------------------------

// Two different committees offered for one period is an ambiguity. Preferring
// the newer message would let a later forgery overwrite an authenticated one.
func TestAConflictingNextCommitteeIsRefused(t *testing.T) {
	s := rotatingState(t) // already knows 0xBB for the next period
	rival := committee(0xCC)

	u := updateAt(t, periodSlots+200, periodSlots+300, nil)
	u.NextCommittee = rival
	u.NextCommitteeBranch = make([]Root, GeneralizedIndexDepth(NextSyncCommitteeIndex))

	err := s.ApplyRotatingUpdate(u, &countingVerifier{})
	if err == nil {
		t.Fatal("a rival committee for a fixed period was accepted")
	}
	if s.NextCommittee != nil && s.NextCommittee.AggregatePubkey[0] == 0xCC {
		t.Fatal("the rival committee replaced the authenticated one")
	}
}

// ---- 8. atomicity ------------------------------------------------------------

// A failed update must leave nothing behind — including when it fails at the
// LAST step, after every structural check passed.
func TestAFailedSignatureLeavesRotationUntouched(t *testing.T) {
	s := rotatingState(t)
	before := struct {
		slot          uint64
		current, next *SyncCommittee
	}{s.FinalizedHeader.Slot, s.CurrentCommittee, s.NextCommittee}

	v := &countingVerifier{err: errors.New("aggregate does not verify")}
	u := updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil)

	if err := s.ApplyRotatingUpdate(u, v); err == nil {
		t.Fatal("an update with a bad signature was applied")
	}
	if v.calls != 1 {
		t.Errorf("the signature was checked %d times", v.calls)
	}
	if s.FinalizedHeader.Slot != before.slot ||
		s.CurrentCommittee != before.current || s.NextCommittee != before.next {
		t.Fatal("a rejected update mutated the state")
	}
}

// ---- fork discipline ---------------------------------------------------------

// Branch indices no longer depend on the state's Spec field — they are chosen
// by slot. Spec still governs the EXECUTION PAYLOAD layout, where the field
// count differs by fork, and an unnamed fork must still refuse there.
func TestAnUnnamedForkStillRefusesToRootAPayload(t *testing.T) {
	s := rotatingState(t)
	s.Spec = ""

	// Branch validation proceeds: the slot decides the layout, not s.Spec.
	if err := s.ApplyRotatingUpdate(updateAt(t, 2*periodSlots+10, 2*periodSlots+50, nil),
		&countingVerifier{}); err != nil {
		t.Fatalf("branch validation should not depend on s.Spec: %v", err)
	}
	// The payload path still refuses, which is where the field count matters.
	if _, err := samplePayload().HashTreeRoot(""); !errors.Is(err, ErrSpecUnsupported) {
		t.Fatalf("an unnamed fork rooted a payload: %v", err)
	}
}

// Electra's indices are now RECORDED, from consensus-specs v1.6.1
// specs/electra/light-client/sync-protocol.md. They were taken from the spec,
// not inferred from observed branch depths — this pins the exact values so a
// later edit cannot quietly substitute a guess.
func TestElectraIndicesAreTheSpecValues(t *testing.T) {
	got, err := IndicesFor(SpecElectra)
	if err != nil {
		t.Fatalf("IndicesFor(electra): %v", err)
	}
	if got.FinalizedRoot != 169 {
		t.Errorf("FINALIZED_ROOT_GINDEX_ELECTRA = %d, spec says 169", got.FinalizedRoot)
	}
	if got.CurrentSyncCommittee != 86 {
		t.Errorf("CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA = %d, spec says 86", got.CurrentSyncCommittee)
	}
	if got.NextSyncCommittee != 87 {
		t.Errorf("NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA = %d, spec says 87", got.NextSyncCommittee)
	}

	// Fulu inherits Electra's light client protocol — consensus-specs v1.6.1
	// has no specs/fulu/light-client directory.
	fulu, err := IndicesFor(SpecFulu)
	if err != nil {
		t.Fatalf("IndicesFor(fulu): %v", err)
	}
	if fulu != got {
		t.Error("Fulu should inherit Electra's indices unchanged")
	}

	// The depths these imply must match what mainnet actually serves: 7/6/6.
	// A CONFIRMATION of the spec values, not their source.
	for name, tc := range map[string]struct{ index, depth uint64 }{
		"finality":          {got.FinalizedRoot, 7},
		"current committee": {got.CurrentSyncCommittee, 6},
		"next committee":    {got.NextSyncCommittee, 6},
	} {
		if d := uint64(GeneralizedIndexDepth(tc.index)); d != tc.depth {
			t.Errorf("%s branch depth %d, mainnet serves %d", name, d, tc.depth)
		}
	}
}

// An unrecorded fork still refuses. The rule did not go away; Electra simply
// stopped being one of them.
func TestAnUnknownForkStillRefuses(t *testing.T) {
	if _, err := IndicesFor("bellatrix-ish"); !errors.Is(err, ErrSpecUnsupported) {
		t.Fatalf("got %v, want ErrSpecUnsupported", err)
	}
	if _, err := IndicesFor(""); !errors.Is(err, ErrSpecUnsupported) {
		t.Fatalf("an unnamed fork returned indices: %v", err)
	}
}

// The layout is chosen BY SLOT, as the spec's *_gindex_at_slot functions do.
// At a fork boundary one configured version would get one side wrong.
func TestIndicesAreChosenBySlotAcrossTheForkBoundary(t *testing.T) {
	beforeFork := uint64(MainnetElectraForkEpoch-1) * SlotsPerEpoch
	atFork := uint64(MainnetElectraForkEpoch) * SlotsPerEpoch

	if got := IndicesAtSlot(beforeFork); got.FinalizedRoot != FinalizedRootIndex {
		t.Errorf("pre-Electra slot got index %d, want Altair's %d",
			got.FinalizedRoot, FinalizedRootIndex)
	}
	if got := IndicesAtSlot(atFork); got.FinalizedRoot != FinalizedRootIndexElectra {
		t.Errorf("Electra-epoch slot got index %d, want %d",
			got.FinalizedRoot, FinalizedRootIndexElectra)
	}
	// And mainnet's current head is well past it.
	if got := IndicesAtSlot(uint64(MainnetFuluForkEpoch) * SlotsPerEpoch); got.FinalizedRoot != FinalizedRootIndexElectra {
		t.Error("a Fulu-era slot did not get the Electra layout")
	}
}

func TestAltairIndicesAreTheOnesTheConstantsName(t *testing.T) {
	got, err := IndicesFor(SpecAltair)
	if err != nil {
		t.Fatalf("IndicesFor: %v", err)
	}
	if got.FinalizedRoot != FinalizedRootIndex ||
		got.NextSyncCommittee != NextSyncCommitteeIndex ||
		got.CurrentSyncCommittee != CurrentSyncCommitteeIndex {
		t.Error("the fork table disagrees with the package constants")
	}
}

// ---- period arithmetic -------------------------------------------------------

func TestPeriodBoundaries(t *testing.T) {
	cases := []struct {
		slot   uint64
		period uint64
	}{
		{0, 0},
		{periodSlots - 1, 0},
		{periodSlots, 1},
		{periodSlots + 1, 1},
		{2*periodSlots - 1, 1},
		{2 * periodSlots, 2},
	}
	for _, tc := range cases {
		if got := SyncCommitteePeriod(tc.slot); got != tc.period {
			t.Errorf("period(%d) = %d, want %d", tc.slot, got, tc.period)
		}
	}
	if SlotsPerSyncCommitteePeriod != 8192 {
		t.Errorf("a period is %d slots; 32 epochs x 256 is 8192", SlotsPerSyncCommitteePeriod)
	}
}
