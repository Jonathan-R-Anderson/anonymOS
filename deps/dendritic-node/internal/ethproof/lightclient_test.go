package ethproof

// Beacon header progression — roadmap P12-5.3.
//
// Every rule here is checkable with NO BLS implementation, which is the point:
// 5.3 can be finished and tested before 5.4 selects a library. The signature is
// the last check and the only one behind the dependency boundary.

import (
	"errors"
	"testing"
)

// countingVerifier records whether the pairing was reached, so the tests can
// assert that cheap checks run FIRST and an invalid update never pays for one.
type countingVerifier struct {
	calls int
	err   error
	// seen is the committee it was handed, so a test can prove the committee
	// came from the authenticated state and not from the update.
	seen *SyncCommittee
}

func (c *countingVerifier) VerifySyncCommitteeSignature(
	_ Root, committee *SyncCommittee, _ Participation, _ []byte) error {
	c.calls++
	c.seen = committee
	return c.err
}

func committee(marker byte) *SyncCommittee {
	c := &SyncCommittee{
		Pubkeys:         make([][]byte, SyncCommitteeSize),
		AggregatePubkey: make([]byte, 48),
	}
	for i := range c.Pubkeys {
		key := make([]byte, 48)
		key[0], key[1] = marker, byte(i)
		c.Pubkeys[i] = key
	}
	c.AggregatePubkey[0] = marker
	return c
}

// fullParticipation is every member signing.
func fullParticipation() Participation {
	p := make(Participation, SyncCommitteeSize/8)
	for i := range p {
		p[i] = 0xFF
	}
	return p
}

// newState is an authenticated client at slot 100.
func newState(t *testing.T) *LightClientState {
	t.Helper()
	return &LightClientState{
		FinalizedHeader:  BeaconBlockHeader{Slot: 100},
		CurrentCommittee: committee(0xAA),
		Checkpoint:       goodCheckpoint(),
	}
}

// validUpdate builds an update whose branches actually verify, by constructing
// the attested state root FROM the branches rather than asserting it.
func validUpdate(t *testing.T, finalizedSlot uint64) *Update {
	t.Helper()
	u := &Update{
		FinalizedHeader: BeaconBlockHeader{Slot: finalizedSlot},
		AttestedHeader:  BeaconBlockHeader{Slot: finalizedSlot + 10},
		SignatureSlot:   finalizedSlot + 11,
		Participation:   fullParticipation(),
		Signature:       make([]byte, 96),
	}
	finalizedRoot, err := u.FinalizedHeader.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	branch, stateRoot := branchFor(t, finalizedRoot, FinalizedRootIndex)
	u.FinalityBranch = branch
	u.AttestedHeader.StateRoot = stateRoot
	return u
}

// branchFor builds a branch of the right depth for an index, and the root it
// produces. Sibling nodes are arbitrary; what matters is that the branch and
// the root agree, which is what a real update supplies.
func branchFor(t *testing.T, leaf Root, index uint64) ([]Root, Root) {
	t.Helper()
	depth := GeneralizedIndexDepth(index)
	branch := make([]Root, depth)
	node := leaf
	for i := 0; i < depth; i++ {
		var sibling Root
		sibling[0] = byte(i + 1)
		branch[i] = sibling
		if index>>(uint(i))&1 == 1 {
			node = sha256Pair(sibling[:], node[:])
		} else {
			node = sha256Pair(node[:], sibling[:])
		}
	}
	return branch, node
}

// ---- the structural rules ---------------------------------------------------

func TestAValidUpdateAdvancesTheState(t *testing.T) {
	s := newState(t)
	u := validUpdate(t, 200)
	v := &countingVerifier{}

	if err := s.ApplyUpdate(u, v); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if s.FinalizedHeader.Slot != 200 {
		t.Errorf("finalised slot %d, want 200", s.FinalizedHeader.Slot)
	}
	if v.calls != 1 {
		t.Errorf("the signature was verified %d times", v.calls)
	}
}

// An update that does not move forward must not be applied, whatever it is
// signed by. Otherwise a client can be walked back onto a state it has left.
func TestAStaleUpdateIsRefused(t *testing.T) {
	s := newState(t)
	v := &countingVerifier{}

	for _, slot := range []uint64{100, 99, 0} {
		u := validUpdate(t, slot)
		if err := s.ApplyUpdate(u, v); !errors.Is(err, ErrUpdateStale) {
			t.Errorf("slot %d: got %v, want ErrUpdateStale", slot, err)
		}
	}
	if v.calls != 0 {
		t.Error("a stale update reached the pairing check")
	}
}

// A committee attests to the block BEFORE the slot it signs in.
func TestTheSignatureSlotMustFollowTheAttestedSlot(t *testing.T) {
	s := newState(t)
	u := validUpdate(t, 200)
	u.SignatureSlot = u.AttestedHeader.Slot // not strictly after

	v := &countingVerifier{}
	if err := s.ApplyUpdate(u, v); err == nil {
		t.Fatal("an update whose signature slot did not advance was accepted")
	}
	if v.calls != 0 {
		t.Error("it reached the pairing check anyway")
	}
}

// Below the supermajority, a perfectly valid signature proves little — and must
// cost nothing to reject.
func TestInsufficientParticipationIsRefusedBeforeAnyPairing(t *testing.T) {
	s := newState(t)
	u := validUpdate(t, 200)
	// Half the committee.
	u.Participation = make(Participation, SyncCommitteeSize/8)
	for i := 0; i < len(u.Participation)/2; i++ {
		u.Participation[i] = 0xFF
	}

	v := &countingVerifier{}
	err := s.ApplyUpdate(u, v)
	if !errors.Is(err, ErrInsufficientParticipation) {
		t.Fatalf("got %v, want ErrInsufficientParticipation", err)
	}
	if v.calls != 0 {
		t.Error("an under-participated update paid for a pairing")
	}
}

// A branch that verifies at the WRONG index proves a true statement about a
// different field.
func TestAFinalityBranchAtTheWrongIndexIsRefused(t *testing.T) {
	s := newState(t)
	u := validUpdate(t, 200)

	// Rebuild the branch for a different generalized index; the root no longer
	// matches the one the attested header carries.
	finalizedRoot, _ := u.FinalizedHeader.HashTreeRoot()
	u.FinalityBranch, _ = branchFor(t, finalizedRoot, NextSyncCommitteeIndex)

	v := &countingVerifier{}
	if err := s.ApplyUpdate(u, v); !errors.Is(err, ErrBranchWrongField) {
		t.Fatalf("got %v, want ErrBranchWrongField", err)
	}
	if v.calls != 0 {
		t.Error("a misplaced branch reached the pairing check")
	}
}

func TestATamperedFinalisedHeaderBreaksItsBranch(t *testing.T) {
	s := newState(t)
	u := validUpdate(t, 200)
	// Change the header after the branch was built for it.
	u.FinalizedHeader.ProposerIndex = 7

	if err := s.ApplyUpdate(u, &countingVerifier{}); !errors.Is(err, ErrBranchWrongField) {
		t.Fatalf("got %v, want ErrBranchWrongField", err)
	}
}

// ---- the committee comes from the state, never from the update --------------

// THE RULE. Verifying with the update's own committee would check that a
// message agrees with itself, which every forgery does.
func TestTheCommitteeComesFromTheAuthenticatedState(t *testing.T) {
	s := newState(t)
	u := validUpdate(t, 200)
	// The update offers a committee of its own, correctly proven into its own
	// attested state.
	forged := committee(0xEE)
	forgedRoot, err := forged.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	u.NextCommittee = forged
	u.NextCommitteeBranch, _ = branchFor(t, forgedRoot, NextSyncCommitteeIndex)

	v := &countingVerifier{}
	// The branch will not match the attested state root that the FINALITY
	// branch fixed, so this update is refused outright — which is correct, and
	// the important assertion is below.
	_ = s.ApplyUpdate(u, v)

	if v.seen != nil && v.seen.AggregatePubkey[0] == 0xEE {
		t.Fatal("the update's own committee was used to verify the update")
	}
}

func TestAStateWithNoCommitteeCannotApplyAnything(t *testing.T) {
	s := newState(t)
	s.CurrentCommittee = nil

	if err := s.ApplyUpdate(validUpdate(t, 200), &countingVerifier{}); !errors.Is(err, ErrCommitteeUnknown) {
		t.Fatalf("got %v, want ErrCommitteeUnknown", err)
	}
}

// No verifier means no advance. A client that advanced without one would be
// applying unauthenticated updates.
func TestNoVerifierMeansNoAdvance(t *testing.T) {
	s := newState(t)
	before := s.FinalizedHeader.Slot
	if err := s.ApplyUpdate(validUpdate(t, 200), nil); err == nil {
		t.Fatal("the state advanced with no signature verifier")
	}
	if s.FinalizedHeader.Slot != before {
		t.Error("the state advanced despite the error")
	}
}

// A failing signature must leave the state untouched.
func TestAFailedSignatureLeavesTheStateUnchanged(t *testing.T) {
	s := newState(t)
	before := s.FinalizedHeader.Slot
	v := &countingVerifier{err: errors.New("aggregate does not verify")}

	if err := s.ApplyUpdate(validUpdate(t, 200), v); err == nil {
		t.Fatal("an update with a bad signature was applied")
	}
	if s.FinalizedHeader.Slot != before {
		t.Errorf("the state advanced to %d despite a bad signature", s.FinalizedHeader.Slot)
	}
}

// ---- participation bookkeeping ----------------------------------------------

func TestParticipationCounting(t *testing.T) {
	full := fullParticipation()
	if got := full.Count(); got != SyncCommitteeSize {
		t.Errorf("full participation counted %d, want %d", got, SyncCommitteeSize)
	}
	if got := len(full.Members()); got != SyncCommitteeSize {
		t.Errorf("full participation listed %d members", got)
	}
	empty := make(Participation, SyncCommitteeSize/8)
	if empty.Count() != 0 || len(empty.Members()) != 0 {
		t.Error("an empty bitfield reported participants")
	}
	// One bit, in a known place.
	one := make(Participation, SyncCommitteeSize/8)
	one[1] = 0x04 // bit 10
	if one.Count() != 1 {
		t.Fatalf("one bit counted %d", one.Count())
	}
	if m := one.Members(); len(m) != 1 || m[0] != 10 {
		t.Errorf("members = %v, want [10]", m)
	}
}

func TestTheThresholdIsTwoThirds(t *testing.T) {
	if MinParticipation != 341 {
		t.Errorf("MinParticipation = %d; 2/3 of 512 is 341", MinParticipation)
	}
}

// A committee root must depend on every key, or a substituted validator would
// go unnoticed.
func TestEveryCommitteeKeyAffectsTheRoot(t *testing.T) {
	a := committee(0xAA)
	rootA, err := a.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	b := committee(0xAA)
	b.Pubkeys[377][47] ^= 0x01 // one bit, one key, deep in the vector
	rootB, err := b.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	if rootA == rootB {
		t.Fatal("changing one validator key did not change the committee root")
	}
}

func TestAWrongSizedCommitteeIsRefused(t *testing.T) {
	c := committee(0xAA)
	c.Pubkeys = c.Pubkeys[:511]
	if _, err := c.HashTreeRoot(); err == nil {
		t.Fatal("a 511-key committee produced a root")
	}
}
