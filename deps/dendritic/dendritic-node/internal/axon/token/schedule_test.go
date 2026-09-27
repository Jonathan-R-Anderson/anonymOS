package token

import (
	"errors"
	"testing"
	"time"
)

func sched() Schedule {
	return Schedule{
		Start:         time.Unix(1_700_000_000, 0),
		Length:        24 * time.Hour,
		Overlap:       2 * time.Hour,
		TokenLifetime: time.Hour,
	}
}

// TestOverlapMustCoverTheTokenLifetime is the rule that is derived rather than
// chosen: a token issued a second before a rotation must still be spendable.
func TestOverlapMustCoverTheTokenLifetime(t *testing.T) {
	s := sched()
	if err := s.Valid(); err != nil {
		t.Fatal(err)
	}
	s.Overlap = s.TokenLifetime - time.Second
	if err := s.Valid(); !errors.Is(err, ErrOverlapTooShort) {
		t.Fatalf("a schedule that voids tokens at every rotation was accepted: %v", err)
	}

	// End to end: issued just before a boundary, spent just after.
	s = sched()
	boundary := s.Start.Add(s.Length)
	issuedAt := boundary.Add(-time.Second)
	e, err := s.EpochAt(issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Accepts(e, boundary.Add(s.TokenLifetime-time.Second)); err != nil {
		t.Fatalf("a token issued 1s before rotation was refused after it: %v", err)
	}
}

// TestAFutureEpochIsRefused is the partition-of-one case.
func TestAFutureEpochIsRefused(t *testing.T) {
	s := sched()
	now := s.Start.Add(s.Length / 2)
	current, _ := s.EpochAt(now)
	if err := s.Accepts(current+1, now); !errors.Is(err, ErrEpochInFuture) {
		t.Fatal("an epoch nobody else can have been issued under was accepted; the " +
			"issuer can pre-sign under it and the only payer in that set is the one " +
			"it chose")
	}
	if _, err := s.EpochAt(s.Start.Add(-time.Second)); !errors.Is(err, ErrEpochInFuture) {
		t.Fatal("a time before epoch 0 produced an epoch")
	}
}

// TestARetiredEpochIsRefusedDistinctly keeps the two refusals apart.
func TestARetiredEpochIsRefusedDistinctly(t *testing.T) {
	s := sched()
	// Epoch 0 dies at Length + Overlap.
	dead := s.Start.Add(s.Length + s.Overlap + time.Second)
	err := s.Accepts(0, dead)
	if !errors.Is(err, ErrEpochRetired) {
		t.Fatalf("a retired epoch was accepted or misreported: %v", err)
	}
	// Still live one second before.
	if err := s.Accepts(0, s.Start.Add(s.Length+s.Overlap-time.Second)); err != nil {
		t.Fatalf("epoch 0 was retired early: %v", err)
	}
}

// TestEpochsAdvanceWithTime is the basic mapping.
func TestEpochsAdvanceWithTime(t *testing.T) {
	s := sched()
	for i := 0; i < 5; i++ {
		got, err := s.EpochAt(s.Start.Add(time.Duration(i)*s.Length + time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if got != Epoch(i) {
			t.Fatalf("at epoch %d the schedule said %d", i, got)
		}
	}
}

// TestTheAnonymitySetIsZeroWithNoPayers is D5's actual finding.
//
// The epoch LENGTH cannot be derived from the requirement it serves while the
// deployed population has no paying clients: P = 0 at every length, so P·B = 0.
// Stating that in code keeps a future reader from assuming a chosen length
// bought something.
func TestTheAnonymitySetIsZeroWithNoPayers(t *testing.T) {
	if got := AnonymitySetBound(0, 1000); got != 0 {
		t.Fatalf("no payers produced an anonymity set of %d", got)
	}
	if got := AnonymitySetBound(50, 10); got != 500 {
		t.Fatalf("P·B is %d, want 500", got)
	}
	// NO NUMBER OF TOKENS RESCUES P = 0, which is the claim that actually holds.
	// An earlier version of this test asserted that P "dominates" B by comparing
	// P·B at swapped values -- 5x1000 against 500x10 -- and they are equal,
	// because the product is symmetric. P is the binding term in PRACTICE, since
	// B is bounded by what one payer buys and P by the whole population, and
	// that is a fact about the deployment rather than about the arithmetic.
	for _, b := range []int{1, 100, 1_000_000} {
		if got := AnonymitySetBound(0, b); got != 0 {
			t.Fatalf("B=%d produced a set of %d with no payers", b, got)
		}
	}
}
