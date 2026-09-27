package channel

import (
	"errors"
	"testing"
	"time"
)

var vNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
var vSession = SessionID{0x01}

func session(t *testing.T, deposit Amount) *Session {
	t.Helper()
	s, err := NewSession(vSession, deposit)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Accept returns the DELTA, not the total. A caller adding the cumulative
// figure to a running balance would double-count every voucher, which is the
// easiest mistake to make against an API that hands back a total.
func TestAcceptReturnsTheNewlyEarnedAmount(t *testing.T) {
	s := session(t, 1000)
	for i, tc := range []struct {
		total, wantDelta Amount
	}{
		{10, 10}, {25, 15}, {100, 75},
	} {
		got, err := s.Accept(NewVoucher(vSession, uint64(i+1), tc.total, vNow))
		if err != nil {
			t.Fatalf("voucher %d: %v", i, err)
		}
		if got != tc.wantDelta {
			t.Errorf("voucher %d: delta %d, want %d", i, got, tc.wantDelta)
		}
	}
	if s.Total() != 100 {
		t.Errorf("total = %d, want 100", s.Total())
	}
}

// The safety rule: an older voucher must never override a newer one, or a
// router could roll the total back and un-pay delivered work.
func TestAnOlderVoucherCannotOverrideANewerOne(t *testing.T) {
	s := session(t, 1000)
	if _, err := s.Accept(NewVoucher(vSession, 5, 100, vNow)); err != nil {
		t.Fatal(err)
	}
	_, err := s.Accept(NewVoucher(vSession, 4, 80, vNow))
	if !errors.Is(err, ErrVoucherStale) {
		t.Fatalf("a stale voucher was accepted: %v", err)
	}
	if s.Total() != 100 {
		t.Errorf("the total was rolled back to %d", s.Total())
	}
}

// Cumulative means monotonic. A newer sequence carrying a LOWER total is either
// a bug or an attempt to un-pay work already delivered.
func TestANewerVoucherCannotLowerTheTotal(t *testing.T) {
	s := session(t, 1000)
	_, _ = s.Accept(NewVoucher(vSession, 1, 100, vNow))
	_, err := s.Accept(NewVoucher(vSession, 2, 50, vNow))
	if !errors.Is(err, ErrVoucherRegressed) {
		t.Fatalf("a decreasing total was accepted: %v", err)
	}
	if s.Total() != 100 {
		t.Errorf("total = %d, want 100", s.Total())
	}
}

// Self-healing: a lost voucher costs nothing, because the next one states the
// total anyway. This is the whole reason for cumulative rather than incremental.
func TestALostVoucherCostsNothing(t *testing.T) {
	s := session(t, 1000)
	_, _ = s.Accept(NewVoucher(vSession, 1, 10, vNow))
	// voucher 2 (total 20) never arrives
	got, err := s.Accept(NewVoucher(vSession, 3, 30, vNow))
	if err != nil {
		t.Fatal(err)
	}
	if got != 20 {
		t.Errorf("delta = %d, want 20 — the gap should be covered", got)
	}
	if s.Total() != 30 {
		t.Errorf("total = %d, want 30", s.Total())
	}
}

// Replaying a voucher must be a no-op, not an addition. With increments a
// replay would add again; with cumulative totals it cannot.
func TestReplayingAVoucherEarnsNothing(t *testing.T) {
	s := session(t, 1000)
	v := NewVoucher(vSession, 1, 50, vNow)
	if got, err := s.Accept(v); err != nil || got != 50 {
		t.Fatalf("first accept: %d %v", got, err)
	}
	for i := 0; i < 5; i++ {
		got, err := s.Accept(v)
		if err != nil {
			t.Fatalf("replay %d errored: %v", i, err)
		}
		if got != 0 {
			t.Fatalf("replay %d earned %d", i, got)
		}
	}
	if s.Total() != 50 {
		t.Errorf("total inflated to %d by replays", s.Total())
	}
}

// Two different totals signed for the same sequence is a conflict, not a choice.
func TestConflictingVouchersAtOneSequenceAreRefused(t *testing.T) {
	s := session(t, 1000)
	_, _ = s.Accept(NewVoucher(vSession, 1, 50, vNow))
	_, err := s.Accept(NewVoucher(vSession, 1, 90, vNow))
	if !errors.Is(err, ErrVoucherRegressed) {
		t.Fatalf("accepted a conflicting voucher at the same sequence: %v", err)
	}
	if s.Total() != 50 {
		t.Errorf("total changed to %d", s.Total())
	}
}

// The deposit is a ceiling: a session must not accumulate a debt nobody funded.
func TestTotalCannotExceedTheDeposit(t *testing.T) {
	s := session(t, 100)
	if _, err := s.Accept(NewVoucher(vSession, 1, 101, vNow)); !errors.Is(err, ErrVoucherExceeds) {
		t.Fatalf("accepted a total above the deposit: %v", err)
	}
	if got, err := s.Accept(NewVoucher(vSession, 1, 100, vNow)); err != nil || got != 100 {
		t.Errorf("the exact deposit should be acceptable: %d %v", got, err)
	}
	if s.Remaining() != 0 {
		t.Errorf("remaining = %d, want 0", s.Remaining())
	}
}

// Tampering must be rejected, not clamped — an altered voucher is not a
// smaller valid one.
func TestTamperedVouchersAreRejected(t *testing.T) {
	s := session(t, 1000)
	v := NewVoucher(vSession, 1, 50, vNow)
	v.CumulativeAmount = 900 // as a router would rewrite it
	if _, err := s.Accept(v); err == nil {
		t.Fatal("a tampered voucher was accepted")
	}
	if s.Total() != 0 {
		t.Errorf("total became %d", s.Total())
	}
}

func TestVouchersFromAnotherSessionAreRefused(t *testing.T) {
	s := session(t, 1000)
	other := NewVoucher(SessionID{0xFF}, 1, 10, vNow)
	if _, err := s.Accept(other); !errors.Is(err, ErrVoucherSession) {
		t.Fatalf("accepted another session's voucher: %v", err)
	}
}

func TestClosedSessionsAcceptNothing(t *testing.T) {
	s := session(t, 1000)
	_, _ = s.Accept(NewVoucher(vSession, 1, 40, vNow))
	if final := s.Close(); final != 40 {
		t.Errorf("close returned %d, want 40", final)
	}
	if _, err := s.Accept(NewVoucher(vSession, 2, 80, vNow)); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("a closed session accepted a voucher: %v", err)
	}
}

// Only the newest voucher is retained. Keeping the history would be a
// per-second record of exactly when somebody was watching.
func TestOnlyTheNewestVoucherIsKept(t *testing.T) {
	s := session(t, 1000)
	for i := 1; i <= 20; i++ {
		if _, err := s.Accept(NewVoucher(vSession, uint64(i), Amount(i*5), vNow)); err != nil {
			t.Fatal(err)
		}
	}
	newest, ok := s.Newest()
	if !ok || newest.Sequence != 20 || newest.CumulativeAmount != 100 {
		t.Fatalf("newest = %+v", newest)
	}
}

func TestZeroDepositSessionIsRefused(t *testing.T) {
	if _, err := NewSession(vSession, 0); err == nil {
		t.Fatal("opened a session with no deposit")
	}
}

// Proofs are per epoch, not per voucher — one proof per voucher would cost more
// than the payments are worth.
func TestProofIsTriggeredByTimeOrValue(t *testing.T) {
	s := session(t, 1000)
	_, _ = s.Accept(NewVoucher(vSession, 1, 10, vNow))

	epoch := time.Minute
	// Neither condition met yet.
	if NeedsProof(s, vNow, vNow.Add(10*time.Second), epoch, 10, 500) {
		t.Error("proved a session that needed neither")
	}
	// Time elapsed.
	if !NeedsProof(s, vNow, vNow.Add(2*time.Minute), epoch, 10, 500) {
		t.Error("an elapsed epoch did not trigger a proof")
	}
	// Value accumulated — a fast session must not wait for the clock.
	if !NeedsProof(s, vNow, vNow.Add(time.Second), epoch, 600, 500) {
		t.Error("accumulated value did not trigger a proof")
	}
}
