package channel

import (
	"errors"
	"math/big"
	"testing"
)

// The headline property: NO TWO HOPS SHARE A LOCK. This is the entire reason
// for not using one payment hash, so it is the first thing asserted.
func TestNoTwoHopsShareALock(t *testing.T) {
	c := DefaultCurve()
	_, Z, err := NewSecret(c)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := range chain.Locks {
		for j := i + 1; j < len(chain.Locks); j++ {
			if chain.Locks[i].Equal(chain.Locks[j]) {
				t.Fatalf("hops %d and %d share a lock — a global correlator", i, j)
			}
		}
	}
	// And none of them equals the recipient's own point, which would let a hop
	// recognise the destination.
	for i, lock := range chain.Locks {
		if lock.Equal(Z) {
			t.Errorf("hop %d's lock is the recipient's point", i)
		}
	}
}

// Every hop's lock must actually be satisfiable by the scalar unwinding gives
// it — the construction is worthless if it is private but does not settle.
func TestEveryHopCanSatisfyItsOwnLock(t *testing.T) {
	c := DefaultCurve()
	z, Z, _ := NewSecret(c)
	chain, _ := BuildLocks(c, Z, 3)

	scalars, err := SettleRoute(c, chain, z)
	if err != nil {
		t.Fatal(err)
	}
	for i, lock := range chain.Locks {
		if err := Satisfies(c, lock, scalars[i]); err != nil {
			t.Errorf("hop %d cannot satisfy its lock: %v", i, err)
		}
	}
}

// The atomicity argument: a hop's scalar must NOT satisfy any other hop's lock.
// If it did, a router could claim upstream without having paid downstream.
func TestOneHopsScalarDoesNotOpenAnother(t *testing.T) {
	c := DefaultCurve()
	z, Z, _ := NewSecret(c)
	chain, _ := BuildLocks(c, Z, 3)
	scalars, _ := SettleRoute(c, chain, z)

	for i := range chain.Locks {
		for j := range scalars {
			if i == j {
				continue
			}
			if err := Satisfies(c, chain.Locks[i], scalars[j]); err == nil {
				t.Errorf("hop %d's scalar opened hop %d's lock", j, i)
			}
		}
	}
}

// Unwinding must be strictly downstream-first. The exit's scalar is derivable
// from z alone; the entry's is not, without every blinding below it.
func TestUpstreamCannotSettleBeforeDownstream(t *testing.T) {
	c := DefaultCurve()
	z, Z, _ := NewSecret(c)
	chain, _ := BuildLocks(c, Z, 3)

	// The exit (index 2) can go straight from z plus its own blinding.
	b2, err := chain.BlindingFor(2)
	if err != nil {
		t.Fatal(err)
	}
	exitScalar := Unwind(c, z, b2)
	if err := Satisfies(c, chain.Locks[2], exitScalar); err != nil {
		t.Fatalf("the exit could not settle from z: %v", err)
	}

	// The entry (index 0) with only its own blinding and z — skipping the
	// hops between — must NOT be able to settle.
	b0, _ := chain.BlindingFor(0)
	if err := Satisfies(c, chain.Locks[0], Unwind(c, z, b0)); err == nil {
		t.Fatal("the entry settled without the downstream hops' scalars")
	}
}

// A hop is given only its own blinding. Handing it the full set would let it
// compute every other lock and recognise the payment elsewhere on the path.
func TestAHopLearnsOnlyItsOwnBlinding(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	chain, _ := BuildLocks(c, Z, 3)

	b0, _ := chain.BlindingFor(0)
	b1, _ := chain.BlindingFor(1)
	if b0.Cmp(b1) == 0 {
		t.Fatal("two hops share a blinding scalar")
	}
	// Out-of-range requests are refused rather than returning a zero value a
	// caller might use.
	if _, err := chain.BlindingFor(99); !errors.Is(err, ErrBadScalar) {
		t.Error("an out-of-range hop index was not refused")
	}
	if _, err := chain.BlindingFor(-1); !errors.Is(err, ErrBadScalar) {
		t.Error("a negative hop index was not refused")
	}
}

// Two payments to the same recipient must produce entirely different locks, or
// the locks themselves become the recipient's identifier.
func TestTwoPaymentsToOneRecipientShareNoLock(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	a, _ := BuildLocks(c, Z, 3)
	b, _ := BuildLocks(c, Z, 3)
	for i := range a.Locks {
		for j := range b.Locks {
			if a.Locks[i].Equal(b.Locks[j]) {
				t.Fatalf("payment A hop %d and payment B hop %d share a lock", i, j)
			}
		}
	}
}

func TestSatisfiesRejectsOutOfRangeScalars(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	chain, _ := BuildLocks(c, Z, 1)

	if err := Satisfies(c, chain.Locks[0], nil); !errors.Is(err, ErrBadScalar) {
		t.Error("nil scalar accepted")
	}
	if err := Satisfies(c, chain.Locks[0], big.NewInt(-1)); !errors.Is(err, ErrBadScalar) {
		t.Error("negative scalar accepted")
	}
	if err := Satisfies(c, chain.Locks[0], c.Params().N); !errors.Is(err, ErrBadScalar) {
		t.Error("a scalar equal to the group order was accepted")
	}
}

func TestWrongSecretDoesNotSettle(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	chain, _ := BuildLocks(c, Z, 3)

	wrong, _, _ := NewSecret(c) // a different recipient's secret
	scalars, err := SettleRoute(c, chain, wrong)
	if err != nil {
		t.Fatal(err)
	}
	for i, lock := range chain.Locks {
		if err := Satisfies(c, lock, scalars[i]); err == nil {
			t.Errorf("hop %d settled with the wrong secret", i)
		}
	}
}

func TestRouteLengthIsBounded(t *testing.T) {
	c := DefaultCurve()
	_, Z, _ := NewSecret(c)
	if _, err := BuildLocks(c, Z, 0); !errors.Is(err, ErrTooManyLocks) {
		t.Error("accepted a zero-hop route")
	}
	if _, err := BuildLocks(c, Z, MaxHops+1); !errors.Is(err, ErrTooManyLocks) {
		t.Error("accepted a route longer than the format allows")
	}
}

// Shorter routes must work too — multipath fragments may be shorter.
func TestShorterRoutesSettle(t *testing.T) {
	c := DefaultCurve()
	for hops := 1; hops <= MaxHops; hops++ {
		z, Z, _ := NewSecret(c)
		chain, err := BuildLocks(c, Z, hops)
		if err != nil {
			t.Fatalf("%d hops: %v", hops, err)
		}
		scalars, err := SettleRoute(c, chain, z)
		if err != nil {
			t.Fatalf("%d hops: %v", hops, err)
		}
		for i, lock := range chain.Locks {
			if err := Satisfies(c, lock, scalars[i]); err != nil {
				t.Errorf("%d hops, hop %d: %v", hops, i, err)
			}
		}
	}
}
