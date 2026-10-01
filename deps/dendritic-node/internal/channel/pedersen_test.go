package channel

import (
	"math/big"
	"testing"
)

// THE property the placeholder could not provide: commitments add, so value
// conservation is checkable without opening anything.
func TestCommitmentsAreHomomorphic(t *testing.T) {
	p := Pedersen{}
	r1, r2 := [32]byte{0x11}, [32]byte{0x22}

	// C(3) + C(5) must equal C(8) with the blindings summed.
	a := p.CommitPoint(3, r1)
	b := p.CommitPoint(5, r2)
	sum := SumPoints([]Point{a, b})

	var combined [32]byte
	n := EthereumCurve().Params().N
	rr := new(big.Int).Mod(new(big.Int).Add(
		new(big.Int).SetBytes(r1[:]), new(big.Int).SetBytes(r2[:])), n)
	rr.FillBytes(combined[:])
	expect := p.CommitPoint(8, combined)

	if !sum.Equal(expect) {
		t.Fatal("C(3)+C(5) != C(8) — commitments are not homomorphic")
	}
}

// The real check: inputs must balance outputs plus fees, without opening any.
func TestBalanceCheckPassesWhenValueIsConserved(t *testing.T) {
	p := Pedersen{}
	// 100 in; 70 + 25 out; 5 fee. Blindings must also sum on both sides.
	in := p.CommitPoint(100, blindingOf(t, 90))
	out1 := p.CommitPoint(70, blindingOf(t, 40))
	out2 := p.CommitPoint(25, blindingOf(t, 30))
	fee := p.CommitPoint(5, blindingOf(t, 20))

	if !CheckBalancePoints([]Point{in}, []Point{out1, out2}, fee) {
		t.Fatal("a conserving transfer failed the balance check")
	}
}

// Value creation must fail. This is the check that stops a proof verifying
// while the books do not balance.
func TestBalanceCheckCatchesValueCreation(t *testing.T) {
	p := Pedersen{}
	in := p.CommitPoint(100, blindingOf(t, 90))
	// 200 out from 100 in.
	out := p.CommitPoint(200, blindingOf(t, 70))
	fee := p.CommitPoint(0, blindingOf(t, 20))
	if CheckBalancePoints([]Point{in}, []Point{out}, fee) {
		t.Fatal("value was created from nothing and the check passed")
	}
}

// Binding: two different values must not give the same commitment.
func TestCommitmentBinds(t *testing.T) {
	p := Pedersen{}
	r := [32]byte{0x07}
	if p.Commit(10, r) == p.Commit(11, r) {
		t.Fatal("two values share a commitment")
	}
	if p.Commit(10, r) == p.Commit(10, [32]byte{0x08}) {
		t.Fatal("the blinding does not affect the commitment")
	}
	if p.Commit(10, r) != p.Commit(10, r) {
		t.Fatal("commitment is not deterministic")
	}
}

// H must be on the curve and must not be G. If H were a multiple of G with a
// known factor, any commitment could be opened to any value.
func TestSecondGeneratorIsSoundlyDerived(t *testing.T) {
	h := generatorH()
	c := EthereumCurve()
	pmod := c.Params().P

	lhs := new(big.Int).Exp(h.Y, big.NewInt(2), pmod)
	rhs := new(big.Int).Exp(h.X, big.NewInt(3), pmod)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, pmod)
	if lhs.Cmp(rhs) != 0 {
		t.Fatal("H is not on secp256k1")
	}
	gx, gy := c.ScalarBaseMult(big.NewInt(1).Bytes())
	if h.X.Cmp(gx) == 0 && h.Y.Cmp(gy) == 0 {
		t.Fatal("H is G — the commitment would not bind")
	}
	// Deterministic: anyone must be able to recompute it and check for a trapdoor.
	if again := generatorH(); !again.Equal(h) {
		t.Fatal("H derivation is not deterministic — it cannot be audited")
	}
}

// The scheme must now declare itself homomorphic, and CheckBalance must stop
// refusing.
func TestCheckBalanceNoLongerRefuses(t *testing.T) {
	if !(Pedersen{}).IsHomomorphic() {
		t.Fatal("Pedersen does not report itself homomorphic")
	}
	if (HashCommitment{}).IsHomomorphic() {
		t.Fatal("the placeholder now claims to be homomorphic")
	}
}

// blindingOf encodes an integer as a scalar, so blindings ADD the way values
// do. A Pedersen balance check requires BOTH sums to hold — the values and the
// blindings — and picking arbitrary blindings fails the check for a transfer
// that conserves value perfectly. That is not a flaw in the scheme; it is the
// scheme, and it means a payer must choose output blindings that sum to the
// input's.
func blindingOf(t *testing.T, n uint64) [32]byte {
	t.Helper()
	var out [32]byte
	new(big.Int).SetUint64(n).FillBytes(out[:])
	return out
}
