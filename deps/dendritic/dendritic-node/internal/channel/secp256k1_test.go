package channel

import (
	"math/big"
	"testing"
)

// The whole point: the atomicity construction must work on the curve Ethereum
// actually verifies, not only on the standard-library one.
func TestAtomicSettlementWorksOnSecp256k1(t *testing.T) {
	c := EthereumCurve()
	z, Z, err := NewSecret(c)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatal(err)
	}
	scalars, err := SettleRoute(c, chain, z)
	if err != nil {
		t.Fatal(err)
	}
	for i, lock := range chain.Locks {
		if err := Satisfies(c, lock, scalars[i]); err != nil {
			t.Fatalf("hop %d cannot settle on secp256k1: %v", i, err)
		}
	}
}

func TestSecp256k1LocksAreStillDistinct(t *testing.T) {
	c := EthereumCurve()
	_, Z, _ := NewSecret(c)
	chain, _ := BuildLocks(c, Z, 3)
	for i := range chain.Locks {
		for j := i + 1; j < len(chain.Locks); j++ {
			if chain.Locks[i].Equal(chain.Locks[j]) {
				t.Fatalf("hops %d and %d share a lock", i, j)
			}
		}
	}
}

// Points must satisfy y² = x³ + 7 over the field. This is what catches using
// the wrong group law: a = -3 formulas produce coordinates that are NOT on
// secp256k1, and nothing else in the pipeline would notice.
func TestGeneratedPointsAreActuallyOnSecp256k1(t *testing.T) {
	c := EthereumCurve()
	p := c.Params().P
	for i := 0; i < 8; i++ {
		_, P, err := NewSecret(c)
		if err != nil {
			t.Fatal(err)
		}
		lhs := new(big.Int).Exp(P.Y, big.NewInt(2), p)
		rhs := new(big.Int).Exp(P.X, big.NewInt(3), p)
		rhs.Add(rhs, big.NewInt(7))
		rhs.Mod(rhs, p)
		if lhs.Cmp(rhs) != 0 {
			t.Fatalf("point %d is not on the curve — wrong group law", i)
		}
	}
}

// Addition must also land on the curve; a wrong Add is the subtler failure.
func TestAdditionStaysOnTheCurve(t *testing.T) {
	c := EthereumCurve()
	p := c.Params().P
	_, A, _ := NewSecret(c)
	_, B, _ := NewSecret(c)
	x, y := c.Add(A.X, A.Y, B.X, B.Y)

	lhs := new(big.Int).Exp(y, big.NewInt(2), p)
	rhs := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, p)
	if lhs.Cmp(rhs) != 0 {
		t.Fatal("A+B is not on secp256k1")
	}
}

// The curve order must be secp256k1's, not P-256's — a mismatched N would
// reduce scalars into the wrong range and produce locks that never open.
func TestCurveOrderIsSecp256k1s(t *testing.T) {
	want, _ := new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if EthereumCurve().Params().N.Cmp(want) != 0 {
		t.Fatal("curve order is not secp256k1's")
	}
	if EthereumCurve().Params().N.Cmp(DefaultCurve().Params().N) == 0 {
		t.Fatal("secp256k1 and P-256 report the same order")
	}
}
