package channel

// secp256k1 — the curve Ethereum actually verifies.
//
// WHY NOT elliptic.CurveParams
// ----------------------------
// The obvious approach is to hand crypto/elliptic a CurveParams describing
// secp256k1 and reuse the generic group law. That produces WRONG POINTS, and
// silently.
//
// Go's generic implementation hardcodes the short-Weierstrass formulas for
// a = -3, because every curve in the standard library (P-224 through P-521) has
// a = -3 and the assumption buys real speed. secp256k1 has **a = 0**. The
// addition and doubling formulas differ, so the arithmetic completes, returns
// plausible-looking coordinates, and is simply not the curve you asked for —
// which for a payment lock means points that never open.
//
// So this wraps decred's secp256k1, already in the dependency tree via libp2p:
// audited, constant-time, and maintained by people who do this for a living.
// Hand-rolling the group law here would be the single worst place in this
// package to be clever.
//
// CONSTANT TIME MATTERS HERE, SPECIFICALLY
// ----------------------------------------
// The blinding scalars in atomic.go are SECRET — learning one lets a router
// compute an adjacent hop's lock and correlate the payment. A variable-time
// scalar multiplication leaks them through timing. That is the concrete reason
// this must be a vetted library rather than math/big: not correctness alone,
// but the side channel.

import (
	"crypto/elliptic"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Secp256k1 implements Curve over the chain's curve.
type Secp256k1 struct{}

// EthereumCurve is what a mainnet deployment must use.
func EthereumCurve() Curve { return Secp256k1{} }

// k1Params carries the curve ORDER and nothing this package relies on beyond it.
//
// A *elliptic.CurveParams is returned because that is the interface's shape, but
// its METHODS must never be called for this curve — they implement the a = -3
// group law and would be wrong here. Only the N field is read (atomic.go reduces
// scalars modulo it), which is plain data and correct.
var k1Params = &elliptic.CurveParams{
	Name:    "secp256k1",
	P:       new(big.Int).Set(secp256k1.S256().P),
	N:       new(big.Int).Set(secp256k1.S256().N),
	B:       big.NewInt(7),
	Gx:      new(big.Int).Set(secp256k1.S256().Gx),
	Gy:      new(big.Int).Set(secp256k1.S256().Gy),
	BitSize: 256,
}

func (Secp256k1) Params() *elliptic.CurveParams { return k1Params }

// ScalarBaseMult returns k·G.
func (Secp256k1) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	var scalar secp256k1.ModNScalar
	// Reduces modulo N rather than rejecting, matching crypto/elliptic's
	// behaviour so callers see one contract across both curves.
	scalar.SetByteSlice(k)
	var result secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&scalar, &result)
	result.ToAffine()
	return new(big.Int).SetBytes(result.X.Bytes()[:]), new(big.Int).SetBytes(result.Y.Bytes()[:])
}

// Add returns P + Q.
func (Secp256k1) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p := jacobianFrom(x1, y1)
	q := jacobianFrom(x2, y2)
	var sum secp256k1.JacobianPoint
	secp256k1.AddNonConst(p, q, &sum)
	sum.ToAffine()
	return new(big.Int).SetBytes(sum.X.Bytes()[:]), new(big.Int).SetBytes(sum.Y.Bytes()[:])
}

func jacobianFrom(x, y *big.Int) *secp256k1.JacobianPoint {
	var fx, fy secp256k1.FieldVal
	var bx, by [32]byte
	x.FillBytes(bx[:])
	y.FillBytes(by[:])
	fx.SetBytes(&bx)
	fy.SetBytes(&by)
	p := &secp256k1.JacobianPoint{X: fx, Y: fy}
	p.Z.SetInt(1)
	return p
}
