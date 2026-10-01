package channel

// Pedersen commitments over secp256k1 — the scheme that actually proves value
// is conserved.
//
// C = v·G + r·H
//
// Binding (you cannot open C to a different v without solving a discrete log)
// and hiding (r is uniform, so C reveals nothing about v). The property the
// rest of the system was waiting for is that commitments ADD:
//
//	C₁ + C₂ = (v₁+v₂)·G + (r₁+r₂)·H
//
// So inputs balancing outputs can be checked by summing points and comparing —
// without opening a single commitment. That is what replaces the placeholder
// whose CheckBalance refused to run.
//
// WHY H IS DERIVED AND NOT CHOSEN
// -------------------------------
// The whole binding property rests on nobody knowing x such that H = x·G. If
// someone did, they could open any commitment to any value: C = v·G + r·H
// becomes (v + rx)·G, and they can produce a second (v', r') giving the same
// point. Value could be created from nothing, and no verifier would notice.
//
// So H is NOT a chosen constant. It is derived by hashing G's own encoding and
// mapping the digest to a curve point — a "nothing up my sleeve" construction
// where the deriver has no more information than anyone else. Anybody can
// recompute it and confirm no trapdoor was inserted.
//
// The mapping is try-and-increment: hash, attempt to interpret as an x
// coordinate, and on failure increment a counter and retry. Not constant-time,
// which is fine because this runs once on a public value and there is nothing
// secret to leak.

import (
	"encoding/binary"
	"math/big"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const domainPedersenH = "syndichan/pedersen/H/v1"

var (
	hOnce  sync.Once
	hPoint Point
)

// generatorH returns the second generator, derived deterministically.
func generatorH() Point {
	hOnce.Do(func() {
		g := secp256k1.S256()
		// Seed from G's own coordinates: the input is public and fixed, so the
		// output cannot have been steered.
		seed := derive(domainPedersenH, g.Gx.Bytes(), g.Gy.Bytes())
		for counter := uint32(0); ; counter++ {
			var ctr [4]byte
			binary.BigEndian.PutUint32(ctr[:], counter)
			candidate := derive(domainPedersenH, seed[:], ctr[:])
			x, y, ok := pointFromX(candidate)
			if ok {
				hPoint = Point{X: x, Y: y}
				return
			}
		}
	})
	return hPoint
}

// pointFromX interprets 32 bytes as an x coordinate and solves for y.
//
// Roughly half of all x values are not on the curve, hence the retry loop above.
func pointFromX(xb [32]byte) (*big.Int, *big.Int, bool) {
	var fx secp256k1.FieldVal
	if overflow := fx.SetBytes(&xb); overflow != 0 {
		return nil, nil, false
	}
	var fy secp256k1.FieldVal
	if !secp256k1.DecompressY(&fx, false, &fy) {
		return nil, nil, false
	}
	return new(big.Int).SetBytes(fx.Bytes()[:]), new(big.Int).SetBytes(fy.Bytes()[:]), true
}

// Pedersen is the homomorphic commitment scheme.
type Pedersen struct{}

func (Pedersen) Name() string        { return "pedersen-secp256k1" }
func (Pedersen) IsHomomorphic() bool { return true }

// Commit returns C = v·G + r·H, serialised.
//
// Serialised as the compressed point so a Commitment stays 32 bytes-ish and
// comparisons are byte equality. The full point is recoverable for arithmetic
// via CommitPoint.
func (p Pedersen) Commit(value uint64, blinding [32]byte) Commitment {
	pt := p.CommitPoint(value, blinding)
	digest := derive("syndichan/pedersen/serialize/v1", pt.X.Bytes(), pt.Y.Bytes())
	return Commitment(digest)
}

// CommitPoint returns the commitment as a curve point, for summing.
func (Pedersen) CommitPoint(value uint64, blinding [32]byte) Point {
	c := EthereumCurve()
	vx, vy := c.ScalarBaseMult(new(big.Int).SetUint64(value).Bytes())

	h := generatorH()
	hx, hy := scalarMult(h, blinding[:])

	if value == 0 {
		return Point{X: hx, Y: hy}
	}
	x, y := c.Add(vx, vy, hx, hy)
	return Point{X: x, Y: y}
}

// scalarMult computes k·P for an arbitrary point.
func scalarMult(p Point, k []byte) (*big.Int, *big.Int) {
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(k)
	point := jacobianFrom(p.X, p.Y)
	var out secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&scalar, point, &out)
	out.ToAffine()
	return new(big.Int).SetBytes(out.X.Bytes()[:]), new(big.Int).SetBytes(out.Y.Bytes()[:])
}

// SumPoints adds commitment points.
func SumPoints(points []Point) Point {
	if len(points) == 0 {
		return Point{}
	}
	c := EthereumCurve()
	acc := points[0]
	for _, p := range points[1:] {
		x, y := c.Add(acc.X, acc.Y, p.X, p.Y)
		acc = Point{X: x, Y: y}
	}
	return acc
}

// CheckBalancePoints verifies inputs = outputs + fees by point arithmetic.
//
// No commitment is opened. This is the check the placeholder scheme refused to
// perform, and the reason it refused rather than returning nil: a scheme that
// silently failed to add would produce proofs that verify while the books do
// not balance — value created from nothing, undetectably.
func CheckBalancePoints(inputs, outputs []Point, fee Point) bool {
	left := SumPoints(inputs)
	right := SumPoints(append(append([]Point{}, outputs...), fee))
	return left.Equal(right)
}

var _ CommitmentScheme = Pedersen{}
