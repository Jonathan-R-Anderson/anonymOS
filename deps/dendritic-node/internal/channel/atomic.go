package channel

// Atomic settlement across three hops, without a value every hop can see.
//
// THE PROBLEM WITH THE OBVIOUS CONSTRUCTION
// -----------------------------------------
// An HTLC locks every hop on one hash H and unlocks them all with one preimage.
// It gives perfect atomicity and it hands every router on the path the same 32
// bytes — so any two colluding routers, or anyone observing both ends, link the
// payment instantly. The onion in this package spends real effort hiding
// position and identity; a shared H gives all of it back in one field.
//
// THE CONSTRUCTION USED INSTEAD
// -----------------------------
// The recipient picks a secret z with point Z = z·G. The payer picks a blinding
// scalar per hop and gives each hop a DIFFERENT point:
//
//	entry  locks on  Z + (b₁+b₂+b₃)·G
//	middle locks on  Z + (b₂+b₃)·G
//	exit   locks on  Z + b₃·G
//	recipient releases z
//
// Unwinding runs backwards: the exit learns z, adds b₃ to satisfy its own lock,
// hands the result upstream; the middle adds b₂; the entry adds b₁. Each hop can
// satisfy its incoming lock only after its outgoing one was satisfied, which is
// exactly the HTLC guarantee — and no two hops ever hold the same value.
//
// WHY THE CURVE IS INJECTED
// -------------------------
// The curve must be the one the settlement chain can verify, because these
// points end up inside adaptor signatures the chain adjudicates. For Ethereum
// that is secp256k1. P-256 is used as the default here only because it is in
// the standard library and this layer's arithmetic is curve-agnostic — a
// production deployment MUST supply the chain's curve, and shipping P-256 to
// mainnet would produce locks no Ethereum contract can settle.

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	ErrBadScalar     = errors.New("channel: scalar is not in range")
	ErrPointMismatch = errors.New("channel: revealed scalar does not satisfy the lock")
	ErrTooManyLocks  = errors.New("channel: more hops than the format allows")
)

// Point is a compressed-ish public point: X and Y as fixed-width bytes. Kept as
// a struct rather than bytes so equality is a value comparison and cannot be
// accidentally done on differing encodings of the same point.
type Point struct {
	X, Y *big.Int
}

// Equal compares two points.
func (p Point) Equal(other Point) bool {
	if p.X == nil || p.Y == nil || other.X == nil || other.Y == nil {
		return false
	}
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

// LockChain is the set of per-hop locks for one payment.
type LockChain struct {
	// Locks[i] is what hop i must satisfy. Deliberately no field holds the
	// recipient's Z on its own: a hop that could see Z could recognise the same
	// payment at another hop.
	Locks []Point
	// blindings[i] is the scalar hop i adds. Held by the PAYER only — a hop
	// receives its own scalar during unwinding, never the others'.
	blindings []*big.Int
}

// Curve is the group these locks live in.
type Curve interface {
	Params() *elliptic.CurveParams
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
}

// DefaultCurve is P-256 — correct for tests, WRONG for Ethereum settlement.
// See the file comment.
func DefaultCurve() Curve { return elliptic.P256() }

// NewSecret draws a recipient secret z and its point Z.
func NewSecret(c Curve) (*big.Int, Point, error) {
	n := c.Params().N
	z, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, Point{}, err
	}
	if z.Sign() == 0 {
		// Zero would make Z the identity and every lock equal to its blinding
		// alone — vanishingly unlikely, catastrophic if unhandled.
		z.SetInt64(1)
	}
	x, y := c.ScalarBaseMult(z.Bytes())
	return z, Point{X: x, Y: y}, nil
}

// BuildLocks makes the per-hop locks for a route of the given length.
//
// Built from the EXIT backwards, accumulating blindings, so each upstream lock
// contains every downstream one's scalar. That ordering is what makes unwinding
// possible in the other direction.
func BuildLocks(c Curve, recipient Point, hops int) (*LockChain, error) {
	if hops <= 0 || hops > MaxHops {
		return nil, ErrTooManyLocks
	}
	n := c.Params().N
	chain := &LockChain{
		Locks:     make([]Point, hops),
		blindings: make([]*big.Int, hops),
	}

	// accumulated is the sum of blindings from this hop to the exit.
	accumulated := big.NewInt(0)
	for i := hops - 1; i >= 0; i-- {
		b, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		if b.Sign() == 0 {
			b.SetInt64(1)
		}
		chain.blindings[i] = b
		accumulated = new(big.Int).Mod(new(big.Int).Add(accumulated, b), n)

		bx, by := c.ScalarBaseMult(accumulated.Bytes())
		x, y := c.Add(recipient.X, recipient.Y, bx, by)
		chain.Locks[i] = Point{X: x, Y: y}
	}
	return chain, nil
}

// BlindingFor returns the scalar hop i adds when unwinding.
//
// A hop is given ONLY its own scalar. Handing a hop the full set would let it
// compute every other hop's lock and recognise the payment elsewhere on the
// path — the shared-hash problem reintroduced through the unwinding path.
func (l *LockChain) BlindingFor(hop int) (*big.Int, error) {
	if hop < 0 || hop >= len(l.blindings) {
		return nil, ErrBadScalar
	}
	return new(big.Int).Set(l.blindings[hop]), nil
}

// Unwind computes the scalar that satisfies hop i's lock, given the scalar that
// satisfied hop i+1's (or z itself at the exit).
//
// This is the whole atomicity argument in one function: a hop cannot produce
// the value its own lock needs until it has been given the downstream one, so
// it cannot claim its incoming payment without having released the outgoing.
func Unwind(c Curve, downstream *big.Int, blinding *big.Int) *big.Int {
	n := c.Params().N
	return new(big.Int).Mod(new(big.Int).Add(downstream, blinding), n)
}

// Satisfies checks a revealed scalar against a lock.
func Satisfies(c Curve, lock Point, scalar *big.Int) error {
	if scalar == nil || scalar.Sign() < 0 || scalar.Cmp(c.Params().N) >= 0 {
		return ErrBadScalar
	}
	x, y := c.ScalarBaseMult(scalar.Bytes())
	if !(Point{X: x, Y: y}).Equal(lock) {
		return ErrPointMismatch
	}
	return nil
}

// SettleRoute runs the full unwind from the recipient's secret back to the
// entry, returning the scalar each hop uses.
//
// Provided as one function so the ordering cannot be got wrong by a caller:
// unwinding in the other direction would let an upstream hop settle before the
// downstream one, which is precisely the failure atomicity exists to prevent.
func SettleRoute(c Curve, chain *LockChain, z *big.Int) ([]*big.Int, error) {
	if chain == nil || len(chain.Locks) == 0 {
		return nil, ErrTooManyLocks
	}
	scalars := make([]*big.Int, len(chain.Locks))
	current := new(big.Int).Set(z)
	for i := len(chain.Locks) - 1; i >= 0; i-- {
		current = Unwind(c, current, chain.blindings[i])
		scalars[i] = new(big.Int).Set(current)
	}
	return scalars, nil
}
