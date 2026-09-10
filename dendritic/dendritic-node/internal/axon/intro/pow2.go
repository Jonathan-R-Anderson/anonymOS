package intro

import "math"

// pow2q is 2^x rounded to the nearest integer, saturating at uint64.
//
// Separated so the quarter-bit encoding has exactly one implementation and the
// round-trip test has something to pin.
func pow2q(x float64) uint64 {
	v := math.Exp2(x)
	if v >= math.MaxUint64 {
		return math.MaxUint64
	}
	return uint64(v + 0.5)
}
