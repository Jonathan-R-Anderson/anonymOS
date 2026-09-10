package intro

import "crypto/sha256"

// ReferenceHashcash is a TEST FIXTURE. It is not a deployment candidate and it
// reports MemoryHard() false so that New refuses it without an explicit
// AllowNonMemoryHardScheme.
//
// It exists because the effort dial, the controller, the queue, seed rotation
// and the verification asymmetry are all testable WITHOUT settling §9.6's
// `[NEEDS RESEARCH]` scheme choice, and shipping them untested until that
// research lands would be worse than shipping them with a fixture.
//
// WHAT IT IS NOT: memory-hard. Solving is a SHA-256 preimage search, which is
// exactly what §9.6 rules out -- "plain hashcash over BLAKE3 satisfies (1) but
// hands a GPU or ASIC adversary a two-to-three order-of-magnitude advantage over
// a phone". Any measurement taken with this scheme establishes something about
// the DIAL, never about the puzzle's resistance to specialised hardware.
type ReferenceHashcash struct{}

func (ReferenceHashcash) Name() string { return "reference-hashcash-NOT-FOR-DEPLOYMENT" }

func (ReferenceHashcash) MemoryHard() bool { return false }

// Solve returns the trivial proof; all the cost lives in the effort dial, which
// is what these tests exercise.
func (ReferenceHashcash) Solve(challenge []byte) ([]byte, error) {
	sum := sha256.Sum256(challenge)
	return sum[:], nil
}

func (ReferenceHashcash) Verify(challenge, proof []byte) bool {
	sum := sha256.Sum256(challenge)
	if len(proof) != len(sum) {
		return false
	}
	for i := range sum {
		if sum[i] != proof[i] {
			return false
		}
	}
	return true
}
