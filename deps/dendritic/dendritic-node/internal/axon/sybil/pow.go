package sybil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Admission proof of work for the CHEAP roles.
//
// WHAT IT IS FOR, AND WHAT IT IS NOT FOR. A bond gates the consequential roles
// — relay, storage, DHT, exit — and a bond is the right gate there, because the
// stake is slashable and the cost is ongoing. It is the wrong gate for a role
// that costs nothing to offer and little to abuse, because a capital
// requirement on a cheap role excludes exactly the volunteers §25(c) warns
// about while barely inconveniencing a funded adversary.
//
// So the cheap roles pay in work instead. Work is a worse anti-Sybil primitive
// than stake in every respect but one: it needs no chain, no token, no price,
// and no deployment, so it is available NOW while every contract in this repo
// is still undeployed.
//
// T14.5 REQUIRES THE COST BE MEASURED, NOT ASSUMED. An unmeasured difficulty is
// an unknown exclusion: it might cost a Raspberry Pi a second or an hour, and
// those are different policies. Measure() is that measurement and the package's
// tests record its result.

var (
	// ErrPoWTooEasy means the solution did not meet the required difficulty.
	ErrPoWTooEasy = errors.New("axon/sybil: proof of work below the required difficulty")
	// ErrPoWStale means the challenge is outside its validity window. A puzzle
	// without an expiry is a puzzle solved once and replayed for ever.
	ErrPoWStale = errors.New("axon/sybil: proof of work challenge is stale")
	// ErrPoWWrongSubject means the solution was computed for another node. It is
	// the check that stops one solved puzzle admitting a fleet.
	ErrPoWWrongSubject = errors.New("axon/sybil: proof of work is bound to a different subject")
)

// Challenge is an admission puzzle.
type Challenge struct {
	// Seed is the verifier's randomness. It must be unpredictable to the
	// solver before issue, or the work can be done in advance.
	Seed [32]byte
	// Subject binds the puzzle to one identity — a NodeIdentity, an auth key,
	// whatever the caller is admitting. Without it the puzzle is a bearer token
	// and one solution admits everybody who copies it.
	Subject []byte
	// Bits is the required difficulty in leading zero bits.
	Bits uint8
	// IssuedAt and TTL bound replay.
	IssuedAt time.Time
	TTL      time.Duration
}

// NewChallenge issues a puzzle at the standard difficulty.
func NewChallenge(subject []byte, now time.Time) (Challenge, error) {
	c := Challenge{
		Subject:  append([]byte(nil), subject...),
		Bits:     params.AdmissionPoWBits,
		IssuedAt: now,
		TTL:      5 * time.Minute,
	}
	if _, err := rand.Read(c.Seed[:]); err != nil {
		return Challenge{}, err
	}
	return c, nil
}

// digest is the hashed statement. Every field the verifier cares about is
// inside it, so none of them can be changed after the fact.
func (c Challenge) digest(nonce uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("axon-admission-pow-v1"))
	h.Write(c.Seed[:])
	h.Write([]byte{c.Bits})
	// The subject is length-prefixed. Concatenating it raw would let two
	// different (subject, nonce) pairs hash identically -- the classic
	// unambiguous-encoding failure, and here it would let one solution admit
	// two identities.
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(c.Subject)))
	h.Write(n[:])
	h.Write(c.Subject)
	binary.BigEndian.PutUint64(n[:], nonce)
	h.Write(n[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// leadingZeros counts leading zero bits of a digest.
func leadingZeros(d [32]byte) int {
	n := 0
	for _, b := range d {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}

// Solve finds a nonce meeting the difficulty. It is the client's cost.
//
// maxTries bounds the search so a caller cannot be wedged by a difficulty it
// cannot meet; zero means unbounded.
func (c Challenge) Solve(maxTries uint64) (uint64, bool) {
	for nonce := uint64(0); maxTries == 0 || nonce < maxTries; nonce++ {
		if leadingZeros(c.digest(nonce)) >= int(c.Bits) {
			return nonce, true
		}
	}
	return 0, false
}

// Verify checks a solution. It is the verifier's cost: one hash.
//
// The asymmetry is the whole mechanism, and it is why the subject and the
// expiry are checked BEFORE the hash: a verifier that hashes first does a unit
// of work for every junk submission, and an attacker who sends junk is then
// buying verifier CPU at no cost to itself.
func (c Challenge) Verify(subject []byte, nonce uint64, now time.Time) error {
	if len(subject) != len(c.Subject) {
		return ErrPoWWrongSubject
	}
	for i := range subject {
		if subject[i] != c.Subject[i] {
			return ErrPoWWrongSubject
		}
	}
	if now.Before(c.IssuedAt) || now.Sub(c.IssuedAt) > c.TTL {
		return ErrPoWStale
	}
	if leadingZeros(c.digest(nonce)) < int(c.Bits) {
		return ErrPoWTooEasy
	}
	return nil
}

// Measurement is what T14.5 asks to be recorded.
type Measurement struct {
	Bits     uint8
	Attempts uint64
	Elapsed  time.Duration
	// HashesPerSecond on the measuring machine. It is the number that makes the
	// result transferable: a reader with a slower machine can scale it.
	HashesPerSecond float64
	// Expected is 2^Bits, the mean attempts for the difficulty. Reporting it
	// beside Attempts is what turns one sample into a sanity check -- a run
	// far from the mean is a bug in the difficulty test, not luck.
	Expected float64
}

// MeasurePoW solves one puzzle and reports the cost.
//
// It is deliberately a real solve rather than a rate extrapolation. The
// quantity T14.5 wants is "what does this cost the machine that has to do it",
// and a hash-rate benchmark multiplied by 2^bits assumes the loop it is
// measuring is the loop that runs.
func MeasurePoW(bitsRequired uint8, subject []byte, now time.Time) (Measurement, error) {
	c, err := NewChallenge(subject, now)
	if err != nil {
		return Measurement{}, err
	}
	c.Bits = bitsRequired

	start := time.Now()
	var attempts uint64
	for nonce := uint64(0); ; nonce++ {
		attempts++
		if leadingZeros(c.digest(nonce)) >= int(bitsRequired) {
			break
		}
	}
	elapsed := time.Since(start)
	return Measurement{
		Bits:            bitsRequired,
		Attempts:        attempts,
		Elapsed:         elapsed,
		HashesPerSecond: float64(attempts) / elapsed.Seconds(),
		Expected:        float64(uint64(1) << bitsRequired),
	}, nil
}
