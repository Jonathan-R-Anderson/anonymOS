// Package intro is P6a: proof-of-work admission for services (PAR-16, R10).
//
// §7.1's IntroPointRecord has carried `pow_seed` and `pow_difficulty` since it
// was written, and the record exists SEPARATELY FROM THE DESCRIPTOR precisely so
// difficulty can move faster than a 3 h descriptor lifetime. The fields were
// designed for this mechanism and the mechanism did not exist. This is it.
//
// WHAT IS BUILT AND WHAT IS NOT
// -----------------------------
// §9.6 fixes the INTERFACE as `[BUILD NOW]` and marks the PARAMETERS
// `[NEEDS RESEARCH]`, because "Equihash (n,k) selection has a history of
// parameter breaks and this document must not pick numbers it cannot defend".
// That split is honoured exactly: the challenge construction, the effort dial,
// seed rotation, the difficulty controller and the admission queue are built and
// tested. NO MEMORY-HARD SCHEME IS CHOSEN, and none is registered by default.
//
// A package that shipped hashcash as the default would satisfy every test here
// and would be the failure §9.6 names: plain hashcash over a fast hash hands a
// GPU or ASIC adversary a two-to-three order-of-magnitude advantage over a
// phone, "converting the puzzle into targeted exclusion of exactly the users who
// most need the service". So the reference scheme reports MemoryHard() false and
// an IntroPoint REFUSES to use a non-memory-hard scheme unless the caller passes
// AllowNonMemoryHardScheme, which exists to be greppable.
//
// THREE CONFLICTS BETWEEN §9.6 AND §23.6, RESOLVED
// ------------------------------------------------
//
//  1. WHO SETS DIFFICULTY. §23.6: "the intro point publishes a seed and a
//     difficulty". §9.6: "The service, not the intro point, sets effort -- only
//     the service knows whether it is overloaded. The IP reports load; the
//     service decides." §9.6 WINS, and its reason is the argument: the intro
//     point sees introductions, but only the service sees whether they are
//     turning into work it cannot do. An intro point that set its own difficulty
//     would raise it under a flood the service was absorbing fine, and leave it
//     low under one it was not.
//
//  2. THE CONTROLLER. §23.6: "DifficultyStep +/-1 bit per 10 s, asymmetric: rise
//     fast, fall slow". THAT PARAMETER CONTRADICTS ITS OWN RATIONALE -- +/-1 bit
//     is x2 up and /2 down, symmetric in log space, so it falls exactly as fast
//     as it rises and an attacker can pulse the load exactly as §23.6 warns.
//     §9.6's multiplicative controller (x1.5+1 up, x0.75 down) IS asymmetric
//     (+0.58 vs -0.42 bits), so it is what §23.6 meant. §9.6 wins.
//
//  3. THE QUEUE THRESHOLD. §23.6: depth > 50 pending introductions. §9.6:
//     q_target = 6 on the INTRODUCE2 queue. These are different queues at
//     different hops and both can hold, but only one of them drives the
//     controller. Per (1) that is the service's, so q_target = 6 is the one used.
package intro

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Scheme is the memory-hard proof of work itself.
//
// It is an INTERFACE AND NOT A CHOICE. §9.6 requires, in priority order:
// (1) verification orders of magnitude cheaper than solving -- which rules out
// Argon2id and every symmetric memory-hard KDF, since they cost the verifier
// exactly what they cost the solver; (2) memory-hard solving; (3) runtime-
// adjustable parameters. Equihash-style schemes satisfy all three. Which one,
// with which parameters, is `[NEEDS RESEARCH]` and is not decided here.
type Scheme interface {
	// Name identifies the scheme on the wire.
	Name() string
	// Solve produces a proof over challenge.
	Solve(challenge []byte) ([]byte, error)
	// Verify checks a proof. It must be orders of magnitude cheaper than Solve.
	Verify(challenge, proof []byte) bool
	// MemoryHard reports whether solving is memory-bound. A scheme returning
	// false is a test fixture, not a deployment candidate.
	MemoryHard() bool
}

// Puzzle is what a client is asked to solve. §23.6's data structure.
type Puzzle struct {
	Seed [32]byte
	// Difficulty is the wire encoding of effort, in QUARTER BITS: the value
	// carried by IntroPointRecord.PoWDifficulty.
	//
	// WHY QUARTER BITS. The field is a uint8 and this is its first definition,
	// since the mechanism has never existed. Whole bits would be the obvious
	// reading and it is too coarse: the smallest representable change would be a
	// DOUBLING, which quantises §9.6's x1.5 rise and x0.75 fall to the same
	// single step and destroys the asymmetry that conflict (2) above exists to
	// preserve. Quarter bits give ~19 % granularity -- finer than the smallest
	// step the controller takes -- and still reach effort 2^63 inside a uint8.
	Difficulty uint8
	// Expires is when the seed rotates; §7.1's republish interval, 10 min.
	Expires int64
	// SchemeName is which Scheme the solution must be for.
	SchemeName string
}

// Solution is a client's answer. §23.6's data structure.
type Solution struct {
	Nonce uint32
	Proof []byte
	// Effort is the LINEAR effort the client claims to have hit. It is a claim,
	// checked by Verify -- never trusted for ordering before that.
	Effort uint64
}

var (
	ErrNoScheme      = errors.New("axon/intro: no proof-of-work scheme is configured; §9.6 leaves the scheme [NEEDS RESEARCH] and this package refuses to invent one")
	ErrWrongScheme   = errors.New("axon/intro: solution is for a different scheme")
	ErrProofInvalid  = errors.New("axon/intro: proof does not verify")
	ErrEffortNotMet  = errors.New("axon/intro: proof verifies but does not meet the claimed effort")
	ErrEffortTooLow  = errors.New("axon/intro: claimed effort is below the current difficulty")
	ErrNotMemoryHard = errors.New("axon/intro: scheme is not memory-hard; a CPU-only puzzle excludes phones and favours the attacker's hardware (§9.6)")
	ErrSeedMismatch  = errors.New("axon/intro: solution is for a superseded seed")
)

// EffortOf converts the wire difficulty (quarter bits) to linear effort.
//
// effort = 2^(difficulty/4), rounded. Difficulty 0 means effort 1, which is
// PuzzleDifficultyMin: no puzzle at all. §23.6 is emphatic about why -- "a
// permanent puzzle taxes every honest user to defend against an attack that is
// not happening".
func EffortOf(difficulty uint8) uint64 {
	if difficulty == 0 {
		return 1
	}
	e := pow2q(float64(difficulty) / 4)
	if e < 1 {
		return 1
	}
	return e
}

// DifficultyFor is EffortOf's inverse: the smallest wire difficulty whose effort
// is at least `effort`. Rounding UP matters -- rounding down would publish a
// difficulty easier than the controller asked for, so a service under load would
// quietly admit more than it decided to.
func DifficultyFor(effort uint64) uint8 {
	if effort <= 1 {
		return 0
	}
	for d := 1; d <= 255; d++ {
		if EffortOf(uint8(d)) >= effort {
			return uint8(d)
		}
	}
	return 255
}

// Challenge is §9.6's construction, byte for byte:
//
//	challenge = SHA256("axon:pow:v1" ‖ pow_seed ‖ K_blind ‖ LE32(effort) ‖ nonce)
//
// Built by hand rather than by an encoder, for the reason every signed and
// hashed pre-image in this tree is: a hash over "whatever the encoder produced"
// is a hash over an encoder version, and a client and an intro point that
// disagree about it disagree silently.
//
// K_blind binds the challenge to the SERVICE, so a solution mined against one
// service is worthless against another. Effort is inside the challenge, so a
// client cannot solve once cheaply and then claim a high effort.
func Challenge(seed [32]byte, kBlind []byte, effort uint64, nonce uint32) []byte {
	h := sha256.New()
	h.Write([]byte("axon:pow:v1"))
	h.Write(seed[:])
	h.Write(kBlind)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(effort))
	h.Write(b[:])
	binary.LittleEndian.PutUint32(b[:], nonce)
	h.Write(b[:])
	return h.Sum(nil)
}

// two256 is 2^256, the numerator of §9.6's effort dial.
var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

// meetsEffort is §9.6's second condition:
//
//	SHA256("axon:pow:check:v1" ‖ challenge ‖ solution) < 2^256 / effort
//
// A CHEAP POST-FILTER ON AN ALREADY MEMORY-HARD SOLUTION. That is the whole
// design: effort scales linearly while the memory floor stays fixed, so the
// service can dial cost without renegotiating scheme parameters -- which is
// §9.6's requirement (3), runtime-adjustable, satisfied without touching (2).
func meetsEffort(challenge, proof []byte, effort uint64) bool {
	if effort <= 1 {
		return true
	}
	h := sha256.New()
	h.Write([]byte("axon:pow:check:v1"))
	h.Write(challenge)
	h.Write(proof)
	sum := h.Sum(nil)
	target := new(big.Int).Div(two256, new(big.Int).SetUint64(effort))
	return new(big.Int).SetBytes(sum).Cmp(target) < 0
}

// Verify checks a solution against a puzzle. §23.6's
// `(*IntroPoint).Verify(sol) (effort, err)`.
//
// IT DOES NO ASYMMETRIC CRYPTOGRAPHY (T6a.4) and it is not a method on anything
// holding a private key, so it cannot acquire any by accident. Both conditions
// are hash-only, which is what makes rejecting a flood cheap: an intro point
// that verified a signature before checking the puzzle would be doing the
// attacker's chosen work at the attacker's chosen rate.
func Verify(s Scheme, p Puzzle, kBlind []byte, sol Solution) (uint64, error) {
	if s == nil {
		return 0, ErrNoScheme
	}
	if p.SchemeName != "" && p.SchemeName != s.Name() {
		return 0, fmt.Errorf("%w: puzzle wants %q, have %q", ErrWrongScheme, p.SchemeName, s.Name())
	}
	need := EffortOf(p.Difficulty)
	if sol.Effort < need {
		return 0, fmt.Errorf("%w: claimed %d, need %d", ErrEffortTooLow, sol.Effort, need)
	}
	ch := Challenge(p.Seed, kBlind, sol.Effort, sol.Nonce)
	if !s.Verify(ch, sol.Proof) {
		return 0, ErrProofInvalid
	}
	if !meetsEffort(ch, sol.Proof, sol.Effort) {
		return 0, ErrEffortNotMet
	}
	return sol.Effort, nil
}
