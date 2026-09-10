package token

import (
	"errors"
	"time"
)

// The epoch key schedule (D5).
//
// WHAT IS DERIVED HERE AND WHAT IS NOT. The epoch LENGTH is a privacy parameter
// and this file does not pick it, for the reason stated at the top of token.go:
// with P payers each buying B tokens per epoch the anonymity set is at most P·B
// and the dominant term is P. A longer epoch raises P and is therefore strictly
// better for anonymity; the only thing pushing the other way is that one key
// covers more issuance, so a compromised key forges more. With the deployed
// population at zero paying clients, P = 0 AT EVERY LENGTH -- so no length can
// be derived from the requirement it exists to serve, and choosing one now
// would be picking a number to look finished.
//
// WHAT IS DERIVED IS THE SHAPE, and it is not a matter of taste:
//
//  1. EPOCHS MUST OVERLAP BY AT LEAST THE TOKEN LIFETIME. A token issued one
//     second before a rotation is spent under the old key, and an issuer that
//     stopped accepting the old key at the boundary would void it. Overlap is
//     what makes rotation invisible to a client that is not watching the clock.
//  2. THE OVERLAP IS THE PRIVACY COST OF ROTATION AND MUST BE BOUNDED. During
//     overlap two keys are live, so a spend narrows the payer to one of two
//     epochs rather than one -- which sounds like a gain and is not, because the
//     issuer knows which key signed. Long overlap simply keeps old keys usable,
//     widening the window in which a compromised key still forges.
//  3. AN EPOCH IN THE FUTURE IS REFUSED. Accepting one lets an issuer pre-sign
//     under a key nobody can yet have been issued under, which is a partition of
//     one: the only payer under that epoch is the one the issuer chose.
type Schedule struct {
	// Start is when epoch 0 began.
	Start time.Time
	// Length is one epoch. POLICY, not derived -- see above.
	Length time.Duration
	// Overlap is how long the previous epoch's key stays acceptable.
	Overlap time.Duration
	// TokenLifetime is the longest a token may sit unspent.
	TokenLifetime time.Duration
}

var (
	ErrOverlapTooShort = errors.New("axon/token: overlap is shorter than the token lifetime, so a token issued just before a rotation is voided by it")
	ErrEpochInFuture   = errors.New("axon/token: epoch is in the future; accepting one would let the issuer pre-sign under a key no other payer can hold (a partition of one)")
	ErrEpochRetired    = errors.New("axon/token: epoch is past its overlap and its key is no longer accepted")
	ErrBadSchedule     = errors.New("axon/token: schedule needs a positive length")
)

// Valid checks the schedule's internal consistency.
//
// The overlap-vs-lifetime rule is checked HERE rather than documented, because a
// schedule that violates it does not fail at configuration time -- it fails as
// occasional voided tokens at rotation boundaries, which reads as a flaky issuer
// rather than as a misconfiguration.
func (s Schedule) Valid() error {
	if s.Length <= 0 {
		return ErrBadSchedule
	}
	if s.Overlap < s.TokenLifetime {
		return ErrOverlapTooShort
	}
	return nil
}

// EpochAt is the epoch containing t.
func (s Schedule) EpochAt(t time.Time) (Epoch, error) {
	if err := s.Valid(); err != nil {
		return 0, err
	}
	if t.Before(s.Start) {
		return 0, ErrEpochInFuture
	}
	return Epoch(t.Sub(s.Start) / s.Length), nil
}

// Accepts reports whether a token signed under `e` may still be spent at time t.
//
// Returns a NAMED error rather than a bool, because "refused" has two causes
// that need opposite responses: a retired epoch means the client should get a
// fresh token, and a future epoch means the issuer is misbehaving.
func (s Schedule) Accepts(e Epoch, t time.Time) error {
	current, err := s.EpochAt(t)
	if err != nil {
		return err
	}
	if e > current {
		return ErrEpochInFuture
	}
	// The epoch ends at its own boundary, and its key stays acceptable for
	// Overlap beyond that.
	end := s.Start.Add(time.Duration(uint64(e)+1) * s.Length).Add(s.Overlap)
	if t.After(end) {
		return ErrEpochRetired
	}
	return nil
}

// AnonymitySetBound is P·B from token.go, made callable so a caller has to look
// at it rather than assume it.
//
// It exists because the honest answer to "how private is this" is a number that
// depends on the population, and a deployment with no payers gets zero from it
// however long the epoch is. Reporting that plainly is the point.
func AnonymitySetBound(payersInEpoch, tokensPerPayer int) int {
	if payersInEpoch <= 0 || tokensPerPayer <= 0 {
		return 0
	}
	return payersInEpoch * tokensPerPayer
}
