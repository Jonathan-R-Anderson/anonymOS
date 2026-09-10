// Package token is P15's relay-payment token: the lifecycle, the spent-set, and
// the batching that carries the privacy property.
//
// WHAT THIS PACKAGE IS FOR, AND THE ONE THING IT DELIBERATELY DOES NOT DO.
//
// §14.3 marks the CONSTRUCTION as [NEEDS RESEARCH] between two standard
// families — Chaum-style blind RSA and a Privacy-Pass-style VOPRF — and says
// "the construction is not new and must not be invented here". That instruction
// is followed: the signature primitive sits behind the Issuer interface, and
// `blindrsa.go` is a MEASUREMENT VEHICLE for settling the choice, not a
// production signer. What production must use is stated there.
//
// What this package does build is everything the choice does not touch: the
// token's shape (T1), offline verification at the relay (T2), double-spend at
// redemption rather than at spend (T3), batched and delayed redemption (T4),
// and the minimum age that stops purchase and spend from being the same moment.
//
// THE PROPERTY, STATED SO IT CANNOT BE OVERCLAIMED (§14.3's own words):
//
//	Given a token presented at a relay, the issuer -- colluding with that relay
//	-- can narrow the payer to the set of payers who were issued a token of that
//	denomination under that issuer key epoch and whose token has not yet been
//	redeemed. Within that set, the blind signature gives no information at all.
//	That is the entire guarantee.
//
// And the arithmetic that bounds it: with P payers each buying B tokens per
// epoch, the anonymity set is at most P·B, and THE DOMINANT TERM IS P. A
// network with 50 paying clients cannot be rescued by a clever token; the set
// is 50. That is why §14.7 puts payments outside v1, and why E15.1 -- the
// network runs with this subsystem disabled -- is the criterion that matters
// most here.
package token

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Denomination is a token's face value.
//
// T1: a token is ONE denomination from ONE issuer key epoch. Mixed
// denominations partition the anonymity set — a rare denomination is an
// identifier — so a relay refuses any denomination it does not know, rather
// than accepting it as a curiosity worth something.
type Denomination uint32

// Denominations are the only values that exist. The set is small and fixed for
// the same reason: every additional denomination halves nothing and splits the
// set.
const (
	Denom1   Denomination = 1
	Denom10  Denomination = 10
	Denom100 Denomination = 100
)

// KnownDenomination reports whether a relay should accept the value at all.
func KnownDenomination(d Denomination) bool {
	return d == Denom1 || d == Denom10 || d == Denom100
}

// Epoch is an issuer key epoch. A token is bound to one.
type Epoch uint32

var (
	// ErrUnknownDenomination is T1's refusal.
	ErrUnknownDenomination = errors.New("axon/token: unknown denomination")
	// ErrBadSignature means the token does not verify under the issuer key.
	ErrBadSignature = errors.New("axon/token: token signature does not verify")
	// ErrUnknownEpoch means the relay holds no verification key for the token's
	// epoch. It is refused rather than deferred to a lookup: T2 forbids a
	// network call on the verification path.
	ErrUnknownEpoch = errors.New("axon/token: no verification key for this epoch")
	// ErrDoubleSpend is raised at REDEMPTION, not at spend (T3).
	ErrDoubleSpend = errors.New("axon/token: token already redeemed")
	// ErrTooYoung means the token was spent before its minimum age. Buying and
	// spending within minutes lets an issuer who is also a relay intersect two
	// small windows, which is the correlation the blinding was for.
	ErrTooYoung = errors.New("axon/token: token spent before its minimum age")
	// ErrBatchTooSmall means a redemption batch is below the floor. A batch of
	// one is a redemption event with a timestamp, which is the timing link T4
	// exists to remove.
	ErrBatchTooSmall = errors.New("axon/token: redemption batch below the minimum size")
)

// Nonce is the token's unique identifier, chosen by the payer before blinding.
// The issuer never sees it at issuance and sees it only at redemption.
type Nonce [32]byte

// Token is what rides in a cell and what a relay keeps.
type Token struct {
	Epoch Epoch
	Denom Denomination
	Nonce Nonce
	// Sig is the unblinded issuer signature over the nonce. Its size depends on
	// the construction; see blindrsa.go and the size measurement in the tests.
	Sig []byte
}

// message is what the issuer signs: the nonce bound to its epoch and
// denomination.
//
// Binding all three is what stops a token issued as a Denom1 being presented as
// a Denom100. Signing the nonce alone would leave denomination and epoch as
// unauthenticated fields a payer could rewrite.
func (t Token) message() []byte {
	var b [4 + 4 + 32]byte
	binary.BigEndian.PutUint32(b[0:4], uint32(t.Epoch))
	binary.BigEndian.PutUint32(b[4:8], uint32(t.Denom))
	copy(b[8:], t.Nonce[:])
	h := sha256.Sum256(append([]byte("axon-token-v1"), b[:]...))
	return h[:]
}

// Verifier checks a token offline. This is T2.
//
// THE INTERFACE IS THE RULING. T2 says the relay verifies "with no network
// call, or the verification path becomes the correlation path" — a relay that
// phoned the issuer on every cell would tell the issuer, in real time, which
// relay is carrying whose traffic, which is worse than not paying at all.
//
// So Verify takes no context and returns no error that could mean "ask again
// later". A construction whose verification needs the issuer's secret cannot
// implement this interface for a relay, and that is the whole of §14.3's T2
// objection to a pure VOPRF, expressed as a type.
type Verifier interface {
	// Verify reports whether the signature is the issuer's, for this epoch.
	Verify(epoch Epoch, msg, sig []byte) bool
	// KnownEpoch reports whether a verification key is held locally.
	KnownEpoch(epoch Epoch) bool
	// SigSize is the signature length in bytes, for the payload arithmetic.
	SigSize() int
}

// Issuer blind-signs. It is separate from Verifier because the two run in
// different places and, in a VOPRF, would need different secrets.
type Issuer interface {
	// SignBlinded signs a blinded message. The issuer learns nothing about the
	// token it is signing beyond its epoch and denomination.
	SignBlinded(epoch Epoch, blinded []byte) ([]byte, error)
	// PublicVerifier is the verifier a relay can hold. A construction that
	// cannot produce one fails T2.
	PublicVerifier() Verifier
}

// ---------------------------------------------------------------------------
// Relay side: accept a token, offline
// ---------------------------------------------------------------------------

// Accept is what a relay does when a token arrives with a cell.
//
// It is deliberately total and fast: three checks and one signature
// verification, no state, no I/O. A relay that accepts a token has NOT been
// paid yet — it has been given something it can redeem later, and T3 puts the
// double-spend check at redemption precisely so that this path stays local.
func Accept(t Token, v Verifier) error {
	if !KnownDenomination(t.Denom) {
		return fmt.Errorf("%w: %d", ErrUnknownDenomination, t.Denom)
	}
	if !v.KnownEpoch(t.Epoch) {
		return fmt.Errorf("%w: %d", ErrUnknownEpoch, t.Epoch)
	}
	if !v.Verify(t.Epoch, t.message(), t.Sig) {
		return ErrBadSignature
	}
	return nil
}

// ---------------------------------------------------------------------------
// Issuer side: the spent set and batched redemption (T3, T4)
// ---------------------------------------------------------------------------

// Policy is the redemption policy. Every field here is a PRIVACY parameter, not
// a performance one, which is why T15.5 pins the window by test.
type Policy struct {
	// MinAge is how long a token must be held before it may be spent. It is the
	// defence against purchase-time/spend-time intersection.
	//
	// PROVISIONAL. Derivation: the anonymity set for a spend is everyone who
	// bought within MinAge of the same moment, so the correct value is a
	// function of the purchase RATE, which is unknown because there are no
	// payers. At low volume no value rescues it -- see the package doc.
	MinAge time.Duration
	// BatchDelay is how long a relay holds spent tokens before redeeming.
	//
	// PROVISIONAL, same reasoning. §14.3's T4: immediate redemption
	// reconstructs the timing link the blinding removed.
	BatchDelay time.Duration
	// MinBatch is the smallest batch a relay may submit. A batch of one is a
	// timestamped redemption of a single token.
	//
	// PROVISIONAL. Derivation: it must exceed 1, and beyond that it trades the
	// relay's cash flow against the batch's anonymity set. An operator who
	// wants to be paid quickly is asking to be linked, and §14.3 says so.
	MinBatch int
}

// DefaultPolicy is the starting point. Every value is provisional; see Policy.
func DefaultPolicy() Policy {
	return Policy{MinAge: 30 * time.Minute, BatchDelay: 1 * time.Hour, MinBatch: 16}
}

// SpentSet is the issuer's double-spend record.
type SpentSet struct {
	mu    sync.Mutex
	spent map[Nonce]time.Time
}

// NewSpentSet builds an empty set.
func NewSpentSet() *SpentSet { return &SpentSet{spent: map[Nonce]time.Time{}} }

// Len is the number of redeemed tokens.
func (s *SpentSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.spent)
}

// Batch is one relay's redemption submission.
type Batch struct {
	// RelayID is the node being credited. It is identified — redemption is the
	// identified half of the protocol and always was.
	RelayID string
	Tokens  []Token
	// SpentAt is when each token was accepted, parallel to Tokens. It is the
	// relay's own record; the issuer uses it only for the minimum-age check and
	// cannot verify it, which is stated in Redeem.
	SpentAt []time.Time
}

// Credit is what a redemption is worth.
type Credit struct {
	RelayID string
	// Value is the summed denomination of the accepted tokens.
	Value uint64
	// Accepted and Rejected count the outcome per token.
	Accepted int
	Rejected int
	// Reasons counts why tokens were rejected, so an operator can tell a
	// double-spend from a stale key without a per-token log that would itself
	// be a linkability surface.
	Reasons map[string]int
}

// Redeem processes one batch. This is where double-spend is caught (T3).
//
// WHAT THE ISSUER CAN AND CANNOT CHECK. It can check the signature, the
// denomination, the epoch and the spent set — all facts it holds. It CANNOT
// verify SpentAt: the relay reports when it accepted a token and could report
// anything. The minimum-age check is therefore a check on the RELAY's honesty
// about its own timing, and a relay that lies about it hurts the payer's
// privacy, not its own revenue. That asymmetry is why MinAge is also enforced
// client-side, at spend time, where the party with the incentive is the one
// doing the checking.
func Redeem(b Batch, v Verifier, spent *SpentSet, pol Policy, now time.Time) (Credit, error) {
	c := Credit{RelayID: b.RelayID, Reasons: map[string]int{}}
	if len(b.Tokens) < pol.MinBatch {
		return c, fmt.Errorf("%w: %d < %d", ErrBatchTooSmall, len(b.Tokens), pol.MinBatch)
	}
	if len(b.SpentAt) != len(b.Tokens) {
		return c, errors.New("axon/token: batch timing record does not match its tokens")
	}

	spent.mu.Lock()
	defer spent.mu.Unlock()

	for _, t := range b.Tokens {
		switch {
		case !KnownDenomination(t.Denom):
			c.Rejected++
			c.Reasons["unknown-denomination"]++
			continue
		case !v.KnownEpoch(t.Epoch):
			c.Rejected++
			c.Reasons["unknown-epoch"]++
			continue
		case !v.Verify(t.Epoch, t.message(), t.Sig):
			c.Rejected++
			c.Reasons["bad-signature"]++
			continue
		}
		if _, ok := spent.spent[t.Nonce]; ok {
			// T3. The relay's exposure is bounded by its redemption interval,
			// not by zero: it already forwarded the traffic. Redeeming often
			// prices that risk down; redeeming immediately costs privacy.
			c.Rejected++
			c.Reasons["double-spend"]++
			continue
		}
		spent.spent[t.Nonce] = now
		c.Accepted++
		c.Value += uint64(t.Denom)
	}
	return c, nil
}

// SpendableAt reports the earliest instant a token bought at `issuedAt` may be
// spent, and is the client-side half of the minimum-age rule.
//
// It is on the client because the client is the party whose privacy the rule
// protects. Enforcing it only at the issuer would leave the payer free to
// destroy its own anonymity and never learn it had.
func SpendableAt(issuedAt time.Time, pol Policy) time.Time {
	return issuedAt.Add(pol.MinAge)
}

// CheckSpendable is the client's pre-spend check.
func CheckSpendable(issuedAt, now time.Time, pol Policy) error {
	if now.Before(SpendableAt(issuedAt, pol)) {
		return fmt.Errorf("%w: held %v, need %v", ErrTooYoung, now.Sub(issuedAt), pol.MinAge)
	}
	return nil
}

// ConstantTimeNonceEqual compares nonces without a timing signal.
//
// It exists because a spent-set lookup that short-circuits on the first
// differing byte is a timing oracle for "is this nonce nearly one you hold",
// and the map lookup above is already constant-ish only by accident of hashing.
// Used by callers that compare nonces directly.
func ConstantTimeNonceEqual(a, b Nonce) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
