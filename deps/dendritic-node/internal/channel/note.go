package channel

// The private payment note: a bearer claim on value that names nobody.
//
// WHAT IS AND IS NOT DECIDED HERE
// -------------------------------
// The derivations in this file — nullifiers, owner commitments, recipient key
// hints — are hashes, and a hash is a hash whatever proving system is chosen
// later. They are correct now and will not change.
//
// The VALUE commitment is different, and the difference matters enough to be
// the first thing said. The circuit proves value is conserved by ADDING
// commitments together without opening them, which requires a homomorphic
// scheme (Pedersen over an elliptic curve). That scheme has to be the one the
// circuit uses, so it cannot be picked before the proving system is — and
// picking it here would mean either rewriting every note when the real choice
// happens, or quietly constraining the choice to whatever this file guessed.
//
// So `HashCommitment` below is a BINDING, HIDING, NON-HOMOMORPHIC placeholder.
// It is honest about what it cannot do: `IsHomomorphic()` returns false, and
// the balance check refuses to run on it rather than appearing to succeed. A
// commitment scheme that silently failed to add would produce proofs that
// verify and books that do not balance, which is the worst failure available
// in a payment system.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

// Note version. Bumped when the encoding or the circuit changes; a note and the
// circuit that spends it must agree, and a version field is how an upgrade
// avoids invalidating notes already in flight.
const NoteVersion uint16 = 1

// Derivation domains. Every hash in this package is domain-separated so a value
// recovered in one role is useless in another — without this, a nullifier seed
// and an encryption key derived from the same secret would be the same bytes,
// and learning one would hand over the other.
const (
	domainNullifier = "syndichan/note/nullifier/v1"
	domainOwner     = "syndichan/note/owner/v1"
	domainKeyHint   = "syndichan/note/keyhint/v1"
	domainValue     = "syndichan/note/value/v1"
	domainContext   = "syndichan/note/context/v1"
	domainRoute     = "syndichan/note/route/v1"
)

var (
	ErrNoteExpired    = errors.New("channel: note has expired")
	ErrNoteVersion    = errors.New("channel: unsupported note version")
	ErrNoteMalformed  = errors.New("channel: note is malformed")
	ErrNotHomomorphic = errors.New("channel: commitment scheme cannot prove balance by addition")
)

// PrivatePaymentNote is the wire form. Everything identifying is a commitment;
// everything else is encrypted to the recipient.
type PrivatePaymentNote struct {
	Version uint16

	// AssetID is an asset COMMITMENT, not a token address. A raw address would
	// partition the anonymity set by token.
	AssetID [32]byte

	// ValueCommitment hides the amount while binding to it.
	ValueCommitment [32]byte

	// OwnerCommitment binds the note to a spending key without naming it.
	OwnerCommitment [32]byte

	// RecipientKeyHint lets the intended recipient trial-decrypt cheaply.
	// Derived per note from the shared secret, so two notes to the same
	// recipient share no hint — a stable hint would be an identifier.
	RecipientKeyHint [32]byte

	// NullifierSeed is the PRIVATE half of the double-spend tag. The published
	// nullifier needs this AND the spending key, so holding a note does not let
	// an observer compute its nullifier and watch for the spend.
	NullifierSeed [32]byte

	// RouteCommitment binds the note to the route it may travel, so a captured
	// note cannot be replayed down an attacker-chosen path.
	RouteCommitment [32]byte

	// ContextCommitment binds the payment to its purpose — this stream, this
	// invoice, this job — without naming it. The recipient can open it; a
	// router sees 32 opaque bytes. This is what lets a service receipt refer to
	// a payment without publishing what was bought.
	ContextCommitment [32]byte

	CreatedAt uint64
	// ExpiresAt bounds the claim. Without it a note is a permanent liability
	// and an unresponsive recipient holds one forever.
	ExpiresAt uint64

	// Nonce makes otherwise-identical notes distinct, so two equal tips from
	// the same payer to the same recipient are not byte-identical.
	Nonce [32]byte

	// Ciphertext carries what only the recipient may read: the true value, the
	// blindings, the context opening, any memo. Padded to a fixed size so its
	// length says nothing.
	Ciphertext []byte
}

// derive is the one hashing primitive, so every derivation in this package is
// domain-separated by construction rather than by remembering to do it.
func derive(domain string, parts ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, []byte(domain))
	for _, p := range parts {
		// Length-prefixed, so derive("a","bc") and derive("ab","c") cannot
		// collide. Concatenating without lengths is the classic way two
		// different inputs hash to the same value.
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		mac.Write(n[:])
		mac.Write(p)
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Nullifier derives the public double-spend tag.
//
// Requires the spending key. That is the whole design: the note carries the
// seed, so a recipient can compute their own nullifier, but an observer holding
// a stolen or forwarded note cannot — which is what stops the nullifier set
// from becoming a public index of which notes have been spent by whom.
func (n PrivatePaymentNote) Nullifier(spendingKey [32]byte) Nullifier {
	return Nullifier(derive(domainNullifier, n.NullifierSeed[:], spendingKey[:]))
}

// OwnerCommitmentFor binds a note to a spending key.
func OwnerCommitmentFor(spendingKey [32]byte, nonce [32]byte) [32]byte {
	return derive(domainOwner, spendingKey[:], nonce[:])
}

// KeyHintFor derives the per-note trial-decryption hint.
//
// Takes the ephemeral shared secret AND the nonce, so the hint differs for
// every note even to the same recipient. A hint derived from the recipient's
// long-term key alone would be a stable identifier printed on every note they
// ever receive.
func KeyHintFor(sharedSecret [32]byte, nonce [32]byte) [32]byte {
	return derive(domainKeyHint, sharedSecret[:], nonce[:])
}

// ContextCommitmentFor binds a payment to its purpose without naming it.
func ContextCommitmentFor(purpose string, opening [32]byte) [32]byte {
	return derive(domainContext, []byte(purpose), opening[:])
}

// RouteCommitmentFor binds a note to one route.
func RouteCommitmentFor(secrets [][32]byte) [32]byte {
	parts := make([][]byte, 0, len(secrets))
	for i := range secrets {
		parts = append(parts, secrets[i][:])
	}
	return derive(domainRoute, parts...)
}

// CommitmentScheme is how values are hidden. An interface because the real one
// is decided by the proving system (see the file comment).
type CommitmentScheme interface {
	Commit(value uint64, blinding [32]byte) Commitment
	// IsHomomorphic reports whether commitments may be ADDED to check that
	// inputs balance outputs. False means the balance check must come from
	// inside the circuit and this scheme cannot stand in for it.
	IsHomomorphic() bool
	Name() string
}

// HashCommitment is the placeholder: binding and hiding, not homomorphic.
//
// Usable for everything that does not need addition — which is most of the
// system today — and explicitly unusable for the conservation-of-value check.
type HashCommitment struct{}

func (HashCommitment) Commit(value uint64, blinding [32]byte) Commitment {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], value)
	return Commitment(derive(domainValue, v[:], blinding[:]))
}
func (HashCommitment) IsHomomorphic() bool { return false }
func (HashCommitment) Name() string        { return "hash-sha256-placeholder" }

var _ CommitmentScheme = HashCommitment{}

// CheckBalance verifies that inputs equal outputs plus fees, by commitment
// arithmetic.
//
// Refuses outright on a non-homomorphic scheme rather than returning a
// misleading answer. A silent failure here would mean proofs that verify while
// the books do not balance — value created from nothing, undetectably.
func CheckBalance(s CommitmentScheme, inputs, outputs []Commitment, fee Commitment) error {
	if s == nil {
		return ErrNotHomomorphic
	}
	if !s.IsHomomorphic() {
		return ErrNotHomomorphic
	}
	// A homomorphic implementation fills this in. Deliberately left as a
	// refusal rather than a plausible-looking stub: a stub that returned nil
	// would read as "balance checked" everywhere it is called.
	return errors.New("channel: homomorphic balance check not implemented for " + s.Name())
}

// Validate checks a note without opening it.
//
// Everything here is checkable by a router that cannot decrypt anything, which
// is the point: a malformed or expired note is rejected at the first hop rather
// than travelling three hops to be refused at the end.
func (n PrivatePaymentNote) Validate(now time.Time) error {
	if n.Version != NoteVersion {
		return ErrNoteVersion
	}
	if n.ExpiresAt == 0 || n.CreatedAt == 0 {
		return ErrNoteMalformed
	}
	if n.ExpiresAt <= n.CreatedAt {
		return ErrNoteMalformed
	}
	if n.Nonce == ([32]byte{}) {
		// An all-zero nonce means two identical payments produce identical
		// notes, which is a correlation handle rather than a cosmetic flaw.
		return ErrNoteMalformed
	}
	if uint64(now.Unix()) >= n.ExpiresAt {
		return ErrNoteExpired
	}
	return nil
}

// Expired is the cheap check a router repeats at every hop.
func (n PrivatePaymentNote) Expired(now time.Time) bool {
	return uint64(now.Unix()) >= n.ExpiresAt
}
