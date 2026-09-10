package channel

import (
	"errors"
	"testing"
	"time"
)

var noteNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

func goodNote() PrivatePaymentNote {
	return PrivatePaymentNote{
		Version:   NoteVersion,
		Nonce:     [32]byte{1},
		CreatedAt: uint64(noteNow.Add(-time.Minute).Unix()),
		ExpiresAt: uint64(noteNow.Add(time.Hour).Unix()),
	}
}

// The core property: holding a note must NOT let you compute its nullifier.
// Otherwise the nullifier set becomes a public index of which notes have been
// spent, and by extension who spent them.
func TestNullifierRequiresTheSpendingKey(t *testing.T) {
	note := goodNote()
	note.NullifierSeed = [32]byte{9, 9, 9}

	owner := note.Nullifier([32]byte{1})
	thief := note.Nullifier([32]byte{2})
	if owner == thief {
		t.Fatal("the nullifier does not depend on the spending key")
	}
	// Same key, same note: stable, or the owner could not recognise their own
	// spend.
	if note.Nullifier([32]byte{1}) != owner {
		t.Error("nullifier derivation is not deterministic")
	}
}

// Two different notes under the same key must produce different nullifiers, or
// spending one would appear to spend the other.
func TestDifferentNotesGiveDifferentNullifiers(t *testing.T) {
	key := [32]byte{7}
	a, b := goodNote(), goodNote()
	a.NullifierSeed = [32]byte{1}
	b.NullifierSeed = [32]byte{2}
	if a.Nullifier(key) == b.Nullifier(key) {
		t.Fatal("two notes share a nullifier")
	}
}

// Domain separation: the same secret used in different roles must not produce
// the same bytes. Without it, learning a value in one role hands over another.
func TestDerivationDomainsDoNotCollide(t *testing.T) {
	secret := [32]byte{42}
	nonce := [32]byte{43}
	seen := map[[32]byte]string{}
	candidates := map[string][32]byte{
		"nullifier": (func() [32]byte {
			n := goodNote()
			n.NullifierSeed = secret
			return [32]byte(n.Nullifier(nonce))
		})(),
		"owner":   OwnerCommitmentFor(secret, nonce),
		"keyhint": KeyHintFor(secret, nonce),
		"context": ContextCommitmentFor("stream:1", secret),
		"route":   RouteCommitmentFor([][32]byte{secret, nonce}),
	}
	for name, value := range candidates {
		if other, clash := seen[value]; clash {
			t.Errorf("%s and %s derive the same bytes", name, other)
		}
		seen[value] = name
	}
}

// Length-prefixing: derive("a","bc") must not equal derive("ab","c"). Without
// it two different inputs collide, which for a commitment means two different
// payments are indistinguishable to the thing meant to distinguish them.
func TestDerivationIsNotAmbiguousAcrossPartBoundaries(t *testing.T) {
	a := derive("d", []byte("a"), []byte("bc"))
	b := derive("d", []byte("ab"), []byte("c"))
	if a == b {
		t.Fatal("concatenation is ambiguous — parts are not length-prefixed")
	}
}

// The key hint must differ per note, or it is a stable identifier printed on
// every note a recipient receives.
func TestKeyHintDiffersPerNote(t *testing.T) {
	secret := [32]byte{5}
	if KeyHintFor(secret, [32]byte{1}) == KeyHintFor(secret, [32]byte{2}) {
		t.Fatal("the key hint is stable across notes — it is an identifier")
	}
}

// The placeholder commitment must be honest about what it cannot do, and the
// balance check must REFUSE rather than appear to succeed. A silent pass here
// would mean value created from nothing, undetectably.
func TestBalanceCheckRefusesANonHomomorphicScheme(t *testing.T) {
	s := HashCommitment{}
	if s.IsHomomorphic() {
		t.Fatal("the placeholder claims to be homomorphic")
	}
	err := CheckBalance(s, []Commitment{{1}}, []Commitment{{2}}, Commitment{3})
	if err == nil {
		t.Fatal("the balance check appeared to succeed on a non-homomorphic scheme")
	}
	if !errors.Is(err, ErrNotHomomorphic) {
		// It may report "not implemented" for a homomorphic scheme, but for
		// this one it must be the categorical refusal.
		t.Errorf("got %v, want ErrNotHomomorphic", err)
	}
	if err := CheckBalance(nil, nil, nil, Commitment{}); !errors.Is(err, ErrNotHomomorphic) {
		t.Error("a nil scheme was not refused")
	}
}

// Commitments must hide and bind: same inputs agree, any change differs.
func TestCommitmentBindsToValueAndBlinding(t *testing.T) {
	s := HashCommitment{}
	base := s.Commit(100, [32]byte{1})
	if s.Commit(100, [32]byte{1}) != base {
		t.Error("commitment is not deterministic")
	}
	if s.Commit(101, [32]byte{1}) == base {
		t.Error("commitment does not bind to the value")
	}
	if s.Commit(100, [32]byte{2}) == base {
		t.Error("commitment does not bind to the blinding")
	}
}

func TestValidateRejectsBadNotes(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*PrivatePaymentNote)
		want error
	}{
		{"wrong version", func(n *PrivatePaymentNote) { n.Version = 99 }, ErrNoteVersion},
		{"no expiry", func(n *PrivatePaymentNote) { n.ExpiresAt = 0 }, ErrNoteMalformed},
		{"expiry before creation", func(n *PrivatePaymentNote) {
			n.ExpiresAt = n.CreatedAt - 1
		}, ErrNoteMalformed},
		{"zero nonce", func(n *PrivatePaymentNote) { n.Nonce = [32]byte{} }, ErrNoteMalformed},
		{"already expired", func(n *PrivatePaymentNote) {
			n.ExpiresAt = uint64(noteNow.Add(-time.Second).Unix())
		}, ErrNoteExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := goodNote()
			tc.mut(&n)
			err := n.Validate(noteNow)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAValidNoteValidates(t *testing.T) {
	if err := goodNote().Validate(noteNow); err != nil {
		t.Fatalf("a good note was rejected: %v", err)
	}
}

// Expiry is re-checked at every hop, so it must be cheap and must not need
// decryption.
func TestExpiredIsCheckableWithoutOpeningTheNote(t *testing.T) {
	n := goodNote()
	if n.Expired(noteNow) {
		t.Error("a live note reported expired")
	}
	if !n.Expired(noteNow.Add(2 * time.Hour)) {
		t.Error("an expired note reported live")
	}
}
