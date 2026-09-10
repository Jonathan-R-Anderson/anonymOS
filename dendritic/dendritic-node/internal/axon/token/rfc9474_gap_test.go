package token

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// D4 / 5.3 — the distance between this implementation and RFC 9474, measured.
//
// blindrsa.go names its own shortfalls, which is right, and this file checks
// them against the code rather than trusting the comment. Two corrections came
// out of doing so, and both are the kind that make a gap list untrustworthy:
// one gap listed is narrower than stated, and one real gap was not listed.

// TestTheIssuerDoesRangeCheck corrects the file's own account.
//
// blindrsa.go says there is "no blinding-factor validity check on the issuer
// side". There is one: SignBlinded rejects values outside 0 < m < N, citing
// RFC 9474 for it. A gap list that overstates a gap is not harmless -- it sends
// the next person to write a check that already exists, and it makes the
// remaining entries easier to disbelieve.
func TestTheIssuerDoesRangeCheck(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := iss.PublicVerifier().(*BlindRSAVerifier)
	n := pub.keys[1].N

	if _, err := iss.SignBlinded(1, big.NewInt(0).Bytes()); err == nil {
		t.Fatal("a zero blinded value was signed")
	}
	if _, err := iss.SignBlinded(1, n.Bytes()); err == nil {
		t.Fatal("a blinded value equal to N was signed; the exponentiation would " +
			"reduce it and the issuer would be signing something the payer did " +
			"not send")
	}
	over := new(big.Int).Add(n, big.NewInt(1))
	if _, err := iss.SignBlinded(1, over.Bytes()); err == nil {
		t.Fatal("a blinded value above N was signed")
	}
}

// TestTheIssuerAcceptsNonCanonicalEncodings is the gap that was NOT listed.
//
// RFC 9474 requires the issuer to check `len(blinded_msg) == modulus_len` and
// reject anything else. This implementation does `SetBytes`, which is
// length-agnostic, so a short encoding and a zero-padded one are the same
// integer and both are signed.
//
// WHY IT MATTERS AND WHY IT IS NOT A BREAK. The signature returned is identical
// either way, so nothing is forged and no key leaks. What breaks is INTEROP and
// canonicality: an RFC 9474 issuer refuses what this one accepts, so a client
// written against the RFC and tested against this issuer would pass here and
// fail in production; and any protocol layer above that hashes or dedupes the
// blinded bytes sees two distinct representations of one request.
func TestTheIssuerAcceptsNonCanonicalEncodings(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := iss.PublicVerifier().(*BlindRSAVerifier)
	modLen := (pub.keys[1].N.BitLen() + 7) / 8

	raw := make([]byte, 16) // deliberately far shorter than the modulus
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	short := new(big.Int).SetBytes(raw)

	padded := make([]byte, modLen)
	copy(padded[modLen-len(short.Bytes()):], short.Bytes())

	a, err := iss.SignBlinded(1, short.Bytes())
	if err != nil {
		t.Fatalf("the short encoding was refused: %v", err)
	}
	b, err := iss.SignBlinded(1, padded)
	if err != nil {
		t.Fatalf("the padded encoding was refused: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("the two encodings produced different signatures, which would be " +
			"a much worse bug than the one this test documents")
	}
	if len(short.Bytes()) == modLen {
		t.Skip("the random value happened to be modulus-length")
	}
	t.Logf("D4 confirmed: a %d-byte and a %d-byte encoding of one blinded value "+
		"are both signed, identically. RFC 9474 requires len(blinded_msg) == %d "+
		"and rejects the rest. Nothing is forged; what is lost is interop and a "+
		"canonical request encoding.", len(short.Bytes()), modLen, modLen)
}

// TestFDHIsNotPSS keeps the headline gap from being forgotten.
//
// This is the one that makes the implementation non-interoperable outright: RFC
// 9474 encodes with PSS and this encodes with a full-domain hash. FDH is the
// classical Chaum construction and is provably secure under RSA in the random
// oracle model -- it is not weak, it is DIFFERENT, and a token issued here
// verifies nowhere else.
func TestFDHIsNotPSS(t *testing.T) {
	a := fdh([]byte("message"), 2048)
	b := fdh([]byte("message"), 2048)
	if a.Cmp(b) != 0 {
		t.Fatal("fdh is not deterministic")
	}
	if a.BitLen() >= 2048 {
		t.Fatalf("fdh output is %d bits, at or above the modulus; a value the "+
			"signer reduces makes two messages share a signature", a.BitLen())
	}
	// PSS is randomised; FDH is not. A single call telling them apart is the
	// cheapest possible reminder that these are different constructions.
	c := fdh([]byte("message2"), 2048)
	if a.Cmp(c) == 0 {
		t.Fatal("two different messages hashed identically")
	}
}
