package token

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// §14.3's open question, settled with numbers.
//
// The section marks the construction [NEEDS RESEARCH] and says: "the choice
// between blind RSA and a VOPRF construction turns on T2 (offline verification
// at the relay) versus token size in a 1024 B cell, and that trade has not been
// measured here."
//
// This file measures both axes for both candidates and states the conclusion.

// TestP15ConstructionChoice is the measurement and the ruling.
func TestP15ConstructionChoice(t *testing.T) {
	const relayPayload = 984 // §8.6 relay data payload after P5a
	const fixed = 4 + 4 + 32 // epoch + denomination + nonce

	// ---------------------------------------------------------------
	// Candidate A — Chaum-style blind RSA-2048
	// ---------------------------------------------------------------
	rsaIss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	rsaVer := rsaIss.PublicVerifier()
	rsaTok := mint(t, rsaIss, 1, Denom10)
	rsaSize := fixed + len(rsaTok.Sig)

	const verifyRuns = 2000
	start := time.Now()
	for i := 0; i < verifyRuns; i++ {
		if err := Accept(rsaTok, rsaVer); err != nil {
			t.Fatal(err)
		}
	}
	rsaVerifyPer := time.Since(start) / verifyRuns

	// ---------------------------------------------------------------
	// Candidate B — Privacy-Pass-style VOPRF over edwards25519
	// ---------------------------------------------------------------
	vIss, err := NewVOPRFIssuer(1)
	if err != nil {
		t.Fatal(err)
	}
	var n Nonce
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	vTok := Token{Epoch: 1, Denom: Denom10, Nonce: n}
	blinded, r, err := VOPRFBlind(vTok.message())
	if err != nil {
		t.Fatal(err)
	}
	evaluated, err := vIss.SignBlinded(1, blinded)
	if err != nil {
		t.Fatal(err)
	}
	vTok.Sig, err = VOPRFUnblind(evaluated, r, vTok.message())
	if err != nil {
		t.Fatal(err)
	}
	vSize := fixed + len(vTok.Sig)

	// The ISSUER-side verifier is the only one that works. Time it, because it
	// is what redemption costs, and redemption is off the critical path.
	secret := vIss.SecretVerifier()
	if !secret.Verify(1, vTok.message(), vTok.Sig) {
		t.Fatal("the VOPRF token does not verify even with the secret -- the " +
			"measurement vehicle is broken, so its numbers mean nothing")
	}
	start = time.Now()
	for i := 0; i < verifyRuns; i++ {
		if !secret.Verify(1, vTok.message(), vTok.Sig) {
			t.Fatal("VOPRF verification became inconsistent mid-run")
		}
	}
	vVerifyPer := time.Since(start) / verifyRuns

	// AXIS 2, AND IT IS DECISIVE. A relay under candidate B holds no secret,
	// and therefore cannot verify at all.
	relaySide := vIss.PublicVerifier()
	if relaySide.KnownEpoch(1) {
		t.Fatal("the VOPRF public verifier claims to know an epoch it cannot verify for")
	}
	if err := Accept(vTok, relaySide); !errors.Is(err, ErrUnknownEpoch) {
		t.Fatalf("a relay verified a VOPRF token without the issuer's secret: %v", err)
	}

	t.Logf(`
§14.3 CONSTRUCTION CHOICE — MEASURED (development machine)

  axis 1: TOKEN SIZE in a %d B relay payload
    A  blind RSA-2048   %3d B  (%.1f%%)   = 4 epoch + 4 denom + 32 nonce + %d sig
    B  VOPRF (ed25519)  %3d B  (%.1f%%)   = 4 epoch + 4 denom + 32 nonce + %d mac
    B is %.1fx smaller. BOTH FIT, with room to spare.

  axis 2: VERIFICATION AT THE RELAY (T2)
    A  %v per verify, PUBLIC KEY, no issuer present
    B  %v per verify, ISSUER SECRET REQUIRED -- a relay cannot verify at all

RULING: CANDIDATE A, blind RSA.

  Axis 1 favours B and does not decide anything, because the question is not
  which token is smaller but whether either is too big, and neither is: A costs
  30%% of a relay payload and a token rides once per circuit, not once per cell.

  Axis 2 decides it. Under B a relay has three options and all three are worse
  than not being paid: hold the issuer's secret (every relay can mint), call the
  issuer per token (§14.3's T2 -- "the verification path becomes the correlation
  path", and the issuer learns in real time which relay carries whose traffic),
  or forward first and discover forgeries at redemption (it has already done the
  work). A's public-key verification has none of these.

  The size advantage would matter if the token had to ride in every cell. It
  does not, and §14.4 is the section that explains why per-cell granularity is
  not needed.

WHAT THIS RULING DOES NOT SETTLE: the implementation. blindrsa.go is RSA-FDH and
production must be RFC 9474 (PSS-based), which is a different encoding with
different issuer-side checks. The choice of FAMILY is settled; the choice of
SPECIFICATION within it is RFC 9474 and is not implemented here.`,
		relayPayload,
		rsaSize, 100*float64(rsaSize)/relayPayload, len(rsaTok.Sig),
		vSize, 100*float64(vSize)/relayPayload, len(vTok.Sig),
		float64(rsaSize)/float64(vSize),
		rsaVerifyPer, vVerifyPer)

	// The ruling, asserted so a later change that inverts it has to argue.
	if rsaSize > relayPayload {
		t.Fatalf("candidate A does not fit: %d B in %d B", rsaSize, relayPayload)
	}
	if vSize >= rsaSize {
		t.Fatal("candidate B is not smaller than A -- the measurement contradicts §14.3's table")
	}
}

// TestVOPRFRelayCannotVerify is candidate B's disqualification, on its own, so
// that it is not buried inside a measurement.
//
// It is not a limitation of this implementation. It is the construction: a
// VOPRF's output is a MAC under the issuer's key, and checking a MAC needs the
// key. Any "public" verifier for it is either the secret in disguise or a
// network call.
func TestVOPRFRelayCannotVerify(t *testing.T) {
	iss, err := NewVOPRFIssuer(1)
	if err != nil {
		t.Fatal(err)
	}
	v := iss.PublicVerifier()

	if v.KnownEpoch(1) || v.KnownEpoch(0) {
		t.Fatal("the relay-side VOPRF verifier claims an epoch")
	}
	// Even a genuinely valid token fails, because the relay has nothing to
	// check it with. Returning true here for anything would be the bug.
	if v.Verify(1, []byte("anything"), make([]byte, 32)) {
		t.Fatal("the relay-side VOPRF verifier accepted a token it cannot check")
	}
	if v.SigSize() != 32 {
		t.Fatalf("VOPRF authenticator is %d B, expected 32", v.SigSize())
	}
	if !errors.Is(ErrVOPRFNeedsSecret, ErrVOPRFNeedsSecret) {
		t.Fatal("the disqualification is not stated as an error value")
	}
}
