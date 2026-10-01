package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"sync"

	"filippo.io/edwards25519"
)

// Privacy-Pass-style VOPRF — CANDIDATE B from §14.3's table.
//
// It is here to be MEASURED AGAINST candidate A, not to be adopted. §14.3's
// open question is whether the smaller token is worth what it costs, and the
// cost is T2: verification needs the issuer's secret.
//
// THE MECHANISM, so the cost is visible rather than asserted. The issuer holds a
// scalar k. The payer hashes its nonce to a group element T, blinds it as rT for
// a random r, and sends rT. The issuer returns k(rT). The payer unblinds to kT
// and keeps (nonce, kT). At spend, the payer presents (nonce, MAC) where the MAC
// is derived from kT.
//
// A relay handed that pair can do exactly nothing with it. To check the MAC it
// must recompute kT, which needs k. So one of three things must happen and all
// three are bad:
//
//	the relay holds k          -- then every relay can mint tokens
//	the relay asks the issuer  -- a network call per cell, which is T2's
//	                              "the verification path becomes the correlation
//	                              path": the issuer learns, in real time, which
//	                              relay carries whose traffic
//	the relay does not verify  -- it forwards for forged tokens and finds out at
//	                              redemption, having already done the work
//
// This file therefore implements Issuer but its Verifier REFUSES to verify
// without the secret, and that refusal is the measurement's result rather than
// an unfinished corner. See voprf_test.go.

// VOPRFIssuer holds one scalar per epoch.
type VOPRFIssuer struct {
	mu   sync.RWMutex
	keys map[Epoch]*edwards25519.Scalar
}

// NewVOPRFIssuer generates a key for one epoch.
func NewVOPRFIssuer(epoch Epoch) (*VOPRFIssuer, error) {
	k, err := randomScalar()
	if err != nil {
		return nil, err
	}
	return &VOPRFIssuer{keys: map[Epoch]*edwards25519.Scalar{epoch: k}}, nil
}

func randomScalar() (*edwards25519.Scalar, error) {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return edwards25519.NewScalar().SetUniformBytes(b[:])
}

// hashToPoint maps a message to a group element.
//
// It is the cheap construction (hash, then interpret as a uniform scalar times
// the base point) rather than a proper hash-to-curve. That is adequate for
// SIZING and TIMING, which is all this file is for, and inadequate for a real
// OPRF: the discrete log of the resulting point is known to whoever computed
// it, which breaks the OPRF's one-more-token security. Stated rather than left
// for a reader to discover.
func hashToPoint(msg []byte) (*edwards25519.Point, error) {
	h := sha512.Sum512(append([]byte("axon-token-voprf-h2p-v1"), msg...))
	s, err := edwards25519.NewScalar().SetUniformBytes(h[:])
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).ScalarBaseMult(s), nil
}

// SignBlinded evaluates the OPRF on the blinded element.
func (i *VOPRFIssuer) SignBlinded(epoch Epoch, blinded []byte) ([]byte, error) {
	i.mu.RLock()
	k, ok := i.keys[epoch]
	i.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %d", errNoEpochKey, epoch)
	}
	p, err := new(edwards25519.Point).SetBytes(blinded)
	if err != nil {
		return nil, fmt.Errorf("axon/token: blinded element is not a group element: %w", err)
	}
	return new(edwards25519.Point).ScalarMult(k, p).Bytes(), nil
}

// PublicVerifier returns a verifier that CANNOT VERIFY. That is the finding.
func (i *VOPRFIssuer) PublicVerifier() Verifier { return voprfPublicVerifier{} }

// ErrVOPRFNeedsSecret is candidate B's disqualification under T2, as an error
// rather than as a paragraph.
var ErrVOPRFNeedsSecret = errors.New(
	"axon/token: VOPRF verification requires the issuer's secret; a relay cannot verify offline (T2)")

// voprfPublicVerifier is what a relay would hold under candidate B: nothing
// useful.
type voprfPublicVerifier struct{}

func (voprfPublicVerifier) KnownEpoch(Epoch) bool { return false }

// Verify always returns false. It is not a stub — it is the accurate answer.
// A relay holding no secret cannot distinguish a valid token from a forged one,
// and returning true for anything would be the bug this file exists to
// demonstrate is unavoidable.
func (voprfPublicVerifier) Verify(Epoch, []byte, []byte) bool { return false }

// SigSize is the token's authenticator size: a 32-byte MAC.
func (voprfPublicVerifier) SigSize() int { return 32 }

// VOPRFSecretVerifier is the ISSUER-SIDE verifier. It exists so redemption can
// be timed, and its existence is the point: under candidate B this is the only
// verifier there is.
type VOPRFSecretVerifier struct {
	mu   sync.RWMutex
	keys map[Epoch]*edwards25519.Scalar
}

// SecretVerifier exposes the issuer-side verifier.
func (i *VOPRFIssuer) SecretVerifier() *VOPRFSecretVerifier {
	i.mu.RLock()
	defer i.mu.RUnlock()
	keys := make(map[Epoch]*edwards25519.Scalar, len(i.keys))
	for e, k := range i.keys {
		keys[e] = k
	}
	return &VOPRFSecretVerifier{keys: keys}
}

func (v *VOPRFSecretVerifier) KnownEpoch(e Epoch) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.keys[e]
	return ok
}

func (v *VOPRFSecretVerifier) SigSize() int { return 32 }

// Verify recomputes kT from the message and checks the MAC.
func (v *VOPRFSecretVerifier) Verify(e Epoch, msg, mac []byte) bool {
	v.mu.RLock()
	k, ok := v.keys[e]
	v.mu.RUnlock()
	if !ok {
		return false
	}
	t, err := hashToPoint(msg)
	if err != nil {
		return false
	}
	kt := new(edwards25519.Point).ScalarMult(k, t)
	return hmac.Equal(mac, voprfMAC(kt, msg))
}

func voprfMAC(kt *edwards25519.Point, msg []byte) []byte {
	m := hmac.New(sha512.New, kt.Bytes())
	m.Write([]byte("axon-token-voprf-mac-v1"))
	m.Write(msg)
	return m.Sum(nil)[:32]
}

// VOPRFBlind blinds a message for issuance.
func VOPRFBlind(msg []byte) ([]byte, *edwards25519.Scalar, error) {
	t, err := hashToPoint(msg)
	if err != nil {
		return nil, nil, err
	}
	r, err := randomScalar()
	if err != nil {
		return nil, nil, err
	}
	return new(edwards25519.Point).ScalarMult(r, t).Bytes(), r, nil
}

// VOPRFUnblind recovers kT and derives the token's MAC.
func VOPRFUnblind(evaluated []byte, r *edwards25519.Scalar, msg []byte) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(evaluated)
	if err != nil {
		return nil, err
	}
	rInv := edwards25519.NewScalar().Invert(r)
	kt := new(edwards25519.Point).ScalarMult(rInv, p)
	return voprfMAC(kt, msg), nil
}
