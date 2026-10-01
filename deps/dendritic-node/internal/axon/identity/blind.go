package identity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/edwards25519"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// Ed25519 key blinding for descriptor keys (section 5.4).
//
// What it buys: a DHT node holding a descriptor learns the blinded key A', an
// index derived from it, and an encrypted blob. It cannot tell which service
// the descriptor belongs to, cannot link this period's descriptor to last
// period's, and cannot serve it to a client who does not already know the
// service.
//
// This is a reimplementation of the construction Tor uses for v3 onion
// services, not a port of its code.
//
// The security note from the roadmap that shapes this file: an implementation
// that blinds the public key correctly but leaks the unblinded key through the
// signature nonce is catastrophic AND passes a naive round-trip test. That is
// why the nonce prefix is itself derived under its own label (see blindPrefix)
// rather than reused from the unblinded key, and why the tests check scalar
// arithmetic directly rather than only that verification succeeds.

// BlindedPub is a period-scoped public key. It verifies signatures made by the
// matching BlindedSigner and by nothing else.
type BlindedPub ed25519.PublicKey

// PeriodNumber returns the time period a given instant falls in.
func PeriodNumber(t time.Time) uint64 {
	if t.Unix() < 0 {
		return 0
	}
	return uint64(t.Unix()) / params.PeriodLengthSeconds
}

// blindingFactor computes the clamped, reduced scalar h for a period.
//
// clientAuth is the optional client-authorisation secret; it is empty in v1 and
// present in the signature so that adding it later is not a wire change.
func blindingFactor(pub ed25519.PublicKey, period uint64, clientAuth []byte) (*edwards25519.Scalar, error) {
	ctx := make([]byte, 0, 16+len(clientAuth))
	ctx = append(ctx, u64be(period)...)
	ctx = append(ctx, u64be(params.PeriodLengthSeconds)...)
	ctx = append(ctx, clientAuth...)

	raw := derive(LabelDescriptorBlind, pub, ctx, 32)

	// Clamp exactly as section 5.4 specifies. Note h[31] &= 63, not 127: the
	// value is kept below 2^254 so that the subsequent reduction is over a
	// comfortably bounded input.
	raw[0] &= 248
	raw[31] &= 63
	raw[31] |= 64

	// Reduce mod L. SetUniformBytes takes 64 little-endian bytes and reduces,
	// so the 32-byte clamped value is zero-extended. edwards25519 owns the
	// modular arithmetic; this package does not implement field operations.
	var wide [64]byte
	copy(wide[:32], raw)
	h, err := edwards25519.NewScalar().SetUniformBytes(wide[:])
	if err != nil {
		return nil, fmt.Errorf("identity: blinding factor: %w", err)
	}
	return h, nil
}

// Blind derives the period-scoped public key A' = h*A.
//
// It needs no secret, which is the property that lets a client compute the DHT
// index for a service it wants to reach while holding only the service's public
// identity.
func Blind(pub ed25519.PublicKey, period uint64) (BlindedPub, error) {
	return BlindWithAuth(pub, period, nil)
}

// BlindWithAuth is Blind with a client-authorisation secret mixed in.
func BlindWithAuth(pub ed25519.PublicKey, period uint64, clientAuth []byte) (BlindedPub, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("identity: blind: bad public key length")
	}
	h, err := blindingFactor(pub, period, clientAuth)
	if err != nil {
		return nil, err
	}
	A, err := (&edwards25519.Point{}).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("identity: blind: decode public key: %w", err)
	}
	// A' = h*A. Since A = a*B, this equals (h*a)*B, which is exactly the public
	// key of the blinded private scalar computed in BlindSigner.
	Aprime := (&edwards25519.Point{}).ScalarMult(h, A)
	return BlindedPub(Aprime.Bytes()), nil
}

// BlindedSigner signs under a blinded key. It implements crypto.Signer so that
// callers hold an interface rather than raw scalars.
type BlindedSigner struct {
	scalar *edwards25519.Scalar // a' = h*a mod L
	prefix [32]byte             // nonce prefix, derived under its own label
	public BlindedPub
}

// Public returns A'.
func (s *BlindedSigner) Public() crypto.PublicKey { return ed25519.PublicKey(s.public) }

// BlindSigner derives the signer for a period from a service's private key.
func BlindSigner(priv ed25519.PrivateKey, period uint64) (*BlindedSigner, error) {
	return BlindSignerWithAuth(priv, period, nil)
}

// BlindSignerWithAuth is BlindSigner with a client-authorisation secret.
func BlindSignerWithAuth(priv ed25519.PrivateKey, period uint64, clientAuth []byte) (*BlindedSigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("identity: blind signer: bad private key length")
	}
	pub := priv.Public().(ed25519.PublicKey)

	// Recover the Ed25519 scalar a and nonce prefix from the seed, per RFC 8032.
	digest := sha512.Sum512(priv.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(digest[:32])
	if err != nil {
		return nil, fmt.Errorf("identity: blind signer: clamp scalar: %w", err)
	}

	h, err := blindingFactor(pub, period, clientAuth)
	if err != nil {
		return nil, err
	}

	// a' = h * a mod L
	aPrime := edwards25519.NewScalar().Multiply(h, a)

	// The nonce prefix must NOT be the unblinded prefix: reusing it across
	// periods would tie two blinded keys together through their nonces, which
	// is precisely the linkage blinding exists to prevent. Derive it under its
	// own label from the unblinded prefix.
	blinded := sha512Prefixed(LabelBlindNonce, digest[32:])
	var prefix [32]byte
	copy(prefix[:], blinded[:32])

	APrime := (&edwards25519.Point{}).ScalarBaseMult(aPrime)

	return &BlindedSigner{
		scalar: aPrime,
		prefix: prefix,
		public: BlindedPub(APrime.Bytes()),
	}, nil
}

// Sign produces an Ed25519 signature under the blinded key, following RFC 8032
// with the blinded scalar in place of the derived one.
//
// crypto.Signer's rand and opts are ignored: Ed25519 signing is deterministic,
// and accepting a caller-supplied nonce source here would be a footgun.
func (s *BlindedSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.SignMessage(message), nil
}

// SignMessage is the concrete-typed form of Sign.
func (s *BlindedSigner) SignMessage(message []byte) []byte {
	// r = SHA-512(prefix' ‖ M) mod L
	hr := sha512.New()
	hr.Write(s.prefix[:])
	hr.Write(message)
	var rWide [64]byte
	copy(rWide[:], hr.Sum(nil))
	r, err := edwards25519.NewScalar().SetUniformBytes(rWide[:])
	if err != nil {
		panic("identity: blinded sign: nonce reduce: " + err.Error())
	}

	// R = r*B
	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	// k = SHA-512(R ‖ A' ‖ M) mod L
	hk := sha512.New()
	hk.Write(R.Bytes())
	hk.Write(s.public)
	hk.Write(message)
	var kWide [64]byte
	copy(kWide[:], hk.Sum(nil))
	k, err := edwards25519.NewScalar().SetUniformBytes(kWide[:])
	if err != nil {
		panic("identity: blinded sign: challenge reduce: " + err.Error())
	}

	// S = r + k*a' mod L
	S := edwards25519.NewScalar().MultiplyAdd(k, s.scalar, r)

	sig := make([]byte, 0, ed25519.SignatureSize)
	sig = append(sig, R.Bytes()...)
	sig = append(sig, S.Bytes()...)
	return sig
}

// SignPrefixed signs under a domain separator, matching signPrefixed.
func (s *BlindedSigner) SignPrefixed(label string, message []byte) []byte {
	buf := make([]byte, 0, len(label)+1+len(message))
	buf = append(buf, label...)
	buf = append(buf, 0x00)
	buf = append(buf, message...)
	return s.SignMessage(buf)
}

// ---------------------------------------------------------------------------
// Credentials and the descriptor index
// ---------------------------------------------------------------------------

// Credential is SHA-256("AXON-credential-v1" ‖ 0x00 ‖ A).
func Credential(pub ed25519.PublicKey) [32]byte {
	return sha256Prefixed(LabelCredential, pub)
}

// Subcredential binds a credential to a period's blinded key, so that keys
// derived for one period cannot decrypt another period's descriptor.
func Subcredential(pub ed25519.PublicKey, blinded BlindedPub) [32]byte {
	cred := Credential(pub)
	return sha256Prefixed(LabelSubcredential, cred[:], blinded)
}

// DescriptorIndex is the DHT key a descriptor is stored under. It is derived
// from the blinded key rather than the service key, so the storing node learns
// neither the service nor a value it could link across periods.
func DescriptorIndex(blinded BlindedPub, srv [32]byte, period uint64) [32]byte {
	return sha256Prefixed(LabelHSDirIndex, blinded, srv[:], u64be(period))
}

// randomSeed is used only by tests that need an independent service key.
func randomSeed() ([]byte, error) {
	b := make([]byte, ed25519.SeedSize)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}
