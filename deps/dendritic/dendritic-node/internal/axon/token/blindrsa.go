package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// Chaum-style blind RSA — CANDIDATE A from §14.3's table.
//
// THIS IS A MEASUREMENT VEHICLE, NOT A PRODUCTION SIGNER, AND THE DISTINCTION
// IS NOT A DISCLAIMER.
//
// §14.3 says "the construction is not new and must not be invented here", and
// what is standardised is RFC 9474, which blinds RSASSA-PSS and specifies the
// message encoding, the blinding-factor sampling, and the checks an issuer must
// perform to avoid signing something it did not intend. What is implemented
// below is the classical RSA-FDH blind signature: correct in structure, and
// short of RFC 9474 in exactly the places a real deployment is attacked.
//
// It exists so that §14.3's open question can be SETTLED WITH NUMBERS rather
// than with a preference — the trade turns on token size against offline
// verifiability, and neither had been measured. Production must replace this
// with an RFC 9474 implementation, and `blindrsa_test.go` records what that
// implementation has to preserve.
//
// WHAT IS SHORT OF RFC 9474, NAMED:
//
//   - The full-domain hash is MGF1 over SHA-256 truncated below the modulus,
//     rather than PSS encoding. FDH is the classical Chaum construction and is
//     provably secure under the RSA assumption in the random-oracle model, but
//     RFC 9474 chose PSS and interop demands PSS.
//   - The issuer does NOT check that the blinded value is modulus-length.
//     RFC 9474 requires `len(blinded_msg) == modulus_len` and rejects anything
//     else; SignBlinded uses SetBytes, which is length-agnostic, so a 16-byte
//     and a 256-byte encoding of one value are both signed and produce the SAME
//     signature. Nothing is forged and no key leaks -- what is lost is interop
//     (a client written against the RFC passes here and fails elsewhere) and a
//     canonical request encoding for anything above that hashes or dedupes the
//     blinded bytes. Demonstrated in rfc9474_gap_test.go.
//
//     An earlier version of this list said there was "no blinding-factor
//     validity check on the issuer side". THAT WAS WRONG: SignBlinded rejects
//     values outside 0 < m < N and cites RFC 9474 for it. A gap list that
//     overstates a gap sends the next reader to write a check that exists, and
//     makes the entries that are accurate easier to disbelieve.
//   - Key generation is Go's, which is fine, but the epoch key SCHEDULE — how
//     long an epoch lasts and how keys are published — is not built here. It is
//     the parameter that sets the anonymity set's denominator and §14.3 leaves
//     it open.

// FDH expands a message to just under the modulus size, in MGF1 counter mode.
//
// Truncating to modBits-1 rather than to a whole number of bytes matters: an
// encoded value that can exceed the modulus is a value the signer reduces, and
// two messages that reduce to the same residue have the same signature.
func fdh(msg []byte, modBits int) *big.Int {
	outBits := modBits - 1
	outLen := (outBits + 7) / 8
	out := make([]byte, 0, outLen+sha256.Size)
	var ctr [4]byte
	for i := uint32(0); len(out) < outLen; i++ {
		binary.BigEndian.PutUint32(ctr[:], i)
		h := sha256.New()
		h.Write([]byte("axon-token-fdh-v1"))
		h.Write(msg)
		h.Write(ctr[:])
		out = h.Sum(out)
	}
	out = out[:outLen]
	// Clear the bits above outBits so the result is always < 2^(modBits-1) < N.
	if excess := outLen*8 - outBits; excess > 0 {
		out[0] &= byte(0xFF >> excess)
	}
	return new(big.Int).SetBytes(out)
}

// BlindRSAIssuer holds one RSA key per epoch.
type BlindRSAIssuer struct {
	mu   sync.RWMutex
	keys map[Epoch]*rsa.PrivateKey
}

// NewBlindRSAIssuer generates a key for one epoch. bits is the modulus size.
func NewBlindRSAIssuer(epoch Epoch, bits int) (*BlindRSAIssuer, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &BlindRSAIssuer{keys: map[Epoch]*rsa.PrivateKey{epoch: k}}, nil
}

// AddEpoch rotates in a new key.
func (i *BlindRSAIssuer) AddEpoch(epoch Epoch, bits int) error {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.keys[epoch] = k
	i.mu.Unlock()
	return nil
}

var errNoEpochKey = errors.New("axon/token: issuer holds no key for this epoch")

// SignBlinded raises the blinded value to d. The issuer sees only this value,
// which is uniformly random to it given a uniformly random blinding factor.
func (i *BlindRSAIssuer) SignBlinded(epoch Epoch, blinded []byte) ([]byte, error) {
	i.mu.RLock()
	k, ok := i.keys[epoch]
	i.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %d", errNoEpochKey, epoch)
	}
	m := new(big.Int).SetBytes(blinded)
	if m.Sign() <= 0 || m.Cmp(k.N) >= 0 {
		// RFC 9474 rejects out-of-range blinded values. So does this, because a
		// value >= N is a value the exponentiation reduces, and an issuer that
		// silently reduces is signing something the payer did not send.
		return nil, errors.New("axon/token: blinded value out of range")
	}
	s := new(big.Int).Exp(m, k.D, k.N)
	return leftPad(s.Bytes(), (k.N.BitLen()+7)/8), nil
}

// PublicVerifier returns the relay-side verifier. Blind RSA CAN produce one --
// that is its advantage under T2 and the reason the measurement settles the way
// it does.
func (i *BlindRSAIssuer) PublicVerifier() Verifier {
	i.mu.RLock()
	defer i.mu.RUnlock()
	pub := make(map[Epoch]*rsa.PublicKey, len(i.keys))
	for e, k := range i.keys {
		pub[e] = &k.PublicKey
	}
	return &BlindRSAVerifier{keys: pub}
}

// BlindRSAVerifier is what a relay holds: public keys only.
type BlindRSAVerifier struct {
	mu   sync.RWMutex
	keys map[Epoch]*rsa.PublicKey
}

// KnownEpoch reports whether the key is held locally.
func (v *BlindRSAVerifier) KnownEpoch(e Epoch) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.keys[e]
	return ok
}

// Verify is one public exponentiation, entirely local. T2.
func (v *BlindRSAVerifier) Verify(e Epoch, msg, sig []byte) bool {
	v.mu.RLock()
	k, ok := v.keys[e]
	v.mu.RUnlock()
	if !ok {
		return false
	}
	s := new(big.Int).SetBytes(sig)
	if s.Sign() <= 0 || s.Cmp(k.N) >= 0 {
		return false
	}
	m := new(big.Int).Exp(s, big.NewInt(int64(k.E)), k.N)
	return m.Cmp(fdh(msg, k.N.BitLen())) == 0
}

// SigSize is the modulus size in bytes.
func (v *BlindRSAVerifier) SigSize() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, k := range v.keys {
		return (k.N.BitLen() + 7) / 8
	}
	return 0
}

// Blinding is the payer's secret for one token.
type Blinding struct {
	r    *big.Int
	rInv *big.Int
	n    *big.Int
}

// Blind produces the value the issuer signs, and the secret to unblind with.
//
// The blinding factor must be sampled uniformly from the units mod N and must
// be FRESH PER TOKEN. Reusing one across two tokens makes the two linkable to
// each other, which is the one thing the whole construction is for.
func Blind(pub *rsa.PublicKey, msg []byte) ([]byte, *Blinding, error) {
	for attempt := 0; attempt < 16; attempt++ {
		r, err := rand.Int(rand.Reader, pub.N)
		if err != nil {
			return nil, nil, err
		}
		if r.Sign() == 0 {
			continue
		}
		rInv := new(big.Int).ModInverse(r, pub.N)
		if rInv == nil {
			// gcd(r, N) != 1. Astronomically unlikely and also a factor of N,
			// so it is retried rather than used.
			continue
		}
		m := fdh(msg, pub.N.BitLen())
		re := new(big.Int).Exp(r, big.NewInt(int64(pub.E)), pub.N)
		blinded := new(big.Int).Mod(new(big.Int).Mul(m, re), pub.N)
		return leftPad(blinded.Bytes(), (pub.N.BitLen()+7)/8),
			&Blinding{r: r, rInv: rInv, n: pub.N}, nil
	}
	return nil, nil, errors.New("axon/token: could not sample a blinding factor")
}

// Unblind recovers the signature on the original message.
func Unblind(blindSig []byte, b *Blinding) []byte {
	s := new(big.Int).SetBytes(blindSig)
	out := new(big.Int).Mod(new(big.Int).Mul(s, b.rInv), b.n)
	return leftPad(out.Bytes(), (b.n.BitLen()+7)/8)
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
