// Package rendez is AXON's L5: two-stage service contact (R10).
//
// A client learns intro points from a blinded descriptor, sends a rendezvous
// request through one, and both sides meet at a rendezvous point neither hosts.
// Six relay hops plus the RP; no participant learns both endpoints' addresses.
//
// WHAT THE RP LEARNS, STATED FIRST because it is the price of the design. The RP
// is by construction a correlation point between the two legs: it sees both
// halves' volume and timing at zero cost (§18.8, T-L4-03). It cannot LOCATE
// either endpoint -- it holds two circuit ids and a cookie and nothing else --
// but it can confirm that this client leg and that service leg are one
// conversation. That is what is bought by not publishing service tunnel
// endpoints directly, and this package does not remove it.
//
// NOT BUILT HERE, per P6's "must NOT be built yet": pools of RPs, descriptor
// publication strategy (P7), client authorisation, and any bandwidth accounting
// at the RP.
package rendez

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Wire sizes from §9.5.
const (
	// CookieSize is the rendezvous cookie: 20 bytes, client-chosen.
	CookieSize = 20

	// IntroPlaintextSize is the FIXED size of INTRODUCE1's encrypted plaintext.
	//
	// It is fixed, and padded to, so the intro point cannot tell a fresh
	// introduction from a resumption, or an authorised client from a public
	// one, BY SIZE. A variable-length body would leak both through a field the
	// IP is allowed to see.
	IntroPlaintextSize = 512

	authKeySize = 32
	pubKeySize  = 32
	authTagSize = 32
)

// Domain-separation labels. Constants because a rename is a wire break.
const (
	introLabel    = "axon:intro:v1"
	rendKeySeed   = "axon:rend:keyseed:v1"
	rendAuthLabel = "axon:rend:auth:v1"
	rendProtoID   = "axon-rend-v1"
)

var (
	ErrPuzzleRequired = errors.New("axon/rendez: INTRODUCE1 carries no puzzle solution")
	ErrPuzzleInvalid  = errors.New("axon/rendez: puzzle solution does not verify")
	ErrUnknownAuthKey = errors.New("axon/rendez: no intro circuit registered for that auth key")
	ErrReplay         = errors.New("axon/rendez: cookie has already been used")
	ErrCookieUnknown  = errors.New("axon/rendez: no circuit established for that cookie")
	ErrRateLimited    = errors.New("axon/rendez: intro point is rate limiting")
	ErrPlaintextSize  = errors.New("axon/rendez: intro plaintext is not the fixed size")
	ErrAuthMismatch   = errors.New("axon/rendez: rendezvous AUTH does not verify")
	ErrLowOrderPoint  = errors.New("axon/rendez: X25519 output is all-zero")
	ErrAlreadySpliced = errors.New("axon/rendez: circuit is already spliced")
	ErrMalformed      = errors.New("axon/rendez: malformed body")
)

// Cookie is the 20-byte rendezvous cookie.
type Cookie [CookieSize]byte

// NewCookie draws a fresh cookie.
func NewCookie(rnd io.Reader) (Cookie, error) {
	var c Cookie
	if rnd == nil {
		rnd = rand.Reader
	}
	_, err := io.ReadFull(rnd, c[:])
	return c, err
}

// AckStatus is INTRODUCE_ACK's verdict.
type AckStatus uint8

const (
	AckOK AckStatus = iota
	AckRateLimited
	AckPuzzleRequired
	AckUnknownAuthKey
	AckReplay
)

func (s AckStatus) String() string {
	switch s {
	case AckOK:
		return "OK"
	case AckRateLimited:
		return "RATE_LIMITED"
	case AckPuzzleRequired:
		return "PUZZLE_REQUIRED"
	case AckUnknownAuthKey:
		return "UNKNOWN_AUTH_KEY"
	default:
		return "REPLAY"
	}
}

// -----------------------------------------------------------------------------
// INTRODUCE1
// -----------------------------------------------------------------------------

// IntroPlaintext is the part of INTRODUCE1 the intro point cannot read.
//
// Every field is fixed-width and the whole struct encodes to exactly
// IntroPlaintextSize bytes. Absent optional fields are ZEROED rather than
// omitted, so their presence does not change the length.
type IntroPlaintext struct {
	Cookie      Cookie
	RPRoutingID [32]byte
	RPOnionKey  [32]byte
	RPLinkHints [80]byte
	// ResumePresent and Session are §9.8's resumption; carried so the layout is
	// right, not interpreted here.
	ResumePresent bool
	SessionID     [16]byte
	SessionCtr    uint32
	SessionProof  [32]byte
	// ClientAuthProof is zeroed when absent (P6 does not build client auth).
	ClientAuthProof [32]byte
	FlowControl     uint16
}

// Encode writes the fixed-size plaintext.
func (p *IntroPlaintext) Encode() []byte {
	b := make([]byte, IntroPlaintextSize)
	o := 0
	o += copy(b[o:], p.Cookie[:])
	o += copy(b[o:], p.RPRoutingID[:])
	o += copy(b[o:], p.RPOnionKey[:])
	o += copy(b[o:], p.RPLinkHints[:])
	if p.ResumePresent {
		b[o] = 1
	}
	o++
	o += copy(b[o:], p.SessionID[:])
	binary.BigEndian.PutUint32(b[o:], p.SessionCtr)
	o += 4
	o += copy(b[o:], p.SessionProof[:])
	o += copy(b[o:], p.ClientAuthProof[:])
	binary.BigEndian.PutUint16(b[o:], p.FlowControl)
	// The remainder is padding, already zero. It is INSIDE the AEAD, so it is
	// not a channel, and it is what makes every introduction the same size.
	return b
}

// DecodeIntroPlaintext parses the fixed-size plaintext.
func DecodeIntroPlaintext(b []byte) (*IntroPlaintext, error) {
	if len(b) != IntroPlaintextSize {
		return nil, fmt.Errorf("%w: %d != %d", ErrPlaintextSize, len(b), IntroPlaintextSize)
	}
	p := &IntroPlaintext{}
	o := 0
	o += copy(p.Cookie[:], b[o:])
	o += copy(p.RPRoutingID[:], b[o:])
	o += copy(p.RPOnionKey[:], b[o:])
	o += copy(p.RPLinkHints[:], b[o:])
	p.ResumePresent = b[o] != 0
	o++
	o += copy(p.SessionID[:], b[o:])
	p.SessionCtr = binary.BigEndian.Uint32(b[o:])
	o += 4
	o += copy(p.SessionProof[:], b[o:])
	o += copy(p.ClientAuthProof[:], b[o:])
	p.FlowControl = binary.BigEndian.Uint16(b[o:])
	return p, nil
}

// Introduce1 is what the client sends to the intro point.
//
// Everything except Encrypted is visible to the IP -- it has to be, because the
// IP finds the circuit by AuthKeyID and checks the extensions itself.
type Introduce1 struct {
	Version   uint8
	AuthKeyID [authKeySize]byte
	// PuzzleProof is the R10 admission proof. Its FORMAT belongs to P6a; this
	// package carries it and hands it to a Verifier.
	PuzzleProof []byte
	// X is the client's ephemeral X25519 public key.
	X [pubKeySize]byte
	// Encrypted is IntroPlaintextSize + 16 bytes of tag.
	Encrypted []byte
}

// header is the AAD the encryption binds to: the fields the IP may read but must
// not be able to alter without breaking the service's decryption.
func (i *Introduce1) header() []byte {
	b := make([]byte, 0, 1+authKeySize+pubKeySize+2)
	b = append(b, i.Version)
	b = append(b, i.AuthKeyID[:]...)
	b = append(b, i.X[:]...)
	return binary.BigEndian.AppendUint16(b, uint16(len(i.Encrypted)))
}

// SealIntro encrypts the plaintext to the intro point's encryption key.
//
// The IP cannot read it: the key derives from X25519(x, B_enc) and the IP holds
// neither x nor b_enc. The header is the AAD, so an IP that rewrites AuthKeyID
// or X to redirect the introduction breaks the service's decryption rather than
// silently succeeding.
func SealIntro(rnd io.Reader, bEnc [32]byte, kSvc [32]byte, authKey [authKeySize]byte,
	subcredential [32]byte, pt *IntroPlaintext, puzzle []byte) (*Introduce1, [32]byte, error) {

	if rnd == nil {
		rnd = rand.Reader
	}
	var x [32]byte
	if _, err := io.ReadFull(rnd, x[:]); err != nil {
		return nil, x, err
	}
	xPub, err := curve25519.X25519(x[:], curve25519.Basepoint)
	if err != nil {
		return nil, x, err
	}
	var X [32]byte
	copy(X[:], xPub)

	shared, err := dh(x[:], bEnc[:])
	if err != nil {
		return nil, x, err
	}

	key, nonce, err := introKey(shared, kSvc, X, bEnc, authKey, subcredential)
	if err != nil {
		return nil, x, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, x, err
	}

	msg := &Introduce1{Version: 1, AuthKeyID: authKey, PuzzleProof: puzzle, X: X}
	msg.Encrypted = make([]byte, IntroPlaintextSize+chacha20poly1305.Overhead)
	msg.Encrypted = aead.Seal(msg.Encrypted[:0], nonce[:], pt.Encode(), msg.header())
	return msg, x, nil
}

// OpenIntro decrypts an INTRODUCE1 at the service.
func OpenIntro(bEncPriv [32]byte, bEnc [32]byte, kSvc [32]byte,
	subcredential [32]byte, msg *Introduce1) (*IntroPlaintext, error) {

	shared, err := dh(bEncPriv[:], msg.X[:])
	if err != nil {
		return nil, err
	}
	key, nonce, err := introKey(shared, kSvc, msg.X, bEnc, msg.AuthKeyID, subcredential)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce[:], msg.Encrypted, msg.header())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return DecodeIntroPlaintext(pt)
}

func introKey(shared [32]byte, kSvc, X, bEnc [32]byte, authKey [authKeySize]byte,
	subcredential [32]byte) (key [32]byte, nonce [chacha20poly1305.NonceSize]byte, err error) {

	ikm := make([]byte, 0, 32*4)
	ikm = append(ikm, shared[:]...)
	ikm = append(ikm, kSvc[:]...)
	ikm = append(ikm, X[:]...)
	ikm = append(ikm, bEnc[:]...)

	info := append([]byte(introLabel), subcredential[:]...)
	r := hkdf.New(sha256.New, ikm, authKey[:], info)
	out := make([]byte, 32+chacha20poly1305.NonceSize)
	if _, err = io.ReadFull(r, out); err != nil {
		return key, nonce, err
	}
	copy(key[:], out[:32])
	copy(nonce[:], out[32:])
	return key, nonce, nil
}

// -----------------------------------------------------------------------------
// Rendezvous handshake
// -----------------------------------------------------------------------------

// Handshake is RENDEZVOUS1's payload: the service's ephemeral key and its proof.
type Handshake struct {
	Y    [pubKeySize]byte
	Auth [authTagSize]byte
}

// ServiceRendezvous completes the service half and returns KEY_SEED plus the
// handshake to send.
//
// Only the holder of b_enc can produce a matching AUTH, which is what stops an
// intro point impersonating the service (T6.5): the IP forwards INTRODUCE1 and
// has neither b_enc nor any way to derive it.
func ServiceRendezvous(rnd io.Reader, bEncPriv, bEnc, kSvc [32]byte, X [32]byte) (
	keySeed [32]byte, hs Handshake, err error) {

	if rnd == nil {
		rnd = rand.Reader
	}
	var y [32]byte
	if _, err = io.ReadFull(rnd, y[:]); err != nil {
		return keySeed, hs, err
	}
	yPub, err := curve25519.X25519(y[:], curve25519.Basepoint)
	if err != nil {
		return keySeed, hs, err
	}
	copy(hs.Y[:], yPub)

	dh1, err := dh(y[:], X[:]) // X25519(y, X)
	if err != nil {
		return keySeed, hs, err
	}
	dh2, err := dh(bEncPriv[:], X[:]) // X25519(b_enc, X)
	if err != nil {
		return keySeed, hs, err
	}
	keySeed, hs.Auth = rendKeys(dh1, dh2, kSvc, bEnc, X, hs.Y)
	return keySeed, hs, nil
}

// ClientRendezvous verifies the service's AUTH and returns KEY_SEED.
func ClientRendezvous(x [32]byte, bEnc, kSvc [32]byte, X [32]byte, hs Handshake) ([32]byte, error) {
	dh1, err := dh(x[:], hs.Y[:]) // X25519(x, Y) == X25519(y, X)
	if err != nil {
		return [32]byte{}, err
	}
	dh2, err := dh(x[:], bEnc[:]) // X25519(x, B_enc) == X25519(b_enc, X)
	if err != nil {
		return [32]byte{}, err
	}
	keySeed, want := rendKeys(dh1, dh2, kSvc, bEnc, X, hs.Y)
	// Constant time: a variable-time compare leaks how many leading bytes of a
	// forged AUTH were right.
	if subtle.ConstantTimeCompare(want[:], hs.Auth[:]) != 1 {
		return [32]byte{}, ErrAuthMismatch
	}
	return keySeed, nil
}

func rendKeys(dh1, dh2, kSvc, bEnc, X, Y [32]byte) (keySeed [32]byte, auth [authTagSize]byte) {
	in := make([]byte, 0, 32*6+len(rendProtoID))
	for _, p := range [][32]byte{dh1, dh2, kSvc, bEnc, X, Y} {
		in = append(in, p[:]...)
	}
	in = append(in, []byte(rendProtoID)...)

	m := hmac.New(sha256.New, []byte(rendKeySeed))
	m.Write(in)
	copy(keySeed[:], m.Sum(nil))

	a := hmac.New(sha256.New, []byte(rendAuthLabel))
	a.Write(in)
	a.Write([]byte("server"))
	copy(auth[:], a.Sum(nil))
	return keySeed, auth
}

func dh(scalar, point []byte) ([32]byte, error) {
	out, err := curve25519.X25519(scalar, point)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrLowOrderPoint, err)
	}
	var zero, res [32]byte
	copy(res[:], out)
	if res == zero {
		return [32]byte{}, ErrLowOrderPoint
	}
	return res, nil
}
